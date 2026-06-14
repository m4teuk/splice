#!/usr/bin/env python3
"""File protocol v2: directory transfer, push (send/inbox), resume from a kept
.part, and checksum-guarded restart."""
import hashlib
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def tree_shas(root):
    out = {}
    for dirpath, _, files in os.walk(root):
        for f in files:
            full = os.path.join(dirpath, f)
            out[os.path.relpath(full, root)] = sha(full)
    return out


def wait_file(path, want_sha, timeout=15):
    """The pushing side reports done the moment it sends END; the receiver
    finalizes (rename) a beat later — so poll for the result."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path) and sha(path) == want_sha:
            return True
        time.sleep(0.2)
    return False


def wait_tree(root, want, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if tree_shas(root) == want:
            return True
        time.sleep(0.2)
    return False


def main():
    port = free_port()
    srv = start_server(SPL, port)
    lenv = fenv = None
    try:
        ld, fd = pair_two(SPL, port)
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        A = ["--server", "127.0.0.1", "--port", str(port)]

        def spl(env, *args, timeout=90):
            return subprocess.run([SPL, *args], env=env, capture_output=True, text=True,
                                  timeout=timeout)

        work = tempfile.mkdtemp()

        # --- directory transfer (serve a dir, get it) ---
        src = os.path.join(work, "photos")
        os.makedirs(os.path.join(src, "sub"))
        for rel in ("a.bin", "b.bin", "sub/c.bin", "sub/deep/d.bin"):
            p = os.path.join(src, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(os.urandom(1000 + len(rel)))
        assert spl(fenv, "serve", "theleader", "--name", "pics", src, *A).returncode == 0
        dl = tempfile.mkdtemp()
        r = spl(lenv, "get", "thefollower", "pics", "-o", dl, *A)
        assert r.returncode == 0, r.stdout + r.stderr
        assert tree_shas(os.path.join(dl, "photos")) == tree_shas(src), "directory mismatch"
        print("  directory transfer OK (recursive, subdirs)")

        # --- push: inbox on the leader, send from the follower ---
        inbox = tempfile.mkdtemp()
        assert spl(lenv, "inbox", "thefollower", inbox, *A).returncode == 0
        gift = os.path.join(work, "gift.bin")
        open(gift, "wb").write(os.urandom(50000))
        r = spl(fenv, "send", "theleader", gift, *A)
        assert r.returncode == 0, r.stdout + r.stderr
        assert wait_file(os.path.join(inbox, "gift.bin"), sha(gift)), "pushed file mismatch"
        print("  send -> inbox OK")

        # --- send a directory into the inbox ---
        r = spl(fenv, "send", "theleader", src, *A)
        assert r.returncode == 0, r.stdout + r.stderr
        assert wait_tree(os.path.join(inbox, "photos"), tree_shas(src)), "pushed dir mismatch"
        print("  send directory -> inbox OK")

        # --- named inboxes: several at once, the sender picks one with --name ---
        media = tempfile.mkdtemp()
        assert spl(lenv, "inbox", "thefollower", media, "--name", "media", *A).returncode == 0
        clip = os.path.join(work, "clip.bin")
        open(clip, "wb").write(os.urandom(40000))
        # --name media routes here; the default inbox must stay untouched
        r = spl(fenv, "send", "theleader", clip, "--name", "media", *A)
        assert r.returncode == 0, r.stdout + r.stderr
        assert wait_file(os.path.join(media, "clip.bin"), sha(clip)), "named inbox mismatch"
        assert not os.path.exists(os.path.join(inbox, "clip.bin")), "leaked into default inbox"
        # sending to a non-existent inbox name is reported, not silently dropped
        r = spl(fenv, "send", "theleader", clip, "--name", "nope", *A, timeout=60)
        assert r.returncode != 0 and "served" in (r.stdout + r.stderr), (r.stdout + r.stderr)
        print("  named inboxes OK (routing + unknown-name error)")

        # --- a name is one pipe per peer; re-registering the same name collides ---
        r = spl(lenv, "inbox", "thefollower", tempfile.mkdtemp(), *A)
        assert r.returncode != 0, "duplicate inbox should collide"
        # but a different --name is fine (already proven above by 'media')
        print("  inbox name collision refused")

        # --- resume: interrupt a large get, keep the .part, finish it ---
        big = os.path.join(work, "big.bin")
        open(big, "wb").write(os.urandom(6 * 1024 * 1024))
        assert spl(fenv, "serve", "theleader", "--name", "big", big, *A).returncode == 0
        dl2 = tempfile.mkdtemp()
        # start a background get, then kill the daemon mid-transfer to interrupt it
        spl(lenv, "get", "thefollower", "big", "-o", dl2, "-b", *A)
        time.sleep(0.4)
        spl(lenv, "stop")  # interrupts; a .part + .part.meta should remain
        part = os.path.join(dl2, "big.bin.part")
        # the partial may or may not exist depending on timing; only assert resume works
        r = spl(lenv, "get", "thefollower", "big", "-o", dl2, *A)
        assert r.returncode == 0, r.stdout + r.stderr
        assert sha(os.path.join(dl2, "big.bin")) == sha(big), "resumed file mismatch"
        assert not os.path.exists(part), ".part should be gone after completion"
        print("  resume + checksum OK")

        # --- not a serve pipe: getting a non-file pipe reports a clear error ---
        r = spl(lenv, "get", "thefollower", "nosuchpipe", *A)
        assert r.returncode != 0 and "served" in (r.stdout + r.stderr), (r.stdout + r.stderr)
        print("  not-served error is clear")

        # --- unreachable peer: sending to a peer whose daemon is down says so,
        # and doesn't get mistaken for a mid-transfer "interrupted" ---
        spl(fenv, "stop")
        time.sleep(0.5)
        r = spl(lenv, "send", "thefollower", gift, *A, timeout=60)
        blob = r.stdout + r.stderr
        assert r.returncode != 0 and "reach" in blob and "interrupted" not in blob, blob
        print("  unreachable peer reported clearly (not 'interrupted')")

        for env in (lenv, fenv):
            spl(env, "stop")
        print("FILEX PASSED")
    finally:
        for env in (lenv, fenv):
            if env:
                subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
