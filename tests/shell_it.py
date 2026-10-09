#!/usr/bin/env python3
"""Daemon-owned SHELL: `revshell` registers a durable shell pipe; `shell`
attaches and gets a PTY-backed shell over the framed protocol. Covers a
round-trip command, durability (attach twice), named + --limit one-shot, and
unregister. The client is driven over pipes (no tty), exercising the same code
path minus raw-mode/winsize."""
import os
import select
import statistics
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def main():
    port = free_port()
    srv = start_server(SPL, port)
    lenv = fenv = None
    try:
        ld, fd = pair_two(SPL, port)
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        A = ["--server", "127.0.0.1", "--port", str(port)]

        def run(env, *args, **kw):
            return subprocess.run([SPL, *args, *A], env=env, capture_output=True, text=True,
                                  timeout=kw.get("timeout", 30))

        def attach(env, send, name=None, timeout=30):
            """Open a shell on the peer, feed `send`, return merged stdout/stderr."""
            cmd = [SPL, "shell", "thefollower"] + (["--name", name] if name else []) + A
            p = subprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            out, _ = p.communicate(send.encode(), timeout=timeout)
            return out.decode(errors="replace")

        # follower offers a shell on itself to the leader
        r = run(fenv, "revshell", "theleader")
        assert r.returncode == 0, r.stdout + r.stderr

        # leader attaches and runs a command end-to-end
        out = attach(lenv, "echo SPLICE_$((6*7))\nexit\n")
        assert "SPLICE_42" in out, out
        print("  shell runs a command end-to-end")

        # durable: the registration persists, so a second attach works too
        out = attach(lenv, "echo SECOND_$((2*2))\nexit\n")
        assert "SECOND_4" in out, out
        print("  shell registration is durable (second attach)")

        # named + one-shot: a --limit 1 shell retires after a single use
        assert run(fenv, "revshell", "theleader", "--name", "once", "--limit", "1").returncode == 0
        out = attach(lenv, "echo ONCE_OK\nexit\n", name="once")
        assert "ONCE_OK" in out, out
        time.sleep(1)  # let the retire (deferred to a tick) land
        out = attach(lenv, "echo SHOULD_NOT_RUN\nexit\n", name="once")
        assert "SHOULD_NOT_RUN" not in out, "one-shot shell served a second attach: " + out
        print("  named + --limit one-shot retires after one use")

        # unregister stops offering it
        assert run(fenv, "unregister", "theleader", "shell").returncode == 0
        out = attach(lenv, "echo GONE\nexit\n")
        assert "GONE" not in out, "unregistered shell still served: " + out
        print("  unregister stops offering")

        # interactivity: small request/response round-trips must be snappy, not
        # stalled on the Nagle x delayed-ACK interaction (that bug was ~150ms each;
        # with Nagle disabled it's well under a millisecond — guard with a wide
        # margin so CI noise can't trip it but a regression will).
        assert run(fenv, "revshell", "theleader").returncode == 0
        p = subprocess.Popen([SPL, "shell", "thefollower"] + A, env=lenv, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        def waitfor(tok, budget=5.0):
            buf, end = b"", time.time() + budget
            while time.time() < end:
                r, _, _ = select.select([p.stdout], [], [], end - time.time())
                if r:
                    b = os.read(p.stdout.fileno(), 65536)
                    if not b:
                        return False
                    buf += b
                    if tok in buf:
                        return True
            return False

        waitfor(b"$", 2.0)  # first prompt
        rtts = []
        for i in range(15):
            tok = f"PONG{i}".encode()
            t0 = time.time()
            p.stdin.write(b"echo " + tok + b"\n")
            p.stdin.flush()
            assert waitfor(tok), f"no response to round-trip {i}"
            rtts.append((time.time() - t0) * 1000)
        p.stdin.write(b"exit\n")
        p.stdin.flush()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        med = statistics.median(rtts)
        assert med < 40, f"interactive round-trip too slow: median {med:.1f}ms (Nagle regression?)"
        print(f"  interactive round-trips snappy (median {med:.1f}ms)")

        # registrations are only offers: unregistering one leaves a live session
        # attached through it running (with a note), and a new, different
        # registration under the same name doesn't take over that session.
        q = subprocess.Popen([SPL, "shell", "thefollower"] + A, env=lenv, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        def expect(tok, budget=5.0):
            buf, end = b"", time.time() + budget
            while time.time() < end:
                r, _, _ = select.select([q.stdout], [], [], end - time.time())
                if r:
                    b = os.read(q.stdout.fileno(), 65536)
                    if not b:
                        return False
                    buf += b
                    if tok in buf:
                        return True
            return False

        def say(cmd):
            q.stdin.write(cmd.encode() + b"\n")
            q.stdin.flush()

        say("echo LIVE_$((1+1))")
        assert expect(b"LIVE_2"), "shell did not come up"
        r = run(fenv, "unregister", "theleader", "shell")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "still active" in r.stdout and "spl close theleader" in r.stdout, r.stdout
        say("echo AFTER_$((2+3))")
        assert expect(b"AFTER_5"), "unregistering the shell killed the live session"
        print("  unregister keeps the live shell, and says so")

        assert run(fenv, "register", "theleader", "shell", "ECHO").returncode == 0
        st = run(fenv, "status").stdout
        offered = st.split("OFFERED", 1)[1].split("CONNECTIONS", 1)[0]
        conns = st.split("CONNECTIONS", 1)[1]
        assert "shell  ECHO  (0 finished, 0 active)" in offered, st
        assert "in   shell  SHELL" in conns, st  # the live one still shows what it attached to
        say("exit")
        try:
            q.wait(timeout=5)
        except subprocess.TimeoutExpired:
            q.kill()
        time.sleep(0.5)
        st = run(fenv, "status").stdout
        assert "shell  ECHO  (0 finished, 0 active)" in st, st  # old session isn't counted here
        assert "in   shell  SHELL" not in st, st
        run(fenv, "unregister", "theleader", "shell")
        print("  re-registering a name doesn't adopt the old session")

        for env in (lenv, fenv):
            run(env, "stop")
        print("SHELL PASSED")
    finally:
        for env in (lenv, fenv):
            if env:
                subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
