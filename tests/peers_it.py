#!/usr/bin/env python3
"""Managing peers while the daemon runs: `spl peer rename/remove` (and `spl
reload` after a hand edit) take effect immediately. A rename keeps the session,
its offers and its live connections; a remove revokes access right away; a peer
file that (re)appears is picked up by `spl reload`."""
import os
import shutil
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def main():
    port = free_port()
    srv = start_server(SPL, port)
    envs = []
    try:
        ld, fd = pair_two(SPL, port)
        A = ["--server", "127.0.0.1", "--port", str(port)]
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        envs = [lenv, fenv]

        def run(env, *args, flags=True):
            return subprocess.run([SPL, *args, *(A if flags else [])], env=env,
                                  capture_output=True, text=True, timeout=30)

        def status(env):
            return run(env, "status", flags=False).stdout

        def ping_ok(env, peer, budget):
            end = time.time() + budget
            while True:
                if run(env, "ping", peer).returncode == 0:
                    return True
                if time.time() > end:
                    return False

        # no daemon: reload is a harmless no-op
        r = run(lenv, "reload", flags=False)
        assert r.returncode == 0 and "not running" in r.stdout, r.stdout + r.stderr

        for env in (lenv, fenv):
            assert run(env, "start").returncode == 0
        assert run(fenv, "register", "theleader", "echo2", "ECHO").returncode == 0
        assert ping_ok(lenv, "thefollower", 20)

        # a live connection, to see it survive the renames below
        p = subprocess.Popen([SPL, "open", "thefollower", "echo2", *A], env=lenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        p.stdin.write("before\n")
        p.stdin.flush()
        assert p.stdout.readline() == "before\n"

        # --- rename on the dialing side: same session under the new name ---
        assert run(lenv, "peer", "rename", "thefollower", "bob", flags=False).returncode == 0
        st = status(lenv)
        assert "PEER bob" in st and "PEER thefollower" not in st, st
        assert st.count("PEER ") == 1, "rename must not leave a second session:\n" + st
        assert ping_ok(lenv, "bob", 10)
        print("  rename takes effect in the running daemon")

        # --- rename on the offering side: the stored offer follows the peer ---
        assert run(fenv, "peer", "rename", "theleader", "alice", flags=False).returncode == 0
        st = status(fenv)
        assert "PEER alice" in st and "PEER theleader" not in st, st
        assert "echo2" in st.split("OFFERED", 1)[1], st
        p.stdin.write("after\n")
        p.stdin.flush()
        assert p.stdout.readline() == "after\n", "the live connection did not survive the renames"
        p.stdin.close()
        stop(p)
        assert run(fenv, "stop").returncode == 0  # …and it survives a restart under the new name
        assert run(fenv, "start").returncode == 0
        assert "echo2" in status(fenv), status(fenv)
        print("  offers and live connections follow a renamed peer")

        # --- remove revokes right away (no daemon restart) ---
        keep = os.path.join(tempfile.mkdtemp(), "alice.conn")
        shutil.copy(os.path.join(fd, "alice.conn"), keep)
        assert ping_ok(lenv, "bob", 30)
        assert run(fenv, "peer", "remove", "alice", flags=False).returncode == 0
        assert "PEER alice" not in status(fenv), status(fenv)
        assert run(lenv, "ping", "bob").returncode != 0, "a removed peer could still reach us"
        print("  remove drops the peer's session immediately")

        # --- a peer file that appears is picked up by a manual reload ---
        shutil.copy(keep, os.path.join(fd, "alice.conn"))
        assert "PEER alice" not in status(fenv)
        r = run(fenv, "reload", flags=False)
        assert r.returncode == 0 and "1 added" in r.stdout, r.stdout + r.stderr
        assert "PEER alice" in status(fenv), status(fenv)
        assert run(fenv, "register", "alice", "echo3", "ECHO").returncode == 0
        assert ping_ok(lenv, "bob", 40), "re-added peer never became reachable"
        print("  spl reload picks up a new peer file")

        print("PEERS PASSED")
    finally:
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
