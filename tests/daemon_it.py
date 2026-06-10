#!/usr/bin/env python3
"""Daemon integration: two daemons, echo over the diagnostic pipe, persistent
registrations across a daemon restart, status, and reset."""
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, start_server, stop, pair_two

SPL = sys.argv[1]


def env_for(cfg, run):
    return dict(os.environ, SPL_CONFIG_DIR=cfg, SPL_RUNTIME_DIR=run)


def spl(env, *args, **kw):
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.STDOUT)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 30)
    return subprocess.run([SPL, *args], env=env, **kw)


def wait_status(env, needle, timeout=20):
    deadline = time.time() + timeout
    out = ""
    while time.time() < deadline:
        out = spl(env, "peer", "status").stdout
        if needle in out:
            return out
        time.sleep(0.3)
    raise RuntimeError(f"status never showed {needle!r}:\n{out}")


def main():
    port = free_port()
    server = start_server(SPL, port)
    try:
        ld, fd = pair_two(SPL, port)
        lrun, frun = tempfile.mkdtemp(), tempfile.mkdtemp()
        lenv, fenv = env_for(ld, lrun), env_for(fd, frun)
        largs = ["--server", "127.0.0.1", "--port", str(port)]

        # start both daemons
        for env in (lenv, fenv):
            r = spl(env, "peer", "start", *largs)
            assert r.returncode == 0, f"peer start failed:\n{r.stdout}"
        wait_status(lenv, "PEER thefollower")
        wait_status(fenv, "PEER theleader")
        print("  daemons up, sessions present")

        # echo through the diagnostic pipe (leader -> follower)
        p = subprocess.Popen(
            [SPL, "peer", "open", "thefollower", "diagnostic"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=lenv,
        )
        p.stdin.write("hello pipes\n")
        p.stdin.flush()
        line = p.stdout.readline()
        assert line == "hello pipes\n", f"echo mismatch: {line!r}"
        p.stdin.close()
        stop(p)
        print("  diagnostic echo OK")

        # the open instance shows up in status counters
        out = spl(lenv, "peer", "status").stdout
        assert "diagnostic" in out, out

        # persistent registration: a second ECHO under a custom name
        r = spl(fenv, "peer", "register", "theleader", "echo2", "ECHO")
        assert r.returncode == 0, r.stdout
        # collision is refused
        r = spl(fenv, "peer", "register", "theleader", "echo2", "ECHO")
        assert r.returncode != 0, "duplicate register accepted"
        # reserved name is refused
        r = spl(fenv, "peer", "register", "theleader", "diagnostic", "ECHO")
        assert r.returncode != 0, "reserved name accepted"

        out = wait_status(fenv, "echo2")
        print("  persistent registration visible")

        # restart the follower daemon; echo2 must survive (it is on disk)
        assert spl(fenv, "peer", "stop").returncode == 0
        assert spl(fenv, "peer", "start", *largs).returncode == 0
        out = wait_status(fenv, "echo2")
        print("  registration survived daemon restart")

        # leader can use it
        p = subprocess.Popen(
            [SPL, "peer", "open", "thefollower", "echo2"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=lenv,
        )
        p.stdin.write("ping2\n")
        p.stdin.flush()
        assert p.stdout.readline() == "ping2\n"
        p.stdin.close()
        stop(p)
        print("  echo over named registration OK")

        # unknown pipe -> client sees EOF quickly (UNKNOWN closes the conn)
        p = subprocess.Popen(
            [SPL, "peer", "open", "thefollower", "nosuchpipe"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=lenv,
        )
        assert p.stdout.read() == "", "unknown pipe produced data"
        stop(p)
        print("  unknown pipe rejected")

        # reset clears echo2 but keeps diagnostic
        assert spl(fenv, "peer", "reset").returncode == 0
        out = spl(fenv, "peer", "status").stdout
        assert "echo2" not in out, out
        assert "diagnostic" in out, out
        print("  reset OK")

        for env in (lenv, fenv):
            spl(env, "peer", "stop")
        print("daemon integration: all OK")
    finally:
        stop(server)


if __name__ == "__main__":
    main()
