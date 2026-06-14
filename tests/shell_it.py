#!/usr/bin/env python3
"""Daemon-owned SHELL: `revshell` registers a durable shell pipe; `shell`
attaches and gets a PTY-backed shell over the framed protocol. Covers a
round-trip command, durability (attach twice), named + --limit one-shot, and
unregister. The client is driven over pipes (no tty), exercising the same code
path minus raw-mode/winsize."""
import os
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
