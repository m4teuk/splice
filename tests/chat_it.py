#!/usr/bin/env python3
"""End-to-end chat test on the daemon: leader hosts a `chat` PIPE, follower
opens it, messages flow both ways, follower hanging up closes its end.

Usage: chat_it.py /path/to/spl
"""
import os
import subprocess
import sys
import tempfile
import threading
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def read_until(stream, needle, timeout):
    got = [b""]

    def reader():
        while needle not in got[0]:
            d = stream.read1(4096)
            if not d:
                break
            got[0] += d

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(timeout)
    return got[0]


def main():
    port = free_port()
    srv = start_server(SPL, port)
    leader = follower = None
    lenv = fenv = None
    try:
        ld, fd = pair_two(SPL, port)
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        args = ["--server", "127.0.0.1", "--port", str(port)]

        # leader (side 0) hosts; follower (side 1) opens.
        leader = subprocess.Popen(
            [SPL, "chat", "thefollower", *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=lenv,
        )
        time.sleep(0.8)
        follower = subprocess.Popen(
            [SPL, "chat", "theleader", *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=fenv,
        )
        time.sleep(0.6)

        # follower -> leader
        follower.stdin.write(b"hello from the follower\n")
        follower.stdin.flush()
        out = read_until(leader.stdout, b"hello from the follower\n", 20)
        assert b"hello from the follower\n" in out, f"leader received {out!r}"
        print("  follower -> leader OK")

        # leader -> follower
        leader.stdin.write(b"hi back\n")
        leader.stdin.flush()
        out = read_until(follower.stdout, b"hi back\n", 20)
        assert b"hi back\n" in out, f"follower received {out!r}"
        print("  leader -> follower OK")

        # follower hangs up; its process exits, the leader keeps hosting.
        follower.stdin.close()
        assert follower.wait(15) == 0, "follower did not exit after ^D"
        assert leader.poll() is None, "leader exited when the follower hung up"
        print("  hangup OK (leader keeps hosting)")

        # leader ^D ends hosting.
        leader.stdin.close()
        assert leader.wait(15) == 0, "leader did not exit after ^D"

        # follower-first: the follower WAITs until the leader shows up.
        follower = subprocess.Popen(
            [SPL, "chat", "theleader", *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=fenv,
        )
        time.sleep(1.5)
        assert follower.poll() is None, "follower gave up before the leader joined"
        leader = subprocess.Popen(
            [SPL, "chat", "thefollower", *args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=lenv,
        )
        follower.stdin.write(b"second round\n")
        follower.stdin.flush()
        out = read_until(leader.stdout, b"second round\n", 20)
        assert b"second round\n" in out, f"leader received {out!r}"
        print("  follower-first OK (waited for the leader)")
        print("CHAT E2E PASSED")
    finally:
        stop(follower)
        stop(leader)
        for env in (lenv, fenv):
            if env:
                subprocess.run([SPL, "peer", "stop"], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
