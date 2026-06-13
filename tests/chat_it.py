#!/usr/bin/env python3
"""Chat is a 1:1 session (host registers `chat` LIMIT 1). Verify messages flow
both ways and that hanging up from EITHER side tears the whole session down, and
that it works regardless of which side starts first.

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
ARGS = []  # filled in with --server/--port


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


def chat(env, peer):
    return subprocess.Popen(
        [SPL, "chat", peer, *ARGS],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
    )


def exited(p, timeout):
    try:
        p.wait(timeout)
        return True
    except subprocess.TimeoutExpired:
        return False


def main():
    global ARGS
    port = free_port()
    srv = start_server(SPL, port)
    procs = []
    lenv = fenv = None
    try:
        ld, fd = pair_two(SPL, port)
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        ARGS = ["--server", "127.0.0.1", "--port", str(port)]

        # --- round 1: leader first, follower hangs up -> both exit ---
        leader = chat(lenv, "thefollower"); procs.append(leader)
        time.sleep(0.8)
        follower = chat(fenv, "theleader"); procs.append(follower)
        time.sleep(0.6)

        follower.stdin.write(b"hello from the follower\n"); follower.stdin.flush()
        assert b"hello from the follower\n" in read_until(leader.stdout, b"hello from the follower\n", 20)
        leader.stdin.write(b"hi back\n"); leader.stdin.flush()
        assert b"hi back\n" in read_until(follower.stdout, b"hi back\n", 20)
        print("  messages flow both ways")

        follower.stdin.close()
        assert exited(follower, 15), "follower did not exit after its own ^D"
        assert exited(leader, 15), "leader did not exit when the follower hung up (LIMIT 1)"
        print("  follower ^D tore down both sides")

        # --- round 2: leader hangs up -> both exit (fresh session) ---
        leader = chat(lenv, "thefollower"); procs.append(leader)
        time.sleep(0.8)
        follower = chat(fenv, "theleader"); procs.append(follower)
        time.sleep(0.6)
        follower.stdin.write(b"ping\n"); follower.stdin.flush()
        assert b"ping\n" in read_until(leader.stdout, b"ping\n", 20)

        leader.stdin.close()
        assert exited(leader, 15), "leader did not exit after its own ^D"
        assert exited(follower, 15), "follower did not exit when the leader hung up"
        print("  leader ^D tore down both sides")

        # --- round 3: follower starts first (WAITs for the host) ---
        follower = chat(fenv, "theleader"); procs.append(follower)
        time.sleep(1.5)
        assert follower.poll() is None, "follower gave up before the host appeared"
        leader = chat(lenv, "thefollower"); procs.append(leader)
        follower.stdin.write(b"second round\n"); follower.stdin.flush()
        assert b"second round\n" in read_until(leader.stdout, b"second round\n", 20)
        print("  follower-first OK (waited for the host)")

        leader.stdin.close()
        assert exited(leader, 15) and exited(follower, 15), "follower-first session did not tear down"
        print("CHAT E2E PASSED")
    finally:
        for p in procs:
            stop(p)
        for env in (lenv, fenv):
            if env:
                subprocess.run([SPL, "peer", "stop"], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
