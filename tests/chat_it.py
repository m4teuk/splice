#!/usr/bin/env python3
"""End-to-end chat test: pair two peers, then deliver a message over `spl chat`.

Usage: chat_it.py /path/to/spl
"""
import os
import subprocess
import sys
import threading
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def main():
    port = free_port()
    srv = start_server(SPL, port)
    leader = follower = None
    try:
        ld, fd = pair_two(SPL, port)
        payload = b"hello over the chat tunnel\n"

        # leader (side 0) listens; follower (side 1) dials.
        leader = subprocess.Popen(
            [SPL, "chat", "thefollower", "--server", "127.0.0.1", "--port", str(port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
        time.sleep(0.8)
        follower = subprocess.Popen(
            [SPL, "chat", "theleader", "--server", "127.0.0.1", "--port", str(port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, SPL_CONFIG_DIR=fd),
        )
        time.sleep(0.6)

        # follower sends the payload then closes its stdin (which tears the chat down).
        follower.stdin.write(payload)
        follower.stdin.flush()
        follower.stdin.close()

        # read the leader's stdout until we see the payload (don't touch its stdin,
        # so the leader stays up until the peer closes).
        got = [b""]

        def reader():
            while True:
                d = leader.stdout.read(4096)
                if not d:
                    break
                got[0] += d
                if payload in got[0]:
                    break

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(15)
        assert payload in got[0], f"leader received {got[0]!r}"
        print("  chat OK: message delivered over the tunnel")
        print("CHAT E2E PASSED")
    finally:
        stop(follower)
        stop(leader)
        stop(srv)


if __name__ == "__main__":
    main()
