#!/usr/bin/env python3
"""End-to-end nc test: pair two peers, then pipe a payload from `spl send`
through the WireGuard/lwIP tunnel to `spl receive`'s stdout.

Usage: nc_it.py /path/to/spl
"""
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

SPL = sys.argv[1]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_server(port):
    proc = subprocess.Popen(
        [SPL, "server", "--bind", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    dl = time.time() + 10
    while time.time() < dl:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return proc
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server not ready")


def read_code(proc, timeout=15):
    res = [None]

    def rdr():
        for line in proc.stdout:
            if line.strip().startswith("Pairing code:"):
                res[0] = line.strip().split()[-1]
                return

    t = threading.Thread(target=rdr, daemon=True)
    t.start()
    t.join(timeout)
    return res[0]


def stop(p):
    if p and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def main():
    port = free_port()
    srv = start_server(port)
    ld, fd = tempfile.mkdtemp(), tempfile.mkdtemp()
    leader = recv = None
    try:
        leader = subprocess.Popen(
            [SPL, "pair", "--server", "127.0.0.1", "--port", str(port), "--name", "thefollower"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
        code = read_code(leader)
        assert code, "leader did not print a pairing code"
        follower = subprocess.run(
            [SPL, "pair", code, "--server", "127.0.0.1", "--port", str(port), "--name", "theleader"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
            env=dict(os.environ, SPL_CONFIG_DIR=fd),
        )
        assert leader.wait(30) == 0 and follower.returncode == 0, "pairing failed"

        payload = "hello over the splice tunnel\n"
        # receiver = follower side (listens on its tunnel address); sender = leader side
        recv = subprocess.Popen(
            [SPL, "receive", "theleader", "--server", "127.0.0.1", "--port", str(port)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            env=dict(os.environ, SPL_CONFIG_DIR=fd),
        )
        time.sleep(0.8)  # let the receiver register + start listening
        send = subprocess.run(
            [SPL, "send", "thefollower", "--server", "127.0.0.1", "--port", str(port)],
            input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
            timeout=40, env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
        assert send.returncode == 0, f"sender rc={send.returncode}"
        try:
            rout = recv.communicate(timeout=20)[0]
        except subprocess.TimeoutExpired:
            recv.kill()
            rout = recv.communicate()[0]
        assert payload.strip() in rout, f"receiver stdout was {rout!r}"
        print("  nc OK: payload piped over the WireGuard/lwIP tunnel")
        print("NC E2E PASSED")
    finally:
        stop(recv)
        stop(leader)
        stop(srv)


if __name__ == "__main__":
    main()
