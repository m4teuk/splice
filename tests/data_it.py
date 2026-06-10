#!/usr/bin/env python3
"""Datapath test on the daemon: data flows while pinned to the relay, the path
upgrades to direct when released, and falls back to the relay when the direct
path is killed — verified with echoes through the diagnostic pipe and the
daemon's STATUS. Talks the control protocol directly over the unix socket.

Usage: data_it.py /path/to/spl
"""
import os
import socket
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def ctl(run_dir, line):
    """One control-protocol command; returns the first reply line."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.path.join(run_dir, "daemon.sock"))
    s.sendall(line.encode() + b"\n")
    buf = b""
    while b"\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    s.close()
    return buf.split(b"\n", 1)[0].decode()


def status(run_dir):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.path.join(run_dir, "daemon.sock"))
    s.sendall(b"STATUS\n")
    out = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        out += d
    s.close()
    return out.decode()


def echo(run_dir, peer, payload, timeout=20):
    """Round-trip payload through the peer's diagnostic pipe."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(os.path.join(run_dir, "daemon.sock"))
    s.sendall(f"OPEN {peer} diagnostic PIPE\n".encode())
    buf = b""
    while b"\n" not in buf:
        buf += s.recv(4096)
    assert buf.split(b"\n", 1)[0].startswith(b"OK"), buf
    rest = buf.split(b"\n", 1)[1]
    s.sendall(payload)
    got = rest
    deadline = time.time() + timeout
    while len(got) < len(payload) and time.time() < deadline:
        got += s.recv(65536)
    s.close()
    assert got == payload, f"echo mismatch ({len(got)}/{len(payload)} bytes)"


def wait_path(run_dir, peer, want, timeout=25):
    deadline = time.time() + timeout
    out = ""
    while time.time() < deadline:
        out = status(run_dir)
        for line in out.splitlines():
            if line.startswith(f"PEER {peer}:") and want in line:
                return
        time.sleep(0.3)
    raise AssertionError(f"path never became {want}:\n{out}")


def main():
    port = free_port()
    srv = start_server(SPL, port)
    lrun, frun = tempfile.mkdtemp(), tempfile.mkdtemp()
    try:
        ld, fd = pair_two(SPL, port)
        largs = ["--server", "127.0.0.1", "--port", str(port)]
        # both daemons start pinned to the relay
        for cfg, run in ((ld, lrun), (fd, frun)):
            env = dict(os.environ, SPL_CONFIG_DIR=cfg, SPL_RUNTIME_DIR=run,
                       SPL_FORCE_RELAY="1")
            r = subprocess.run([SPL, "peer", "start", *largs], env=env,
                               capture_output=True, text=True, timeout=30)
            assert r.returncode == 0, r.stdout + r.stderr

        # 1. data flows while everything rides the relay
        echo(lrun, "thefollower", os.urandom(64 * 1024))
        wait_path(lrun, "thefollower", "RELAY", 5)
        print("  relay OK: echo while pinned to the relay")

        # 2. released -> upgrades to a direct path
        assert ctl(lrun, "FORCE_RELAY thefollower 0") == "OK"
        assert ctl(frun, "FORCE_RELAY theleader 0") == "OK"
        wait_path(lrun, "thefollower", "DIRECT")
        wait_path(frun, "theleader", "DIRECT")
        echo(lrun, "thefollower", os.urandom(64 * 1024))
        print("  upgrade OK: direct path, echo verified")

        # 3. direct path dies on one side -> that side falls back to the relay
        assert ctl(lrun, "FORCE_RELAY thefollower 1") == "OK"
        wait_path(lrun, "thefollower", "RELAY", 10)
        echo(lrun, "thefollower", os.urandom(64 * 1024))
        print("  fallback OK: relay again, echo verified")

        print("DATAPATH E2E PASSED")
    finally:
        for run in (lrun, frun):
            try:
                ctl(run, "STOP")
            except OSError:
                pass
        stop(srv)


if __name__ == "__main__":
    main()
