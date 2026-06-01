#!/usr/bin/env python3
"""End-to-end datapath test: pair two peers, then run the WireGuard data path
(hand-crafted IPv6 echo) through the server and confirm it starts on the relay
and upgrades to a direct path.

Usage: data_it.py /path/to/spl
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


def read_line_containing(proc, needle, timeout):
    res = [None]

    def rdr():
        for line in proc.stdout:
            if needle in line:
                res[0] = line.strip()
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


def run_datatest(port, ld, fd, init_extra, resp_extra, timeout):
    resp = subprocess.Popen(
        [SPL, "__datatest", "theleader", "--server", "127.0.0.1", "--port", str(port)] + resp_extra,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=dict(os.environ, SPL_CONFIG_DIR=fd),
    )
    try:
        return subprocess.run(
            [SPL, "__datatest", "thefollower", "--server", "127.0.0.1", "--port", str(port),
             "--initiate"] + init_extra,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout,
            env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
    finally:
        stop(resp)


def reply_paths(stdout):
    return [ln.split()[-1] for ln in stdout.splitlines() if ln.startswith("reply seq=")]


def main():
    port = free_port()
    srv = start_server(port)
    ld, fd = tempfile.mkdtemp(), tempfile.mkdtemp()
    leader = None
    try:
        # --- pair the two peers ---
        leader = subprocess.Popen(
            [SPL, "pair", "--server", "127.0.0.1", "--port", str(port), "--name", "thefollower"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
        codeline = read_line_containing(leader, "Pairing code:", 15)
        assert codeline, "leader did not print a pairing code"
        code = codeline.split()[-1]
        follower = subprocess.run(
            [SPL, "pair", code, "--server", "127.0.0.1", "--port", str(port), "--name", "theleader"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
            env=dict(os.environ, SPL_CONFIG_DIR=fd),
        )
        assert leader.wait(30) == 0 and follower.returncode == 0, "pairing failed"

        # Disco is delayed ~2s on both sides so traffic is observably relayed first.
        # --- scenario 1: relay-first, then upgrade to a direct path ---
        up = run_datatest(port, ld, fd, ["--disco-delay", "2000"], ["--disco-delay", "2000"], 40)
        assert "over RELAY" in up.stdout, f"no relay traffic:\n{up.stdout}"
        assert "over DIRECT" in up.stdout, f"never upgraded to direct:\n{up.stdout}"
        assert "UPGRADE OK" in up.stdout and up.returncode == 0, f"no upgrade:\n{up.stdout}"
        print("  upgrade OK: relay-first, then direct")

        # --- scenario 2: direct path dies mid-session -> fall back to relay ---
        fb = run_datatest(port, ld, fd,
                          ["--disco-delay", "2000", "--run-seconds", "13"],
                          ["--disco-delay", "2000", "--kill-direct-after", "5000"], 40)
        paths = reply_paths(fb.stdout)
        assert "DIRECT" in paths, f"never went direct:\n{fb.stdout}"
        last_direct = max(i for i, p in enumerate(paths) if p == "DIRECT")
        assert any(p == "RELAY" for p in paths[last_direct + 1:]), \
            f"did not fall back to relay after direct died:\n{fb.stdout}"
        print("  fallback OK: direct died, returned to relay")
        print("DATAPATH E2E PASSED")
    finally:
        stop(leader)
        stop(srv)


if __name__ == "__main__":
    main()
