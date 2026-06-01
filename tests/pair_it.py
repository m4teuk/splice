#!/usr/bin/env python3
"""End-to-end pairing test: two `spl pair` peers rendezvous through `spl server`.

Verifies (1) a successful pairing produces mirrored stored records, and
(2) a wrong SPAKE2 code aborts at key confirmation with nothing stored.

Usage: pair_it.py /path/to/spl
"""
import base64
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
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return proc
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not become ready")


def read_code(proc, timeout=15):
    # Read in a thread: select()+buffered readline() races because the first
    # readline pulls every available line into Python's buffer, leaving the OS
    # pipe empty so select never fires again.
    result = [None]

    def reader():
        for line in proc.stdout:
            if line.strip().startswith("Pairing code:"):
                result[0] = line.strip().split()[-1]  # "<id>-<digits>"
                return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]


def parse_conn(path):
    d = {}
    with open(path) as f:
        for line in f:
            if ": " in line:
                k, v = line.rstrip("\n").split(": ", 1)
                d[k] = v
    return d


def stop(proc):
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def run_pair_ok():
    port = free_port()
    srv = start_server(port)
    ld, fd = tempfile.mkdtemp(), tempfile.mkdtemp()
    leader = None
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
        lrc = leader.wait(timeout=30)
        assert lrc == 0, f"leader rc={lrc}\n{leader.stdout.read()}"
        assert follower.returncode == 0, f"follower rc={follower.returncode}\n{follower.stdout}"

        L = parse_conn(os.path.join(ld, "thefollower.conn"))
        F = parse_conn(os.path.join(fd, "theleader.conn"))
        luid, fuid = base64.b64decode(L["uid"]), base64.b64decode(F["uid"])
        assert luid[:31] == fuid[:31], "uid upper 255 bits differ"
        assert luid[31] & 1 == 0 and fuid[31] & 1 == 1, "side bits wrong"
        assert L["side"] == "0" and F["side"] == "1"
        assert L["peer_pub"] == F["own_pub"], "leader.peer_pub != follower.own_pub"
        assert F["peer_pub"] == L["own_pub"], "follower.peer_pub != leader.own_pub"
        assert L["ula_base"] == F["ula_base"], "ULA base mismatch"
        print("  pair OK: records mirror (uid sides, cross-matched keys, shared ULA)")
    finally:
        stop(leader)
        stop(srv)


def run_tamper():
    port = free_port()
    srv = start_server(port)
    ld, fd = tempfile.mkdtemp(), tempfile.mkdtemp()
    leader = None
    try:
        leader = subprocess.Popen(
            [SPL, "pair", "--server", "127.0.0.1", "--port", str(port), "--name", "x"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
        code = read_code(leader)
        assert code, "leader did not print a pairing code"
        pid, sp = code.split("-")
        wrong = pid + "-" + ("000000" if sp != "000000" else "111111")
        follower = subprocess.run(
            [SPL, "pair", wrong, "--server", "127.0.0.1", "--port", str(port), "--name", "y"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
            env=dict(os.environ, SPL_CONFIG_DIR=fd),
        )
        lrc = leader.wait(timeout=30)
        assert follower.returncode != 0, "follower must fail on wrong code"
        assert lrc != 0, "leader must fail on wrong code"
        assert not os.path.exists(os.path.join(fd, "y.conn")), "follower must not persist on failure"
        assert not os.path.exists(os.path.join(ld, "x.conn")), "leader must not persist on failure"
        print("  tamper OK: wrong SPAKE2 code aborts at key confirmation, nothing stored")
    finally:
        stop(leader)
        stop(srv)


def main():
    ok = True
    for t in (run_pair_ok, run_tamper):
        try:
            t()
        except Exception as e:
            ok = False
            print(f"  {t.__name__} FAILED: {e!r}")
    print("PAIRING E2E PASSED" if ok else "PAIRING E2E FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
