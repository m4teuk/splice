"""Shared helpers for the peer integration tests."""
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_server(spl, port):
    proc = subprocess.Popen(
        [spl, "server", "--bind", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return proc
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not become ready")


def _read_line(proc, needle, timeout):
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


def pair_two(spl, port, leader_name="thefollower", follower_name="theleader"):
    """Pair two peers; returns (leader_config_dir, follower_config_dir)."""
    ld, fd = tempfile.mkdtemp(), tempfile.mkdtemp()
    leader = subprocess.Popen(
        [spl, "pair", "--server", "127.0.0.1", "--port", str(port), "--insecure", "--name",
         leader_name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=dict(os.environ, SPL_CONFIG_DIR=ld),
    )
    line = _read_line(leader, "Pairing code:", 15)
    if not line:
        stop(leader)
        raise RuntimeError("leader did not print a pairing code")
    code = line.split()[-1]
    follower = subprocess.run(
        [spl, "pair", code, "--server", "127.0.0.1", "--port", str(port), "--insecure", "--name",
         follower_name],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30,
        env=dict(os.environ, SPL_CONFIG_DIR=fd),
    )
    if leader.wait(30) != 0 or follower.returncode != 0:
        raise RuntimeError("pairing failed: " + (follower.stdout or ""))
    return ld, fd
