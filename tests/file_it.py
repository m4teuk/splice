#!/usr/bin/env python3
"""End-to-end file-transfer tests: integrity + rename, path-traversal safety, and
collision handling.

Usage: file_it.py /path/to/spl
"""
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def mkfile(content):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "src.bin")
    with open(p, "wb") as f:
        f.write(content)
    return p


def run_xfer(port, ld, fd, sendarg, recv_stdin=None, recvdir=None):
    """Run one receive<-send transfer; returns (send_result, recvdir)."""
    if recvdir is None:
        recvdir = tempfile.mkdtemp()
    recv = subprocess.Popen(
        [SPL, "receive", "theleader", "--server", "127.0.0.1", "--port", str(port)],
        cwd=recvdir,
        stdin=subprocess.PIPE if recv_stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=dict(os.environ, SPL_CONFIG_DIR=fd),
    )
    if recv_stdin is not None:
        recv.stdin.write(recv_stdin)
        recv.stdin.flush()
    time.sleep(0.8)
    send = subprocess.run(
        [SPL, "send", "thefollower", sendarg, "--server", "127.0.0.1", "--port", str(port)],
        capture_output=True, text=True, timeout=60, env=dict(os.environ, SPL_CONFIG_DIR=ld),
    )
    try:
        recv.wait(15)
    except subprocess.TimeoutExpired:
        recv.kill()
    return send, recvdir


def main():
    port = free_port()
    srv = start_server(SPL, port)
    try:
        ld, fd = pair_two(SPL, port)

        # 1. integrity + rename, large enough to exercise flow control.
        content = os.urandom(256 * 1024)
        send, rdir = run_xfer(port, ld, fd, mkfile(content) + ":got.bin")
        assert send.returncode == 0, f"send failed: {send.stdout}{send.stderr}"
        with open(os.path.join(rdir, "got.bin"), "rb") as f:
            assert f.read() == content, "content mismatch"
        print(f"  transfer OK ({len(content)} bytes, renamed)")

        # 2. path-traversal safety: a hostile name is reduced to a basename in cwd.
        c2 = os.urandom(1024)
        send, rdir = run_xfer(port, ld, fd, mkfile(c2) + ":../../../escape.bin")
        assert send.returncode == 0
        assert os.path.exists(os.path.join(rdir, "escape.bin")), "not written as basename"
        assert not os.path.exists(os.path.join(rdir, "..", "..", "..", "escape.bin")), "escaped cwd!"
        with open(os.path.join(rdir, "escape.bin"), "rb") as f:
            assert f.read() == c2
        print("  path-traversal OK (written as basename inside cwd)")

        # 3. collision: an existing file is not overwritten without consent.
        c3 = os.urandom(1024)
        rdir3 = tempfile.mkdtemp()
        with open(os.path.join(rdir3, "got.bin"), "wb") as f:
            f.write(b"ORIGINAL")
        send, _ = run_xfer(port, ld, fd, mkfile(c3) + ":got.bin", recv_stdin="c\n", recvdir=rdir3)
        assert send.returncode != 0, "cancelled transfer should fail the sender"
        with open(os.path.join(rdir3, "got.bin"), "rb") as f:
            assert f.read() == b"ORIGINAL", "existing file was clobbered on cancel"
        print("  collision OK (cancel preserves the existing file)")

        print("FILE E2E PASSED")
    finally:
        stop(srv)


if __name__ == "__main__":
    main()
