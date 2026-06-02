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

        # 4. multiple paths + a directory tree, with subdirs recreated safely.
        work = tempfile.mkdtemp()
        with open(os.path.join(work, "notes.txt"), "wb") as f:
            f.write(b"hello notes")
        d = os.path.join(work, "proj")
        os.makedirs(os.path.join(d, "sub"))
        a, b = os.urandom(5000), os.urandom(3000)
        with open(os.path.join(d, "a.bin"), "wb") as f:
            f.write(a)
        with open(os.path.join(d, "sub", "b.bin"), "wb") as f:
            f.write(b)
        rdir = tempfile.mkdtemp()
        recv = subprocess.Popen(
            [SPL, "receive", "theleader", "--server", "127.0.0.1", "--port", str(port)],
            cwd=rdir, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=dict(os.environ, SPL_CONFIG_DIR=fd),
        )
        time.sleep(0.8)
        send = subprocess.run(
            [SPL, "send", "thefollower", os.path.join(work, "notes.txt"), d, "--server",
             "127.0.0.1", "--port", str(port)],
            capture_output=True, text=True, timeout=60, env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
        assert send.returncode == 0, f"multi-send failed: {send.stdout}"
        try:
            recv.wait(15)
        except subprocess.TimeoutExpired:
            recv.kill()

        def rd(p):
            with open(os.path.join(rdir, p), "rb") as f:
                return f.read()

        assert rd("notes.txt") == b"hello notes"
        assert rd("proj/a.bin") == a and rd("proj/sub/b.bin") == b
        print("  multi-file + directory OK (3 files, tree preserved)")

        # 5. sender started *before* the receiver: `spl send` must wait and retry
        # past a connect-fail window until `spl receive` appears, then transfer.
        data = os.urandom(80 * 1024)
        sp = mkfile(data)
        rdir = tempfile.mkdtemp()
        snd = subprocess.Popen(
            [SPL, "send", "thefollower", sp + ":got.bin", "--server", "127.0.0.1",
             "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=dict(os.environ, SPL_CONFIG_DIR=ld),
        )
        time.sleep(12)  # past a per-attempt connect budget -> at least one retry
        assert snd.poll() is None, "sender should still be waiting for the peer, not exited"
        rcv = subprocess.Popen(
            [SPL, "receive", "theleader", "--server", "127.0.0.1", "--port", str(port)],
            cwd=rdir, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=dict(os.environ, SPL_CONFIG_DIR=fd),
        )
        assert snd.wait(40) == 0, "sender did not complete after the receiver came online"
        try:
            rcv.wait(10)
        except subprocess.TimeoutExpired:
            rcv.kill()
        with open(os.path.join(rdir, "got.bin"), "rb") as f:
            assert f.read() == data
        print("  sender-first OK (waited for receiver, then transferred)")

        print("FILE E2E PASSED")
    finally:
        stop(srv)


if __name__ == "__main__":
    main()
