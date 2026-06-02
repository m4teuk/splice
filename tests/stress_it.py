#!/usr/bin/env python3
"""Stress tests: a large file, many small files, and a transfer over a lossy path
(SPL_LOSS drops a fraction of egress UDP packets).

Usage: stress_it.py /path/to/spl
"""
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def xfer(port, ld, fd, sendargs, env_extra=None, timeout=120):
    recvdir = tempfile.mkdtemp()
    renv = dict(os.environ, SPL_CONFIG_DIR=fd)
    senv = dict(os.environ, SPL_CONFIG_DIR=ld)
    if env_extra:
        renv.update(env_extra)
        senv.update(env_extra)
    recv = subprocess.Popen(
        [SPL, "receive", "theleader", "--server", "127.0.0.1", "--port", str(port)],
        cwd=recvdir, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, env=renv,
    )
    time.sleep(0.8)
    send = subprocess.run(
        [SPL, "send", "thefollower", *sendargs, "--server", "127.0.0.1", "--port", str(port)],
        capture_output=True, text=True, timeout=timeout, env=senv,
    )
    try:
        recv.wait(20)
    except subprocess.TimeoutExpired:
        recv.kill()
    return send, recvdir


def main():
    port = free_port()
    srv = start_server(SPL, port)
    try:
        ld, fd = pair_two(SPL, port)

        # 1. one large file.
        big = os.urandom(8 * 1024 * 1024)
        p = tempfile.mktemp()
        with open(p, "wb") as f:
            f.write(big)
        t0 = time.time()
        send, rdir = xfer(port, ld, fd, [p + ":big.bin"])
        assert send.returncode == 0, send.stdout
        with open(os.path.join(rdir, "big.bin"), "rb") as f:
            assert f.read() == big
        print(f"  large file OK: 8 MB in {time.time() - t0:.1f}s")

        # 2. many small files (one directory).
        work = tempfile.mkdtemp()
        os.makedirs(os.path.join(work, "many"))
        contents = {}
        for i in range(60):
            c = os.urandom(1000 + i)
            contents[f"f{i}.bin"] = c
            with open(os.path.join(work, "many", f"f{i}.bin"), "wb") as f:
                f.write(c)
        send, rdir = xfer(port, ld, fd, [os.path.join(work, "many")])
        assert send.returncode == 0, send.stdout
        for n, c in contents.items():
            with open(os.path.join(rdir, "many", n), "rb") as f:
                assert f.read() == c, f"mismatch in {n}"
        print("  many files OK: 60 files, all intact")

        # 3. a transfer over a lossy path (drops a fraction of egress packets).
        c = os.urandom(128 * 1024)
        p = tempfile.mktemp()
        with open(p, "wb") as f:
            f.write(c)
        t0 = time.time()
        send, rdir = xfer(port, ld, fd, [p + ":lossy.bin"], env_extra={"SPL_LOSS": "0.05"})
        assert send.returncode == 0, f"lossy send failed: {send.stdout}"
        with open(os.path.join(rdir, "lossy.bin"), "rb") as f:
            assert f.read() == c
        print(f"  lossy path OK: 128 KB over 5% loss in {time.time() - t0:.1f}s")

        print("STRESS PASSED")
    finally:
        stop(srv)


if __name__ == "__main__":
    main()
