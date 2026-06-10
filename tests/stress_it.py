#!/usr/bin/env python3
"""Stress tests on the daemon: a large file, many pipes, and a transfer over a
lossy path (SPL_LOSS drops a fraction of egress UDP packets).

Usage: stress_it.py /path/to/spl
"""
import hashlib
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    port = free_port()
    srv = start_server(SPL, port)
    lrun, frun = tempfile.mkdtemp(), tempfile.mkdtemp()
    lenv = fenv = None
    try:
        ld, fd = pair_two(SPL, port)
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=lrun)
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=frun)
        largs = ["--server", "127.0.0.1", "--port", str(port)]

        def spl(env, *args, timeout=120):
            return subprocess.run([SPL, *args], env=env, capture_output=True,
                                  text=True, timeout=timeout)

        work = tempfile.mkdtemp()

        # 1. one large file.
        big = os.path.join(work, "big.bin")
        with open(big, "wb") as f:
            f.write(os.urandom(8 * 1024 * 1024))
        r = spl(fenv, "serve", "theleader", "--name", "big", big, *largs)
        assert r.returncode == 0, r.stdout + r.stderr
        dl = tempfile.mkdtemp()
        t0 = time.time()
        r = spl(lenv, "get", "thefollower", "big", "-o", dl, *largs)
        assert r.returncode == 0, r.stdout + r.stderr
        assert sha(os.path.join(dl, "big.bin")) == sha(big)
        print(f"  large file OK: 8 MB in {time.time() - t0:.1f}s")

        # 2. many pipes: 40 files, one registration + one get each.
        contents = {}
        for i in range(40):
            p = os.path.join(work, f"f{i}.bin")
            with open(p, "wb") as f:
                f.write(os.urandom(1000 + i))
            contents[f"f{i}.bin"] = p
            r = spl(fenv, "serve", "theleader", "--name", f"f{i}", p, *largs)
            assert r.returncode == 0, r.stdout + r.stderr
        dl2 = tempfile.mkdtemp()
        for i in range(40):
            r = spl(lenv, "get", "thefollower", f"f{i}", "-o", dl2, *largs, timeout=60)
            assert r.returncode == 0, f"f{i}: {r.stdout}{r.stderr}"
        for n, p in contents.items():
            assert sha(os.path.join(dl2, n)) == sha(p), f"mismatch in {n}"
        print("  many pipes OK: 40 registrations, all fetched intact")

        # 3. a lossy path: restart both daemons with SPL_LOSS; the registrations
        # persist, TCP retransmits through the dropped packets.
        for env in (lenv, fenv):
            spl(env, "peer", "stop")
        lenv["SPL_LOSS"] = fenv["SPL_LOSS"] = "0.03"
        lossy = os.path.join(work, "lossy.bin")
        with open(lossy, "wb") as f:
            f.write(os.urandom(256 * 1024))
        r = spl(fenv, "serve", "theleader", "--name", "lossy", lossy, *largs)
        assert r.returncode == 0, r.stdout + r.stderr
        dl3 = tempfile.mkdtemp()
        t0 = time.time()
        r = spl(lenv, "get", "thefollower", "lossy", "-o", dl3, *largs, timeout=120)
        assert r.returncode == 0, r.stdout + r.stderr
        assert sha(os.path.join(dl3, "lossy.bin")) == sha(lossy)
        print(f"  lossy path OK: 256 KB at 3% loss in {time.time() - t0:.1f}s")

        print("STRESS PASSED")
    finally:
        for env in (lenv, fenv):
            if env:
                subprocess.run([SPL, "peer", "stop"], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
