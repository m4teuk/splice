#!/usr/bin/env python3
"""Raw pipes are flow-controlled end to end: a `spl pipe open` client that
stops reading neither stalls its daemon nor makes it buffer the whole stream —
the sender is held back — and once it reads again every byte arrives in order."""
import hashlib
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]
SIZE = 8 * 1024 * 1024


def main():
    port = free_port()
    srv = start_server(SPL, port)
    envs, procs = [], []
    try:
        ld, fd = pair_two(SPL, port)
        A = ["--server", "127.0.0.1", "--port", str(port)]
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        envs = [lenv, fenv]
        for env in (lenv, fenv):
            assert subprocess.run([SPL, "start", *A], env=env, capture_output=True,
                                  timeout=30).returncode == 0

        blob = os.path.join(tempfile.mkdtemp(), "blob")
        with open(blob, "wb") as f:
            f.write(os.urandom(SIZE))
        want = hashlib.sha256(open(blob, "rb").read()).hexdigest()

        # the follower offers a PIPE fed from the file: whoever connects gets 8 MB
        src = open(blob, "rb")
        sender = subprocess.Popen([SPL, "pipe", "register", "theleader", "big", "PIPE", *A],
                                  env=fenv, stdin=src, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        procs.append(sender)
        time.sleep(1)

        # the leader connects… and doesn't read
        reader = subprocess.Popen([SPL, "pipe", "open", "thefollower", "big", *A], env=lenv,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
        procs.append(reader)
        time.sleep(3)

        t0 = time.time()
        st = subprocess.run([SPL, "status"], env=lenv, capture_output=True, text=True, timeout=10)
        assert st.returncode == 0 and time.time() - t0 < 2, "a client not reading stalled its daemon"
        print("  the daemon stays responsive while its client doesn't read")

        fdinfo = f"/proc/{sender.pid}/fdinfo/0"
        if os.path.exists(fdinfo):
            pos = int(open(fdinfo).read().split("pos:")[1].split()[0])
            # only what fits in the buffers in between (sockets, TCP windows)
            assert pos < 3 * 1024 * 1024, f"the sender ran {pos} bytes ahead of a stalled reader"
            print(f"  the sender is held back ({pos // 1024} KiB ahead)")

        got = hashlib.sha256()
        n = 0
        deadline = time.time() + 120
        while n < SIZE and time.time() < deadline:
            chunk = reader.stdout.read1(1 << 16)
            if not chunk:
                break
            got.update(chunk)
            n += len(chunk)
        assert n == SIZE and got.hexdigest() == want, f"got {n} of {SIZE} bytes (or corrupted)"
        print("  once it reads, all 8 MB arrive intact")
        print("FLOW PASSED")
    finally:
        for p in procs:
            p.kill()
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
