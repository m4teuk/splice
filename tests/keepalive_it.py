#!/usr/bin/env python3
"""A connection whose peer silently vanishes is torn down by TCP keepalive, while
a healthy idle one survives. Runs with SPL_KEEPALIVE_MS=3000 (default ~3 min).
The "vanished" peer is a SIGSTOPped daemon: it stops answering without closing
anything, like a machine that lost its network or went to sleep."""
import os
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]
KEEPALIVE_MS = 3000


def main():
    port = free_port()
    srv = start_server(SPL, port)
    envs = []
    stopped_pid = None
    try:
        ld, fd = pair_two(SPL, port)
        A = ["--server", "127.0.0.1", "--port", str(port)]
        base = dict(os.environ, SPL_KEEPALIVE_MS=str(KEEPALIVE_MS))
        lenv = dict(base, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(base, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        envs = [lenv, fenv]

        def run(env, *args):
            return subprocess.run([SPL, *args, *A], env=env, capture_output=True, text=True,
                                  timeout=30)

        assert run(lenv, "start").returncode == 0
        r = run(fenv, "start")
        assert r.returncode == 0, r.stdout + r.stderr
        m = re.search(r"pid (\d+)", r.stdout + r.stderr)
        assert m, "could not find the follower daemon's pid:\n" + r.stdout + r.stderr
        fpid = int(m.group(1))
        assert run(fenv, "revshell", "theleader").returncode == 0

        q = subprocess.Popen([SPL, "shell", "thefollower", *A], env=lenv, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        def expect(tok, budget=5.0):
            buf, end = b"", time.time() + budget
            while time.time() < end:
                rr, _, _ = select.select([q.stdout], [], [], max(0, end - time.time()))
                if rr:
                    b = os.read(q.stdout.fileno(), 65536)
                    if not b:
                        return False
                    buf += b
                    if tok in buf:
                        return True
            return False

        def say(cmd):
            q.stdin.write(cmd.encode() + b"\n")
            q.stdin.flush()

        say("echo UP_$((1+1))")
        assert expect(b"UP_2"), "shell did not come up"

        # healthy but idle for twice the keepalive window: must survive
        time.sleep(2 * KEEPALIVE_MS / 1000)
        say("echo IDLE_$((2+2))")
        assert expect(b"IDLE_4"), "keepalive killed a healthy idle connection"
        print("  healthy idle connection survives the keepalive window")

        # the host vanishes (no FIN, no RST): the client must notice and exit
        os.kill(fpid, signal.SIGSTOP)
        stopped_pid = fpid
        t0 = time.time()
        try:
            q.wait(timeout=KEEPALIVE_MS / 1000 + 10)
        except subprocess.TimeoutExpired:
            q.kill()
            raise AssertionError("spl shell hung after the peer vanished")
        print(f"  client noticed the vanished peer after {time.time() - t0:.1f}s and exited")
        st = run(lenv, "status").stdout
        assert "CONNECTIONS" not in st, st

        # once the host is back it must not keep the orphaned shell around
        os.kill(fpid, signal.SIGCONT)
        stopped_pid = None
        deadline = time.time() + KEEPALIVE_MS / 1000 + 10
        while time.time() < deadline and "CONNECTIONS" in run(fenv, "status").stdout:
            time.sleep(0.3)
        st = run(fenv, "status").stdout
        assert "CONNECTIONS" not in st, "host kept the orphaned shell:\n" + st
        print("  host dropped the orphaned shell")
        print("KEEPALIVE PASSED")
    finally:
        if stopped_pid:
            os.kill(stopped_pid, signal.SIGCONT)
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
