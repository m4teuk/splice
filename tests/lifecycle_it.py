#!/usr/bin/env python3
"""Daemon lifecycle: auto-started daemons auto-stop when idle; `spl start` makes
a daemon sticky (stays up); a registration keeps even a non-sticky daemon alive."""
import os
import socket
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def running(run_dir):
    """True if the daemon socket answers PING."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(os.path.join(run_dir, "daemon.sock"))
        s.sendall(b"PING\n")
        ok = s.recv(16).startswith(b"OK")
        s.close()
        return ok
    except OSError:
        return False


def wait_gone(run_dir, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not running(run_dir):
            return True
        time.sleep(0.2)
    return False


def main():
    port = free_port()
    srv = start_server(SPL, port)
    try:
        ld, fd = pair_two(SPL, port)
        largs = ["--server", "127.0.0.1", "--port", str(port)]

        # --- auto-started daemon (idle 1.5s) stops on its own ---
        run1 = tempfile.mkdtemp()
        env1 = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=run1, SPL_IDLE_STOP_MS="1500")
        # `spl ls <peer>` auto-starts the daemon (does a LIST), registers nothing.
        subprocess.run([SPL, "ls", "thefollower", *largs], env=env1, capture_output=True,
                       text=True, timeout=30)
        assert running(run1), "daemon should be up right after an auto-starting command"
        assert wait_gone(run1, 10), "auto-started daemon did not auto-stop when idle"
        print("  auto-started daemon auto-stops when idle")

        # --- `spl start` is sticky: stays up past the idle window ---
        run2 = tempfile.mkdtemp()
        env2 = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=run2, SPL_IDLE_STOP_MS="1500")
        r = subprocess.run([SPL, "start", *largs], env=env2, capture_output=True, text=True,
                           timeout=30)
        assert r.returncode == 0, r.stdout + r.stderr
        time.sleep(4)  # well past the 1.5s idle window
        assert running(run2), "sticky daemon (spl start) must not auto-stop"
        assert subprocess.run([SPL, "stop"], env=env2, capture_output=True).returncode == 0
        assert wait_gone(run2, 5), "daemon did not stop on `spl stop`"
        print("  `spl start` is sticky; `spl stop` stops it")

        # --- a registration keeps a non-sticky daemon alive ---
        run3 = tempfile.mkdtemp()
        env3 = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=run3, SPL_IDLE_STOP_MS="1500")
        big = os.path.join(tempfile.mkdtemp(), "f.bin")
        open(big, "wb").write(b"x" * 100)
        r = subprocess.run([SPL, "serve", "theleader", "--name", "f", big, *largs], env=env3,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stdout + r.stderr
        time.sleep(4)
        assert running(run3), "a daemon with a registration must stay up even if non-sticky"
        # remove the registration -> now idle -> auto-stops
        subprocess.run([SPL, "unregister", "theleader", "f", *largs], env=env3,
                       capture_output=True, timeout=15)
        assert wait_gone(run3, 10), "daemon did not auto-stop after its registration was removed"
        print("  a registration keeps it alive; removing it lets it stop")

        # --- ping: reachable when the peer serves something, else unreachable ---
        run4 = tempfile.mkdtemp()
        run5 = tempfile.mkdtemp()
        env_l = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=run4)
        env_f = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=run5)
        # follower not up yet -> unreachable
        r = subprocess.run([SPL, "ping", "thefollower", *largs], env=env_l,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode != 0 and "unreachable" in r.stdout, r.stdout
        # bring the follower up with a registration so it's reachable
        assert subprocess.run([SPL, "start", *largs], env=env_f, capture_output=True,
                              text=True, timeout=30).returncode == 0
        big = os.path.join(tempfile.mkdtemp(), "f")
        open(big, "wb").write(b"x")
        subprocess.run([SPL, "serve", "theleader", "--name", "f", big, *largs], env=env_f,
                       capture_output=True, timeout=30)
        deadline = time.time() + 20
        ok = False
        while time.time() < deadline:
            r = subprocess.run([SPL, "ping", "thefollower", *largs], env=env_l,
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and "reachable" in r.stdout:
                ok = True
                break
            time.sleep(0.5)
        assert ok, "ping never reported the serving peer reachable: " + r.stdout
        print("  ping OK (unreachable then reachable)")
        for env in (env_l, env_f):
            subprocess.run([SPL, "stop"], env=env, capture_output=True)

        print("LIFECYCLE PASSED")
    finally:
        stop(srv)


if __name__ == "__main__":
    main()
