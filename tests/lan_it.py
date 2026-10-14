#!/usr/bin/env python3
"""LAN discovery: two paired daemons find each other and move data with NO server
at all. Pairing happens normally, then the server is shut down and both daemons
are started against its dead port; discovery must give them a direct path.

Loopback has no broadcast, and two daemons on one host can't share the discovery
port for unicast, so each gets its own port (SPL_LAN_PORT) and is pointed at the
other's (SPL_LAN_TARGETS) — the query/answer exchange is the real one."""
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def udp_port():
    import socket
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    port = free_port()
    srv = start_server(SPL, port)
    envs = []
    try:
        ld, fd = pair_two(SPL, port)
        stop(srv)  # from here on there is no server: nothing answers on `port`
        srv = None

        A = ["--server", "127.0.0.1", "--port", str(port)]
        lport, fport = udp_port(), udp_port()
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp(),
                    SPL_LAN_PORT=str(lport), SPL_LAN_TARGETS=f"127.0.0.1:{fport}")
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp(),
                    SPL_LAN_PORT=str(fport), SPL_LAN_TARGETS=f"127.0.0.1:{lport}")
        envs = [lenv, fenv]

        def run(env, *args):
            return subprocess.run([SPL, *args, *A], env=env, capture_output=True, text=True,
                                  timeout=30)

        # control: with discovery pointed at a port nobody listens on, the peers
        # can't find each other (so what follows really is discovery at work)
        nowhere = f"127.0.0.1:{udp_port()}"
        for env in (lenv, fenv):
            assert run(dict(env, SPL_LAN_TARGETS=nowhere), "start").returncode == 0
        assert run(fenv, "pipe", "register", "theleader", "echo", "ECHO").returncode == 0
        assert run(lenv, "ping", "thefollower").returncode != 0, "reachable with no way to find it?"
        for env in (lenv, fenv):
            assert run(env, "stop").returncode == 0
        print("  without discovery (and no server) the peer is unreachable")

        # an address hint on ONE side is enough: the leader is told where to ask,
        # and its verified query tells the follower where the leader is.
        hint = f"127.0.0.1:{fport}"
        r = subprocess.run([SPL, "peer", "add-address", "thefollower", hint], env=lenv,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stdout + r.stderr
        show = subprocess.run([SPL, "peer", "show", "thefollower"], env=lenv, capture_output=True,
                              text=True).stdout
        assert hint in show, show
        for env in (lenv, fenv):
            assert run(dict(env, SPL_LAN_TARGETS=nowhere), "start").returncode == 0
        assert run(lenv, "ping", "thefollower").returncode == 0, "the address hint didn't work"
        r = subprocess.run([SPL, "peer", "remove-address", "thefollower", hint], env=lenv,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stdout + r.stderr
        assert hint not in subprocess.run([SPL, "peer", "show", "thefollower"], env=lenv,
                                          capture_output=True, text=True).stdout
        for env in (lenv, fenv):
            assert run(env, "stop").returncode == 0
        print("  an address hint on one side finds the peer (still no server)")

        for env in (lenv, fenv):
            r = run(env, "start")
            assert r.returncode == 0, r.stdout + r.stderr

        # data flows end to end with no relay anywhere
        p = subprocess.Popen([SPL, "pipe", "open", "thefollower", "echo", *A], env=lenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        p.stdin.write("no server needed\n")
        p.stdin.flush()
        line = p.stdout.readline()
        assert line == "no server needed\n", f"no data without the server: {line!r}"
        print("  paired peers connect and move data with the server gone")

        for name, env, peer in (("leader", lenv, "thefollower"), ("follower", fenv, "theleader")):
            deadline = time.time() + 10
            st = ""
            while time.time() < deadline:
                st = subprocess.run([SPL, "status"], env=env, capture_output=True,
                                    text=True).stdout
                if f"PEER {peer}: DIRECT" in st:
                    break
                time.sleep(0.3)
            assert f"PEER {peer}: DIRECT" in st, f"{name} never got a direct path:\n{st}"
        print("  both sides are on a direct path found by discovery")
        p.stdin.close()
        stop(p)

        print("LAN PASSED")
    finally:
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        if srv:
            stop(srv)


if __name__ == "__main__":
    main()
