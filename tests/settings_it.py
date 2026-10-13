#!/usr/bin/env python3
"""Per-peer settings decide how a peer may be found, and apply to a running
daemon: `relay off` keeps the relay out of it, `lan-discovery off` stops our
broadcasts (we still answer the peer's), and `remember-address` lets a restarted
daemon go straight back to the address that worked.

Each daemon gets its own discovery port and explicit targets (see lan_it.py), so
"discovery" here is exactly what the test points it at."""
import os
import socket
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def udp_port():
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
        A = ["--server", "127.0.0.1", "--port", str(port)]
        lport, fport = udp_port(), udp_port()
        nowhere = f"127.0.0.1:{udp_port()}"
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp(),
                    SPL_LAN_PORT=str(lport), SPL_LAN_TARGETS=f"127.0.0.1:{fport}")
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp(),
                    SPL_LAN_PORT=str(fport), SPL_LAN_TARGETS=f"127.0.0.1:{lport}")
        envs = [lenv, fenv]
        blind = lambda env: dict(env, SPL_LAN_TARGETS=nowhere)  # discovery finds nothing

        def run(env, *args):
            return subprocess.run([SPL, *args, *A], env=env, capture_output=True, text=True,
                                  timeout=30)

        def peer(env, *args):
            r = subprocess.run([SPL, "peer", *args], env=env, capture_output=True, text=True,
                               timeout=30)
            assert r.returncode == 0, r.stdout + r.stderr
            return r.stdout

        def ping(env, name):
            return run(env, "ping", name).returncode == 0

        def start(l, f):
            for env in (l, f):
                assert run(env, "start").returncode == 0

        def stop_all():
            for env in (lenv, fenv):
                run(env, "stop")

        assert run(fenv, "register", "theleader", "echo", "ECHO").returncode == 0
        stop_all()

        # ---- relay ----
        # Discovery blind, so the relay is the only way to meet. With it off on one
        # side the peers never find each other; turning it on (live) fixes that.
        out = peer(lenv, "set", "thefollower", "relay", "off")
        assert "relay off" in out, out
        start(blind(lenv), blind(fenv))
        st = run(lenv, "status").stdout
        assert "relay off" in st and "addresses known" in st, st
        assert "relay off" in peer(lenv, "ls"), peer(lenv, "ls")
        assert not ping(lenv, "thefollower"), "reached the peer with relay off and no discovery"
        peer(lenv, "set", "thefollower", "relay", "on")
        assert ping(lenv, "thefollower") or ping(lenv, "thefollower"), "relay on (live) did not help"
        stop_all()
        print("  relay off keeps the relay out; relay on applies to the running daemon")

        stop(srv)  # the rest needs no server at all
        srv = None

        # ---- lan-discovery ----
        # Off on both sides: nobody asks, so nobody is found. On again on one side
        # (live): it asks, the other still answers.
        peer(lenv, "set", "thefollower", "lan-discovery", "off")
        peer(fenv, "set", "theleader", "lan-discovery", "off")
        peer(lenv, "set", "thefollower", "remember-address", "off")  # keep this phase clean
        start(lenv, fenv)
        assert not ping(lenv, "thefollower"), "found the peer with lan-discovery off on both sides"
        peer(lenv, "set", "thefollower", "lan-discovery", "on")
        assert ping(lenv, "thefollower") or ping(lenv, "thefollower"), "lan-discovery on did not help"
        print("  lan-discovery off stops our queries (we still answer); on applies live")

        # ---- remember-address ----
        peer(lenv, "set", "thefollower", "remember-address", "on")
        deadline = time.time() + 15
        while time.time() < deadline and "(seen" not in peer(lenv, "show", "thefollower"):
            ping(lenv, "thefollower")
            time.sleep(0.5)
        show = peer(lenv, "show", "thefollower")
        assert "(seen" in show, "the working address was never remembered:\n" + show
        # Restart only our daemon, with nothing able to discover anything: the
        # remembered address (the follower's still-running socket) must be enough.
        peer(lenv, "set", "thefollower", "lan-discovery", "off")
        run(lenv, "stop")
        assert run(blind(lenv), "start").returncode == 0
        assert ping(lenv, "thefollower") or ping(lenv, "thefollower"), \
            "a remembered address was not tried after a restart"
        print("  remember-address reconnects a restarted daemon straight away")

        # …and turning it off forgets, so the same restart now finds nothing.
        out = peer(lenv, "set", "thefollower", "remember-address", "off")
        assert "(seen" not in peer(lenv, "show", "thefollower")
        run(lenv, "stop")
        assert run(blind(lenv), "start").returncode == 0
        assert not ping(lenv, "thefollower"), "still reachable after forgetting the address"
        print("  remember-address off forgets what was remembered")

        print("SETTINGS PASSED")
    finally:
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        if srv:
            stop(srv)


if __name__ == "__main__":
    main()
