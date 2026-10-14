#!/usr/bin/env python3
"""Local pairing: two devices pair with no server at any point, then connect and
move data — the whole life of a pairing offline. Covers finding the leader by
discovery and by `--at`, a wrong id, a wrong code, the automatic fallback when
the relay can't be reached, and the address learned at pairing being saved.

Loopback has no broadcast, so the follower's query is pointed at the leader's
discovery port with SPL_LAN_TARGETS (see lan_it.py)."""
import os
import socket
import subprocess
import sys
import tempfile
import time

from itlib import _read_line, free_port, stop

SPL = sys.argv[1]


def udp_port():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_leader(cfg, udp, tcp, extra=("--local",)):
    env = dict(os.environ, SPL_CONFIG_DIR=cfg, SPL_LAN_PORT=str(udp), SPL_LAN_PAIR_PORT=str(tcp))
    p = subprocess.Popen([SPL, "pair", *extra, "--name", "thefollower"], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = _read_line(p, "Pairing code:", 15)
    assert line, "leader printed no pairing code"
    return p, line.split()[-1]


def lan_port_of(cfg, name):
    for line in show(cfg, name).splitlines():
        if line.strip().startswith("lan port"):
            return line.split()[2]
    return None


def join(cfg, code, *args, env_extra=None):
    env = dict(os.environ, SPL_CONFIG_DIR=cfg, **(env_extra or {}))
    return subprocess.run([SPL, "pair", code, *args, "--name", "theleader"], env=env,
                          capture_output=True, text=True, timeout=40)


def show(cfg, name):
    return subprocess.run([SPL, "peer", "show", name], env=dict(os.environ, SPL_CONFIG_DIR=cfg),
                          capture_output=True, text=True).stdout


def main():
    dead = free_port()  # a "relay" nobody runs
    envs = []
    try:
        # ---- found by discovery ----
        ld, fd = tempfile.mkdtemp(), tempfile.mkdtemp()
        ludp, ltcp, fudp = udp_port(), free_port(), udp_port()
        leader, code = start_leader(ld, ludp, ltcp)
        assert code.startswith("L") and "-" in code, code
        # Each device listens on its own (non-default) LAN port, as a real one
        # would with `[peer] lan_port` set; the leader's is given with --lan-port.
        r = join(fd, code, "--lan-port", str(ludp),
                 env_extra={"SPL_LAN_PORT": str(fudp), "SPL_LAN_TARGETS": "127.0.0.1"})
        assert r.returncode == 0, r.stdout + r.stderr
        assert leader.wait(30) == 0
        for cfg, name in ((ld, "thefollower"), (fd, "theleader")):
            assert "127.0.0.1" in show(cfg, name), "learned address not saved:\n" + show(cfg, name)
        assert lan_port_of(fd, "theleader") == str(ludp), show(fd, "theleader")
        assert lan_port_of(ld, "thefollower") == str(fudp), show(ld, "thefollower")
        print("  paired by local discovery, no server; each saved the other's address and LAN port")

        # ---- …and the pairing works: daemons connect and move data, still no server ----
        A = ["--server", "127.0.0.1", "--port", str(dead)]
        # No discovery targets are given here: the daemons find each other purely
        # from what pairing saved (the other's address + the port it listens on).
        nowhere = f"127.0.0.1:{udp_port()}"
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp(),
                    SPL_LAN_PORT=str(ludp), SPL_LAN_TARGETS=nowhere)
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp(),
                    SPL_LAN_PORT=str(fudp), SPL_LAN_TARGETS=nowhere)
        envs = [lenv, fenv]
        for env in envs:
            assert subprocess.run([SPL, "start", *A], env=env, capture_output=True).returncode == 0
        assert subprocess.run([SPL, "pipe", "register", "theleader", "echo", "ECHO", *A], env=fenv,
                              capture_output=True).returncode == 0
        p = subprocess.Popen([SPL, "pipe", "open", "thefollower", "echo", *A], env=lenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        p.stdin.write("never saw a server\n")
        p.stdin.flush()
        assert p.stdout.readline() == "never saw a server\n"
        p.stdin.close()
        stop(p)
        print("  the locally paired devices connect and move data")

        # ---- the follower moves to another LAN port: the leader is told, and follows ----
        moved = udp_port()
        subprocess.run([SPL, "stop"], env=fenv, capture_output=True)
        fenv = dict(fenv, SPL_LAN_PORT=str(moved))
        envs[1] = fenv
        assert subprocess.run([SPL, "start", *A], env=fenv, capture_output=True).returncode == 0
        deadline = time.time() + 40
        while time.time() < deadline and lan_port_of(ld, "thefollower") != str(moved):
            time.sleep(0.5)
        s = show(ld, "thefollower")
        assert lan_port_of(ld, "thefollower") == str(moved), "the leader never learned the new port:\n" + s
        assert "told by the peer" in s, s
        ls = subprocess.run([SPL, "peer", "ls"], env=dict(os.environ, SPL_CONFIG_DIR=ld),
                            capture_output=True, text=True).stdout
        assert f"lan-port {moved}" in ls, ls
        # …and they are connected again, the leader now asking on the new port
        p = subprocess.Popen([SPL, "pipe", "open", "thefollower", "echo", *A], env=lenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        p.stdin.write("found you again\n")
        p.stdin.flush()
        assert p.stdout.readline() == "found you again\n"
        p.stdin.close()
        stop(p)
        # a hand-set value replaces what the peer said (until it says otherwise again)
        r = subprocess.run([SPL, "peer", "set", "thefollower", "lan-port", "default"],
                           env=dict(os.environ, SPL_CONFIG_DIR=ld), capture_output=True, text=True)
        assert r.returncode == 0 and "lan-port" not in r.stdout, r.stdout + r.stderr
        print("  a peer that moves its LAN port is followed automatically")

        # ---- told where the leader is (--at), after a wrong id is turned away ----
        ld2, fd2 = tempfile.mkdtemp(), tempfile.mkdtemp()
        ludp, ltcp = udp_port(), free_port()
        leader, code = start_leader(ld2, ludp, ltcp)
        at = f"127.0.0.1:{ltcp}"
        r = join(tempfile.mkdtemp(), "L1-000000", "--at", at)
        assert r.returncode != 0 and "unknown pairing code" in r.stdout + r.stderr, r.stdout + r.stderr
        assert leader.poll() is None, "a wrong id must not end the leader's wait"
        r = join(fd2, code, "--at", at)
        assert r.returncode == 0, r.stdout + r.stderr
        assert leader.wait(30) == 0
        s = show(fd2, "theleader")
        assert "127.0.0.1 " in s and at not in s, "--at host should be saved without the pairing port:\n" + s
        print("  paired with --at; a wrong id is refused and the leader keeps waiting")

        # ---- a wrong code fails at key confirmation; nothing is stored ----
        ld3, fd3 = tempfile.mkdtemp(), tempfile.mkdtemp()
        ludp, ltcp = udp_port(), free_port()
        leader, code = start_leader(ld3, ludp, ltcp)
        ident, digits = code.split("-")
        wrong = f"{ident}-{(int(digits) + 1) % 1000000:06d}"
        r = join(fd3, wrong, "--at", f"127.0.0.1:{ltcp}")
        assert r.returncode != 0 and "key confirmation mismatch" in r.stdout + r.stderr, r.stdout + r.stderr
        assert leader.wait(30) != 0
        for cfg in (ld3, fd3):
            assert not [f for f in os.listdir(cfg) if f.endswith(".conn")], "a failed pairing left a record"
        print("  a wrong code aborts at key confirmation, nothing stored")

        # ---- no relay reachable: the leader falls back to a local code by itself ----
        ld4 = tempfile.mkdtemp()
        leader, code = start_leader(ld4, udp_port(), free_port(),
                                    extra=("--server", "127.0.0.1", "--port", str(dead)))
        assert code.startswith("L"), f"expected a local code without a relay, got {code}"
        stop(leader)
        # …while a relay code can't be joined without the relay, and says what to do
        r = subprocess.run([SPL, "pair", "3-123456", "--server", "127.0.0.1", "--port", str(dead)],
                           env=dict(os.environ, SPL_CONFIG_DIR=tempfile.mkdtemp()),
                           capture_output=True, text=True, timeout=30)
        assert r.returncode != 0 and "--local" in r.stdout + r.stderr, r.stdout + r.stderr
        print("  with no relay, `spl pair` goes local on its own")

        print("PAIR LOCAL PASSED")
    finally:
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
