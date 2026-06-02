#!/usr/bin/env python3
"""Onboarding: the `spl server` setup walkthrough writes a config, and a
config-only server (no flags) then runs and relays a real pairing.

Usage: setup_it.py /path/to/spl
"""
import os
import socket
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, stop

SPL = sys.argv[1]


def wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def main():
    cfgdir = tempfile.mkdtemp()
    port = free_port()
    env = dict(os.environ, SPL_CONFIG_DIR=cfgdir)

    # 1. Drive the walkthrough non-interactively (--setup forces it, reads stdin).
    #    Answer bind + port, accept the rest of the suggestions with blank lines.
    proc = subprocess.Popen(
        [SPL, "server", "--setup"], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=env,
    )
    proc.stdin.write(f"127.0.0.1\n{port}\n\n\n\n\n\n")
    proc.stdin.flush()
    if not wait_port(port):
        stop(proc)
        raise SystemExit("setup did not start a server")
    stop(proc)

    with open(os.path.join(cfgdir, "config")) as f:
        cfg = f.read()
    assert "addr = 127.0.0.1" in cfg, cfg
    assert f"port = {port}" in cfg, cfg
    assert "per_ip_rate = 500" in cfg, cfg
    assert "[peer]" in cfg and "this server" in cfg.lower(), "missing client-setup comment"
    print("  walkthrough wrote a complete config + client comment OK")

    # 2. A config-only run (no flags at all) must bind from that config.
    while wait_port(port, 0.2):  # let the setup server's port fully release
        time.sleep(0.1)
    srv = subprocess.Popen([SPL, "server"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, env=env)
    try:
        if not wait_port(port):
            raise SystemExit("config-only `spl server` did not bind")
        print("  config-only `spl server` binds from config OK")

        # 3. And it actually works: two peers pair through it.
        pair_two(SPL, port)
        print("  pairing through the config-only server OK")
    finally:
        stop(srv)

    print("SETUP E2E PASSED")


if __name__ == "__main__":
    main()
