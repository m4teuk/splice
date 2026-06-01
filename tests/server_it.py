#!/usr/bin/env python3
"""CTest wrapper: launches `spl server` on a free port, runs smoke_server.py
against it, and tears the server down.

Usage: server_it.py /path/to/spl
"""
import os
import signal
import socket
import subprocess
import sys

spl = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))

# Reserve a free TCP port (the server uses the same number for UDP).
s = socket.socket()
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()

srv = subprocess.Popen(
    [spl, "server", "--bind", "127.0.0.1", "--port", str(port)],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    rc = subprocess.call(
        [sys.executable, os.path.join(here, "smoke_server.py"), "127.0.0.1", str(port)]
    )
finally:
    srv.send_signal(signal.SIGTERM)
    try:
        srv.wait(timeout=5)
    except subprocess.TimeoutExpired:
        srv.kill()

sys.exit(rc)
