#!/usr/bin/env python3
"""End-to-end smoke test for `spl server`: whereami, relay, and TLS pairing.

Usage: smoke_server.py [host] [port]
"""
import socket
import ssl
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 7799


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise EOFError("connection closed")
        buf += d
    return buf


def send_frame(s, payload):
    s.sendall(struct.pack(">I", len(payload)) + payload)


def read_frame(s):
    ln = struct.unpack(">I", recvn(s, 4))[0]
    return recvn(s, ln)


def client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_connect(ctx):
    raw = socket.create_connection((HOST, PORT), timeout=4)
    return ctx.wrap_socket(raw, server_hostname="splice")


def test_whereami():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    token = 0xCAFEBABE
    # retry a few times in case the server is still coming up
    last = None
    for _ in range(20):
        try:
            s.sendto(bytes([0x02]) + struct.pack(">I", token), (HOST, PORT))
            data, _ = s.recvfrom(2048)
            break
        except socket.timeout as e:
            last = e
    else:
        raise last
    assert data[0] == 0x02, "bad reply type"
    assert struct.unpack(">I", data[1:5])[0] == token, "token mismatch"
    port = struct.unpack(">H", data[21:23])[0]
    print(f"  whereami OK: server sees this client at port {port}")


def test_relay():
    uid_a = bytes([0x33] * 31 + [0x10])  # side bit 0
    uid_b = bytes([0x33] * 31 + [0x11])  # side bit 1 (peer of A)
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.settimeout(3)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b.settimeout(3)
    a.sendto(bytes([0x01]) + uid_a + b"hello-A", (HOST, PORT))  # A registers
    b.sendto(bytes([0x01]) + uid_b + b"hello-B", (HOST, PORT))  # B -> forwarded to A
    data, _ = a.recvfrom(2048)
    assert data[0] == 0x01 and data[1:] == b"hello-B", data
    a.sendto(bytes([0x01]) + uid_a + b"reply-A", (HOST, PORT))  # A -> forwarded to B
    data, _ = b.recvfrom(2048)
    assert data[1:] == b"reply-A", data
    print("  relay OK: bidirectional forwarding via side-bit flip works")


def test_pairing_bridge():
    ctx = client_ctx()
    leader = tls_connect(ctx)
    send_frame(leader, bytes([0x01]) + struct.pack(">H", 1))  # INIT
    body = read_frame(leader)
    assert body[0] == 0x02, f"expected CODE got {body[0]:#x}"
    code = struct.unpack(">Q", body[1:9])[0]

    follower = tls_connect(ctx)
    send_frame(follower, bytes([0x03]) + struct.pack(">Q", code))  # JOIN

    assert read_frame(leader)[0] == 0x04, "leader expected PAIRED"
    assert read_frame(follower)[0] == 0x04, "follower expected PAIRED"

    # Leader speaks first (turn-based). Relay both directions.
    send_frame(leader, bytes([0x10]) + b"spake-leader")
    assert read_frame(follower) == bytes([0x10]) + b"spake-leader"
    send_frame(follower, bytes([0x10]) + b"spake-follower")
    assert read_frame(leader) == bytes([0x10]) + b"spake-follower"
    print(f"  pairing OK: code={code}, PAIRED both sides, turn-based bridge relays")
    leader.close()
    follower.close()


def test_pairing_bad_code():
    ctx = client_ctx()
    c = tls_connect(ctx)
    send_frame(c, bytes([0x03]) + struct.pack(">Q", 999999))  # JOIN unknown code
    body = read_frame(c)
    assert body[0] == 0x05, f"expected ERR got {body[0]:#x}"  # 0x05 = CtrlType::kError
    print("  pairing OK: unknown code rejected with ERR")
    c.close()


def main():
    tests = [test_whereami, test_relay, test_pairing_bridge, test_pairing_bad_code]
    ok = True
    for t in tests:
        try:
            t()
        except Exception as e:
            ok = False
            print(f"  {t.__name__} FAILED: {e!r}")
    print("ALL SERVER SMOKE TESTS PASSED" if ok else "SERVER SMOKE TESTS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
