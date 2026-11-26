#!/usr/bin/env python3
"""Prints the SHA-256 of the TLS certificate served by a lab machine.

  tls_cert.py rdp <host> [port]    Remote Desktop: X.224 connection request
                                   with an RDP negotiation request (TLS or
                                   CredSSP, [MS-RDPBCGR] 2.2.1.1), then TLS
  tls_cert.py tls <host> <port>    plain TLS (LDAPS...)

Lab tool only: it reads the certificate to compare it with the fingerprint
the machine reported, it does not authenticate anything.
"""

import hashlib
import socket
import ssl
import struct
import sys

PROTOCOL_SSL = 0x1
PROTOCOL_HYBRID = 0x2


def x224_negotiate(sock):
    neg_req = struct.pack("<BBHI", 0x01, 0x00, 8, PROTOCOL_SSL | PROTOCOL_HYBRID)
    x224 = bytes([6 + len(neg_req), 0xE0, 0, 0, 0, 0, 0]) + neg_req
    sock.sendall(struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224)
    header = recv_exact(sock, 4)
    if header[0] != 3:
        raise SystemExit("not a TPKT answer")
    body = recv_exact(sock, struct.unpack(">H", header[2:4])[0] - 4)
    if len(body) < 7 or body[1] & 0xF0 != 0xD0:
        raise SystemExit("not an X.224 connection confirm")
    neg = body[7:]
    if len(neg) < 8:
        raise SystemExit("no RDP negotiation response")
    kind, _flags, _length, value = struct.unpack("<BBHI", neg[:8])
    if kind == 0x03:
        raise SystemExit(f"negotiation failure, code {value}")
    if kind != 0x02 or value not in (PROTOCOL_SSL, PROTOCOL_HYBRID):
        raise SystemExit(f"unexpected negotiation response {kind}/{value}")


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise SystemExit("connection closed")
        data += chunk
    return data


def main(argv):
    if len(argv) < 3 or argv[1] not in ("rdp", "tls"):
        raise SystemExit(__doc__)
    mode, host = argv[1], argv[2]
    port = int(argv[3]) if len(argv) > 3 else 3389
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15) as sock:
        if mode == "rdp":
            x224_negotiate(sock)
        with ctx.wrap_socket(sock, server_hostname=None) as tls:
            der = tls.getpeercert(binary_form=True)
    print(hashlib.sha256(der).hexdigest())


if __name__ == "__main__":
    main(sys.argv)
