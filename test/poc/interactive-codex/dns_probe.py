# SPDX-License-Identifier: Apache-2.0
#
# dns_probe.py — one DNS query for example.com, sent to the machine's resolver (127.0.0.53, systemd-resolved) the two ways
# a resolver can send it, from inside a contract with `net.dns.mode: off` at tier landlock (run.sh, P4). Not Codex: a
# program of its own, so the result is about tego and not about what Codex asks. It prints whether an answer came back.
#   connected     socket.connect() then send(): what glibc's resolver does. The supervisor refuses the connect.
#   unconnected   sendto() with the address: what musl's resolver does, and Codex is a musl program. The supervisor
#                 reads the address, records the datagram as refused, and lets the syscall through (SEMANTICS.md,
#                 "UDP": best effort in the unprivileged tier), so the query is sent and the answer comes back.
import socket
import struct

query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
for how in ("connected", "unconnected"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        if how == "connected":
            s.connect(("127.0.0.53", 53))
            s.send(query)
        else:
            s.sendto(query, ("127.0.0.53", 53))
        data, peer = s.recvfrom(512)
        print(f"{how:<12} query sent, an ANSWER CAME BACK from {peer[0]}:{peer[1]} ({len(data)} bytes)")
    except OSError as e:
        print(f"{how:<12} not sent: {e.strerror} (errno {e.errno})")
    finally:
        s.close()
