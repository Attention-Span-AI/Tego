#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable-guest witness: another process cannot write an inherited broker socket."""
import json
import os
from pathlib import Path
import socket
import struct
import sys


def witness(directory, launcher, ask, approve):
    # The driver retains the real launch PID; compare the server's kernel credentials.
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        connection.settimeout(5)
        connection.connect(str(Path(directory) / "ask.sock"))
        pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != launcher or uid != 0:
            raise RuntimeError("socket is not the driver's actual root launcher")
        hello = json.loads(connection.recv(65536))
        if len(hello.get("ready", "")) != 32:
            raise RuntimeError("root parent was not admitted to the managed broker")
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            status = 0
            try:
                packet = dict(action="answer", nonce=hello["ready"], ask_id=ask, approve=approve)
                connection.send(json.dumps(packet).encode())
                reply = json.loads(connection.recv(65536))
                if reply.get("code") != "owner-only" or "only root may answer once" not in reply.get("error", ""):
                    raise RuntimeError("inherited writer was not refused by the managed broker")
                result = dict(parent_pid=os.getppid(), writer_pid=os.getpid(), writer_euid=os.geteuid(), approve=approve, code=reply["code"])
                os.write(write_fd, json.dumps(result).encode())
            except Exception as error:
                os.write(write_fd, json.dumps(dict(error=str(error))).encode())
                status = 1
            finally:
                os.close(write_fd)
            os._exit(status)
        os.close(write_fd)
        result = os.read(read_fd, 65536)
        os.close(read_fd)
        _, status = os.waitpid(child, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError(result.decode())
        return json.loads(result)


def main():
    if os.geteuid() != 0 or os.environ.get("TEGO_DISPOSABLE_HOST") != "kvm" or not Path("/run/roles1-guest").is_file():
        raise RuntimeError("requires explicit disposable guest root")
    directory, launcher, ask = sys.argv[1:]
    print(json.dumps([witness(directory, int(launcher), ask, approve) for approve in (True, False)], indent=2))


if __name__ == "__main__":
    main()
