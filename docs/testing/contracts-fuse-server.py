#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Guest-only read-only FUSE fixture. It normally answers, then accepts SIGSTOP.

Use: python3 -I contracts-fuse-server.py MOUNTPOINT UID GID SOURCE
No Python FUSE package, compiler, library or external staged fixture is needed.
The caller must be real root inside a disposable guest, with /dev/fuse available.
"""

import ctypes
import errno
import os
import stat
import struct
import sys


def serve(mountpoint, uid, gid, source):
    data = open(source, 'rb').read()
    modes = {1: stat.S_IFDIR | 0o755, 2: stat.S_IFDIR | 0o755,
             3: stat.S_IFREG | 0o644}
    names = {(1, b'project'): 2, (2, b'agent.yaml'): 3}

    def attr(node):
        size = len(data) if node == 3 else 0
        # fuse_attr, Linux fuse.h: six u64 fields, ten u32 fields.
        return struct.pack('<6Q10I', node, size, (size + 511) // 512,
                           0, 0, 0, 0, 0, 0, modes[node],
                           1 if node == 3 else 2, uid, gid, 0, 4096, 0)

    libc = ctypes.CDLL(None, use_errno=True)
    fd = os.open('/dev/fuse', os.O_RDWR)
    options = (f'fd={fd},rootmode=40000,user_id=0,group_id=0,'
               'allow_other,max_read=131072').encode()
    if libc.mount(b'contracts-proof', os.fsencode(mountpoint), b'fuse', 7,
                  options) != 0:
        raise OSError(ctypes.get_errno(), 'mount FUSE')
    print('MOUNTED', mountpoint, flush=True)
    while True:
        try:
            request = os.read(fd, 1 << 20)
        except OSError as error:
            if error.errno in (errno.ENODEV, errno.ECONNABORTED):
                return
            raise
        if not request:
            return
        length, op, unique, node = struct.unpack_from('<IIQQ', request)
        body = request[40:length]
        result, error = b'', 0
        print(f'REQUEST op={op} unique={unique} node={node}', flush=True)
        if op == 26:  # FUSE_INIT, protocol 7.31, no optional capabilities.
            major, minor = struct.unpack_from('<II', body)
            assert major == 7
            result = struct.pack('<IIIIHHIIHHII', 7, min(minor, 31),
                                 131072, 0, 12, 9, 131072, 1,
                                 32, 0, 0, 0) + bytes(24)
        elif op in (2, 42):  # FORGET/BATCH_FORGET have no reply.
            continue
        elif op == 1:  # LOOKUP; zero TTL prevents cached success after SIGSTOP.
            child = names.get((node, body.rstrip(b'\0')))
            if child is None:
                error = errno.ENOENT
            else:
                result = struct.pack('<4Q2I', child, 1, 0, 0, 0, 0) + attr(child)
        elif op == 3:  # GETATTR, zero TTL.
            result = struct.pack('<QII', 0, 0, 0) + attr(node)
        elif op in (14, 27):  # OPEN/OPENDIR; FOPEN_DIRECT_IO on regular files.
            result = struct.pack('<QII', node, 1 if op == 14 else 0, 0)
        elif op == 15:  # READ.
            offset, size = struct.unpack_from('<QI', body, 8)
            result = data[offset:offset + size]
        elif op == 28:  # READDIR, offsets are entry indices.
            offset, size = struct.unpack_from('<QI', body, 8)
            entries = [(node, b'.', 4), (1, b'..', 4)]
            entries += [(2, b'project', 4)] if node == 1 else [(3, b'agent.yaml', 8)]
            for index, (ino, name, kind) in enumerate(entries):
                if index < offset:
                    continue
                entry = struct.pack('<QQII', ino, index + 1, len(name), kind) + name
                entry += bytes((-len(entry)) % 8)
                if len(result) + len(entry) > size:
                    break
                result += entry
        elif op == 17:  # STATFS: fuse_kstatfs is five u64 and ten u32 (80 bytes); the kernel refuses any other size.
            result = struct.pack('<5Q10I', 1024, 1024, 1024, 3, 1021,
                                 4096, 255, 4096, 0, 0, 0, 0, 0, 0, 0)
        elif op in (18, 20, 25, 29, 30, 34, 38):
            pass  # RELEASE, FSYNC, FLUSH, FSYNCDIR, ACCESS, DESTROY.
        elif op in (21, 22, 23, 24):
            error = errno.ENODATA  # No extended attributes.
        else:
            error = errno.ENOSYS
        try:
            os.write(fd, struct.pack('<IiQ', 16 + len(result), -error, unique) + result)
        except OSError as failure:
            # Timed-out callers may cancel a request while the server is
            # stopped. A cancelled unique has no waiting recipient. Abort can
            # also race this reply; neither outcome is a failed fixture server.
            if failure.errno == errno.ENOENT:
                continue
            if failure.errno in (errno.ENODEV, errno.ECONNABORTED):
                return
            raise


if __name__ == '__main__':
    if os.getuid() != 0 or os.environ.get('TEGO_DISPOSABLE_HOST') != 'kvm':
        sys.exit('guest root only: require TEGO_DISPOSABLE_HOST=kvm')
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    serve(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
