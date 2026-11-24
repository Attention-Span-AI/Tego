#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Read launcher-owned status to stdout without following links or writing as root."""
import os
from pathlib import PurePosixPath
import stat
import sys

LIMIT = 4096


def read_status(path):
    parsed = PurePosixPath(path)
    if not parsed.is_absolute() or path.startswith('//') or str(parsed) != path or '..' in parsed.parts:
        raise ValueError('status path must be absolute and clean')
    parts = parsed.parts[1:]
    if not parts or parts[-1] != 'run-status.json':
        raise ValueError('expected run-status.json')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory)
            os.close(directory)
            directory = next_fd
        parent = os.fstat(directory)
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError('status parent must be launcher-owned mode 0700')
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or
                    info.st_size > LIMIT):
                raise ValueError('status must be launcher-owned singly-linked regular mode 0600 within 4096 bytes')
            with os.fdopen(fd, 'rb', closefd=False) as source:
                data = source.read(LIMIT + 1)
            after = os.fstat(fd)
            if (len(data) != info.st_size or len(data) > LIMIT or
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                    (info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
                raise ValueError('status changed while reading')
            return data
        finally:
            os.close(fd)
    finally:
        os.close(directory)


if __name__ == '__main__':
    try:
        if sys.argv[1:2] != ['read'] or len(sys.argv) != 3:
            raise ValueError('usage: status.py read ABSOLUTE_STATUS_FILE')
        sys.stdout.buffer.write(read_status(sys.argv[2]))
    except (ValueError, OSError) as error:
        print('tego-ci status: ' + str(error), file=sys.stderr)
        sys.exit(125)
