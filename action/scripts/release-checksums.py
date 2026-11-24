#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Strict release checksum membership without executing downloaded bytes."""
import hashlib
import pathlib
import re
import sys


def validate(checksums, asset, binary, independent):
    if len(checksums) > 1024 * 1024:
        raise ValueError('release checksums exceed 1 MiB')
    entries = {}
    for line in checksums.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        if not match or match[2] in entries:
            raise ValueError('malformed or duplicate release checksum entry')
        entries[match[2]] = match[1]
    got = hashlib.sha256(binary).hexdigest()
    if entries.get(asset) != got or got != independent:
        raise ValueError('named release binary checksum mismatch')


if __name__ == '__main__':
    try:
        validate(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[2],
                 pathlib.Path(sys.argv[3]).read_bytes(), sys.argv[4])
    except (ValueError, OSError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(125)
