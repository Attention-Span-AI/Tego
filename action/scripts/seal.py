#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze before launch; system sha256sum checks this code before inventory recheck."""
import hashlib
import json
from pathlib import Path
import stat
import sys


def entries(root):
    result = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError('collector contains a link or special file')
        if any(c in str(path) for c in '\n\r\\'):
            raise ValueError('collector path cannot be represented in digest inventory')
        result[path.relative_to(root).as_posix()] = dict(mode=stat.S_IMODE(mode), directory=path.is_dir())
    return result


def freeze(source, dest, manifest):
    dest.mkdir(mode=0o700)
    original = entries(source)
    rows = []
    for name, info in original.items():
        path, target = source / name, dest / name
        if info['directory']:
            target.mkdir(mode=0o700)
            continue
        data = path.read_bytes()
        with target.open('xb') as out:
            out.write(data)
        target.chmod(0o700 if info['mode'] & 0o111 else 0o600)
        digest = hashlib.sha256(data).hexdigest()
        rows += [f'{digest}  {path}\n', f'{digest}  {target}\n']
    inventory = manifest.with_suffix('.json')
    data = json.dumps(dict(original=original, frozen=entries(dest)), sort_keys=True).encode()
    with inventory.open('xb') as out:
        out.write(data)
    inventory.chmod(0o600)
    rows += [f'{hashlib.sha256(data).hexdigest()}  {inventory}\n']
    with manifest.open('x') as out:
        out.writelines(rows)
    manifest.chmod(0o600)


def verify(source, dest, manifest):
    expected = json.loads(manifest.with_suffix('.json').read_text())
    if entries(source) != expected['original'] or entries(dest) != expected['frozen']:
        raise ValueError('collector inventory, type or permissions changed')


try:
    if sys.argv[1] == 'verify':
        verify(*map(Path, sys.argv[2:]))
    else:
        freeze(*map(Path, sys.argv[1:]))
except (ValueError, OSError, KeyError) as error:
    print(str(error), file=sys.stderr)
    sys.exit(125)
