#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise the actual --file staging functions and loop without fetching or booting a guest.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python3 -I -B - "$here/kvm-run.sh" "$@" <<'PY'
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('source')
parser.add_argument('--original')
args = parser.parse_args()
source = Path(args.original or args.source).read_text()
functions = ''
for name in ('check_guest_destination', 'stage_guest_file'):
    matches = re.findall(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
    if len(matches) != (0 if args.original else 1):
        raise SystemExit('FAIL expected actual staging function ' + name)
    functions += '\n'.join(matches) + '\n'
loops = re.findall(r'^for spec in .*?^done$', source, re.M | re.S)
writes = re.findall(r'^echo "\$nonce" >"\$P/\.vm/nonce"$', source, re.M)
if len(loops) != 1 or len(writes) != 1:
    raise SystemExit('FAIL expected one staging loop and nonce write')
failed = 0


def check(ok, message):
    global failed
    print(('ok   ' if ok else 'FAIL ') + message, flush=True)
    failed += not ok


with tempfile.TemporaryDirectory(prefix='tego-kvm-files.', dir='/tmp') as name:
    base = Path(name)
    driver = base / 'driver.sh'
    driver.write_text('set -euo pipefail\nP=$3\nrun_dir=$4\nfiles=("$1:$2")\n'
                      'shift 4\nfiles+=("$@")\n'
                      'EXIT_USAGE=2\nstatus() { :; }\n' + functions + loops[0]
                      + '\nnonce=fixture\n' + writes[0] + '\n')

    # unchanged_identity is what staging could change about the marker: its inode, type, permissions, links,
    # owner, size and content/inode change times. The access time is left out: reading the marker to compare its
    # contents updates atime under relatime, which made the whole-stat comparison pass or fail with the clock tick.
    def unchanged_identity(st):
        return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid, st.st_size,
                st.st_mtime_ns, st.st_ctime_ns)

    def invoke(label, arrange, expected, fail_find=False):
        root = base / label
        payload = root / 'payload'
        (payload / '.vm').mkdir(parents=True)
        outside = root / 'outside'
        outside.mkdir()
        marker = outside / 'marker'
        marker.write_text('unchanged\n')
        before = unchanged_identity(marker.stat())
        source = root / 'input'
        source.write_text('copied\n')
        src, dst, *extra = arrange(root, payload, outside, source)
        env = {**os.environ, 'LC_ALL': 'C'}
        if fail_find:
            tools = root / 'tools'
            tools.mkdir()
            (tools / 'find').write_text('#!/bin/sh\nprintf called >"$FIND_MARKER"\nexit 23\n')
            (tools / 'find').chmod(0o755)
            env.update(PATH=str(tools) + ':' + env['PATH'], FIND_MARKER=str(root / 'find-called'))
        result = subprocess.run(['bash', str(driver), str(src), dst, str(payload), str(root), *extra],
                                capture_output=True, text=True, timeout=10,
                                env=env)
        check(result.returncode == expected,
              label + ': actual staging exit=' + str(result.returncode)
              + ' want=' + str(expected) + ' ' + result.stderr.strip())
        after = unchanged_identity(marker.stat())
        check(after == before and marker.read_text() == 'unchanged\n',
              label + ': private outside marker unchanged')
        if fail_find:
            check((root / 'find-called').exists() and (root / 'find-called').read_text() == 'called'
                  and not (payload / 'vm/target').exists(),
                  'failed source enumeration occurs before any copy')
        return payload

    def traversal(root, payload, outside, source):
        return source, '/../outside/marker'

    def parent_link(root, payload, outside, source):
        (payload / 'jump').symlink_to(outside, target_is_directory=True)
        return source, '/jump/marker'

    def final_link(root, payload, outside, source):
        (payload / 'leaf').symlink_to(outside / 'marker')
        return source, '/leaf'

    def recursive_link(root, payload, outside, source):
        source.unlink()
        (source / 'inner').mkdir(parents=True)
        (source / 'inner/marker').write_text('copied\n')
        (payload / 'input/inner').mkdir(parents=True)
        (payload / 'input/inner/marker').symlink_to(outside / 'marker')
        return source, '/'

    def metadata(root, payload, outside, source):
        source.unlink()
        (source / '.vm').mkdir(parents=True)
        (source / '.vm/nonce').symlink_to(outside / 'marker')
        return str(source) + '/.', '/'

    def relative(root, payload, outside, source):
        return source, 'vm/input'

    def copied_parent_link(root, payload, outside, source):
        link = root / 'incoming-link'
        link.symlink_to(outside, target_is_directory=True)
        return link, '/jump', str(source) + ':/jump/marker'

    def recursive_parent_link(root, payload, outside, source):
        source.unlink()
        (source / 'inner/sub').mkdir(parents=True)
        (source / 'inner/sub/marker').write_text('copied\n')
        (payload / 'input').mkdir()
        (payload / 'input/inner').symlink_to(outside, target_is_directory=True)
        return source, '/'

    for label, arrange in [('parent-traversal', traversal), ('symlink-parent', parent_link),
                           ('symlink-leaf', final_link), ('recursive-symlink', recursive_link),
                           ('reserved-metadata', metadata), ('relative-destination', relative),
                           ('second-copy-symlink', copied_parent_link),
                           ('recursive-symlink-parent', recursive_parent_link)]:
        invoke(label, arrange, 2)

    payload = invoke('ordinary-file', lambda r, p, o, s: (s, '/vm/input'), 0)
    check((payload / 'vm/input').read_text() == 'copied\n', 'ordinary guest file is copied')

    def existing_directory(root, payload, outside, source):
        (payload / 'vm').mkdir()
        return source, '/vm'

    payload = invoke('existing-directory', existing_directory, 0)
    check((payload / 'vm/input').read_text() == 'copied\n',
          'existing destination directory appends the source basename')

    def root_merge(root, payload, outside, source):
        source.unlink()
        (source / 'etc').mkdir(parents=True)
        (source / 'etc/value').write_text('guest root merge\n')
        return str(source) + '/.', '/'

    payload = invoke('guest-root-merge', root_merge, 0)
    check((payload / 'etc/value').read_text() == 'guest root merge\n',
          'source/. merges its contents at the guest root')

    def links(root, payload, outside, source):
        source.unlink()
        (source / 'space and\nnewline').mkdir(parents=True)
        first = source / 'space and\nnewline/first'
        first.write_text('hardlinked guest file\n')
        os.link(first, source / 'space and\nnewline/second')
        (source / 'guest-link').symlink_to('/etc/guest-target')
        return source, '/vm/links'

    payload = invoke('guest-links', links, 0)
    first = payload / 'vm/links/space and\nnewline/first'
    second = payload / 'vm/links/space and\nnewline/second'
    check(first.read_text() == 'hardlinked guest file\n' and first.stat().st_ino == second.stat().st_ino,
          'recursive staging preserves hardlinks and newline paths')
    check(os.readlink(payload / 'vm/links/guest-link') == '/etc/guest-target',
          'copied guest symlink remains a leaf rather than being followed on the host')
    invoke('failed-enumeration', lambda r, p, o, s: root_merge(r, p, o, s)[:1] + ('/vm/target',),
           2, fail_find=True)
raise SystemExit(1 if failed else 0)
PY
