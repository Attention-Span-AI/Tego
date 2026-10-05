#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the actual VM EXIT cleanup against a private copied source tree, without booting a guest.
# Restoring directory permissions must allow removal while leaving symlink targets and hardlinked
# file modes unchanged. The historical cleanup is a negative control for the read-only failure.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python3 - "$here/kvm-run.sh" <<'PY'
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]).read_text()
matches = re.findall(r'^cleanup\(\) \{\n.*?^\}', source, re.MULTILINE | re.DOTALL)
if len(matches) != 1:
    raise SystemExit('FAIL expected exactly one VM cleanup function')
cleanup = matches[0]
# Root bypasses directory write permissions. Run only this hermetic regression as an ordinary UID
# even when the harness gate was invoked as root; every fixture is created after the credential drop.
if os.geteuid() == 0:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


def restore_directories(path):
    if path.is_symlink() or not path.is_dir():
        return
    path.chmod(path.stat().st_mode | stat.S_IRWXU)
    for child in path.iterdir():
        restore_directories(child)


def check(ok, message):
    if not ok:
        raise AssertionError(message)
    print('ok   ' + message, flush=True)


with tempfile.TemporaryDirectory(prefix='tego-kvm-cleanup-test.', dir='/tmp') as name:
    tmp = Path(name)

    def stage(name, restrictive=False):
        run = tmp / name
        leaf = run / 'payload' / 'source copy' / 'nested'
        leaf.mkdir(parents=True)
        (leaf / 'code.txt').write_text('private source copy\n')
        (leaf / 'code.txt').chmod(0o444)
        for directory in (leaf, leaf.parent, leaf.parent.parent):
            directory.chmod(0o555)
        if restrictive:
            leaf.parent.chmod(0)
        return run

    def invoke(function, run, status=0):
        driver = tmp / 'trap.sh'
        driver.write_text('set -euo pipefail\n'
                          'run_dir=$1\ntrace=$2\n'
                          'guarded_kill() { printf "called\\n" >> "$trace"; }\n'
                          + function + '\ntrap cleanup EXIT\nexit "$3"\n')
        trace = tmp / (run.name + '.guarded-kill')
        result = subprocess.run(['bash', str(driver), str(run), str(trace), str(status)],
                                capture_output=True, text=True, timeout=10,
                                env={**os.environ, 'LC_ALL': 'C'})
        check(trace.read_text() == 'called\n', run.name + ': guarded guest cleanup ran once')
        return result

    try:
        legacy = 'cleanup() {\n\tguarded_kill\n\trm -rf "$run_dir"\n}'
        run = stage('historical-readonly')
        result = invoke(legacy, run)
        check(result.returncode != 0 and run.exists() and 'Permission denied' in result.stderr,
              'historical cleanup reproduces the read-only-directory failure')
        restore_directories(run)
        shutil.rmtree(run)

        run = stage('readonly-success')
        result = invoke(cleanup, run)
        check(result.returncode == 0 and not run.exists(),
              'actual EXIT cleanup removes the read-only copied tree and retains exit 0: '
              + repr(result.stderr))

        run = stage('readonly-command-failure')
        result = invoke(cleanup, run, 7)
        check(result.returncode == 7 and not run.exists(),
              'actual EXIT cleanup retains the original command exit 7')

        run = stage('restrictive-directories', restrictive=True)
        result = invoke(cleanup, run)
        check(result.returncode == 0 and not run.exists(),
              'owned mode-000 directories become traversable before descent')

        outside = tmp / 'external'
        outside.mkdir()
        external_dir = outside / 'read-only-directory'
        external_dir.mkdir()
        target = external_dir / 'target.txt'
        target.write_text('external control\n')
        target.chmod(0o444)
        external_dir.chmod(0o555)
        directory_before = external_dir.stat()
        target_before = target.stat()
        run = stage('external-symlinks')
        os.symlink(external_dir, run / 'external-directory')
        os.symlink(target, run / 'external-file')
        result = invoke(cleanup, run)
        check(result.returncode == 0 and not run.exists()
              and external_dir.stat() == directory_before and target.stat() == target_before
              and target.read_text() == 'external control\n',
              'external symlink targets retain their identity, permissions, and content')

        external_file = outside / 'hardlinked-source.txt'
        external_file.write_text('hardlinked external control\n')
        external_file.chmod(0o444)
        before = external_file.stat()
        run = stage('external-hardlink')
        os.link(external_file, run / 'source-alias')
        result = invoke(cleanup, run)
        after = external_file.stat()
        check(result.returncode == 0 and not run.exists()
              and (after.st_dev, after.st_ino, after.st_mode, after.st_nlink)
              == (before.st_dev, before.st_ino, before.st_mode, before.st_nlink)
              and external_file.read_text() == 'hardlinked external control\n',
              'external hardlinked file retains its identity, permissions, content, and final link count')
    finally:
        restore_directories(tmp)
PY
