#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise the actual pipeline and timeout boundary with exact owned-pidfd cleanup.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python3 -I -B - "$here" <<'PY'
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types

here = Path(sys.argv[1])
helper = here / 'owned_children.py'
owned = types.ModuleType('owned_children')
exec(compile(helper.read_bytes(), str(helper), 'exec'), owned.__dict__)
if not shutil.which('flock') or not shutil.which('timeout'):
    raise SystemExit('FAIL flock and timeout are required')


def check(ok, message):
    if not ok:
        raise RuntimeError(message)
    print('ok   ' + message, flush=True)


def all_exited(owner):
    deadline = time.monotonic() + .5
    while time.monotonic() < deadline and not all(owner.exited(pid) for pid in owner.refs):
        time.sleep(.01)
    return all(owner.exited(pid) for pid in owner.refs)


with tempfile.TemporaryDirectory(prefix='tego-guarded-test.', dir='/tmp') as name:
    base = Path(name)
    unrelated = owned.OwnedProcess(['/bin/sleep', '399.7'])
    try:
        console, status = base / 'console', base / 'status'
        command = '. "$1"; guarded_run "$2" "$3" sh -c "echo hello; exit 7" </dev/null'
        owner = owned.OwnedProcess(['bash', '-c', command, 'fixture', str(here / 'guarded-run.sh'),
                                    str(console), str(status)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, _ = owner.proc.communicate(timeout=5)
            check(owner.proc.returncode == 0 and out.strip() == b'hello', 'command output reaches stdout')
            check(console.read_text().strip() == 'hello' and status.read_text().strip() == '7',
                  'actual console and status files preserve command output and exit 7')
            check(all_exited(owner), 'status pipeline exited before fixture cleanup')
        finally:
            owner.close()

        for sig in (signal.SIGTERM, signal.SIGHUP):
            case = base / sig.name
            case.mkdir()
            step = case / 'step.sh'
            step.write_text('#!/usr/bin/env bash\n'
                            'sleep 120 &\nchild=$!\n'
                            'trap \'kill "$child"; wait "$child"; exit 124\' TERM\n'
                            'printf "%s\\n" "$$" >"$1/step.pid"\n'
                            'printf "%s\\n" "$child" >"$1/child.pid"\nwait "$child"\n')
            step.chmod(0o700)
            lock = case / 'lock'
            driver = case / 'run.sh'
            driver.write_text('. ' + shlex.quote(str(here / 'guarded-run.sh')) + '\n'
                              + 'exec 9>' + shlex.quote(str(lock)) + '\nflock 9\n'
                              + shlex.join(['guarded_run', str(case / 'console'), str(case / 'status'),
                                            'timeout', '-k', '2', '120', str(step), str(case)])
                              + ' </dev/null\n')
            owner = owned.OwnedProcess(['bash', str(driver)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                owned.await_file(case / 'step.pid', owner)
                owned.await_file(case / 'child.pid', owner)
                try:
                    owner.pin(unrelated.proc.pid)
                except (OSError, RuntimeError):
                    pass
                else:
                    raise RuntimeError('unrelated child was admitted for fixture cleanup')
                check(not unrelated.exited(unrelated.proc.pid), 'unrelated matching sleep remains live')
                owner.send(sig)
                owner.proc.communicate(timeout=5)
                check(owner.proc.returncode == 143, sig.name + ': script exits 143')
                check(all_exited(owner), sig.name + ': timeout, guarded step and child actually exited')
                result = subprocess.run(['flock', '-n', str(lock), 'true'], timeout=2)
                check(result.returncode == 0, sig.name + ': inherited lock released')
            finally:
                owner.close()
            check(not unrelated.exited(unrelated.proc.pid), 'owned cleanup preserves unrelated matching sleep')
    finally:
        unrelated.close()
print('guarded-run_test: ok')
PY
