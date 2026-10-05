#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise actual forwarding without selecting unrelated tasks by command-line patterns.
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
if not shutil.which('flock'):
    raise SystemExit('FAIL flock is required')


def check(ok, message):
    if not ok:
        raise RuntimeError(message)
    print('ok   ' + message, flush=True)


def all_exited(owner):
    deadline = time.monotonic() + .5
    while time.monotonic() < deadline and not all(owner.exited(pid) for pid in owner.refs):
        time.sleep(.01)
    return all(owner.exited(pid) for pid in owner.refs)


with tempfile.TemporaryDirectory(prefix='tego-fwd-test.', dir='/tmp') as name:
    base = Path(name)
    unrelated = owned.OwnedProcess(['/bin/sleep', '399.9'])
    try:
        owner = owned.OwnedProcess(['bash', '-c', '. "$1"; fwd_run sh -c "exit 7" </dev/null',
                                    'fixture', str(here / 'fwd-run.sh')],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            owner.proc.communicate(timeout=5)
            check(owner.proc.returncode == 7, 'fwd_run returns the actual step status')
            check(all_exited(owner), 'status case has exited before fixture cleanup')
        finally:
            owner.close()

        for mode in ('plain', 'lock'):
            for sig in (signal.SIGTERM, signal.SIGHUP):
                case = base / (mode + '-' + sig.name)
                case.mkdir()
                step = case / 'step.sh'
                step.write_text('#!/usr/bin/env bash\n'
                                'trap \'kill "$child"; wait "$child"; exit 124\' TERM\n'
                                'sleep 120 &\nchild=$!\n'
                                'printf "%s\\n" "$$" >"$1/step.pid"\n'
                                'printf "%s\\n" "$child" >"$1/child.pid"\nwait "$child"\n')
                step.chmod(0o700)
                lock = case / 'lock'
                command = ['fwd_run']
                if mode == 'lock':
                    command += ['-L', 'flock', '-o', str(lock)]
                command += [str(step), str(case)]
                driver = case / 'run.sh'
                driver.write_text('. ' + shlex.quote(str(here / 'fwd-run.sh')) + '\n'
                                  + shlex.join(command) + ' </dev/null\n')
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
                    check(owner.proc.returncode == 143, mode + ' ' + sig.name + ': script exits 143')
                    check(all_exited(owner), mode + ' ' + sig.name + ': step and child actually exited')
                    if mode == 'lock':
                        result = subprocess.run(['flock', '-n', str(lock), 'true'], timeout=2)
                        check(result.returncode == 0, sig.name + ': lock released')
                finally:
                    owner.close()
                check(not unrelated.exited(unrelated.proc.pid), 'owned cleanup preserves unrelated matching sleep')
    finally:
        unrelated.close()
print('fwd-run_test: ok')
PY
