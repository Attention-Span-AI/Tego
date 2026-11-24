#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""The Windows command's fixed guest entry point; caller argv travels as data."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request


def invocation(payload):
    args = json.loads(base64.b64decode(payload, validate=True).decode('utf-8'))
    if not isinstance(args, list) or not all(isinstance(a, str) and '\0' not in a for a in args):
        raise ValueError('expected an array of arguments without NUL')
    return args


def working_folder(home):
    try:
        last = (home / '.config/tego/last-project').read_text().strip()
        if Path(last).is_absolute() and Path(last).is_dir():
            return last
    except OSError:
        pass
    return str(home)


def install_release(values):
    tag, base, digest, installer_hash, test_http = [base64.b64decode(v, validate=True).decode('utf-8') for v in values]
    import hashlib
    with tempfile.TemporaryDirectory(prefix='tego-install-') as folder:
        script = Path(folder) / 'install.sh'
        with urllib.request.urlopen(base + '/' + tag + '/install.sh', timeout=300) as source:
            data = source.read()
        if hashlib.sha256(data).hexdigest() != installer_hash:
            raise ValueError('installer digest changed; retry the Windows installer')
        script.write_bytes(data)
        # Windows already checked this exact checksums digest. The Linux step
        # checks the pinned bytes; it must not imply a second publisher check.
        env = dict(os.environ, TEGO_VERSION=tag, TEGO_BASE_URL=base, TEGO_CHECKSUMS_SHA256=digest,
                   TEGO_VERIFY='sha256', TEGO_TEST_HTTP='1' if test_http == 'True' else '')
        installed = subprocess.run(['sh', str(script)], env=env, capture_output=True, text=True)
        if installed.returncode:
            print(installed.stdout + installed.stderr, end='', file=sys.stderr)
            return 125
    binary = str(Path.home()/'.local/bin/tego')
    check = subprocess.run([binary, 'machine', 'check', '--json'], capture_output=True, text=True)
    try:
        facts = json.loads(check.stdout) if check.returncode in (0, 1) else {}
    except ValueError:
        facts = {}
    if not facts.get('tier'):
        reason = next(iter(check.stderr.strip().splitlines()), 'the machine check reported no available protection level')
        print('Tego installed, but this PC does not give it a protection level. It will not run agents safely. Reason: ' + reason[:300])
        return 211
    # A usable kernel tier alone does not establish that the guide can start.
    # In particular, default WSL has a private cgroup namespace: the existing
    # governed-caller guard must keep refusing that uncertainty.
    guide = subprocess.run([binary, 'setup', '--json'], capture_output=True, text=True)
    if guide.returncode:
        print("Tego is installed, but the guide's safety check did not pass in this Linux session.")
        return 212
    level = {'landlock': 'Basic', 'cgroup': 'Plus', 'bpflsm': 'Max'}.get(facts['tier'], facts['tier'])
    print('Tego is installed. ' + level + ' protection is available here. Details: tego doctor.')
    return 0


def wait_for_user_bus(runtime, timeout=60):
    # A cold WSL command can begin before logind has opened this lingering
    # user's bus. Never run outside the user scope to get past that race.
    deadline = time.monotonic() + timeout
    bus = Path(runtime) / 'bus'
    while not bus.is_socket():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)
    return True


def main(args):
    home = Path.home()
    os.chdir(working_folder(home))
    os.environ['PATH'] = str(home / '.local/bin') + ':/usr/local/bin:/usr/bin:/bin'
    os.environ['TEGO_HOST_KIND'] = 'windows'
    uid = os.getuid()
    os.environ['XDG_RUNTIME_DIR'] = '/run/user/' + str(uid)
    os.environ.pop('DBUS_SESSION_BUS_ADDRESS', None)
    os.environ.pop('TEGO_WINDOWS_NATIVE', None)
    if args and args[0] == '--scoped':
        cgroup = Path('/proc/self/cgroup').read_text()
        if '/user@' + str(uid) + '.service/' not in cgroup:
            raise RuntimeError('scope entry did not reach this user manager: ' + cgroup.strip())
        if args[1] == '--ready':
            print('TEGO_SCOPE_READY', flush=True)
            while sys.stdin.buffer.read(4096):
                pass
            return 0
        if args[1] == '--install':
            return install_release(args[2:])
        # The dashboard relay's two Linux modes (docs/adr/0123, "A browser on Windows"): fixed arguments only,
        # started here, inside this user's scope, so their sockets to the dashboard are made outside every run.
        # Standard output is the relay's binary pipe or its one open line: nothing else may be printed to it.
        if args[1] in ('--relay', '--dashboard-open'):
            mode = 'serve' if args[1] == '--relay' else 'open'
            return os.execv(str(home/'.local/bin/tego'), ['tego', 'dashboard-relay', mode])
        command = invocation(args[1])
        if not command or command[0] == 'shell':
            if not command or len(command) == 1:
                print("In Tego's Linux, inside Windows: " + os.getcwd() + '. Type exit to go back to Windows.', flush=True)
            return os.execv('/bin/bash', ['bash', '-l'] + command[1:])
        if command == ['serve', '--open']:
            command = ['dashboard']
        # Said only to commands the Windows tego command runs (never to the shell above): the Windows command
        # opens the dashboard in the person's browser after tego dashboard or the guide returns.
        os.environ['TEGO_WINDOWS_NATIVE'] = '1'
        return os.execv(str(home/'.local/bin/tego'), ['tego'] + command)
    # Only fixed bootstrap code crosses the command-line parser. systemd's
    # environment expansion cannot reinterpret the base64 payload.
    if not wait_for_user_bus(os.environ['XDG_RUNTIME_DIR']):
        print('tego: Linux user services are still starting. Next: wait a moment, then retry this command.', file=sys.stderr)
        return 125
    command = ['/usr/bin/systemd-run', '--user', '--scope', '--quiet', '--',
               '/usr/bin/python3', str(Path(__file__).resolve()), '--scoped'] + args
    return os.execv(command[0], command)


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        next_step = '' if '--install' in sys.argv[1:] else '. Next: type exit to return to Windows if needed, then rerun the Windows installer.'
        print('tego: ' + str(error) + next_step, file=sys.stderr)
        sys.exit(125)
