#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Hosted Mac infrastructure: bounded subprocesses, real PTYs and redacted logs.
# https://docs.github.com/en/actions/reference/workflows-and-actions/variables
import os
import sys
if __name__ == '__main__' and (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
    print('this script installs the real product and is only for GitHub-hosted machines', file=sys.stderr)
    raise SystemExit(2)
import errno
import fcntl
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time


# The two questions of the Mac command's tego uninstall; the check in mac-install-ci_test.py keeps them equal to install.sh.
UNINSTALL_FIRST = b'Remove what is listed under "Tego will remove"?'
UNINSTALL_SECOND = b'Also delete the VM and your records and contracts in it?'


def require_hosted():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        print('this script installs the real product and is only for GitHub-hosted machines', file=sys.stderr)
        raise SystemExit(2)


def scrub(data):
    # Query tokens, fragments and Authorization headers, including encoded links.
    data = re.sub(rb'(?i)([?&](?:t|token|access_token)=)[^\s&\x1b<>"\']+', rb'\1[REDACTED]', data)
    data = re.sub(rb'(?i)(%3[fF](?:t|token)%3[dD])[^\s&\x1b<>"\']+', rb'\1[REDACTED]', data)
    return re.sub(rb'(?i)(authorization:\s*(?:bearer\s+)?)[^\r\n]+', rb'\1[REDACTED]', data)


def show(path, code):
    sys.stdout.buffer.write(scrub(path.read_bytes()))
    print(f"CHECK {path.name}: exit={code}", flush=True)


def bound(seconds, path, command):
    require_hosted()
    with path.open('wb') as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            log.write(b'\nCHECK bounded wait expired\n')
            code = 124
    show(path, code)
    return code


def terminal(seconds, path, mode, command):
    require_hosted()
    # TERM=dumb chooses the guide's accessible prompts, as runGuide in
    # internal/cli/setup_guide_test.go does. It remains a real terminal, so the
    # guide starts the real dashboard, and limactl allocates the guest terminal.
    actions = {
        'install': [],
        'guide': [(b'Which agent do you want to supervise?', b'3\n'),
                  (b'What command starts it?', b'/bin/sh\n'),
                  (b'Which project should', b'1\n'),
                  (b'Which rules should', b'1\n'),
                  (b'TEGO_CI_PROJECT_SHELL>', b'pwd; test -f README.md && echo CHECK_PROJECT_FILES; exit\n')],
        'shell': [(b'TEGO_CI_PROJECT_SHELL>', b'pwd; test -f README.md && echo CHECK_PROJECT_FILES; exit\n')],
        'dashboard': [(b'Open it, or start a new one?', b'1\n')],
        # tego uninstall asks twice on a terminal; the words are the Mac command's own, written by scripts/install.sh.
        'uninstall-decline': [(UNINSTALL_FIRST, b'n\n')],
        'uninstall-keep': [(UNINSTALL_FIRST, b'\n'), (UNINSTALL_SECOND, b'\n')],
    }[mode]
    gate_read, gate_write = os.pipe()
    pid, fd = pty.fork()
    if pid == 0:
        os.close(gate_write)
        os.read(gate_read, 1)
        os.close(gate_read)
        os.environ.update(TERM='dumb', NO_COLOR='1', HISTFILE='/dev/null')
        os.execvp(command[0], command)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 120, 0, 0))
    os.close(gate_read)
    before = termios.tcgetattr(fd)
    os.write(gate_write, b'1')
    os.close(gate_write)
    output = bytearray()
    pending = list(actions)
    deadline = time.monotonic() + seconds
    status = None
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], .1)[0]:
                try:
                    data = os.read(fd, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    break
                if not data:
                    break
                output.extend(data)
                if pending and pending[0][0] in output:
                    prompt, answer = pending.pop(0)
                    print('CHECK PTY answered ' + prompt.decode(), flush=True)
                    os.write(fd, answer)
                    # Do not allow an old prompt to answer a later question.
                    # Each prompt in this sequence is unique.
        else:
            output.extend(b'\nCHECK terminal deadline expired\n')
            os.killpg(pid, signal.SIGKILL)
        # EOF alone does not prove exit: a child can close its terminal and
        # keep running. Join it only until the same operation deadline.
        while time.monotonic() < deadline:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            time.sleep(.05)
        else:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(pid, 0)
        restored = termios.tcgetattr(fd) == before
    finally:
        os.close(fd)
    code = os.waitstatus_to_exitcode(status)
    output.extend(f'\nCHECK terminal restored={restored}; unanswered={len(pending)}\n'.encode())
    path.write_bytes(output)
    show(path, code)
    if not restored or (pending and mode != 'dashboard'):
        return 125
    return code if code >= 0 else 128 - code


def collect(destination):
    destination.mkdir(parents=True, exist_ok=True)
    roots = [Path(os.environ['MAC_CI_LOGS']), Path.home() / '.lima']
    # Never upload disks, ssh keys, sockets, or unredacted raw directories.
    for root in roots:
        if not root.exists():
            continue
        for source in root.rglob('*'):
            if source.is_symlink() or not source.is_file():
                continue
            if source.suffix not in ('.log', '.txt', '.json', '.yaml') and 'serial' not in source.name:
                continue
            if root.name == '.lima' and not (source.suffix == '.log' or 'serial' in source.name):
                continue
            target = destination / root.name / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(scrub(source.read_bytes()))
    temp = Path(os.environ['MAC_CI_TMP'])
    for source in temp.glob('tego-install.*/install.log'):
        target = destination / ('installer-' + source.parent.name + '.log')
        target.write_bytes(scrub(source.read_bytes()))
    print('CHECK upload contains only scrubbed text logs, including serial logs')


def dispatch(args):
    require_hosted()
    # Test-only seam. The product does not read these variables or reference this
    # helper. No template bytes/digests are changed. Only the fixture directory is
    # mounted read-only; no Mac home or project folders are shared.
    real = os.environ['MAC_CI_LIMACTL']
    if args and args[0] == 'start' and '--name=tego' in args:
        driver = os.environ.get('MAC_CI_DRIVER', '')
        if driver:
            args.append('--vm-type=' + driver)
            if driver == 'qemu':
                args.append('--mount-type=9p')
        args = [x for x in args if x != '--mount-none']
        args.append('--mount=' + os.environ['MAC_CI_ASSETS'])
        record = 'CHECK CI-only Lima overrides: ' + ' '.join(args)
        print(record, flush=True)
        if os.environ.get('MAC_CI_LOGS'):
            with (Path(os.environ['MAC_CI_LOGS']) / 'lima-launch.txt').open('a') as log:
                log.write(record + '\n')
    os.execv(real, [real] + args)


if __name__ == '__main__':
    op, *args = sys.argv[1:]
    if op == 'bound':
        sys.exit(bound(int(args[0]), Path(args[1]), args[2:]))
    elif op == 'terminal':
        sys.exit(terminal(int(args[0]), Path(args[1]), args[2], args[3:]))
    elif op == 'collect':
        collect(Path(args[0]))
    elif op == 'dispatch':
        dispatch(args)
    else:
        raise SystemExit('unknown operation: ' + op)
