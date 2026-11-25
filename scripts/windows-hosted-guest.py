#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hosted WSL proof: a real terminal, user scope, sample run and refusal record."""
import base64
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import time

ENTRY = '/usr/local/lib/tego/windows-entry'


def encoded(args):
    return base64.b64encode(json.dumps(args, ensure_ascii=False).encode()).decode()


def number_of(label):
    """The answer to a numbered question: the number of the item that offers label, once the whole list is drawn.

    The guide orders the first question by what the machine has (a demonstration agent comes first when no agent is
    installed and signed in), so the number of "Another program" is read from the list, never assumed."""
    item = re.compile(rb'^[ \t]*(\d+)\. ' + re.escape(label), re.M)
    def pick(shown):
        if b'Enter a number' not in shown:
            return None
        found = item.search(shown)
        if found is None:
            raise RuntimeError('the question does not offer ' + label.decode() + ': ' + repr(shown[-600:]))
        return found.group(1) + b'\n'
    return pick


def terminal():
    master, slave = pty.openpty()
    def session():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    env = dict(os.environ, TERM='dumb', NO_COLOR='1', HISTFILE='/dev/null')
    child = subprocess.Popen([ENTRY, encoded(['start'])], stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=session)
    os.close(slave)
    answers = [(b'Which agent do you want to supervise?', number_of(b'Another program')),
               (b'What command starts it?', b'python3 tests/test_notes.py\n'),
               (b'Which project should python3 work in?', b'1\n'),
               (b'Which rules should python3 follow?', b'1\n')]
    output = b''
    deadline = time.monotonic()+90
    try:
        while time.monotonic()<deadline:
            if select.select([master],[],[],0.25)[0]:
                try: data=os.read(master,65536)
                except OSError: break
                if not data: break
                sys.stdout.buffer.write(data);sys.stdout.buffer.flush();output+=data
                if answers and answers[0][0] in output:
                    ask,answer=answers[0]
                    if callable(answer): answer=answer(output[output.index(ask):])
                    if answer is not None:
                        answers.pop(0);os.write(master,answer)
            if child.poll() is not None:
                # A final Ready panel may still be buffered after process exit.
                while select.select([master], [], [], 0.25)[0]:
                    try: data = os.read(master, 65536)
                    except OSError: break
                    if not data: break
                    sys.stdout.buffer.write(data); sys.stdout.buffer.flush(); output += data
                break
        if child.poll() is None:
            raise RuntimeError('guide timed out at '+repr(answers[:1]))
        if child.wait()!=0 or answers or b'Ready' not in output or b'2/4  Login' not in output:
            raise RuntimeError('four-step guide did not complete')
    finally:
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL);child.wait()
        os.close(master)


def main():
    terminal()
    print('CHECK: four guide steps and Ready panel completed', flush=True)
    # The entry point itself reads /proc/self/cgroup after systemd-run; also
    # measure it from the command invoked in that same scope.
    result = subprocess.run([ENTRY,encoded(['doctor'])], text=True, capture_output=True)
    print(result.stdout, result.stderr, flush=True)
    if result.returncode: raise RuntimeError('doctor found no protection level')
    before = set((Path.home()/'.tego').rglob('events.jsonl'))
    run = subprocess.run([ENTRY,encoded(['run','tego-sample'])], text=True, capture_output=True)
    print(run.stdout,run.stderr,flush=True)
    if run.returncode: raise RuntimeError('sample run failed')
    records = set((Path.home()/'.tego').rglob('events.jsonl')) - before
    if len(records) != 1:
        raise RuntimeError('expected exactly one new sample record, got '+str(records))
    events = [json.loads(line) for line in records.pop().read_text().splitlines()]
    start = events[0]
    if start.get('kind') != 'run_start' or start.get('agent') != 'tego-sample':
        raise RuntimeError('new record did not belong to the sample run')
    secret = str(Path.home()/'tego-sample/.env')
    if not any(event.get('verdict') == 'refused' and event.get('path') == secret
               and event.get('rule', '').startswith('fs.deny_read') for event in events):
        raise RuntimeError('sample .env read was not refused by its deny-read rule')
    for command in [['session','list'], ['session','show','--last']]:
        shown = subprocess.run([ENTRY,encoded(command)], text=True, capture_output=True)
        print(shown.stdout, shown.stderr, flush=True)
        if shown.returncode: raise RuntimeError('session command failed: '+repr(command))
    print('CHECK: sample run completed with a recorded refusal', flush=True)


if __name__=='__main__':
    main()
