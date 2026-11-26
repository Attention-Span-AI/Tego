#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression controls for the Windows acceptance driver, without running Tego."""
import importlib.util
import io
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

source = Path(os.environ.get('TEGO_HOSTED_DRIVER_SOURCE', str(Path(__file__).with_name('windows-hosted-guest.py'))))
spec = importlib.util.spec_from_file_location('driver', source)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


# The first question as the guide draws it on a terminal of its accessible kind (TERM=dumb), in both orders it uses.
MENU_DEMO_FIRST = (b'? Which agent do you want to supervise? \r\n'
                   b"1. Demonstration agent (recommended)   Tego's own short script \xc2\xb7 needs no account and no network\r\n"
                   b"2. Claude Code                         Anthropic's agent \xc2\xb7 not installed\r\n"
                   b"3. Codex                               OpenAI's agent \xc2\xb7 not installed\r\n"
                   b'4. Another program                     Any command, such as a script or a bot\r\n'
                   b'Enter a number between 1 and 4: ')
MENU_CLAUDE_READY = (b'? Which agent do you want to supervise? \r\n'
                     b"1. Claude Code (recommended)           Anthropic's agent \xc2\xb7 installed, signed in\r\n"
                     b"2. Codex                               OpenAI's agent \xc2\xb7 not installed\r\n"
                     b'3. Another program                     Any command, such as a script or a bot\r\n'
                     b"4. Demonstration agent                  Tego's own short script \xc2\xb7 needs no account and no network\r\n"
                     b'Enter a number between 1 and 4: ')


class DriverTests(unittest.TestCase):
    def test_terminal_drains_ready_after_child_exit(self):
        messages = [MENU_DEMO_FIRST, b'What command starts it?',
                    b'Which project should python3 work in?', b'Which rules should python3 follow?',
                    b'2/4  Login\nReady\n']
        child = SimpleNamespace(poll=lambda: 0 if len(messages) <= 1 else None, wait=lambda timeout=None: 0)
        with mock.patch.object(driver.pty, 'openpty', return_value=(10, 11)), \
                mock.patch.object(driver.os, 'close'), mock.patch.object(driver.os, 'write') as write, \
                mock.patch.object(driver.os, 'read', side_effect=lambda *_: messages.pop(0)), \
                mock.patch.object(driver.select, 'select', side_effect=lambda *_: ([10] if messages else [], [], [])), \
                mock.patch.object(driver.subprocess, 'Popen', return_value=child), \
                mock.patch.object(driver.sys, 'stdout', SimpleNamespace(buffer=io.BytesIO())):
            driver.terminal()
            self.assertEqual([call.args[1] for call in write.call_args_list],
                             [b'4\n', b'python3 tests/test_notes.py\n', b'1\n', b'1\n'])
            self.assertEqual(messages, [])

    def test_terminal_waits_for_the_exit_when_the_terminal_ends_first(self):
        # The guide closes its terminal a moment before the process is gone: the read then fails while the child
        # still has no exit status (hosted run 45871838507: "guide timed out at []" 0.1 s after the last line).
        steps = [MENU_DEMO_FIRST, b'What command starts it?', b'Which project should python3 work in?',
                 b'Which rules should python3 follow?', b'2/4  Login\nReady\n']
        def read(*_):
            if steps: return steps.pop(0)
            raise OSError(5, 'Input/output error')
        exited = []
        def wait(timeout=None):
            exited.append(timeout)
            return 0
        child = SimpleNamespace(pid=1, poll=lambda: 0 if exited else None, wait=wait)
        with mock.patch.object(driver.pty, 'openpty', return_value=(10, 11)), \
                mock.patch.object(driver.os, 'close'), mock.patch.object(driver.os, 'write'), \
                mock.patch.object(driver.os, 'killpg'), \
                mock.patch.object(driver.os, 'read', side_effect=read), \
                mock.patch.object(driver.select, 'select', return_value=([10], [], [])), \
                mock.patch.object(driver.subprocess, 'Popen', return_value=child), \
                mock.patch.object(driver.sys, 'stdout', SimpleNamespace(buffer=io.BytesIO())):
            driver.terminal()
        self.assertIsNotNone(exited[0])  # the first wait is bounded

    def test_a_guide_that_never_exits_is_still_a_failure(self):
        steps = [MENU_DEMO_FIRST]
        def read(*_):
            if steps: return steps.pop(0)
            raise OSError(5, 'Input/output error')
        def wait(timeout=None):
            if timeout is not None: raise driver.subprocess.TimeoutExpired('guide', timeout)
            return -9
        child = SimpleNamespace(pid=1, poll=lambda: None, wait=wait)
        with mock.patch.object(driver.pty, 'openpty', return_value=(10, 11)), \
                mock.patch.object(driver.os, 'close'), mock.patch.object(driver.os, 'write'), \
                mock.patch.object(driver.os, 'killpg'), \
                mock.patch.object(driver.os, 'read', side_effect=read), \
                mock.patch.object(driver.select, 'select', return_value=([10], [], [])), \
                mock.patch.object(driver.subprocess, 'Popen', return_value=child), \
                mock.patch.object(driver.sys, 'stdout', SimpleNamespace(buffer=io.BytesIO())):
            with self.assertRaisesRegex(RuntimeError, 'guide timed out'):
                driver.terminal()

    def test_the_first_answer_is_read_from_the_list_the_guide_drew(self):
        # What tego start asks first follows the machine: with no agent installed and signed in, the demonstration
        # agent is first and "Another program" is fourth; with one ready, it is third.
        pick = driver.number_of(b'Another program')
        self.assertEqual(pick(MENU_DEMO_FIRST), b'4\n')
        self.assertEqual(pick(MENU_CLAUDE_READY), b'3\n')
        # The list is drawn before its prompt: until then there is no answer, and none may be guessed.
        self.assertIsNone(pick(MENU_DEMO_FIRST.split(b'Enter a number')[0]))
        self.assertIsNone(pick(b'Which agent do you want to supervise?\n'))
        # A list without the item is a failure naming the list, not a wrong number.
        with self.assertRaises(RuntimeError):
            pick(b'Which agent do you want to supervise?\n1. Codex  x\nEnter a number between 1 and 1: ')
        # The label may not be matched inside another item's words.
        self.assertEqual(driver.number_of(b'Codex')(MENU_DEMO_FIRST), b'3\n')

    def test_only_a_new_sample_secret_refusal_proves_the_run(self):
        for case in ['stale', 'wrong-agent', 'wrong-rule', 'sample']:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as folder:
                home = Path(folder)
                ledger = home/'.tego'
                ledger.mkdir()
                (ledger/'events.jsonl').write_text('{"verdict":"refused"}\n')
                def command(argv, **_):
                    if argv[-1] == driver.encoded(['run', 'tego-sample']):
                        if case != 'stale':
                            new = ledger/'new'
                            new.mkdir()
                            events = [dict(kind='run_start', agent='other' if case == 'wrong-agent' else 'tego-sample'),
                                      dict(verdict='refused', path=str(home/'tego-sample/.env'),
                                           rule='net.deny' if case == 'wrong-rule' else 'fs.deny_read.env')]
                            (new/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                with mock.patch.object(driver, 'terminal'), mock.patch.object(Path, 'home', return_value=home), \
                        mock.patch.object(driver.subprocess, 'run', side_effect=command), mock.patch('builtins.print'):
                    if case == 'sample':
                        driver.main()
                    else:
                        with self.assertRaises(RuntimeError):
                            driver.main()


HOSTED_SCRIPT = Path(__file__).with_name('windows-hosted-test.ps1').read_text(encoding='utf-8')


class HostedScriptTests(unittest.TestCase):
    def test_no_script_for_bash_goes_through_the_powershell_pipeline(self):
        # Windows PowerShell 5.1 puts a byte-order mark in front of text piped to a native command whatever
        # $OutputEncoding says (hosted runs 45728952833 and 45871838507: "set: command not found"). PowerShell 7 does
        # not, so no stand-in can show the mark: what is checked is that nothing is piped into bash at all.
        for number, line in enumerate(HOSTED_SCRIPT.splitlines(), 1):
            if re.search(r'\|\s*&\s*\$wsl\b.*\b(bash|sh)\b', line):
                self.fail('line %d pipes text into a shell through PowerShell: %s' % (number, line.strip()))

    def test_the_bytes_handed_to_bash_have_no_mark(self):
        pwsh = shutil.which(os.environ.get('TEGO_PWSH', 'pwsh'))
        if pwsh is None:
            self.skipTest('PowerShell is not present')
        function = re.search(r'^function Invoke-GuestBash.*?^}\n', HOSTED_SCRIPT, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder)/'wsl'
            fake.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done > "$ARGS_OUT"\n')
            fake.chmod(0o755)
            out = Path(folder)/'args'
            # Carriage returns in the source text (a checkout with CRLF) must not reach bash either.
            text = "set -eu\r\n[ \"$(id -u)\" != 0 ]\r\necho caf\u00e9\r\n"
            program = '$wsl = $env:FAKE_WSL\n' + function + '\nInvoke-GuestBash $env:SCRIPT_TEXT\n'
            env = dict(os.environ, FAKE_WSL=str(fake), ARGS_OUT=str(out), SCRIPT_TEXT=text, POWERSHELL_TELEMETRY_OPTOUT='1')
            subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-Command', program], env=env, check=True, timeout=120)
            args = out.read_text().splitlines()
        self.assertEqual(args[:7], ['-d', 'tego', '-u', 'tego', '--exec', 'sh', '-c'])
        self.assertEqual(args[8], 'sh')
        carried = base64.b64decode(args[9], validate=True)
        self.assertEqual(carried, ("set -eu\n[ \"$(id -u)\" != 0 ]\necho caf\u00e9\n\nexit\n").encode('utf-8'))
        self.assertFalse(carried.startswith(b'\xef\xbb\xbf'))
        self.assertRegex(args[9], r'^[A-Za-z0-9+/=]+$')


if __name__ == '__main__':
    unittest.main()
