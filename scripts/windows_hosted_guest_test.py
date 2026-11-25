#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression controls for the Windows acceptance driver, without running Tego."""
import importlib.util
import io
import json
import os
from pathlib import Path
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
        child = SimpleNamespace(poll=lambda: 0 if len(messages) <= 1 else None, wait=lambda: 0)
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


if __name__ == '__main__':
    unittest.main()
