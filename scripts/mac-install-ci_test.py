#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Infrastructure contracts only; these never start Lima or a product binary."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name('mac-install-ci.py')
spec = importlib.util.spec_from_file_location('macci', HELPER)
macci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(macci)


class Infrastructure(unittest.TestCase):
    def test_tokens_scrubbed_including_serial_and_browser_logs(self):
        data = b'url http://127.0.0.1:8484/?t=secret-token\r\nAuthorization: Bearer secret-header\n'
        clean = macci.scrub(data)
        self.assertNotIn(b'secret', clean)
        self.assertIn(b'http://127.0.0.1:8484/?t=[REDACTED]', clean)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home, logs, work = root/'home', root/'raw', root/'tmp'
            logs.mkdir()
            serial = home/'.lima/tego/serial.log'
            serial.parent.mkdir(parents=True)
            serial.write_bytes(data)
            (serial.parent/'id_ed25519').write_text('PRIVATE KEY')
            (logs/'browser-links.txt').write_bytes(data)
            (logs/'dashboard.html').write_bytes(data)
            install = work/'tego-install.abc/install.log'
            install.parent.mkdir(parents=True)
            install.write_bytes(data)
            env = dict(os.environ, HOME=str(home), MAC_CI_LOGS=str(logs), MAC_CI_TMP=str(work))
            subprocess.run([sys.executable, str(HELPER), 'collect', str(root/'safe')], env=env, check=True)
            artifacts = list((root/'safe').rglob('*'))
            self.assertEqual(3, sum(p.is_file() for p in artifacts))
            for p in artifacts:
                if p.is_file():
                    self.assertNotIn(b'secret', p.read_bytes())
                    self.assertNotIn(b'PRIVATE KEY', p.read_bytes())

    def helper(self, operation, seconds, log, *args):
        return subprocess.run([sys.executable, str(HELPER), operation, str(seconds), str(log), *args],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)

    def test_bound_keeps_failure_status_and_redacts_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp)/'failure.log'
            p = self.helper('bound', 3, log, '/bin/sh', '-c', 'echo "http://localhost/?t=secret"; exit 8')
            self.assertEqual(8, p.returncode, p.stdout)
            self.assertIn(b'secret', log.read_bytes())
            self.assertNotIn(b'secret', p.stdout)

    def test_bound_timeout_is_a_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.helper('bound', 1, Path(tmp)/'timeout.log', '/bin/sh', '-c', 'sleep 30')
            self.assertEqual(124, p.returncode, p.stdout)

    def test_pty_preserves_installer_exit_and_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.helper('terminal', 3, Path(tmp)/'pty.log', 'install', '/bin/sh', '-c', 'test -t 0 || exit 42; exit 8')
            self.assertEqual(8, p.returncode, p.stdout)
            self.assertIn(b'restored=True', p.stdout)

    def test_pty_detects_broken_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.helper('terminal', 3, Path(tmp)/'pty.log', 'install', '/bin/sh', '-c', 'stty -echo')
            self.assertEqual(125, p.returncode, p.stdout)
            self.assertIn(b'restored=False', p.stdout)

    def test_dashboard_answers_existing_instance_and_needs_no_prompt_for_new_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            for script in ('echo "Started the dashboard"',
                           'printf "Open it, or start a new one?"; read -r a; test "$a" = 1'):
                p = self.helper('terminal', 3, Path(tmp)/'dashboard.log', 'dashboard', '/bin/sh', '-c', script)
                self.assertEqual(0, p.returncode, p.stdout)

    def test_pty_deadline_also_bounds_a_child_that_closes_its_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self.helper('terminal', 1, Path(tmp)/'closed.log', 'install', '/bin/sh', '-c',
                            'exec 0<&- 1>&- 2>&-; sleep 30')
            self.assertNotEqual(0, p.returncode)

    def test_driver_seam_preserves_template_and_verification_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root/'real-limactl'
            real.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@"\n')
            real.chmod(0o755)
            env = dict(os.environ, MAC_CI_LIMACTL=str(real), MAC_CI_DRIVER='qemu', MAC_CI_ASSETS=str(root/'assets'))
            args = ['start', '--name=tego', '--mount-none', '--param=installer_sha256=abc', 'verified.yaml']
            p = subprocess.run([sys.executable, str(HELPER), 'dispatch', *args], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
            lines = p.stdout.decode().splitlines()
            self.assertIn('--vm-type=qemu', lines)
            self.assertIn('--mount-type=9p', lines)
            self.assertIn('--mount='+str(root/'assets'), lines)
            self.assertIn('--param=installer_sha256=abc', lines)
            self.assertIn('verified.yaml', lines)
            self.assertNotIn('--mount-none', lines)
            # Shell, stop, other instance names etc. reach real Lima unchanged.
            p = subprocess.run([sys.executable, str(HELPER), 'dispatch', 'shell', 'tego', 'uname', '-a'],
                               env=env, stdout=subprocess.PIPE, check=True)
            self.assertEqual(['shell', 'tego', 'uname', '-a'], p.stdout.decode().splitlines())

    def test_guide_answers_only_observed_prompts(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = '''printf 'Which agent do you want to supervise?'; read -r a; test "$a" = 3 || exit 2
printf 'What command starts it?'; read -r a; test "$a" = /bin/sh || exit 3
printf 'Which project should sh work in?'; read -r a; test "$a" = 1 || exit 4
printf 'Which rules should sh follow?'; read -r a; test "$a" = 1 || exit 5
printf 'TEGO_CI_PROJECT_SHELL>'; read -r a; echo "$a" | grep -q CHECK_PROJECT_FILES || exit 6
'''
            p = self.helper('terminal', 3, Path(tmp)/'guide.log', 'guide', '/bin/sh', '-c', command)
            self.assertEqual(0, p.returncode, p.stdout)
            self.assertIn(b'unanswered=0', p.stdout)


if __name__ == '__main__':
    unittest.main()
