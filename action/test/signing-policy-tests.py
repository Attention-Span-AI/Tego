#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Offline decision regressions, including real repository/PR lookup failures."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

A = Path(os.environ.get('ACTION_UNDER_TEST', Path(__file__).resolve().parents[1]))
SPEC = importlib.util.spec_from_file_location('signing', A/'scripts/signing.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class Decision(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['WORK'])
        self.addCleanup(self.tmp.cleanup)
        self.event = Path(self.tmp.name)/'event.json'
        self.event.write_text(json.dumps(dict(number=7)))
        self.env = dict(IN_SIGN='auto', IN_SIGN_CONSENT=S.CONSENT,
                        GITHUB_EVENT_NAME='push', GITHUB_REPOSITORY='example/app',
                        GITHUB_EVENT_PATH=str(self.event))
        self.repo = dict(full_name='example/app', id=123, owner=dict(id=456), visibility='public')

    def test_disabled_and_unsupported_decisions_never_fetch_metadata(self):
        for event in ('push', 'pull_request', 'issue_comment', 'workflow_run'):
            for sign in ('auto', 'true', 'false'):
                if sign != 'false' and event in ('push', 'pull_request'):
                    continue
                env = dict(IN_SIGN=sign, GITHUB_EVENT_NAME=event)
                with self.subTest(event=event, sign=sign), patch.dict(os.environ, env, clear=True), \
                        patch.object(S, 'api', side_effect=AssertionError('must not fetch')) as api:
                    result = S.decision()
                    self.assertFalse(result['sign'])
                    self.assertTrue(result['reason'].startswith('disabled:' if sign == 'false' else 'trigger:'))
                    self.assertEqual(result['repository'], {})
                    api.assert_not_called()

    def test_invalid_selection_and_target_refuse_before_metadata(self):
        for sign, event, message in (('yes', 'push', 'sign must'),
                                     ('false', 'pull_request_target', 'pull_request_target'),
                                     ('auto', 'pull_request_target', 'pull_request_target'),
                                     ('true', 'pull_request_target', 'pull_request_target')):
            with self.subTest(sign=sign, event=event), \
                    patch.dict(os.environ, dict(IN_SIGN=sign, GITHUB_EVENT_NAME=event), clear=True), \
                    patch.object(S, 'api') as api, self.assertRaisesRegex(ValueError, message):
                S.decision()
            api.assert_not_called()

    def test_api_failures_are_unknown_auto_but_explicit_requests_refuse(self):
        failures = (subprocess.TimeoutExpired('gh api', 60),
                    subprocess.CalledProcessError(1, 'gh api', stderr=b'HTTP 403'),
                    OSError('API process unavailable'))
        for event, fail_at in (('push', 0), ('pull_request', 0), ('pull_request', 1)):
            for failure in failures:
                for sign in ('auto', 'true'):
                    responses = [failure] if fail_at == 0 else [self.repo, failure]
                    with self.subTest(event=event, fail_at=fail_at, failure=type(failure).__name__, sign=sign), \
                            patch.dict(os.environ, dict(self.env, GITHUB_EVENT_NAME=event, IN_SIGN=sign), clear=True), \
                            patch.object(S, 'api', side_effect=responses) as api:
                        if sign == 'true':
                            with self.assertRaisesRegex(ValueError, 'cannot authenticate'):
                                S.decision()
                        else:
                            result = S.decision()
                            self.assertFalse(result['sign'])
                            self.assertTrue(result['reason'].startswith('unknown:'))
                            self.assertEqual(result['repository'], {})
                        self.assertEqual(api.call_count, fail_at+1)

    def test_authenticated_fork_stays_unsigned_without_consent(self):
        pull = dict(head=dict(repo=dict(id=999)), base=dict(repo=dict(id=123)))
        for sign in ('auto', 'true'):
            with self.subTest(sign=sign), \
                    patch.dict(os.environ, dict(self.env, IN_SIGN=sign, IN_SIGN_CONSENT='', GITHUB_EVENT_NAME='pull_request'), clear=True), \
                    patch.object(S, 'api', side_effect=[self.repo, pull]):
                result = S.decision()
                self.assertFalse(result['sign'])
                self.assertTrue(result['reason'].startswith('fork:'))

    def test_authenticated_public_and_private_decisions(self):
        for visibility in ('public', 'private', 'internal'):
            for sign in ('auto', 'true'):
                with self.subTest(visibility=visibility, sign=sign), \
                        patch.dict(os.environ, dict(self.env, IN_SIGN=sign), clear=True), \
                        patch.object(S, 'api', return_value=dict(self.repo, visibility=visibility)):
                    result = S.decision()
                    self.assertEqual(result['sign'], sign == 'true' or visibility == 'public')


class Prelaunch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['WORK'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scripts = self.root/'scripts'
        self.scripts.mkdir()
        self.gh = self.root/'gh'
        self.gh.write_text('''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['POLICY_FIXTURE'])
with (root/'api-calls').open('a') as out:
    out.write(json.dumps(sys.argv[1:])+'\\n')
mode = (root/'mode').read_text()
if '/pulls/' in sys.argv[-1]:
    if mode in ('pull-timeout', 'pull-403'):
        print('API request timed out' if mode == 'pull-timeout' else 'HTTP 403', file=sys.stderr)
        sys.exit(124 if mode == 'pull-timeout' else 1)
    if mode == 'pull-malformed':
        print('{')
        sys.exit(0)
    print(json.dumps(dict(head=dict(repo=dict(id=999 if mode == 'fork' else 123)), base=dict(repo=dict(id=123)))))
elif mode in ('timeout', '403'):
    print('API request timed out' if mode == 'timeout' else 'HTTP 403', file=sys.stderr)
    sys.exit(124 if mode == 'timeout' else 1)
elif mode == 'malformed':
    print('{')
else:
    print(json.dumps(dict(full_name='example/app', id=123, owner=dict(id=456), visibility='public')))
''')
        self.gh.chmod(0o700)
        # Replace the absolute API executable in a scratch copy and satisfy its
        # tool-presence check using the stub. All policy and parser code runs.
        script = (A/'scripts/check.sh').read_text().replace('/usr/bin/gh', str(self.gh))
        script = script.replace('[ -x "/usr/bin/$tool" ]',
                                '[ -x "/usr/bin/$tool" ] || { [ "$tool" = gh ] && [ -x "'+str(self.gh)+'" ]; }')
        (self.scripts/'check.sh').write_text(script)
        for name in ('lib.sh', 'eligibility.py', 'environment.py'):
            shutil.copyfile(A/'scripts'/name, self.scripts/name)
        (self.root/'state').mkdir()
        (self.root/'evidence').mkdir()
        (self.root/'workspace').mkdir()
        (self.root/'event.json').write_text('{"number":7}')
        self.env = dict(POLICY_FIXTURE=str(self.root), DIR=str(self.root),
                        GITHUB_SERVER_URL='https://github.com', GITHUB_EVENT_NAME='push',
                        GITHUB_REPOSITORY='example/app', GITHUB_EVENT_PATH=str(self.root/'event.json'),
                        GITHUB_WORKSPACE=str(self.root/'workspace'), GITHUB_OUTPUT=str(self.root/'outputs'),
                        IN_USE_SUDO='false', IN_ON_REFUSAL='fail', IN_COMMENT='auto', IN_SIGN='auto')

    def check(self, mode='public', **env):
        (self.root/'mode').write_text(mode)
        (self.root/'api-calls').unlink(missing_ok=True)
        (self.root/'outputs').unlink(missing_ok=True)
        result = subprocess.run(['/bin/bash', str(self.scripts/'check.sh'), '--tego-ci-clean'],
                                env=dict(self.env, **env), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads((self.root/'evidence/eligibility.json').read_text())

    def test_disabled_and_excluded_prelaunch_never_fetch_metadata(self):
        for event in ('push', 'pull_request', 'issue_comment'):
            with self.subTest(event=event):
                selected = self.check(IN_SIGN='false', GITHUB_EVENT_NAME=event)
                self.assertTrue(selected['reason'].startswith('disabled:'))
                self.assertFalse((self.root/'api-calls').exists())
                if event == 'pull_request':
                    outputs = (self.root/'outputs').read_text()
                    self.assertIn('comment=true\n', outputs)
                    self.assertIn('pr=7\n', outputs)
        for sign in ('auto', 'true'):
            selected = self.check(IN_SIGN=sign, GITHUB_EVENT_NAME='issue_comment')
            self.assertTrue(selected['reason'].startswith('trigger:'))
            self.assertFalse((self.root/'api-calls').exists())

    def test_repository_api_failure_and_successful_pr_do_not_abort_prelaunch(self):
        for mode in ('timeout', '403', 'malformed'):
            for event in ('push', 'pull_request'):
                for sign in ('auto', 'true'):
                    with self.subTest(mode=mode, event=event, sign=sign):
                        selected = self.check(mode, IN_SIGN=sign, GITHUB_EVENT_NAME=event)
                        self.assertTrue(selected['reason'].startswith('unknown:'), selected)
                        self.assertTrue((self.root/'state/api-error').read_text())

    def test_pr_api_failures_remain_unknown_prelaunch(self):
        for mode in ('pull-timeout', 'pull-403', 'pull-malformed'):
            for sign in ('auto', 'true'):
                with self.subTest(mode=mode, sign=sign):
                    selected = self.check(mode, IN_SIGN=sign, GITHUB_EVENT_NAME='pull_request')
                    self.assertTrue(selected['reason'].startswith('unknown:'), selected)
                    self.assertTrue((self.root/'state/api-error').read_text())

    def test_authenticated_same_repository_and_fork_displays(self):
        for mode, reason in (('public', 'pending:'), ('fork', 'fork:')):
            with self.subTest(mode=mode):
                selected = self.check(mode, GITHUB_EVENT_NAME='pull_request')
                self.assertTrue(selected['reason'].startswith(reason), selected)
                self.assertEqual(len((self.root/'api-calls').read_text().splitlines()), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
