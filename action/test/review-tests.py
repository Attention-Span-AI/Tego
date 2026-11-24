#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline regressions for ACTION-REVIEW, plus the job trust boundary."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

A = Path(__file__).resolve().parents[1]
ROOT = A.parent
WORK = Path(os.environ['WORK'])
WORK.mkdir(parents=True, exist_ok=True)


def execute(script, env=None, *args, action=A):
    e = dict(os.environ, **(env or {}))
    return subprocess.run([str(action / 'scripts' / script), *map(str, args)], env=e,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def workflow_yaml_files(action=A, root=ROOT):
    return sorted({*action.rglob('*.yml'), *action.rglob('*.yaml'),
                   root / '.github/workflows/ci-receipt.yml', root / '.github/workflows/ci-receipt-sign.yml'})


def workflow_steps(data):
    steps = list(data.get('runs', {}).get('steps', []))
    for job in data.get('jobs', {}).values():
        steps.extend(job.get('steps', []))
    return steps


def string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from string_values(item)


def workflow_shell_findings(action=A, root=ROOT):
    import yaml
    findings = []
    for path in workflow_yaml_files(action, root):
        for step in workflow_steps(yaml.safe_load(path.read_text()) or {}):
            for field, value in step.items():
                if field in {'with', 'if', 'name', 'env'}:
                    continue
                if any('${{' in text for text in string_values(value)):
                    findings.append((path, field))
    return findings


class Review(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        (self.d / 'evidence').mkdir()
        (self.d / 'state').mkdir()
        self.r = json.loads((A / 'testdata/receipt.json').read_text())
        self.s = json.loads((A / 'testdata/run_start.json').read_text())
        self.c = json.loads((A / 'testdata/compile.json').read_text())
        self.env = dict(DIR=str(self.d), WORKSPACE='/home/tego',
                        GITHUB_WORKFLOW_REF='example/app/.github/workflows/agent.yml@refs/heads/main',
                        GITHUB_JOB='agent', GITHUB_ACTION='receipt', IN_MATRIX_KEY='single',
                        UNSIGNED_REASON='pending: separate signing job requires consent and complete verification')

    def render(self):
        for name, obj in [('receipt', self.r), ('run_start', self.s), ('compile', self.c)]:
            (self.d / f'evidence/{name}.json').write_text(json.dumps(obj))
        shutil.copy(A / 'testdata/verify.json', self.d / 'evidence/verify.json')
        digest = hashlib.sha256((self.d / 'evidence/receipt.json').read_bytes()).hexdigest()
        (self.d / 'evidence/tego-ci.json').write_text(json.dumps({'receipt_sha256': digest}))
        p = execute('render.sh', self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return (self.d / 'evidence/receipt.md').read_text()

    def policy(self, merged, protected=None):
        (self.d / 'merged.json').write_text(json.dumps(merged))
        (self.d / 'compile.json').write_text(json.dumps(self.c))
        return execute('policy.py', None, self.d / 'merged.json', self.d / 'compile.json',
                       *(protected or [self.d / 'protected']))

    def test_M1_report_headline(self):
        text = (A / 'README.md').read_text()
        self.assertNotRegex(text.splitlines()[2], r'(?i)proof|every action')
        self.assertIn('report, not evidence', text)

    def test_M2_workflow_control_limit(self):
        for text in [(A / 'README.md').read_text(), self.render()]:
            self.assertIn('pull request', text)
            self.assertIn('workflow file', text)
            self.assertIn('protected branch', text)

    def test_M3_only_bot_marker_is_updated(self):
        md = self.render()
        marker = md.splitlines()[0]
        gh = self.d / 'gh'
        gh.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['GH_LOG'], 'a') as f: f.write(json.dumps(args) + '\\n')
if '--paginate' in args:
 print(json.dumps([{'id': 22, 'user': {'login': 'github-actions[bot]', 'type': 'Bot'}, 'body': os.environ['MARKER']}, {'id': 99, 'user': {'login': 'human', 'type': 'User'}, 'body': os.environ['MARKER']}]))
else:
 sys.stdin.read()
''')
        gh.chmod(0o755)
        e = dict(self.env, MD=str(self.d / 'evidence/receipt.md'), DO_COMMENT='true', PR_NUMBER='7',
                 GITHUB_REPOSITORY='example/app',
                 GH_LOG=str(self.d / 'gh.log'), MARKER=marker)
        # Instrument only a scratch action copy; production keeps its fixed tool paths.
        action = self.d / 'action'
        shutil.copytree(A, action)
        post = action / 'scripts/post.sh'
        self.assertIn('/usr/bin/gh', post.read_text())
        post.write_text(post.read_text().replace('/usr/bin/gh', str(gh)))
        p = execute('post.sh', e, action=action)
        self.assertEqual(p.returncode, 0, p.stderr)
        log = (self.d / 'gh.log').read_text()
        self.assertIn('comments/22', log)
        self.assertNotIn('comments/99', log)

    def test_M4_reads_by_capability_and_receipt_note(self):
        self.s['tier'] = 'cgroup'
        self.s['reads_notified'] = {'notified': False, 'why': 'kernel'}
        md = self.render()
        self.assertNotIn('did not record the files it read', md)
        self.s['tier'] = 'landlock'
        self.s['capabilities']['record.reads_mmap_chmod'] = False
        self.s['reads_notified'] = {'notified': True, 'why': 'reason'}
        self.r['sensitive_reads_unknown'] = True
        self.r['sensitive_reads_note'] = 'only refused reads are listed; allowed reads were not recorded'
        self.assertIn(self.r['sensitive_reads_note'], self.render())

    def test_M5_compiled_hash_label(self):
        md = self.render()
        self.assertIn('Compiled contract hash', md)
        self.assertNotRegex(md, r'Contract[^\n]*sha256 `9bc51')

    def test_M6_lower_bounds_and_all_notes(self):
        self.s['run_command_grant'] = '/bin/bash'
        self.s['runtime_grants'] = ['harness.generated-canary']
        self.r['programs_more'] = 7
        self.r['connections_more'] = 8
        self.r['connections_note'] = 'connections-note-canary'
        self.r['files'].update(truncated=True, recorded=False, note='files-note-canary')
        self.r['notes'] = ['receipt-note-canary']
        self.r['refusals']['list_truncated'] = True
        md = self.render()
        for text in ['at least 1', '7 more programs', '8 more connections', 'connections-note-canary',
                     'files-note-canary', 'receipt-note-canary', 'refusal list was truncated',
                     'Additional command grant', '/bin/bash', 'harness.generated-canary']:
            self.assertIn(text, md)

    def test_S1_refuse_setuid_after_merge(self):
        p = self.policy({'setuid': True})
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('setuid', p.stderr)

    def test_S2_caps_and_limits_first(self):
        self.r['sensitive_reads'] *= 1000
        self.r['refusals']['by_rule'] *= 1000
        md = self.render()
        self.assertLess(len(md.encode()), 60000)
        self.assertLess(md.index('What this record does not cover'), md.index('What it did'))
        self.assertLessEqual(md.count('- `k2-secret.txt` (refused'), 10)

    def test_S3_hashed_marker(self):
        self.env['GITHUB_WORKFLOW_REF'] = 'x-->@octocat/<img src=x>/<!--'
        marker = self.render().splitlines()[0]
        self.assertRegex(marker, r'^<!-- tego-receipt:[0-9a-f]{64} -->$')

    def test_S4_controls_and_bidi_in_every_rendered_field(self):
        bad = '\u0085\u200b\u200f\u2028\u2029\u202e\u2066\ufeff\x01'
        self.r['agent'] += bad
        self.r['coverage']['gaps'][0]['why'] += bad
        self.r['notes'] = ['a' + bad + '<img src=x> @octocat']
        self.r['refusals']['list'][0]['ts'] += bad
        self.r['sensitive_reads_note'] = 'a' + bad
        self.env['UNSIGNED_REASON'] += bad
        md = self.render()
        self.assertFalse(any(char in md for char in bad))
        outside = re.sub(r'`[^`\n]*`', '', md)
        self.assertNotIn('<img', outside)
        self.assertNotIn('@octocat', outside)

    def test_S5_matrix_markers_canonical(self):
        self.env['IN_MATRIX_KEY'] = '{"os":"a","python":3}'
        a = self.render().splitlines()[0]
        self.env['IN_MATRIX_KEY'] = '{"python":3,"os":"a"}'
        self.assertEqual(a, self.render().splitlines()[0])
        self.env['IN_MATRIX_KEY'] = '{"os":"b","python":3}'
        self.assertNotEqual(a, self.render().splitlines()[0])

    def test_S6_protect_actions_runner_tools_and_aliases(self):
        protected = self.d / '_actions'
        protected.mkdir()
        alias = self.d / 'alias'
        alias.symlink_to(protected, target_is_directory=True)
        self.c['fs'] = [{'kind': 'write', 'path': str(alias)}]
        p = self.policy({}, [protected])
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('covers', p.stderr)
        text = (A / 'scripts/prepare.sh').read_text()
        for term in ['_actions', 'RUNNER_TOOL_CACHE', 'RUNNER_ROOT', '.github']:
            self.assertIn(term, text)

    def test_S7_no_secret_values_in_exec_argv(self):
        # A harmless executable models the launcher. Inspect what the real launch helper hands it.
        fake = self.d / 'capture'
        fake.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ['CAPTURE']).write_text(json.dumps({'argv': sys.argv, 'secret': os.environ.get('MODEL_KEY'), 'token': os.environ.get('GITHUB_TOKEN')}))
''')
        fake.chmod(0o755)
        e = dict(self.env, MODEL_KEY='private-canary-value', GITHUB_TOKEN='token-canary',
                 CAPTURE=str(self.d / 'launch.json'), IN_ENV_PASS='MODEL_KEY,CAPTURE',
                 TEGO=str(fake), CONTRACT='contract.yaml', IN_RUN='true', IN_USE_SUDO='false')
        p = execute('launch.py', e, '--direct-test')
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads((self.d / 'launch.json').read_text())
        self.assertEqual(data['secret'], 'private-canary-value')
        self.assertIsNone(data['token'])
        self.assertNotIn('private-canary-value', json.dumps(data['argv']))

    def test_S8_doctor_summary_and_exit_211(self):
        (self.d / 'state/prepare-exit').write_text('211')
        (self.d / 'state/tier-wanted').write_text('landlock')
        doctor = json.loads((A / 'testdata/doctor.json').read_text())
        doctor['missing']['landlock'] = ['missing canary\u202e\u0085']
        (self.d / 'evidence/doctor.json').write_text(json.dumps(doctor))
        p = execute('diagnostic.sh', self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        md = (self.d / 'evidence/receipt.md').read_text()
        self.assertIn('No receipt: this runner cannot provide tier', md)
        self.assertIn('The agent did not start', md)
        self.assertNotIn('GRUB', md)
        self.assertNotIn('\u202e', md)
        self.assertNotIn('\u0085', md)
        p = execute('gate.sh', dict(self.env, PREPARE_EXIT='211', AGENT_EXIT=''))
        self.assertEqual(p.returncode, 211, p.stderr)

    def test_S9_document_conditions(self):
        text = (A / 'README.md').read_text()
        for phrase in ['base variables', 'no-prod', 'enable-linger', 'advisory against a hostile process',
                       'can miss lines']:
            self.assertIn(phrase, text)

    def test_S10_unsigned_bytes_digest_and_text_limit(self):
        md = self.render()
        digest = hashlib.sha256((self.d / 'evidence/receipt.json').read_bytes()).hexdigest()
        for text in ['not signed', 'report, not evidence', 'receipt.json', digest, 'This text is a display']:
            self.assertIn(text, md)
        self.assertNotIn('attestation:', md)

    def test_S11_unsigned_reasons_without_oidc(self):
        script = A / 'scripts/eligibility.py'
        cases = [('pull_request', 'public', 'true', 'auto', 'fork'),
                 ('issue_comment', 'public', 'false', 'auto', 'trigger'),
                 ('schedule', 'private', 'false', 'auto', 'private'),
                 ('push', 'unknown', 'false', 'auto', 'unknown'),
                 ('push', 'public', 'false', 'false', 'disabled')]
        for event, visibility, fork, sign, reason in cases:
            p = subprocess.run([sys.executable, '-I', str(script)], text=True, capture_output=True,
                               env=dict(self.env, GITHUB_EVENT_NAME=event, VISIBILITY=visibility,
                                        IS_FORK=fork, IN_SIGN=sign))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(json.loads(p.stdout)['reason'].startswith(reason), p.stdout)

    def test_S12_visible_samples(self):
        self.assertTrue((A / 'SAMPLE-RECEIPT.md').read_text().startswith('**Sample'))
        for path in ['summary.md', 'comment.md', 'doctor-summary.md']:
            text = (A / 'testdata' / path).read_text()
            self.assertIn('Sample', text)
            self.assertIn('not signed', text)

    def test_S13_plain_capability_names(self):
        md = self.render()
        self.assertNotIn('namespace_sandbox', md)
        self.assertIn('nested container isolation', md)
        self.assertNotRegex(md, '(?i)sandbox|coding[ -]agent|AI[ -]coding')

    def test_permissions_and_two_fresh_jobs(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci-receipt.yml').read_text())
        self.assertEqual(workflow['permissions'], {})
        jobs = workflow['jobs']
        self.assertEqual(set(jobs), {'agent', 'report'})
        self.assertNotIn('id-token', (ROOT / '.github/workflows/ci-receipt.yml').read_text())
        signer = yaml.safe_load((ROOT / '.github/workflows/ci-receipt-sign.yml').read_text())
        jobs = dict(jobs, **signer['jobs'])
        self.assertEqual(jobs['agent']['permissions'], {'contents': 'read'})
        self.assertEqual(jobs['report']['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(jobs['sign']['permissions'], {'contents': 'read', 'actions': 'read', 'id-token': 'write'})
        self.assertEqual(jobs['sign']['runs-on'], 'ubuntu-24.04')
        self.assertNotIn('needs', jobs['sign'])
        self.assertNotIn('id-token', jobs['agent']['permissions'])
        self.assertNotIn('id-token', jobs['report']['permissions'])

    def test_c0_push_is_scoped_and_transparency_is_permanent(self):
        import yaml
        c0 = A / 'testdata/c0'
        data = yaml.safe_load((c0 / 'c0.yml').read_text())
        triggers = data.get('on', data.get(True))
        self.assertEqual(triggers['push'], {'branches': ['c0/**']})
        readme = (c0 / 'README.md').read_text()
        self.assertIn("lab repository's name, owner and run", readme)
        self.assertIn('public Rekor transparency log', readme)
        self.assertIn('permanent', readme)

    def test_no_workflow_input_interpolation_in_shell(self):
        import yaml
        self.assertEqual(workflow_shell_findings(), [])
        for path in workflow_yaml_files():
            for step in workflow_steps(yaml.safe_load(path.read_text()) or {}):
                if 'uses' in step and not step['uses'].startswith('./'):
                    self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')

    def test_workflow_interpolation_guard_catches_step_fields_and_fixtures(self):
        import yaml
        root = self.d / 'repo'
        action = root / 'action'
        targets = [Path('action/action.yml'), Path('action/examples/agent-receipt.yml'),
                   Path('action/testdata/c0/c0.yml'), Path('action/testdata/c0/c0-reusable.yml'),
                   Path('.github/workflows/ci-receipt.yml'), Path('.github/workflows/ci-receipt-sign.yml')]
        for relative in targets:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, target)
        self.assertEqual(workflow_shell_findings(action, root), [])
        for relative in targets:
            target = root / relative
            original = target.read_text()
            for field in ['run', 'shell', 'working-directory']:
                with self.subTest(path=relative, field=field):
                    data = yaml.safe_load(original)
                    step = next(iter(workflow_steps(data)))
                    step.clear()
                    step.update(run='true', shell='bash')
                    step[field] = '${{ inputs.contract }}'
                    target.write_text(yaml.safe_dump(data))
                    try:
                        self.assertIn((target, field), workflow_shell_findings(action, root))
                    finally:
                        target.write_text(original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
