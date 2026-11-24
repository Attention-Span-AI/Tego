#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline fresh-job regressions. Scratch tool stubs never contact GitHub."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

A = Path(os.environ.get('ACTION_UNDER_TEST', Path(__file__).resolve().parents[1]))
WORK = Path(os.environ['WORK'])
SPEC = importlib.util.spec_from_file_location('handoff_fix_tests', A / 'scripts/handoff.py')
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class VerifierFixes(unittest.TestCase):
    maxDiff = 800
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.action = self.d / 'action'
        shutil.copytree(A, self.action)
        self.evidence = self.d / 'evidence'
        self.evidence.mkdir()
        for name in ['receipt.json', 'verify.json', 'run_start.json', 'compile.json', 'contract.yaml']:
            shutil.copy(A / 'testdata' / name, self.evidence / name)
        (self.evidence / 'run').mkdir()
        shutil.copy(A / 'testdata/events.jsonl', self.evidence / 'run/events.jsonl')
        self.receipt = json.loads((self.evidence / 'receipt.json').read_text())
        self.start = json.loads((self.evidence / 'run_start.json').read_text())
        self.meta = {'run': self.receipt['run'], 'contract_hash': self.start['contract_hash'],
                     'agent_exit_code': self.receipt['exit_code']}
        (self.evidence / 'eligibility.json').write_text('{"reason":"disabled: offline fixture"}')
        self.event = self.d / 'event.json'
        self.event.write_text('{"number":7,"pull_request":{"number":7}}')
        self.tools = self.d / 'tools'
        self.tools.mkdir()
        gh = self.tools / 'gh'
        gh.write_text('''#!/usr/bin/python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['GH_LOG'], 'a') as f:
 f.write(json.dumps({'args':args,'body':sys.stdin.read() if '--input' in args else ''})+'\\n')
if '--paginate' in args:
 print(json.dumps([{'id':22,'user':{'login':'github-actions[bot]','type':'Bot'},'body':os.environ['OLD_MARKER']+'\\nold receipt'}]))
elif args[-1].endswith('/zip'):
 sys.stdout.buffer.write(Path(os.environ['LOCAL_ARCHIVE']).read_bytes())
else:
 print(json.dumps({'id':7,'workflow_run':{'id':42},'name':'tego-receipt-42-1-'+'b'*64,'expired':False,'size_in_bytes':Path(os.environ['LOCAL_ARCHIVE']).stat().st_size}))
''')
        gh.chmod(0o755)
        curl = self.tools / 'curl'
        curl.write_text('''#!/usr/bin/python3
import os, shutil, sys
shutil.copyfile(os.environ['LOCAL_BINARY'],sys.argv[sys.argv.index('-o')+1])
''')
        curl.chmod(0o755)
        # Production has no tool override: adapt trusted scratch code to absolute
        # offline stand-ins, including both pre-hardening and pinned tool spellings.
        for path in [*self.action.rglob('*.sh'), self.action / 'scripts/handoff.py']:
            text = path.read_text()
            text = text.replace('/usr/bin/gh', str(gh)).replace('/usr/bin/curl', str(curl))
            if path.suffix == '.py':
                text = text.replace("['gh',", repr([str(gh)])[0:-1] + ',')
            else:
                import re
                text = re.sub(r'(?<![\w/.-])gh(?= (?:api|>/dev/null))', str(gh), text)
                text = re.sub(r'(?<![\w/.-])curl(?= )', str(curl), text)
            path.write_text(text)
        # Authentication has a separate offline suite; this fixture isolates
        # transport and fresh comparison, using a clearly stubbed installer.
        (self.action / 'scripts/install.sh').write_text('#!/bin/bash -p\nset -euo pipefail\nmkdir -p "$DIR/bin" "$DIR/state"\ncp "$LOCAL_BINARY" "$DIR/bin/tego"\nchmod 755 "$DIR/bin/tego"\nprintf \'%s\\n\' "$IN_SHA256" >"$DIR/state/binary-sha256"\n')
        self.runtime = self.d / 'runtime'
        self.runtime.mkdir()
        self.env = dict(os.environ, LOCAL_BINARY=str(A / 'test/fake-tego'), LOCAL_ARCHIVE=str(self.d / 'archive.zip'),
                        PATH=str(self.tools) + ':' + os.environ['PATH'], IN_SHA256=digest(A / 'test/fake-tego'),
                        IN_VERSION='v9.8.7', ARTIFACT_ID='7', MATRIX_SHA256='b'*64,
                        ARTIFACT_ATTEMPT='1', ARTIFACT_NAME='tego-receipt-42-1-'+'b'*64,
                        GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1', GITHUB_REPOSITORY='example/app',
                        GITHUB_SHA='a'*40, GITHUB_EVENT_NAME='pull_request', GITHUB_EVENT_PATH=str(self.event),
                        GITHUB_JOB='sign', GITHUB_WORKFLOW_REF='example/app/.github/workflows/ci.yml@refs/heads/main',
                        RUNNER_TEMP=str(self.runtime), RUN_ID='forged-run', AGENT_EXIT='0', PREPARE_EXIT='0',
                        EVIDENCE_EXIT='0', VERIFIED='true', REFUSALS='0', PR_NUMBER='999',
                        IN_ON_REFUSAL='warn', IN_SIGN='auto', IN_MATRIX_KEY='single', TIER_WANTED='landlock',
                        FAKE_TEGO_DATA=str(A / 'testdata'), DO_COMMENT='false', GH_LOG=str(self.d / 'gh.log'),
                        GITHUB_STEP_SUMMARY=str(self.d / 'summary.md'))
        ident = subprocess.run(['/usr/bin/python3', '-I', str(A / 'scripts/identity.py')],
                               env=self.env, capture_output=True, text=True, check=True)
        self.env['OLD_MARKER'] = json.loads(ident.stdout)['marker']

    def archive(self):
        (self.evidence / 'receipt.json').write_text(json.dumps(self.receipt))
        self.meta.update(receipt_sha256=digest(self.evidence / 'receipt.json'),
                         events_sha256=digest(self.evidence / 'run/events.jsonl'),
                         contract_file_sha256=digest(self.evidence / 'contract.yaml'))
        (self.evidence / 'tego-ci.json').write_text(json.dumps(self.meta))
        return self.pack()

    def pack(self):
        archive = Path(self.env['LOCAL_ARCHIVE'])
        with zipfile.ZipFile(archive, 'w') as zipped:
            for path in self.evidence.rglob('*'):
                if path.is_file(): zipped.write(path, path.relative_to(self.evidence).as_posix())
        self.env.update(ARTIFACT_DIGEST=digest(archive), INVENTORY_SHA256=H.sha(H.inventory(self.evidence)))

    def verify(self):
        return subprocess.run([str(self.action / 'scripts/verify.sh')], env=self.env,
                              capture_output=True, text=True)

    def product_binding_pipeline(self, version):
        # The receipt/check pair is generated by TestWorkflowBindingFixtures.
        # Only CLI transport is stubbed: collection and fresh verification run
        # their production scripts over each product binding shape.
        data = self.d / 'product-data'
        shutil.copytree(A / 'testdata', data)
        for name in ['receipt.json', 'check.json']:
            shutil.copy(A / 'testdata/bindings' / version / name, data / name)
        self.receipt = json.loads((data / 'receipt.json').read_text())
        self.env['FAKE_TEGO_DATA'] = str(data)
        collect = self.d / 'collect'
        (collect / 'evidence').mkdir(parents=True)
        (collect / 'state').mkdir()
        ledger = self.d / 'ledger'
        run = self.receipt['run']
        (ledger / run).mkdir(parents=True)
        shutil.copy(data / 'events.jsonl', ledger / run / 'events.jsonl')
        for name in ['contract.yaml', 'compile.json']:
            shutil.copy(data / name, collect / 'evidence' / name)
        (collect / 'state/runs-before.txt').write_text('')
        (collect / 'state/protected-paths.json').write_text(json.dumps([str(collect), '/usr/bin', '/bin']))
        (collect / 'state/binary-sha256').write_text(digest(A / 'test/fake-tego')+'\n')
        anchor = self.d / 'anchor.txt'
        anchor.write_text(run+' '+self.receipt['binding']['chain']['head']+'\n')
        env = dict(self.env, DIR=str(collect), TEGO=str(A / 'test/fake-tego'),
                   LEDGER_ROOT=str(ledger), FAKE_ANCHOR=str(anchor), AGENT_EXIT='0',
                   GITHUB_OUTPUT=str(self.d / 'collect-output'))
        proc = subprocess.run([str(self.action / 'scripts/collect.sh')], env=env,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        check = json.loads((collect / 'evidence/agent-check.json').read_text())
        self.assertEqual(check['binding_v'], int(version[1:]))
        self.archive()
        proc = self.verify()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        checked = json.loads((self.runtime / 'tego-verifier/signer-check.json').read_text())
        self.assertEqual(checked['binding_v'], int(version[1:]))

    def test_product_binding_v1_collection_and_verification(self):
        self.product_binding_pipeline('v1')

    def test_product_binding_v2_collection_and_verification(self):
        self.product_binding_pipeline('v2')

    def test_gate_refusals_come_from_checked_receipt(self):
        self.archive()
        self.env['IN_ON_REFUSAL'] = 'fail'
        proc = self.verify()
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_gate_exit_comes_from_checked_receipt(self):
        self.receipt['exit_code'] = self.meta['agent_exit_code'] = 3
        self.archive()
        proc = self.verify()
        self.assertEqual(proc.returncode, 3, proc.stderr)

    def test_non_exit_status_comes_from_checked_record(self):
        self.receipt.pop('exit_code')
        self.receipt.update(end_reason='signal', signal=15)
        self.meta['agent_exit_code'] = 143
        path = self.evidence / 'run/events.jsonl'
        lines = path.read_text().splitlines()
        end = json.loads(lines[-1])
        end.update(reason='signal', exit_code=143, signal=15)
        lines[-1] = json.dumps(end)
        path.write_text('\n'.join(lines)+'\n')
        self.archive()
        proc = self.verify()
        self.assertEqual(proc.returncode, 143, proc.stderr)

    def test_gate_verified_run_ignore_agent_outputs(self):
        self.archive()
        self.env.update(VERIFIED='false', RUN_ID='', EVIDENCE_EXIT='125', PREPARE_EXIT='211', AGENT_EXIT='9')
        proc = self.verify()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('Tego receipt', (self.d / 'summary.md').read_text())

    def test_comment_target_comes_from_fresh_event(self):
        self.archive()
        self.env['DO_COMMENT'] = 'true'
        proc = self.verify()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = (self.d / 'gh.log').read_text()
        self.assertTrue('issues/7/comments' in log, 'fresh event PR was not selected')
        self.assertNotIn('issues/999/comments', log)

    def test_failed_check_replaces_stale_comment_with_commit(self):
        self.archive()
        self.env.update(ARTIFACT_DIGEST='f'*64, DO_COMMENT='true')
        proc = self.verify()
        self.assertEqual(proc.returncode, 125, proc.stderr)
        log = (self.d / 'gh.log').read_text()
        self.assertIn('comments/22', log)
        self.assertIn('No checked receipt for commit', log)
        self.assertIn('a'*40, log)

    def test_render_names_event_commit(self):
        self.archive()
        proc = self.verify()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue('| Event commit | `'+'a'*40+'` |' in (self.d / 'summary.md').read_text())

    def test_failed_receipt_comparison_replaces_stale_comment(self):
        self.archive()
        data = self.d / 'cli-data'
        shutil.copytree(A / 'testdata', data)
        check = json.loads((data / 'check.json').read_text())
        check['result'] = 'mismatch'
        (data / 'check.json').write_text(json.dumps(check))
        self.env.update(FAKE_TEGO_DATA=str(data), DO_COMMENT='true')
        proc = self.verify()
        self.assertEqual(proc.returncode, 125, proc.stderr)
        log = (self.d / 'gh.log').read_text()
        self.assertIn('comments/22', log)
        self.assertIn('No checked receipt for commit', log)

    def test_partial_rerun_uses_agent_artifact_attempt(self):
        self.archive()
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        proc = self.verify()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_failed_agent_partial_rerun_preserves_checked_exit(self):
        self.receipt['exit_code'] = self.meta['agent_exit_code'] = 3
        self.archive()
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        proc = self.verify()
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn('Tego receipt', (self.d / 'summary.md').read_text())

    def configure_reporting_policy(self):
        path=self.action/'scripts/signing.py'
        text=path.read_text().replace('data, fork = repository()',
                "data, fork = ({'full_name':'example/app','id':7,'owner':{'id':8},'visibility':'public'}, False)")
        path.write_text(text)
        self.env.update(DEFER_GATE='true',IN_SIGN='true')

    def test_report_refuses_missing_consent_after_comparison(self):
        self.configure_reporting_policy()
        self.env['IN_SIGN_CONSENT']=''
        self.archive()
        result=self.verify()
        self.assertEqual(result.returncode,125,result.stderr)
        self.assertIn('explicit consent',result.stderr)
        self.assertTrue((self.runtime/'tego-verifier/signer-check.json').is_file())

    def test_report_never_schedules_signer_without_core_teardown(self):
        self.configure_reporting_policy()
        self.env['IN_SIGN_CONSENT']='I consent to publish repository and workflow names in the permanent public Sigstore log'
        self.archive()
        result=self.verify()
        self.assertEqual(result.returncode,125,result.stderr)
        self.assertIn('out-of-band',result.stderr)
        self.assertNotIn('should-sign=true',result.stdout)

    def test_artifact_name_is_explicit_and_checked(self):
        self.archive()
        self.env['ARTIFACT_NAME'] = 'unrelated-artifact'
        proc = self.verify()
        self.assertEqual(proc.returncode, 125, proc.stderr)

    def test_wrong_producer_attempt_is_refused(self):
        self.archive()
        self.env.update(ARTIFACT_ATTEMPT='2', ARTIFACT_NAME='tego-receipt-42-2-'+'b'*64,
                        GITHUB_RUN_ATTEMPT='2')
        proc = self.verify()
        self.assertEqual(proc.returncode, 125, proc.stderr)

    def test_doctor_refusal_comes_from_inventory_bound_diagnostic(self):
        for path in list(self.evidence.rglob('*')):
            if path.is_file(): path.unlink()
        (self.evidence / 'run').rmdir()
        (self.evidence / 'doctor.json').write_text('{"tiers":{"landlock":false},"missing":{"landlock":["test kernel capability"]}}')
        self.pack()
        self.env.update(PREPARE_EXIT='0', AGENT_EXIT='0')
        proc = self.verify()
        self.assertEqual(proc.returncode, 211, proc.stderr)
        self.assertIn('test kernel capability', (self.d / 'summary.md').read_text())

    def test_unsubstantiated_doctor_refusal_cannot_override_checked_run(self):
        self.archive()
        self.env['PREPARE_EXIT'] = '211'
        proc = self.verify()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_metadata_exit_disagreement_fails_closed(self):
        self.meta['agent_exit_code'] = 9
        self.archive()
        proc = self.verify()
        self.assertEqual(proc.returncode, 125, proc.stderr)

    def test_truncation_does_not_append_unopened_details(self):
        md = self.evidence / 'receipt.md'
        md.write_text(self.env['OLD_MARKER']+'\n'+'x'*61000)
        (self.d / 'state').mkdir()
        env = dict(self.env, DIR=str(self.d), MD=str(md))
        proc = subprocess.run([str(self.action / 'scripts/post.sh')], env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse('</details>' in (self.d / 'state/comment.md').read_text())

    def test_verifier_workflow_waits_without_running_after_cancellation(self):
        import yaml
        workflow = yaml.safe_load((A.parent / '.github/workflows/ci-receipt-sign.yml').read_text())
        self.assertIn('!cancelled()', workflow['jobs']['sign']['if'])
        env = workflow['jobs']['sign']['steps'][2]['env']
        for key in ['RUN_ID', 'AGENT_EXIT', 'PREPARE_EXIT', 'EVIDENCE_EXIT', 'VERIFIED', 'REFUSALS', 'PR_NUMBER']:
            self.assertNotIn(key, env)


if __name__ == '__main__':
    unittest.main(verbosity=2)
