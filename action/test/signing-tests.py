#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Offline policy, strict-input, teardown and signed-manifest regressions."""
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml

A = Path(os.environ.get('ACTION_UNDER_TEST', Path(__file__).resolve().parents[1]))
SPEC = importlib.util.spec_from_file_location('signing', A/'scripts/signing.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class Signing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['WORK'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_policy_matrix(self):
        cases = 0
        refusals = 0
        for event in ('push', 'schedule', 'workflow_dispatch', 'pull_request', 'issue_comment', 'workflow_run'):
            for visibility in ('public', 'private', 'internal', 'unknown'):
                for sign in ('auto', 'true', 'false'):
                    for fork in (False, True, None):
                        unknown_request = (sign == 'true' and fork is not True and
                                           event not in ('issue_comment','workflow_run') and
                                           (visibility == 'unknown' or (event == 'pull_request' and fork is None)))
                        if unknown_request:
                            refusals += 1
                            with self.assertRaisesRegex(ValueError,'cannot authenticate'):
                                S.eligibility(sign,S.CONSENT,event,visibility,fork)
                            cases += 1
                            continue
                        should, _ = S.eligibility(sign, S.CONSENT, event, visibility, fork)
                        expected = (sign != 'false' and fork is not True and visibility != 'unknown' and
                                    event not in ('issue_comment', 'workflow_run') and
                                    (event != 'pull_request' or fork is False) and
                                    (sign == 'true' or visibility == 'public'))
                        self.assertEqual(should, expected, (event, visibility, sign, fork))
                        cases += 1
        self.assertEqual(cases, 216)
        self.assertEqual(refusals, 11)

    def test_missing_consent_refuses_eligible_requests(self):
        for consent in ('', 'true', 'yes', S.CONSENT+' '):
            for visibility, sign in (('public','auto'), ('public','true'), ('private','true'), ('internal','true')):
                with self.subTest(consent=consent, visibility=visibility, sign=sign), self.assertRaisesRegex(ValueError, 'explicit consent'):
                    S.eligibility(sign, consent, 'push', visibility, False)

    def test_target_always_refused(self):
        for sign in ('auto', 'true', 'false'):
            with self.assertRaisesRegex(ValueError, 'pull_request_target'):
                S.eligibility(sign, S.CONSENT, 'pull_request_target', 'public', False)

    def test_script_consent_boundary_precedes_every_other_operation(self):
        env = dict(os.environ, RUNNER_TEMP=str(self.root), IN_SIGN='true', IN_SIGN_CONSENT='',
                   ACTIONS_ID_TOKEN_REQUEST_URL='https://invalid.example', ACTIONS_ID_TOKEN_REQUEST_TOKEN='must-never-use')
        result = subprocess.run([str(A/'scripts/sign.sh')], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn('consent', result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def check_fixture(self):
        names = ('receipt','binding','made_by','run','chain','head','bytes','facts','ended','teardown','coverage')
        return dict(check_v=1,binding_v=2,result='match',ended=True,coverage_complete=True,complete=True,
                    checks=[dict(name=n,result='pass') for n in names])

    def test_complete_product_check_and_each_mutation(self):
        path = self.root/'check.json'
        value = self.check_fixture()
        path.write_text(json.dumps(value))
        self.assertEqual(S.full_check(path), value)
        for key, bad in (('binding_v',1),('binding_v',True),('complete',False),('ended',False),('coverage_complete',False),('result','match-unended')):
            modified = dict(value, **{key:bad})
            path.write_text(json.dumps(modified))
            with self.subTest(key=key,bad=bad), self.assertRaises(ValueError):
                S.full_check(path)
        for step in value['checks']:
            modified = self.check_fixture()
            modified['checks'] = [c for c in modified['checks'] if c['name'] != step['name']]
            path.write_text(json.dumps(modified))
            with self.subTest(missing=step['name']), self.assertRaises(ValueError):
                S.full_check(path)
        for extra in (dict(name='future',result='unknown'),dict(name='facts',result='pass')):
            modified = self.check_fixture()
            modified['checks'].append(extra)
            path.write_text(json.dumps(modified))
            with self.assertRaises(ValueError):
                S.full_check(path)

    def test_strict_inputs(self):
        for raw in ('{"a":1,"a":1}', '{"a":{"b":1,"b":2}}', '{"a":NaN}', '{} {}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                S.strict(raw)
        path = self.root/'input'
        path.symlink_to('/dev/null')
        with self.assertRaises(OSError):
            S.load(path)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            S.load(path)

    def test_teardown_ordinary_scope_and_uncertainty(self):
        path = self.root/'status.json'
        status = dict(schema='tego.run-status/1',run='r-test',scope='/sys/fs/cgroup/tego-cisign-nonexistent-scope',cgroup_id='7',removed=True,deferred=False)
        path.write_text(json.dumps(status))
        self.assertEqual(S.teardown(path,'r-test'),status)
        for key, value in (('removed',False),('deferred',True),('scope','/sys/fs/cgroup/'),('scope','/sys/fs/cgroup/../other'),('cgroup_id',''),('run','r-stale')):
            path.write_text(json.dumps(dict(status,**{key:value})))
            with self.subTest(key=key,value=value), self.assertRaises((ValueError,OSError)):
                S.teardown(path,'r-test')

    def test_core_inventory_exact_five_files(self):
        for name in S.CORE:
            path=self.root/name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(name.encode())
        lines=S.core_inventory(self.root).decode().splitlines()
        self.assertEqual([line.split(' ',2)[2] for line in lines],sorted(S.CORE))
        for line in lines:
            digest,size,name=line.split(' ',2)
            self.assertEqual(digest,hashlib.sha256(name.encode()).hexdigest())
            self.assertEqual(int(size),len(name))

    def test_core_channel_matches_and_refuses_each_changed_field(self):
        for name in S.CORE:
            path=self.root/name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(name.encode())
        env={}
        for label,name in zip(('receipt','record','anchor','contract','status'),
                              ('receipt.json','run/events.jsonl','anchor-line.txt','contract.yaml','run-status.json')):
            env['CORE_'+label.upper()+'_SHA256']=S.digest(self.root/name)
            env['CORE_'+label.upper()+'_BYTES']=str((self.root/name).stat().st_size)
        env['CORE_INVENTORY_SHA256']=hashlib.sha256(S.core_inventory(self.root)).hexdigest()
        with patch.dict(os.environ,env):
            S.check_core_outputs(self.root)
            for key in env:
                with self.subTest(key=key), patch.dict(os.environ,{key:'substituted'}), self.assertRaises(ValueError):
                    S.check_core_outputs(self.root)

    def manifest_fixture(self, fixture_root=None):
        base = fixture_root or self.root
        root = base/'evidence'
        root.mkdir()
        (root/'run').mkdir()
        (base/'state').mkdir()
        env=dict(DIR=str(base),IN_VERSION='v0.2.0',IN_RELEASE_COMMIT='a'*40,TEGO_CODE_SHA='a'*40,
                 GITHUB_REPOSITORY='example/app',GITHUB_SHA='b'*40,GITHUB_REF='refs/heads/main',
                 GITHUB_WORKFLOW_REF='example/app/.github/workflows/ci.yml@refs/heads/main',GITHUB_WORKFLOW_SHA='c'*40,
                 GITHUB_EVENT_NAME='push',GITHUB_RUN_ID='42',GITHUB_RUN_ATTEMPT='2',ARTIFACT_ATTEMPT='1',ARTIFACT_ID='9',
                 CANONICAL_MATRIX_KEY='"single"',ImageOS='ubuntu24',ImageVersion='20261101.1',GITHUB_EVENT_PATH=str(base/'event.json'))
        (base/'event.json').write_text('{}')
        image=dict(environment='github-hosted',image='ubuntu24',version='20261101.1',arch='ARM64')
        binary=dict(asset='tego_0.2.0_linux_arm64',binary_sha256='d'*64)
        chain=dict(run='r-test',bytes=7,lines=1,head='e'*64,ended=True)
        receipt=dict(binding=dict(v=2,chain=chain,binary_sha256='d'*64,contract_hash='f'*64,
                                 receipt_by=dict(tego_version='v0.2.0',commit='a'*40)))
        (root/'receipt.json').write_text(json.dumps(receipt))
        (root/'producer.json').write_text(json.dumps(binary))
        (root/'signer-check.json').write_text(json.dumps(self.check_fixture()))
        (root/'run/events.jsonl').write_text('record\n')
        for name in ('contract.yaml','anchor-line.txt','run-status.json'):
            (root/name).write_text(name)
        meta=dict(github=dict(repository='example/app',checkout_sha='b'*40,action_sha='a'*40,sha='b'*40,
                              workflow_sha='c'*40,workflow_ref=env['GITHUB_WORKFLOW_REF'],run_id='42',run_attempt='1',
                              ref=env['GITHUB_REF'],event='push',runner_name='GitHub Actions 7',agent_runner=image))
        (root/'tego-ci.json').write_text(json.dumps(meta))
        (base/'state/binary-asset').write_text('tego_0.2.0_linux_amd64')
        (base/'state/binary-sha256').write_text('1'*64)
        (base/'state/release-checksums.txt').write_text('d'*64+'  tego_0.2.0_linux_arm64\n'+'1'*64+'  tego_0.2.0_linux_amd64\n')
        claims=dict(job_workflow_ref='Attention-Span-AI/Tego/.github/workflows/ci-receipt-sign.yml@'+'a'*40,job_workflow_sha='a'*40)
        repo=dict(id=123,owner=dict(id=456),visibility='private')
        jobs=[dict(runner_name='GitHub Actions 7',name='receipt / agent',status='completed',runner_group_id=0,runner_group_name='GitHub Actions',labels=['ubuntu-24.04-arm'])]
        return root,env,claims,repo,jobs

    def test_manifest_binds_exact_bytes_and_cross_architecture_assets(self):
        root,env,claims,repo,jobs=self.manifest_fixture()
        with patch.dict(os.environ,env), patch.object(S,'attempt_jobs',return_value=jobs):
            value=S.manifest(root,repo,claims)
        self.assertEqual(value['schema'],'tego.ci-receipt/1')
        self.assertEqual(value['github']['run_attempt'],'2')
        self.assertEqual(value['github']['agent_runner']['arch'],'ARM64')
        self.assertEqual(value['github']['signer_runner']['arch'],'X64')
        self.assertNotEqual(value['tego']['producer']['binary_sha256'],value['tego']['signer']['binary_sha256'])
        for key in ('receipt','record','anchor','teardown','signer_check'):
            field=value[key]
            self.assertEqual(field['sha256'],S.digest(root/field['file']))
        self.assertEqual(value['artifact']['inventory_sha256'],hashlib.sha256(S.core_inventory(root)).hexdigest())
        self.assertLess(len(json.dumps(value)),64*1024)

    def test_manifest_refuses_substitution_and_self_hosted_agent(self):
        root,env,claims,repo,jobs=self.manifest_fixture()
        with patch.dict(os.environ,env), patch.object(S,'attempt_jobs',return_value=jobs):
            for field in ('repository','checkout_sha','action_sha','workflow_sha','run_id','run_attempt','ref','event'):
                meta=S.load(root/'tego-ci.json')
                original=json.dumps(meta)
                meta['github'][field]='substituted'
                (root/'tego-ci.json').write_text(json.dumps(meta))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    S.manifest(root,repo,claims)
                (root/'tego-ci.json').write_text(original)
            jobs[0]['labels'].append('self-hosted')
            with self.assertRaisesRegex(ValueError,'GitHub-hosted'):
                S.manifest(root,repo,claims)
            jobs[0]['labels'].remove('self-hosted')
            for group in (None,1,False):
                jobs[0]['runner_group_id']=group
                with self.assertRaisesRegex(ValueError,'GitHub-hosted'):
                    S.manifest(root,repo,claims)
            jobs[0]['runner_group_id']=0
            producer=S.load(root/'producer.json')
            producer['binary_sha256']='0'*64
            (root/'producer.json').write_text(json.dumps(producer))
            with self.assertRaisesRegex(ValueError,'authenticated release'):
                S.manifest(root,repo,claims)

    def signer_fixture(self):
        base = Path(tempfile.mkdtemp(dir=self.root))
        prepared = base/'prepared'
        prepared.mkdir()
        evidence, env, claims, repo, jobs = self.manifest_fixture(prepared)
        fixture = base/'fixture'
        shutil.copytree(A/'scripts', fixture/'scripts')
        scripts = fixture/'scripts'
        # Keep sign.sh byte-for-byte. Replace only verification/installation,
        # network transports and the pinned external executable with fixtures.
        (scripts/'signing.py').rename(scripts/'signing-implementation.py')
        shutil.copyfile(A/'test/signer-service.py', scripts/'signing.py')
        (scripts/'verify.sh').write_text('#!/bin/bash -p\nset -eu\n/bin/cp -R "$SIGNER_PREPARED" "$RUNNER_TEMP/tego-verifier"\n')
        (scripts/'verify.sh').chmod(0o755)
        runner = base/'runner'
        runner.mkdir()
        actual = runner/'tego-verifier'
        (prepared/'bin').mkdir()
        shutil.copyfile(A/'test/signer-service.py', prepared/'bin/cosign')
        (prepared/'bin/cosign').chmod(0o755)
        cosign_hash = S.digest(prepared/'bin/cosign')
        trust = (scripts/'trust.sh').read_text()
        # The fake executable still passes the production before/after pin and
        # trust checks, and runs via the production clean cosign environment.
        trust = trust.replace('4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71', cosign_hash)
        trust = trust.replace('c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a', cosign_hash)
        (scripts/'trust.sh').write_text(trust)
        trust_root = prepared/'sigstore'
        (trust_root/'home').mkdir(parents=True)
        targets = trust_root/'tuf/tuf-repo-cdn.sigstore.dev/targets'
        targets.mkdir(parents=True)
        for name in ('root.json', 'trusted_root.json', 'signing_config.v0.2.json'):
            shutil.copyfile(A/'trust'/name, trust_root/name)
            target = targets.parent/name if name == 'root.json' else targets/name
            shutil.copyfile(A/'trust'/name, target)
        (trust_root/'tuf/remote.json').write_text('{"mirror":"https://tuf-repo-cdn.sigstore.dev"}\n')
        # setup_trust writes this tool-owned state. Its fixture bytes get an
        # independent pin; the production trust_assert logic is unchanged.
        trust = (scripts/'trust.sh').read_text()
        remote_check = next(line for line in trust.splitlines() if 'trust_hash "$DIR/sigstore/tuf/remote.json"' in line)
        remote_hash = remote_check.split('" ')[1].split()[0]
        (scripts/'trust.sh').write_text(trust.replace(remote_hash, S.digest(trust_root/'tuf/remote.json')))
        env.update(DIR=str(actual), RUNNER_TEMP=str(runner), IN_SIGN='true', IN_SIGN_CONSENT=S.CONSENT,
                   SIGNER_FIXTURE=str(fixture), SIGNER_PREPARED=str(prepared),
                   ACTIONS_ID_TOKEN_REQUEST_URL='https://fixture.actions.githubusercontent.com/token?run=42',
                   ACTIONS_ID_TOKEN_REQUEST_TOKEN='fixture-request-token', GITHUB_OUTPUT=str(base/'outputs'),
                   GITHUB_STEP_SUMMARY=str(base/'summary'), SIGSTORE_ID_TOKEN='inherited-token-must-not-win')
        claims.update(repository=env['GITHUB_REPOSITORY'], repository_id=str(repo['id']),
                      repository_owner_id=str(repo['owner']['id']), repository_visibility=repo['visibility'],
                      sha=env['GITHUB_SHA'], ref=env['GITHUB_REF'], run_id=env['GITHUB_RUN_ID'],
                      run_attempt=env['GITHUB_RUN_ATTEMPT'], event_name=env['GITHUB_EVENT_NAME'],
                      workflow_ref=env['GITHUB_WORKFLOW_REF'], workflow_sha=env['GITHUB_WORKFLOW_SHA'],
                      runner_environment='github-hosted', iss='https://token.actions.githubusercontent.com', aud='sigstore')
        repo.update(full_name='example/app')
        service = dict(claims=claims, repository=repo, jobs=jobs)
        (fixture/'service.json').write_text(json.dumps(service))
        self.assertEqual((scripts/'sign.sh').read_bytes(), (A/'scripts/sign.sh').read_bytes())
        return base, prepared, actual, scripts, env, service

    def run_signer(self, fixture):
        _, _, _, scripts, env, _ = fixture
        return subprocess.run([str(scripts/'sign.sh')], env=dict(os.environ, **env), capture_output=True, text=True)

    def test_sign_script_signs_exact_blobs_and_publishes_complete_artifact(self):
        fixture = self.signer_fixture()
        base, prepared, actual, _, env, _ = fixture
        result = self.run_signer(fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (actual/'state/cosign-calls.jsonl').read_text().splitlines()]
        self.assertEqual([Path(call['blob']).name for call in calls], ['receipt.json', 'manifest.json'])
        for call, name in zip(calls, ('receipt', 'manifest')):
            self.assertEqual(call['args'], ['sign-blob', '--yes', '--signing-config', str(actual/'sigstore/signing_config.v0.2.json'),
                                           '--trusted-root', str(actual/'sigstore/trusted_root.json'), '--bundle',
                                           str(actual/(name+'.sigstore.json')), str(actual/('evidence/'+name+'.json'))])
            self.assertEqual(call['sha256'], S.digest(actual/('evidence/'+name+'.json')))
            self.assertEqual(set(call['environment']), {'PATH', 'HOME', 'TUF_ROOT', 'SIGSTORE_ID_TOKEN', 'LC_CTYPE'})
            self.assertEqual(call['environment']['PATH'], '/usr/bin:/bin')
            self.assertEqual(call['environment']['HOME'], str(actual/'sigstore/home'))
            self.assertEqual(call['environment']['TUF_ROOT'], str(actual/'sigstore/tuf'))
            self.assertTrue(call['token'].startswith('header.'))
            self.assertNotEqual(call['token'], env['SIGSTORE_ID_TOKEN'])
            bundle = S.load(actual/('signed/'+name+'.sigstore.json'))
            self.assertEqual(bundle, dict(fixture_bundle=True, blob_sha256=call['sha256']))
        self.assertFalse((actual/'state/identity-token').exists())
        expected = {p.relative_to(prepared/'evidence').as_posix() for p in (prepared/'evidence').rglob('*') if p.is_file()}
        expected.update(('manifest.json', 'receipt.sigstore.json', 'manifest.sigstore.json', 'SIGNATURE.md'))
        published = {p.relative_to(actual/'signed').as_posix() for p in (actual/'signed').rglob('*') if p.is_file()}
        self.assertEqual(published, expected)
        self.assertEqual((actual/'signed/manifest.json').read_bytes(), (actual/'evidence/manifest.json').read_bytes())
        for name in expected - {'manifest.json', 'receipt.sigstore.json', 'manifest.sigstore.json', 'SIGNATURE.md'}:
            self.assertEqual((actual/'signed'/name).read_bytes(), (prepared/'evidence'/name).read_bytes())
        self.assertEqual((base/'outputs').read_text(), 'signed-dir='+str(actual/'signed')+'\n')
        self.assertEqual((base/'summary').read_bytes(), (actual/'signed/SIGNATURE.md').read_bytes())
        token_calls = [json.loads(line) for line in (base/'fixture/token-calls.jsonl').read_text().splitlines()]
        self.assertEqual(token_calls, [dict(url=env['ACTIONS_ID_TOKEN_REQUEST_URL']+'&audience=sigstore',
                                         authorization='Bearer fixture-request-token', timeout=30)])

    def assert_claim_refuses(self, key, value):
        fixture = self.signer_fixture()
        base, _, actual, _, _, service = fixture
        service['claims'][key] = value
        (base/'fixture/service.json').write_text(json.dumps(service))
        result = self.run_signer(fixture)
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertRegex(result.stderr, 'OIDC|reusable signer workflow')
        self.assertFalse((actual/'signed').exists())
        self.assertFalse((actual/'state/cosign-calls.jsonl').exists())

    def test_sign_script_each_claim_mismatch_refuses(self):
        # Mutating every bound claim catches deletion of individual comparisons,
        # including exact reusable workflow path, owner and ref suffix.
        for key in ('repository', 'repository_id', 'repository_owner_id', 'repository_visibility', 'sha', 'ref',
                    'run_id', 'run_attempt', 'event_name', 'workflow_ref', 'workflow_sha', 'runner_environment',
                    'job_workflow_sha', 'iss', 'aud', 'job_workflow_ref'):
            with self.subTest(claim=key):
                self.assert_claim_refuses(key, 'substituted')
        for workflow in ('Other/Tego/.github/workflows/ci-receipt-sign.yml@'+'a'*40,
                         'Attention-Span-AI/Tego/.github/workflows/ci-receipt.yml@'+'a'*40,
                         'Attention-Span-AI/Tego/.github/workflows/ci-receipt-sign.yml@refs/heads/main',
                         'Attention-Span-AI/Tego/.github/workflows/ci-receipt-sign.yml@'+'b'*40):
            with self.subTest(workflow=workflow):
                self.assert_claim_refuses('job_workflow_ref', workflow)

    def test_sign_script_each_consent_mismatch_refuses_before_token(self):
        for consent in ('', 'true', 'yes', S.CONSENT+' '):
            with self.subTest(consent=consent):
                fixture = self.signer_fixture()
                base, _, actual, _, env, _ = fixture
                env['IN_SIGN_CONSENT'] = consent
                result = self.run_signer(fixture)
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertIn('consent', result.stderr)
                self.assertFalse((base/'fixture/token-calls.jsonl').exists())
                self.assertFalse((base/'fixture/api-calls.jsonl').exists())
                self.assertFalse(actual.exists())

    def test_sign_script_each_signing_failure_never_publishes(self):
        for blob in ('receipt.json', 'manifest.json'):
            with self.subTest(blob=blob):
                fixture = self.signer_fixture()
                _, prepared, actual, _, _, _ = fixture
                (prepared/'state/fail-blob').write_text(blob)
                result = self.run_signer(fixture)
                self.assertEqual(result.returncode, 125, result.stderr)
                self.assertFalse((actual/'signed').exists())
                self.assertFalse((actual/'state/identity-token').exists())
                calls = [json.loads(line) for line in (actual/'state/cosign-calls.jsonl').read_text().splitlines()]
                expected = ['receipt.json'] if blob == 'receipt.json' else ['receipt.json', 'manifest.json']
                self.assertEqual([Path(call['blob']).name for call in calls], expected)

    def test_sign_script_evidence_change_never_publishes(self):
        fixture = self.signer_fixture()
        _, prepared, actual, _, _, _ = fixture
        (prepared/'state/mutate-blob').touch()
        result = self.run_signer(fixture)
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn('evidence changed during signing', result.stderr)
        self.assertFalse((actual/'signed').exists())

    def test_workflow_handoff_preserves_all_independent_channels(self):
        workflow = yaml.safe_load((A.parent/'.github/workflows/ci-receipt.yml').read_text())
        signer = yaml.safe_load((A.parent/'.github/workflows/ci-receipt-sign.yml').read_text())
        call_outputs = workflow[True]['workflow_call']['outputs']
        self.assertEqual(call_outputs['handoff']['value'], '${{ jobs.report.outputs.handoff }}')
        self.assertEqual(call_outputs['should-sign']['value'], '${{ jobs.report.outputs.should-sign }}')
        report = workflow['jobs']['report']
        self.assertEqual(report['outputs']['handoff'], '${{ steps.handoff.outputs.value }}')
        self.assertEqual(report['outputs']['should-sign'], '${{ steps.verify.outputs.should-sign }}')
        report_steps = {step['id']: step for step in report['steps'] if 'id' in step}
        handoff = report_steps['handoff']
        self.assertEqual(handoff['env'], {'AGENT_OUTPUTS': '${{ toJSON(needs.agent.outputs) }}'})
        signing_step = next(step for step in signer['jobs']['sign']['steps'] if step.get('id') == 'sign')
        channels = {f'CORE_{name.upper()}_{kind.upper()}': name+'-'+kind
                    for name in ('receipt', 'record', 'anchor', 'contract', 'status') for kind in ('sha256', 'bytes')}
        channels.update(CORE_INVENTORY_SHA256='core-inventory-sha256', ARTIFACT_ID='artifact-id',
                        ARTIFACT_NAME='artifact-name', ARTIFACT_ATTEMPT='artifact-attempt',
                        ARTIFACT_DIGEST='artifact-digest', MATRIX_SHA256='matrix-key', INVENTORY_SHA256='inventory-sha256')
        agent_outputs = workflow['jobs']['agent']['outputs']
        for env_name, key in channels.items():
            with self.subTest(channel=key):
                source = 'upload' if key in ('artifact-id', 'artifact-digest') else 'collect'
                self.assertEqual(agent_outputs[key], '${{ steps.'+source+'.outputs.'+key+' }}')
                self.assertEqual(report_steps['verify']['env'][env_name], '${{ needs.agent.outputs.'+key+' }}')
                self.assertEqual(signing_step['env'][env_name], '${{ fromJSON(inputs.handoff).'+key+' }}')
        # Execute the exact handoff formatter as well: newlines and shell text
        # remain JSON string data on the single GitHub output line.
        values = {key: 'fixture-'+key for key in channels.values()}
        values['future-field'] = 'line one\nline two $(false) "quoted"'
        output = self.root/'handoff-output'
        result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-peuo', 'pipefail', '-c', handoff['run']],
                                env=dict(os.environ, AGENT_OUTPUTS=json.dumps(values), GITHUB_OUTPUT=str(output)),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = output.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('value='))
        self.assertEqual(json.loads(lines[0].removeprefix('value=')), values)

    def receipt_only_outcome(self, sign, agent_exit, refusals, on_refusal, expected):
        # Model checked report outputs and a successful upload. Execute the shipped
        # gate and its workflow condition; no downstream signing call is present.
        workflow = yaml.safe_load((A.parent/'.github/workflows/ci-receipt.yml').read_text())
        self.assertEqual(set(workflow['jobs']), {'agent', 'report'})
        steps = workflow['jobs']['report']['steps']
        gate = next(step for step in steps if 'gate.sh' in step.get('run', ''))
        upload = next(step for step in steps if step.get('name') == 'retain the fresh receipt comparison')
        self.assertLess(steps.index(upload), steps.index(gate))
        selected, _ = S.eligibility(sign, S.CONSENT, 'push', 'public', False)
        checked = {'agent-exit-code': str(agent_exit), 'prepare-exit': '0',
                   'evidence-exit': '0', 'run-id': 'checked-fixture-run',
                   'refusals': str(refusals), 'verified': 'true',
                   'should-sign': str(selected).lower()}
        condition = gate.get('if', '')
        # Recognize the old condition as well so the negative overlay reproduces
        # its green conclusion, instead of failing only on a text assertion.
        if condition in ('', 'always()', '${{ always() }}'):
            runs = True
        elif condition == "steps.verify.outputs.should-sign != 'true'":
            runs = not selected
        else:
            self.fail('unmodeled receipt gate condition: '+condition)
        code = 0
        if runs:
            workspace = Path(tempfile.mkdtemp(dir=self.root))
            (workspace/'tego-code').symlink_to(A.parent.resolve(), target_is_directory=True)
            env = dict(os.environ, GITHUB_WORKSPACE=str(workspace))
            values = {'${{ steps.verify.outputs.'+key+' }}': value for key, value in checked.items()}
            values['${{ inputs.on-refusal }}'] = on_refusal
            for key, expression in gate['env'].items():
                self.assertIn(expression, values)
                env[key] = values[expression]
            result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-peuo', 'pipefail', '-c', gate['run']],
                                    env=env, capture_output=True, text=True)
            code = result.returncode
        self.assertEqual(code, expected, (sign, agent_exit, refusals, on_refusal, 'gate ran', runs))
        self.assertTrue(runs, 'receipt outcome gate was skipped for signing selection')
        self.assertIn(condition, ('always()', '${{ always() }}'), 'gate must also run after a failed upload')

    def test_receipt_only_agent_failure_when_signing_selected(self):
        self.receipt_only_outcome('true', 3, 0, 'warn', 3)

    def test_receipt_only_refusal_failure_when_signing_selected(self):
        self.receipt_only_outcome('true', 0, 2, 'fail', 1)

    def test_receipt_only_outcome_matrix(self):
        for sign in ('true', 'false', 'auto'):
            for agent_exit, refusals, policy, expected in ((0, 0, 'warn', 0), (3, 0, 'warn', 3),
                                                          (0, 2, 'fail', 1), (0, 2, 'warn', 0)):
                with self.subTest(sign=sign, agent_exit=agent_exit, refusals=refusals, on_refusal=policy):
                    self.receipt_only_outcome(sign, agent_exit, refusals, policy, expected)

    def test_workflow_authority_and_upload_before_gate(self):
        unsigned_path = A.parent/'.github/workflows/ci-receipt.yml'
        workflow = yaml.safe_load(unsigned_path.read_text())
        signer = yaml.safe_load((A.parent/'.github/workflows/ci-receipt-sign.yml').read_text())
        jobs = workflow['jobs']
        self.assertEqual(set(jobs), {'agent', 'report'})
        self.assertNotIn('id-token', unsigned_path.read_text())
        self.assertEqual(workflow['permissions'], {})
        self.assertEqual(workflow[True]['workflow_call']['inputs']['sign']['default'], 'false')
        self.assertEqual(set(signer['jobs']), {'sign'})
        signing_job = signer['jobs']['sign']
        self.assertEqual(signing_job['permissions'], {'contents': 'read', 'actions': 'read', 'id-token': 'write'})
        self.assertEqual(signer['permissions'], {})
        for job in list(jobs.values()) + [signing_job]:
            self.assertNotIn('pull-requests', job['permissions'])
            for step in job['steps']:
                if step.get('uses', '').startswith('actions/upload-artifact@'):
                    self.assertEqual(step['with']['retention-days'], 7)
        steps = signing_job['steps']
        self.assertIn('CONSENT', steps[0]['run'])
        self.assertNotIn('uses', steps[0])
        self.assertEqual(steps[-2]['id'], 'signed-upload')
        self.assertIn('gate.sh', steps[-1]['run'])
        disclosure = signer[True]['workflow_call']['inputs']['sign-consent']['description']
        self.assertTrue(signer[True]['workflow_call']['inputs']['sign-consent']['required'])
        for word in ('organisation', 'repository', 'workflow', 'public', 'permanent'):
            self.assertIn(word, disclosure)


if __name__ == '__main__':
    unittest.main(verbosity=2)
