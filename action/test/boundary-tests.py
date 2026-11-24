#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline adversarial checks at the unsigned job boundary."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
sys.dont_write_bytecode = True
A = Path(__file__).resolve().parents[1]
WORK = Path(os.environ['WORK'])


def load(name):
    spec = importlib.util.spec_from_file_location(name, A / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = load('handoff')
p = load('policy')


class Boundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.root = self.d / 'evidence'
        self.root.mkdir()
        (self.root / 'receipt.json').write_text('{}')

    def instrument_action(self, tools):
        # Fixed production paths are replaced only in this disposable copy.
        self.action = self.d / 'action'
        shutil.copytree(A, self.action)
        for name, stub in tools.items():
            self.assertTrue(stub.is_absolute())
            literal = '/usr/bin/' + name
            replaced = 0
            for script in (self.action / 'scripts').iterdir():
                if script.suffix not in {'.sh', '.py'}:
                    continue
                text = script.read_text()
                replaced += text.count(literal)
                script.write_text(text.replace(literal, str(stub)))
            self.assertGreater(replaced, 0, literal)
        return self.action

    def archive(self, name='receipt.json', value=b'{}', mode=None):
        zpath = self.d / 'artifact.zip'
        with zipfile.ZipFile(zpath, 'w') as z:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            z.writestr(info, value)
        return zpath

    def extract(self, archive, digest=None, inv=None):
        h.extract(archive, self.d / 'downloaded', digest or h.sha(archive.read_bytes()),
                  inv or h.sha(h.inventory(self.root)))

    def test_regular_archive_roundtrip(self):
        self.extract(self.archive())
        self.assertEqual((self.d / 'downloaded/receipt.json').read_text(), '{}')

    def test_changed_archive_byte(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.extract(self.archive(), digest='a' * 64)

    def test_changed_inventory(self):
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.extract(self.archive(), inv='a' * 64)

    def test_missing_out_of_band_digest(self):
        z = self.archive()
        with self.assertRaisesRegex(ValueError, 'out-of-band'):
            h.extract(z, self.d / 'downloaded', '', h.sha(h.inventory(self.root)))

    def test_traversal(self):
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            self.extract(self.archive('../receipt.json'))
        self.assertFalse((self.d / 'receipt.json').exists())

    def test_absolute_path(self):
        with self.assertRaises(ValueError):
            self.extract(self.archive('/receipt.json'))

    def test_symlink(self):
        with self.assertRaisesRegex(ValueError, 'non-regular'):
            self.extract(self.archive(mode=stat.S_IFLNK | 0o777))

    def test_duplicate_zip_name(self):
        import warnings
        z = self.archive()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(z, 'a') as archive:
                archive.writestr('receipt.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.extract(z)

    def test_unexpected_executable(self):
        with self.assertRaises(ValueError):
            self.extract(self.archive('tego', b'exec me'))

    def test_preexisting_extraction_root(self):
        (self.d / 'downloaded').mkdir()
        with self.assertRaises(FileExistsError):
            self.extract(self.archive())

    def test_inventory_refuses_symlink(self):
        (self.root / 'contract.yaml').symlink_to('receipt.json')
        with self.assertRaisesRegex(ValueError, 'link'):
            h.inventory(self.root)

    def test_inventory_bounds_file_size(self):
        with (self.root / 'receipt.json').open('wb') as f:
            f.truncate(h.MAX_FILE + 1)
        with self.assertRaisesRegex(ValueError, 'oversized'):
            h.inventory(self.root)

    def test_canonical_flags_include_profiles(self):
        for key in ['setuid', 'keep_descendants']:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, key):
                p.flags('version: 0\n' + key + ': true\n')
        with self.assertRaisesRegex(ValueError, 'off'):
            p.flags('version: 0\nrecord: "off"\n')

    def test_canonical_augment_has_no_duplicate_keys(self):
        import yaml
        for text in ['version: 0\nname: x\n', 'version: 0\nfs:\n  write:\n    - ./out/\n',
                     'version: 0\nfs:\n  deny_read: []\n  deny_write:\n    - ./.github/\nenv:\n  pass: []\n']:
            result = p.augment(text, ['/runner/temp', '/runner/tools'])
            d = yaml.safe_load(result)
            self.assertEqual(result.count('  deny_read:'), 1)
            self.assertEqual(result.count('  deny_write:'), 1)
            self.assertIn('/runner/temp', d['fs']['deny_read'])
            self.assertIn('/runner/tools', d['fs']['deny_write'])

    def test_tools_write_protection_keeps_tool_reads(self):
        import yaml
        d = yaml.safe_load(p.augment('version: 0\n', ['/runner/tools', '/runner/temp'], ['/runner/temp']))
        self.assertIn('/runner/tools', d['fs']['deny_write'])
        self.assertNotIn('/runner/tools', d['fs']['deny_read'])
        self.assertIn('/runner/temp', d['fs']['deny_read'])

    def test_child_regrant_and_parent_refused(self):
        for write, protected in [('/runner', '/runner/tools'), ('/runner/tools/sub', '/runner/tools')]:
            with self.assertRaises(ValueError):
                p.check_writes({'fs': [{'kind': 'write', 'path': write}]}, [protected])
        p.check_writes({'fs': [{'kind': 'write', 'path': '/runner/toolbox'}]}, ['/runner/tools'])

    def test_hardlink_refused(self):
        protected = self.d / 'tool'
        protected.write_text('x')
        alias = self.d / 'alias'
        os.link(protected, alias)
        with self.assertRaises(ValueError):
            p.check_writes({'fs': [{'kind': 'write', 'path': str(alias)}]}, [protected])

    def test_denied_env_names_cannot_be_passed(self):
        for name in ['GH_TOKEN', 'SIGSTORE_ID_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'INPUT_TOKEN',
                     'BASH_ENV', 'LD_PRELOAD', 'PYTHONPATH', 'TEGO_CONFIG']:
            self.assertTrue(p.forbidden(name), name)
            proc = subprocess.run([sys.executable, '-I', str(A / 'scripts/launch.py'), '--direct-test'],
                                  env=dict(os.environ, IN_ENV_PASS=name), text=True, capture_output=True)
            self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertFalse(p.forbidden('MODEL_KEY'))

    def test_privileged_trigger_refused_before_launch(self):
        proc = subprocess.run([sys.executable, '-I', str(A / 'scripts/eligibility.py')],
                              env=dict(os.environ, GITHUB_EVENT_NAME='pull_request_target'), capture_output=True)
        self.assertEqual(proc.returncode, 125)

    def test_ended_false_with_match_is_refused(self):
        check = json.loads((A / 'testdata/check.json').read_text())
        self.assertEqual(check['result'], 'match')
        check['ended'] = False
        path = self.d / 'check.json'
        path.write_text(json.dumps(check))
        proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_match_unended_and_missing_facts_refused(self):
        check = json.loads((A / 'testdata/check.json').read_text())
        for update in [{'result': 'match-unended'}, {'checks': []},
                       {'checks': [{'name': 'facts', 'result': 'pass'}]}]:
            data = dict(check, **update)
            path = self.d / 'check.json'
            path.write_text(json.dumps(data))
            proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)

    def test_every_additional_product_check_must_explicitly_pass(self):
        for version in ['v1', 'v2']:
            check = json.loads((A / 'testdata/bindings' / version / 'check.json').read_text())
            for result in ['pass', 'fail', 'not-checked', 'unknown', None]:
                with self.subTest(version=version, result=result):
                    extra = {'name': 'future-check', 'result': result}
                    data = dict(check, checks=check['checks']+[extra])
                    path = self.d / 'check.json'
                    path.write_text(json.dumps(data))
                    proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
                    self.assertEqual(proc.returncode == 0, result == 'pass', proc.stderr)

    def test_binding_v2_requires_binding_check(self):
        check = json.loads((A / 'testdata/bindings/v2/check.json').read_text())
        check['checks'] = [c for c in check['checks'] if c['name'] != 'binding']
        path = self.d / 'check.json'
        path.write_text(json.dumps(check))
        proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_binding_v3_requires_binding_check(self):
        check = json.loads((A / 'testdata/bindings/v2/check.json').read_text())
        check['binding_v'] = 3
        path = self.d / 'check.json'
        path.write_text(json.dumps(check))
        proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        check['checks'] = [c for c in check['checks'] if c['name'] != 'binding']
        path.write_text(json.dumps(check))
        proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_unknown_binding_versions_refused(self):
        check = json.loads((A / 'testdata/bindings/v2/check.json').read_text())
        for version in [0, 4, -1, 1.0, 2.0, 2.5, 3.0, None, True, '2']:
            with self.subTest(version=version):
                path = self.d / 'check.json'
                path.write_text(json.dumps(dict(check, binding_v=version)))
                proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
                self.assertNotEqual(proc.returncode, 0)
        del check['binding_v']
        path.write_text(json.dumps(check))
        proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_duplicate_check_file_keys_refused_at_every_level(self):
        check = (A / 'testdata/bindings/v2/check.json').read_text()
        for duplicate in [
                '"result":"mismatch","result":"match"',
                '"result":"match","result":"match"',
                r'"res\u0075lt":"mismatch","result":"match"',
                '"extra":[{"x":1,"x":2}],"result":"match"',
                '"extra":{"a":{"x":1,"x":2}},"result":"match"',
                '"extra":{"a":{"x":1},"a":{"y":2}},"result":"match"',
                '"extra":{"a":{},"a":[]},"result":"match"']:
            with self.subTest(duplicate=duplicate):
                path = self.d / 'check.json'
                path.write_text(check.replace('"result": "match"', duplicate, 1))
                proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
                self.assertNotEqual(proc.returncode, 0)
        path.write_text(check.replace('"result": "pass"', '"result":"fail","result":"pass"', 1))
        proc = subprocess.run([str(A / 'scripts/full-match.sh'), str(path)], capture_output=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_agent_failure_precedes_refusal_and_evidence_precedes_agent(self):
        for agent, evidence, expected in [('3', '0', 3), ('3', '125', 125), ('0', '0', 1)]:
            e = dict(os.environ, RUN_ID='r-1', AGENT_EXIT=agent, EVIDENCE_EXIT=evidence,
                     REFUSALS='2', VERIFIED='true', IN_ON_REFUSAL='fail')
            proc = subprocess.run([str(A / 'scripts/gate.sh')], env=e, capture_output=True)
            self.assertEqual(proc.returncode, expected, proc.stderr)
            if evidence != '0':
                self.assertIn(b'agent exit: 3', proc.stderr)

    def test_replaced_binary_refused(self):
        (self.d / 'state').mkdir()
        (self.d / 'state/binary-sha256').write_text('a' * 64)
        binary = self.d / 'tego'
        binary.write_text('changed')
        proc = subprocess.run(['bash', '-c', '. "$1"; verify_binary', '_', str(A / 'scripts/lib.sh')],
                              env=dict(os.environ, DIR=str(self.d), TEGO=str(binary)), capture_output=True)
        self.assertEqual(proc.returncode, 125)

    def test_installer_refuses_wrong_checksum(self):
        tools = self.d / 'tools'
        tools.mkdir()
        curl = tools / 'curl'
        curl.write_text('#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\nPath(sys.argv[sys.argv.index("-o")+1]).write_bytes(b"wrong executable")\n')
        curl.chmod(0o755)
        env = dict(os.environ, DIR=str(self.d), IN_VERSION='v9.8.7', IN_SHA256='a'*64,
                   GITHUB_EVENT_NAME='push', IN_RELEASE_COMMIT='a'*40, TEGO_CODE_SHA='a'*40)
        action = self.instrument_action({'curl': curl})
        # Reach checksum parsing; bootstrap and signature verification are
        # exercised independently by trust-tests.py.
        with (action / 'scripts/trust.sh').open('a') as fixture:
            fixture.write('\nsetup_trust() { TRUSTED_ROOT=/unused; mkdir -p "$DIR/download" "$DIR/bin" "$DIR/state"; }\ncosign_clean() { return 0; }\n')
        proc = subprocess.run([str(action / 'scripts/install.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 125)
        self.assertFalse((self.d / 'bin/tego').exists())

    def test_prepare_doctor_refusal_does_not_launch(self):
        tools = self.d / 'tools'
        tools.mkdir()
        sudo = tools / 'sudo'
        sudo.write_text('#!/bin/bash\nwhile [[ "$1" == -* ]]; do shift; done\nexec "$@"\n')
        sudo.chmod(0o755)
        fake = tools / 'tego'
        fake.write_text("""#!/bin/bash
if [ "$*" = "doctor --json" ]; then echo '{"tiers":{"cgroup":false}}'; else exit 211; fi
""")
        fake.chmod(0o755)
        (self.d / 'state').mkdir()
        (self.d / 'state/binary-sha256').write_text(h.sha(fake.read_bytes()))
        env = dict(os.environ, DIR=str(self.d), TEGO=str(fake), IN_USE_SUDO='true',
                   GITHUB_WORKSPACE=str(self.d), RUNNER_TEMP=str(self.d),
                   GITHUB_EVENT_NAME='push')
        action = self.instrument_action({'sudo': sudo})
        proc = subprocess.run([str(action / 'scripts/prepare.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 211, proc.stderr)
        self.assertTrue((self.root / 'doctor.json').is_file())
        self.assertFalse((self.d / 'agent.yaml').exists())

    def verifier_fixture(self):
        for name in ['receipt.json', 'verify.json', 'run_start.json', 'compile.json', 'contract.yaml']:
            shutil.copy(A / 'testdata' / name, self.root / name)
        receipt = json.loads((self.root / 'receipt.json').read_text())
        receipt.update(exit_code=3, ended=True)
        (self.root / 'receipt.json').write_text(json.dumps(receipt))
        (self.root / 'run').mkdir()
        shutil.copy(A / 'testdata/events.jsonl', self.root / 'run/events.jsonl')
        start = json.loads((self.root / 'run_start.json').read_text())
        meta = {'run': start['run'], 'contract_hash': start['contract_hash'], 'agent_exit_code': 3,
                'receipt_sha256': h.sha((self.root / 'receipt.json').read_bytes()),
                'events_sha256': h.sha((self.root / 'run/events.jsonl').read_bytes()),
                'contract_file_sha256': h.sha((self.root / 'contract.yaml').read_bytes())}
        (self.root / 'tego-ci.json').write_text(json.dumps(meta))
        (self.root / 'eligibility.json').write_text('{"reason":"disabled: offline fixture"}')
        inv = h.sha(h.inventory(self.root))
        archive = self.d / 'complete.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for path in self.root.rglob('*'):
                if path.is_file(): z.write(path, path.relative_to(self.root).as_posix())
        tools = self.d / 'tools'
        tools.mkdir()
        gh = tools / 'gh'
        gh.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
archive = Path(os.environ['LOCAL_ARCHIVE'])
if sys.argv[-1].endswith('/zip'): sys.stdout.buffer.write(archive.read_bytes())
else: print(json.dumps({'id':7,'workflow_run':{'id':42,'run_attempt':1},'name':'tego-receipt-42-1-' + 'b'*64,'expired':False,'size_in_bytes':archive.stat().st_size}))
""")
        curl = tools / 'curl'
        curl.write_text("""#!/usr/bin/env python3
import os, shutil, sys
shutil.copyfile(os.environ['LOCAL_BINARY'],sys.argv[sys.argv.index('-o')+1])
""")
        for path in [gh, curl]: path.chmod(0o755)
        self.instrument_action({'gh': gh, 'curl': curl})
        # Authentication has a separate offline suite; preserve this test's
        # transport/check boundary with an explicit installer stand-in.
        (self.action / 'scripts/install.sh').write_text('#!/bin/bash -p\nset -euo pipefail\nmkdir -p "$DIR/bin" "$DIR/state"\ncp "$LOCAL_BINARY" "$DIR/bin/tego"\nchmod 755 "$DIR/bin/tego"\nprintf \'%s\\n\' "$IN_SHA256" >"$DIR/state/binary-sha256"\n')
        runtime = self.d / 'runtime'
        runtime.mkdir()
        return dict(os.environ, LOCAL_ARCHIVE=str(archive), LOCAL_BINARY=str(A / 'test/fake-tego'),
                    IN_SHA256=h.sha((A / 'test/fake-tego').read_bytes()),
                    IN_VERSION='v9.8.7', ARTIFACT_ID='7', ARTIFACT_DIGEST=h.sha(archive.read_bytes()),
                    INVENTORY_SHA256=inv, GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1',
                    ARTIFACT_ATTEMPT='1', ARTIFACT_NAME='tego-receipt-42-1-' + 'b'*64,
                    MATRIX_SHA256='b'*64, GITHUB_REPOSITORY='example/app', GITHUB_EVENT_NAME='push',
                    RUNNER_TEMP=str(runtime), RUN_ID=start['run'], AGENT_EXIT='3', PREPARE_EXIT='0',
                    EVIDENCE_EXIT='0', VERIFIED='true', REFUSALS='1', IN_ON_REFUSAL='warn', IN_SIGN='auto',
                    FAKE_TEGO_DATA=str(A / 'testdata'), DO_COMMENT='false', GITHUB_STEP_SUMMARY=str(self.d / 'summary.md'))

    def test_fresh_verifier_preserves_agent_3_after_report(self):
        env = self.verifier_fixture()
        proc = subprocess.run([str(self.action / 'scripts/verify.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertIn('not signed', (self.d / 'summary.md').read_text())
        self.assertTrue((Path(env['RUNNER_TEMP']) / 'tego-verifier/signer-check.json').is_file())

    def test_unsigned_verifier_never_signs_and_preserves_checked_agent_exit(self):
        env = dict(self.verifier_fixture(), AGENT_EXIT='0', IN_SIGN='true')
        proc = subprocess.run([str(self.action / 'scripts/verify.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertFalse(list(Path(env['RUNNER_TEMP']).rglob('*.sigstore.json')))
        self.assertIn('not signed', (self.d / 'summary.md').read_text())

    def test_fresh_verifier_bad_digest_leaves_agent_exit_unknown(self):
        env = dict(self.verifier_fixture(), ARTIFACT_DIGEST='a' * 64)
        proc = subprocess.run([str(self.action / 'scripts/verify.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn(b'agent exit: unknown', proc.stderr)

    def test_display_sidecars_cannot_substitute_another_run(self):
        self.verifier_fixture()
        h.check_display(self.root)
        start = json.loads((self.root / 'run_start.json').read_text())
        start['contract_hash'] = 'a' * 64
        (self.root / 'run_start.json').write_text(json.dumps(start))
        with self.assertRaisesRegex(ValueError, 'run_start'):
            h.check_display(self.root)

    def test_full_workflow_lints(self):
        sc = os.environ['SHELLCHECK']
        al = os.environ['ACTIONLINT']
        lab = self.d / 'lab'
        (lab / '.github/workflows').mkdir(parents=True)
        (lab / '.git').mkdir()
        for fixture in (A / 'testdata/c0').glob('*.yml'):
            shutil.copy(fixture, lab / '.github/workflows' / fixture.name)
        # actionlint resolves local reusable workflows in the first file's
        # project. The lab is a separate project, regardless of our .git layout.
        for cwd, paths in [(A.parent, [A.parent / '.github/workflows/ci-receipt.yml', A.parent / '.github/workflows/ci-receipt-sign.yml']),
                           (lab, sorted((lab / '.github/workflows').glob('*.yml')))]:
            with self.subTest(project=cwd):
                proc = subprocess.run([al, '-shellcheck', sc, *map(str, paths)], cwd=cwd,
                                      capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
