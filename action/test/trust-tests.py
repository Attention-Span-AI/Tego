#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Offline tool/transport fixtures. They assert shell boundaries, not Sigstore trust."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get('WORK') or os.environ['TMPDIR']) / 'trust-tests'
SCRATCH.mkdir(parents=True, exist_ok=True)
SPEC = importlib.util.spec_from_file_location('checksums', ROOT / 'scripts/release-checksums.py')
checksums = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checksums)
SHA = 'a' * 40
BINARY = b'fixture executable never run'
DIGEST = hashlib.sha256(BINARY).hexdigest()


class ReleaseTrust(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.base = Path(self.tmp.name)
        self.action = self.base / 'action'
        shutil.copytree(ROOT / 'scripts', self.action / 'scripts')
        shutil.copytree(ROOT / 'trust', self.action / 'trust')
        self.run = self.base / 'run'
        self.run.mkdir()
        self.env = dict(os.environ, DIR=str(self.run), IN_VERSION='v0.2.0',
                        IN_SHA256=DIGEST, IN_RELEASE_COMMIT=SHA, TEGO_CODE_SHA=SHA,
                        SIGSTORE_ID_TOKEN='inherited-secret', HTTPS_PROXY='bad-proxy',
                        XDG_CONFIG_HOME='untrusted-xdg', ACTIONS_ID_TOKEN_REQUEST_TOKEN='unwanted')
        self.env.pop('GITHUB_OUTPUT', None)
        self.tool = self.base / 'fixture-cosign'
        self.tool.write_text('''#!/usr/bin/python3
import json, os, pathlib, shutil, sys
home = pathlib.Path(os.environ['HOME'])
with (home.parent / 'calls.jsonl').open('a') as log:
    log.write(json.dumps({'args':sys.argv[1:], 'env':dict(os.environ)})+'\\n')
if sys.argv[1] == 'initialize':
    cache = pathlib.Path(os.environ['TUF_ROOT'])
    source = pathlib.Path(SOURCE)
    (cache / 'remote.json').write_text(json.dumps({'mirror':'https://tuf-repo-cdn.sigstore.dev'}, separators=(',', ':')))
    target = cache / 'tuf-repo-cdn.sigstore.dev'
    (target / 'targets').mkdir(parents=True)
    shutil.copyfile(source / 'root.json', target / 'root.json')
    for file in ['trusted_root.json','signing_config.v0.2.json']:
        shutil.copyfile(source / file, target / 'targets' / file)
if sys.argv[1] == 'verify-blob' and pathlib.Path(MODE).exists():
    sys.exit(17)
'''.replace('SOURCE', repr(str(self.action / 'trust'))).replace('MODE', repr(str(self.base / 'reject'))))
        self.tool.chmod(0o755)
        fake_digest = hashlib.sha256(self.tool.read_bytes()).hexdigest()
        trust = self.action / 'scripts/trust.sh'
        text = trust.read_text()
        for pinned in ['4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71',
                       'c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a']:
            text = text.replace(pinned, fake_digest)
        trust.write_text(text)
        self.curl = self.base / 'fixture-curl'
        self.curl.write_text('''#!/usr/bin/python3
import pathlib, shutil, sys
args=sys.argv[1:]
out=pathlib.Path(args[args.index('-o')+1])
name=args[-1].rsplit('/',1)[-1]
if name.startswith('cosign-linux-'):
    shutil.copyfile(TOOL,out)
elif name.endswith('_checksums.txt'):
    out.write_text(DIGEST+'  tego_0.2.0_linux_amd64\\n'+DIGEST+'  tego_0.2.0_linux_arm64\\n')
elif name.endswith('.sigstore.json'):
    out.write_text('{}')
else:
    out.write_bytes(BINARY)
'''.replace('TOOL', repr(str(self.tool))).replace('DIGEST', repr(DIGEST)).replace('BINARY', repr(BINARY)))
        self.curl.chmod(0o755)
        for file in ['install.sh', 'trust.sh']:
            p = self.action / 'scripts' / file
            p.write_text(p.read_text().replace('/usr/bin/curl', str(self.curl)))

    def tearDown(self):
        self.tmp.cleanup()

    def install(self):
        return subprocess.run(['/bin/bash', '-p', str(self.action / 'scripts/install.sh')],
                              env=self.env, capture_output=True, text=True)

    def shell(self, command):
        return subprocess.run(['/bin/bash', '-pc',
                               '. "$1/trust.sh"; trust_load; ' + command, '_',
                               str(self.action / 'scripts')], env=self.env,
                              capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in (self.run / 'sigstore/calls.jsonl').read_text().splitlines()]

    def test_amd64_install_exact_authentication_and_scrubbed_environment(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.run / 'bin/tego').read_bytes(), BINARY)
        verify = self.calls()[1]
        args = verify['args']
        for flag, expected in {
            '--certificate-identity': 'https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/v0.2.0',
            '--certificate-oidc-issuer': 'https://token.actions.githubusercontent.com',
            '--certificate-github-workflow-repository': 'Attention-Span-AI/Tego',
            '--certificate-github-workflow-ref': 'refs/tags/v0.2.0',
            '--certificate-github-workflow-trigger': 'push',
            '--certificate-github-workflow-sha': SHA,
        }.items():
            self.assertEqual(args[args.index(flag)+1], expected)
        for call in self.calls():
            self.assertEqual(set(call['env']) - {'LC_CTYPE'}, {'PATH', 'HOME', 'TUF_ROOT'})
            self.assertEqual(call['env']['HOME'], str(self.run / 'sigstore/home'))
        self.assertEqual((self.run / 'state/binary-asset').read_text(), 'tego_0.2.0_linux_amd64\n')

    def test_arm64_install(self):
        for file in ['install.sh', 'trust.sh']:
            p = self.action / 'scripts' / file
            p.write_text(p.read_text().replace('/usr/bin/uname -m', 'printf aarch64'))
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.run / 'state/binary-asset').read_text(), 'tego_0.2.0_linux_arm64\n')

    def test_missing_release_commit_refused_before_fetch(self):
        del self.env['IN_RELEASE_COMMIT']
        self.assertNotEqual(self.install().returncode, 0)
        self.assertFalse((self.run / 'sigstore').exists())

    def test_unreleased_implementation_refused_before_fetch(self):
        self.env['TEGO_CODE_SHA'] = 'b' * 40
        self.assertEqual(self.install().returncode, 125)
        self.assertFalse((self.run / 'sigstore').exists())

    def test_failed_signature_never_installs_tego(self):
        (self.base / 'reject').touch()
        self.assertEqual(self.install().returncode, 125)
        self.assertFalse((self.run / 'bin/tego').exists())

    def test_signed_checksum_must_match_independent_pin(self):
        self.env['IN_SHA256'] = 'b' * 64
        self.assertEqual(self.install().returncode, 125)
        self.assertFalse((self.run / 'bin/tego').exists())

    def test_explicit_token_only_and_no_token_in_cosign_argv(self):
        self.assertEqual(self.install().returncode, 0)
        result = self.shell('cosign_clean --identity-token explicit-token sign-blob --yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.calls()[-1]
        self.assertEqual(call['env']['SIGSTORE_ID_TOKEN'], 'explicit-token')
        self.assertNotIn('explicit-token', call['args'])
        self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN', call['env'])

    def test_each_mutated_trust_file_fails_before_cosign(self):
        self.assertEqual(self.install().returncode, 0)
        count = len(self.calls())
        paths = ['bin/cosign', 'sigstore/root.json', 'sigstore/trusted_root.json',
                 'sigstore/signing_config.v0.2.json',
                 'sigstore/tuf/tuf-repo-cdn.sigstore.dev/root.json',
                 'sigstore/tuf/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json',
                 'sigstore/tuf/tuf-repo-cdn.sigstore.dev/targets/signing_config.v0.2.json',
                 'sigstore/tuf/remote.json']
        for path in paths:
            with self.subTest(path=path):
                file = self.run / path
                original = file.read_bytes()
                file.write_bytes(b'{}')
                self.assertNotEqual(self.shell('cosign_clean verify-blob blob').returncode, 0)
                self.assertEqual(len(self.calls()), count)
                file.write_bytes(original)

    def test_stale_sigstore_directory_refused(self):
        (self.run / 'sigstore').mkdir()
        self.assertEqual(self.install().returncode, 125)

    def test_ordinary_contract_corpus_release_admission(self):
        # Release admission must be independent of contract path/layout. This
        # does not claim these contracts compile or execute on a hosted runner.
        groups = [('examples', ROOT.parent / 'examples'),
                  ('presets', ROOT.parent / 'pkg/spec/presets'),
                  ('conformance', ROOT.parent / 'spec/policy/conformance')]
        for group, corpus in groups:
            paths = sorted(p for p in corpus.rglob('*') if p.suffix in {'.yaml', '.yml'})
            self.assertTrue(paths, group)
            for index, contract in enumerate(paths):
                with self.subTest(group=group, contract=str(contract)):
                    self.run = self.base / (group + str(index))
                    self.run.mkdir()
                    self.env.update(DIR=str(self.run), IN_CONTRACT=str(contract))
                    result = self.install()
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((self.run / 'bin/tego').read_bytes(), BINARY)

    def test_checksum_ordinary_assets_and_refusal_matrix(self):
        ordinary = (DIGEST + '  tego_0.2.0_linux_amd64\n' + DIGEST + '  install.sh\n').encode()
        checksums.validate(ordinary, 'tego_0.2.0_linux_amd64', BINARY, DIGEST)
        negatives = {
            'duplicate': ordinary + ordinary.splitlines(keepends=True)[0],
            'traversal': (DIGEST + '  ../tego\n').encode(),
            'absolute': (DIGEST + '  /tego\n').encode(),
            'extra-column': (DIGEST + '  tego_0.2.0_linux_amd64 extra\n').encode(),
            'wrong-hash': ordinary.replace(DIGEST.encode(), b'b' * 64),
            'missing-name': (DIGEST + '  install.sh\n').encode(),
            'size-limit': b'x' * (1024 * 1024 + 1),
        }
        for name, data in negatives.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                checksums.validate(data, 'tego_0.2.0_linux_amd64', BINARY, DIGEST)


if __name__ == '__main__':
    unittest.main(verbosity=2)
