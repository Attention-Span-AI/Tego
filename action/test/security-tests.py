#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Post-run execution and evidence-boundary regressions, without a real agent."""
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

A = Path(os.environ.get('SECURITY_ACTION', Path(__file__).resolve().parents[1]))
WORK = Path(os.environ['WORK'])


def policy():
    spec = importlib.util.spec_from_file_location('policy', A / 'scripts/policy.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Security(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)

    def caller_workspace(self):
        # agent.sh records the caller's HEAD. Never borrow the source checkout:
        # release exports have no repository and callers can use any .git layout.
        workspace = self.d / 'caller'
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
        subprocess.run(['/usr/bin/git', '-c', 'init.templateDir=', 'init', '-q', str(workspace)],
                       env=env, check=True, capture_output=True)
        subprocess.run(['/usr/bin/git', '-C', str(workspace), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.invalid', '-c', 'core.hooksPath=/dev/null',
                        'commit', '--quiet', '--allow-empty', '--no-gpg-sign', '-m', 'fixture'],
                       env=env, check=True, capture_output=True)
        return workspace

    def test_job_path_and_startup_grants_refused(self):
        p = policy()
        home = self.d / 'home'
        path = str(home / '.local/bin') + ':relative/bin::' + str(home / '.cargo/bin')
        paths = p.environment_paths(path, str(home), str(self.d))
        for folder in [home / '.local/bin', home / '.cargo/bin', self.d / 'relative/bin',
                       self.d, home / '.bashrc', home / '.profile', home / '.jq', Path('/usr/bin')]:
            self.assertIn(str(folder), paths)
            grant = str(folder.parent if folder.name.startswith('.') else folder)
            with self.assertRaisesRegex(ValueError, 'write entry.*protected path'):
                p.check_writes({'fs': [{'kind': 'write', 'path': grant}]}, paths)

    def prepare_with_grant(self, grant, **extra_env):
        action = self.d / 'code/action'
        shutil.copytree(A, action)
        caller, runtime, home = self.d / 'caller', self.d / 'runner/_temp', self.d / 'home'
        toolcache, runner, job = self.d / 'toolcache', self.d / 'runnerbin', runtime / 'job'
        for path in [caller, home / '.tego', runtime.parent / '_actions', toolcache, runner, job / 'state', job / 'evidence']:
            path.mkdir(parents=True, exist_ok=True)
        folder = home / '.local/bin'
        folder.mkdir(parents=True)
        (caller / 'agent.yaml').write_text('version: 0\n')
        (job / 'bin').mkdir()
        binary = job / 'bin/tego-stub'
        table = {'fs': [{'kind': 'write', 'path': str(grant)}], 'env_deny': sorted(policy().DENIED),
                 'machine': [{'key': 'ledger_root', 'value': str(job / 'ledger')}]}
        binary.write_text('''#!/usr/bin/python3
import json,sys
if sys.argv[1:]==['doctor','--json']: print('{'+'"tiers":{"cgroup":true}'+'}')
elif sys.argv[1:3]==['doctor','--require']: pass
elif sys.argv[1:3]==['compile','--merged']: print('version: 0')
elif sys.argv[1:3]==['compile','--json']: print(''' + repr(json.dumps(table)) + ''')
elif sys.argv[1]=='compile': print('compiled')
else: sys.exit(99)
''')
        binary.chmod(0o700)
        (job / 'state/binary-sha256').write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
        sudo = self.d / 'sudo-stub'
        sudo.write_text('#!/bin/bash -p\nwhile [[ "$1" == -* ]]; do shift; done\nexec "$@"\n')
        sudo.chmod(0o700)
        script = action / 'scripts/prepare.sh'
        text = script.read_text().replace('/usr/bin/sudo', str(sudo))
        import re
        text = re.sub(r'(?<![\w/])sudo(?= )', str(sudo), text)
        script.write_text(text)
        env = dict(os.environ, DIR=str(job), TEGO=str(binary),
                              IN_USE_SUDO='true', IN_CONTRACT='agent.yaml', HOME=str(home), AGENT_HOME=str(home),
                              JOB_PATH=str(folder)+':/usr/bin:/bin', GITHUB_WORKSPACE=str(caller),
                              GITHUB_ACTION_PATH=str(action), COLLECTOR_SOURCE=str(action), RUNNER_TEMP=str(runtime),
                              RUNNER_ROOT=str(runner), RUNNER_TOOL_CACHE=str(toolcache))
        env.update(extra_env)
        return subprocess.run([str(script)], env=env, capture_output=True, text=True)

    def test_prepare_refuses_original_path_grant_with_named_folder(self):
        grant = self.d / 'home/.local'
        folder = grant / 'bin'
        proc = self.prepare_with_grant(grant)
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn(str(grant), proc.stderr)
        self.assertIn(str(folder), proc.stderr)
        self.assertIn('write entry', proc.stderr)

    def test_prepare_refuses_home_gitconfig_grant(self):
        grant = self.d / 'home/.gitconfig'
        proc = self.prepare_with_grant(grant)
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn(str(grant), proc.stderr)

    def test_prepare_refuses_default_xdg_git_configuration_grant(self):
        grant = self.d / 'home/.config/git/config'
        proc = self.prepare_with_grant(grant, XDG_CONFIG_HOME='')
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn(str(grant), proc.stderr)

    def test_prepare_refuses_explicit_xdg_git_configuration_grant(self):
        grant = self.d / 'xdg/git/config'
        proc = self.prepare_with_grant(grant, XDG_CONFIG_HOME=str(self.d / 'xdg'))
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn(str(grant), proc.stderr)

    def test_prepare_refuses_system_git_configuration_grant(self):
        proc = self.prepare_with_grant(Path('/etc/gitconfig'))
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn('/etc/gitconfig', proc.stderr)

    def test_prepare_refuses_git_configuration_overrides(self):
        grant = self.d / 'custom-gitconfig'
        proc = self.prepare_with_grant(grant, GIT_CONFIG_SYSTEM=str(grant), GIT_CONFIG_GLOBAL=str(grant))
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn(str(grant), proc.stderr)

    def test_passwd_home_git_configuration_protected(self):
        import pwd
        proc = subprocess.run(['/usr/bin/python3', '-I', str(A / 'scripts/policy.py'), 'environment-paths'],
                              env=dict(os.environ, JOB_PATH='/usr/bin:/bin', AGENT_HOME=str(self.d / 'home'),
                                       GITHUB_WORKSPACE=str(self.d)), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(str(Path(pwd.getpwuid(os.getuid()).pw_dir) / '.gitconfig'), proc.stdout.splitlines())

    def test_worktree_git_configuration_and_includes_protected(self):
        caller = self.caller_workspace()
        env = dict(os.environ, HOME=str(self.d / 'home'), AGENT_HOME=str(self.d / 'home'),
                   GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
        subprocess.run(['/usr/bin/git', '-C', str(caller), 'config', 'extensions.worktreeConfig', 'true'],
                       env=env, check=True)
        linked = self.d / 'linked'
        subprocess.run(['/usr/bin/git', '-C', str(caller), '-c', 'core.hooksPath=/dev/null',
                        'worktree', 'add', '-q', '-b', 'linked', str(linked)], env=env, check=True)
        include = self.d / 'included-gitconfig'
        empty = self.d / 'empty-gitconfig'
        empty.touch()
        missing = self.d / 'missing-gitconfig'
        include.write_text('[fixture]\n  value = harmless\n[include]\n  path = empty-gitconfig\n  path = missing-gitconfig\n')
        subprocess.run(['/usr/bin/git', '-C', str(linked), 'config', '--worktree', 'include.path', str(include)],
                       env=env, check=True)
        proc = subprocess.run(['/usr/bin/python3', '-I', str(A / 'scripts/policy.py'), 'git-paths', str(linked)],
                              env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        paths = proc.stdout.splitlines()
        config = caller / '.git/worktrees/linked/config.worktree'
        for protected in [caller / '.git/config', config, include, empty, missing]:
            self.assertIn(str(protected), paths)
            with self.assertRaisesRegex(ValueError, 'write entry.*protected path'):
                policy().check_writes({'fs': [{'kind': 'write', 'path': str(protected)}]}, paths)

    def test_prepare_persists_complete_refusal_list(self):
        proc = self.prepare_with_grant(self.d / 'caller/out')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        paths = json.loads((self.d / 'runner/_temp/job/state/protected-paths.json').read_text())
        for path in [self.d / 'runner/_temp', self.d / 'caller/.github', self.d / 'caller/.git',
                     self.d / 'home/.local/bin', self.d / 'home/.gitconfig', Path('/etc/gitconfig')]:
            self.assertIn(str(path), paths)

    def test_compile_path_shadow_is_error_in_ci(self):
        proc = subprocess.run(['/usr/bin/python3', '-I', str(A / 'scripts/policy.py'), 'diagnostics', '-'],
                              input='warning [path-shadow]: fs.write "./tool/" shadows /runner/tool/bin\n',
                              text=True, capture_output=True)
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertIn('path-shadow', proc.stderr)

    def test_collector_snapshot_and_original_digest_checked(self):
        src = self.d / 'action'
        shutil.copytree(A, src)
        dest = self.d / 'collector'
        manifest = self.d / 'digests'
        proc = subprocess.run(['/usr/bin/python3', '-I', str(A / 'scripts/seal.py'),
                               str(src), str(dest), str(manifest)], capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
        for target in [src / 'scripts/collect.sh', dest / 'scripts/render.sh']:
            data = target.read_bytes()
            target.write_bytes(data + b'\n# changed\n')
            proc = subprocess.run(['/usr/bin/sha256sum', '--check', '--strict', '--status', str(manifest)])
            self.assertNotEqual(proc.returncode, 0)
            target.write_bytes(data)
        self.assertEqual(subprocess.run(['/usr/bin/sha256sum', '--check', '--strict', '--status', str(manifest)]).returncode, 0)
        agent = (A / 'scripts/agent.sh').read_text()
        self.assertLess(agent.index('seal.py'), agent.index('"$here/run.sh"'))
        after = agent[agent.index('"$here/run.sh"'):]
        self.assertLess(after.index('--check --strict --status'), after.index('"$here/collect.sh"'))

    def fixture(self):
        (self.d / 'evidence').mkdir()
        (self.d / 'state').mkdir()
        for name in ['receipt.json', 'verify.json', 'run_start.json', 'compile.json']:
            shutil.copy(A / 'testdata' / name, self.d / 'evidence' / name)
        (self.d / 'evidence/tego-ci.json').write_text('{"receipt_sha256":"' + 'a'*64 + '"}')
        poison = self.d / 'poison'
        poison.mkdir()
        canary = self.d / 'canary'
        for name in ['bash', 'jq', 'python3', 'dirname']:
            script = poison / name
            script.write_text('#!/bin/sh\necho poisoned >>"$CANARY"\nexit 98\n')
            script.chmod(0o755)
        hook = self.d / 'startup'
        hook.write_text('echo startup >>"$CANARY"\n')
        return dict(os.environ, DIR=str(self.d), PATH=str(poison)+':/usr/bin:/bin',
                    BASH_ENV=str(hook), ENV=str(hook), PROMPT_COMMAND='touch '+str(canary),
                    CANARY=str(canary), **{'BASH_FUNC_jq%%': '() { echo function >>"$CANARY"; }'})

    def test_postrun_scripts_ignore_path_startup_and_functions(self):
        env = self.fixture()
        proc = subprocess.run([str(A / 'scripts/render.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((self.d / 'canary').exists())

    def test_exported_functions_are_removed_from_child_environment(self):
        script = self.d / 'capture.sh'
        script.write_text('''#!/bin/bash -p
/usr/bin/python3 -I -c 'import os; assert not any(k.startswith("BASH_FUNC_") for k in os.environ)'
''')
        proc = subprocess.run(['/usr/bin/python3', '-I', str(A / 'scripts/environment.py'), str(script)],
                              env=dict(os.environ, **{'BASH_FUNC_canary%%': '() { :; }'}), capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_failed_collection_tool_cannot_hide_in_process_substitution(self):
        (self.d / 'state').mkdir()
        (self.d / 'evidence').mkdir()
        (self.d / 'state/runs-before.txt').write_text('')
        binary = A / 'test/fake-tego'
        (self.d / 'state/binary-sha256').write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
        proc = subprocess.run([str(A / 'scripts/collect.sh')],
                              env=dict(os.environ, DIR=str(self.d), TEGO=str(binary),
                                       LEDGER_ROOT=str(self.d / 'missing-ledger')), capture_output=True)
        self.assertNotEqual(proc.returncode, 0)
        text = (A / 'scripts/collect.sh').read_text()
        self.assertNotIn('mapfile -t new < <(', text)

    def test_original_mutation_stops_before_collector(self):
        action = self.d / 'action'
        shutil.copytree(A, action)
        scripts = action / 'scripts'
        for name in ['check.sh', 'install.sh', 'prepare.sh', 'render.sh', 'post.sh']:
            (scripts / name).write_text('#!/bin/bash -p\nexit 0\n')
        (scripts / 'run.sh').write_text('''#!/bin/bash -p
printf '0\\n' >"$DIR/state/agent-exit"
printf '#!/bin/bash -p\\nprintf attacked >"$CANARY"\\n' >"$SOURCE/scripts/collect.sh"
''')
        env = dict(os.environ, HOME=str(self.d / 'original-home'), RUNNER_TEMP=str(self.d / 'runtime'),
                   GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1', GITHUB_WORKSPACE=str(self.caller_workspace()),
                   SOURCE=str(action), CANARY=str(self.d / 'canary'))
        proc = subprocess.run([str(scripts / 'agent.sh')], env=env, capture_output=True)
        self.assertTrue(list((self.d / 'runtime').rglob('agent-exit')), proc.stderr)
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertFalse((self.d / 'canary').exists())

    def test_collector_receives_private_ledger_configuration(self):
        action = self.d / 'action'
        shutil.copytree(A, action)
        scripts = action / 'scripts'
        for name in ['check.sh', 'install.sh', 'post.sh']:
            (scripts / name).write_text('#!/bin/bash -p\nexit 0\n')
        (scripts / 'prepare.sh').write_text('''#!/bin/bash -p
printf 'ledger_root: %s/ledger\\n' "$DIR" >"$DIR/config.yaml"
''')
        (scripts / 'run.sh').write_text('#!/bin/bash -p\nprintf "0\\n" >"$DIR/state/agent-exit"\n')
        (scripts / 'collect.sh').write_text('''#!/bin/bash -p
printf '%s\\n' "$TEGO_CONFIG" >"$CAPTURE"
printf '{"reason":"disabled: fixture"}\\n' >"$DIR/evidence/eligibility.json"
''')
        (scripts / 'render.sh').write_text('#!/bin/bash -p\nprintf "report\\n" >"$DIR/evidence/receipt.md"\n')
        env = dict(os.environ, HOME=str(self.d / 'original-home'), RUNNER_TEMP=str(self.d / 'runtime'),
                   GITHUB_RUN_ID='42', GITHUB_RUN_ATTEMPT='1', TEGO_CONFIG='caller-config-must-not-win',
                   GITHUB_WORKSPACE=str(self.caller_workspace()), CAPTURE=str(self.d / 'capture'))
        proc = subprocess.run([str(scripts / 'agent.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        config = next((self.d / 'runtime').rglob('config.yaml'))
        self.assertEqual((self.d / 'capture').read_text().strip(), str(config))

    def test_added_collector_module_and_mode_change_refused(self):
        source = self.d / 'source'
        source.mkdir()
        (source / 'x').write_text('content')
        dest, manifest = self.d / 'copy', self.d / 'digests'
        tool = A / 'scripts/seal.py'
        subprocess.run(['/usr/bin/python3', '-I', str(tool), str(source), str(dest), str(manifest)], check=True)
        for root in [source, dest]:
            extra = root / 'extra.py'
            extra.write_text('injected')
            proc = subprocess.run(['/usr/bin/python3', '-I', str(tool), 'verify', str(source), str(dest), str(manifest)], capture_output=True)
            self.assertEqual(proc.returncode, 125, proc.stderr)
            extra.unlink()
            target = root / 'x'
            mode = target.stat().st_mode & 0o777
            target.chmod(0o777)
            proc = subprocess.run(['/usr/bin/python3', '-I', str(tool), 'verify', str(source), str(dest), str(manifest)], capture_output=True)
            self.assertEqual(proc.returncode, 125, proc.stderr)
            target.chmod(mode)

    def collection_fixture(self):
        env = self.fixture()
        run = json.loads((A / 'testdata/receipt.json').read_text())['run']
        ledger = self.d / 'ledger' / run
        ledger.mkdir(parents=True)
        shutil.copy(A / 'testdata/events.jsonl', ledger / 'events.jsonl')
        shutil.copy(A / 'testdata/contract.yaml', self.d / 'evidence/contract.yaml')
        (self.d / 'state/runs-before.txt').write_text('')
        anchor = self.d / 'anchor'
        head = json.loads((A / 'testdata/verify.json').read_text())['head']
        anchor.write_text(run + ' ' + head + '\n')
        binary = self.d / 'tego-stub'
        binary.write_text((A / 'test/fake-tego').read_text().replace('#!/usr/bin/env bash', '#!/bin/bash -p'))
        binary.chmod(0o700)
        (self.d / 'state/binary-sha256').write_text(hashlib.sha256(binary.read_bytes()).hexdigest())
        env.update(TEGO=str(binary), LEDGER_ROOT=str(ledger.parent), FAKE_TEGO_DATA=str(A / 'testdata'),
                   FAKE_ANCHOR=str(anchor), AGENT_EXIT='0')
        (self.d / 'state/protected-paths.json').write_text(json.dumps([str(self.d / 'poison'), str(self.d / 'home/.gitconfig')]))
        return env

    def runtime_fixture(self, grants):
        env = self.collection_fixture()
        data = self.d / 'agent-data'
        shutil.copytree(A / 'testdata', data)
        start = json.loads((data / 'run_start.json').read_text())
        start['runtime_grants'] = grants
        (data / 'run_start.json').write_text(json.dumps(start) + '\n')
        (self.d / 'evidence/receipt.json').unlink()
        env['FAKE_TEGO_DATA'] = str(data)
        return env

    def refused_runtime(self, env):
        proc = subprocess.run([str(A / 'scripts/collect.sh')], env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 125, proc.stderr)
        self.assertFalse((self.d / 'evidence/receipt.json').exists())
        return proc

    def test_runtime_codex_home_write_overlap_refused(self):
        proc = self.refused_runtime(self.runtime_fixture([f'fs.codex_home[{self.d}/poison]']))
        self.assertIn('runtime', proc.stderr)
        self.assertIn(str(self.d / 'poison'), proc.stderr)

    def test_runtime_harness_state_write_overlap_refused(self):
        proc = self.refused_runtime(self.runtime_fixture([f'fs.harness-state[{self.d}/home]']))
        self.assertIn(str(self.d / 'home/.gitconfig'), proc.stderr)

    def test_runtime_write_alias_overlap_refused(self):
        alias = self.d / 'alias'
        alias.symlink_to(self.d / 'poison', target_is_directory=True)
        self.refused_runtime(self.runtime_fixture([f'fs.codex_home[{alias}]']))

    def test_runtime_write_grants_allow_disjoint_paths(self):
        env = self.runtime_fixture([f'fs.codex_home[{self.d}/codex]', f'fs.harness-state[{self.d}/hooks]',
                                    'net.capture[127.0.0.1:1234]', 'exec.harness-hook[/usr/bin/tego]'])
        proc = subprocess.run([str(A / 'scripts/collect.sh')], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_runtime_write_grants_fail_closed_on_unknown_or_malformed_data(self):
        env = self.runtime_fixture([])
        path = Path(env['FAKE_TEGO_DATA']) / 'run_start.json'
        start = json.loads(path.read_text())
        for update in [{'runtime_grants': ['fs.future-write[/elsewhere]']},
                       {'runtime_grants': ['fs.codex_home[relative]']}, {'runtime_grants': 'not-a-list'},
                       {'runtime_grants': [None]}, {'record_minor': 10}, {'record_minor': None}]:
            with self.subTest(update=update):
                path.write_text(json.dumps(dict(start, **update)) + '\n')
                self.refused_runtime(env)

    def test_runtime_write_grants_require_prelaunch_refusal_list(self):
        env = self.runtime_fixture([])
        (self.d / 'state/protected-paths.json').unlink()
        self.refused_runtime(env)

    def test_collect_ignores_planted_bash_jq_and_startup(self):
        proc = subprocess.run([str(A / 'scripts/collect.sh')], env=self.collection_fixture(), capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((self.d / 'canary').exists())

    def instrument(self, script, tool, replacement):
        action = self.d / 'instrumented'
        shutil.copytree(A, action)
        path = action / 'scripts' / script
        text = path.read_text().replace('/usr/bin/' + tool, str(replacement))
        # Baseline scripts use bare command names.
        import re
        text = re.sub(r'(?<![\w/])' + tool + r'(?= )', str(replacement), text)
        path.write_text(text)
        return path

    def test_failed_find_is_not_hidden_by_process_substitution(self):
        env = self.collection_fixture()
        run = json.loads((A / 'testdata/receipt.json').read_text())['run']
        fail = self.d / 'find-fails'
        fail.write_text('#!/bin/sh\nprintf "%s\\n" ' + run + '\nexit 97\n')
        fail.chmod(0o700)
        script = self.instrument('collect.sh', 'find', fail)
        proc = subprocess.run([str(script)], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 97, proc.stderr)

    def test_failed_final_jq_is_not_hidden_by_output_helper(self):
        env = self.collection_fixture()
        fail = self.d / 'jq-fails'
        fail.write_text('''#!/usr/bin/python3
import os,sys
if any(x in ('.tier', '.tier // empty') for x in sys.argv): sys.exit(97)
os.execv('/usr/bin/jq', ['/usr/bin/jq'] + sys.argv[1:])
''')
        fail.chmod(0o700)
        script = self.instrument('collect.sh', 'jq', fail)
        proc = subprocess.run([str(script)], env=env, capture_output=True)
        self.assertEqual(proc.returncode, 97, proc.stderr)

    def test_failed_comment_size_tool_aborts(self):
        (self.d / 'state').mkdir()
        md = self.d / 'receipt.md'
        md.write_text('report')
        fail = self.d / 'wc-fails'
        fail.write_text('#!/bin/sh\nexit 97\n')
        fail.chmod(0o700)
        script = self.instrument('post.sh', 'wc', fail)
        proc = subprocess.run([str(script)], env=dict(os.environ, DIR=str(self.d), MD=str(md)), capture_output=True)
        self.assertEqual(proc.returncode, 97, proc.stderr)

    def test_private_collector_home_and_diagnostic_read_refusal(self):
        agent = (A / 'scripts/agent.sh').read_text()
        self.assertIn('HOME="$DIR/home"', agent)
        self.assertLess(agent.index('HOME="$DIR/home"'), agent.index('"$here/run.sh"'))
        launch = (A / 'scripts/launch.py').read_text()
        self.assertIn("clean['HOME'] = os.environ.get('AGENT_HOME'", launch)
        prepare = (A / 'scripts/prepare.sh').read_text()
        self.assertIn('$RUNNER_ROOT/_diag', prepare)
        self.assertIn('environment-paths', prepare)
        self.assertIn('$GITHUB_WORKSPACE/.git', prepare)
        self.assertIn('--git-common-dir', (A / 'scripts/policy.py').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
