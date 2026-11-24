#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Offline launcher ownership and bounded status-copy checks. No root or Tego."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

A = Path(os.environ.get('ACTION_UNDER_TEST', Path(__file__).resolve().parents[1]))
SPEC = importlib.util.spec_from_file_location('status_reader', A/'scripts/status.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class Status(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['WORK'])
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scripts = self.root/'scripts'
        shutil.copytree(A/'scripts', self.scripts)
        self.run = self.root/'run'
        self.run.mkdir(mode=0o700)
        (self.run/'state').mkdir()
        self.log = self.root/'calls.jsonl'
        self.sudo = self.root/'sudo-standin'
        # Only a stand-in: install ownership flags are asserted, never executed
        # with root. The guest must establish actual root ownership and handoff.
        self.sudo.write_text('''#!/usr/bin/python3
import json, os, pathlib, sys
args=sys.argv[1:]
with pathlib.Path(LOG).open('a') as log: log.write(json.dumps(args)+'\\n')
args=args[args.index('--')+1:]
if args[0]=='/usr/bin/install':
    assert args[1:8]==['-d','-m','0700','-o','0','-g','0']
    pathlib.Path(args[-1]).mkdir(mode=0o700)
else:
    os.execve(args[0],args,dict(os.environ))
'''.replace('LOG',repr(str(self.log))))
        self.sudo.chmod(0o755)
        self.systemd = self.root/'systemd-standin'
        self.systemd.write_text('''#!/usr/bin/python3
import os, sys
args=sys.argv[1:]; args=args[args.index('--')+1:]
os.execve(args[0],args,dict(os.environ))
''')
        self.systemd.chmod(0o755)
        for name in ('run.sh','collect.sh','launch.py'):
            path=self.scripts/name
            path.write_text(path.read_text().replace('/usr/bin/sudo',str(self.sudo)).replace('/usr/bin/systemd-run',str(self.systemd)))
        self.binary=self.root/'fake-launcher'
        self.binary.write_text('''#!/usr/bin/python3
import json, os, pathlib, stat, sys
args=sys.argv[1:]
path=pathlib.Path(args[args.index('--status-file')+1])
assert path.parent.stat().st_uid==os.geteuid()
assert stat.S_IMODE(path.parent.stat().st_mode)==0o700
with pathlib.Path(LOG).open('a') as log: log.write(json.dumps(['launch',str(path)])+'\\n')
'''.replace('LOG',repr(str(self.log))))
        self.binary.chmod(0o755)
        import hashlib
        (self.run/'state/binary-sha256').write_text(hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.env=dict(os.environ,DIR=str(self.run),TEGO=str(self.binary),CONTRACT='/unused-contract',
                      IN_RUN='true',IN_USE_SUDO='false',GITHUB_WORKSPACE=str(self.root),
                      AGENT_HOME=str(self.root),GITHUB_OUTPUT=str(self.root/'outputs'))

    def status_file(self):
        directory=self.run/'status'
        directory.mkdir(mode=0o700)
        file=directory/'run-status.json'
        file.write_text('{"schema":"tego.run-status/1"}\n')
        file.chmod(0o600)
        return file

    def launch(self):
        return subprocess.run([str(self.scripts/'run.sh')],env=self.env,capture_output=True,text=True)

    def copy(self):
        # Execute the exact collector block without fabricating a complete
        # receipt/ledger fixture. Full collector transport has separate tests.
        text=(self.scripts/'collect.sh').read_text()
        start=text.index('if [ -e "$DIR/status" ]')
        end=text.index('if [ -e "$DIR/run-status.json" ]',start)
        return subprocess.run(['/bin/bash','-peuc',text[start:end],str(self.scripts/'collect.sh')],
                              env=self.env,capture_output=True,text=True)

    def test_ordinary_launcher_gets_private_owned_status_parent(self):
        result=self.launch()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.log.read_text().splitlines()[-1]),
                         ['launch',str(self.run/'status/run-status.json')])
        self.assertEqual(stat.S_IMODE((self.run/'status').stat().st_mode),0o700)
        self.assertEqual((self.run/'status').stat().st_uid,os.geteuid())

    def test_sudo_launcher_asks_for_root_owned_parent_before_launch(self):
        self.env['IN_USE_SUDO']='true'
        result=self.launch()
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(calls[0],['-n','--','/usr/bin/install','-d','-m','0700','-o','0','-g','0',str(self.run/'status')])
        self.assertEqual(calls[-1],['launch',str(self.run/'status/run-status.json')])
        self.assertFalse((self.run/'run-status.json').exists())

    def test_stale_status_parent_refused_before_launcher(self):
        (self.run/'status').mkdir()
        self.assertEqual(self.launch().returncode,125)
        self.assertFalse(self.log.exists())

    def test_failed_sudo_status_setup_keeps_unknown_agent_outcome(self):
        self.env['IN_USE_SUDO']='true'
        self.sudo.write_text('#!/bin/sh\nexit 1\n')
        result=self.launch()
        self.assertEqual(result.returncode,125,result.stderr)
        self.assertEqual((self.run/'state/agent-exit').read_text(),'unknown\n')
        self.assertFalse(self.log.exists())
        self.assertFalse((self.run/'status').exists())

    def test_agent_retains_diagnostics_after_status_setup_failure(self):
        action=self.root/'full-action'
        shutil.copytree(A,action)
        scripts=action/'scripts'
        (scripts/'run.sh').write_text((self.scripts/'run.sh').read_text())
        self.sudo.write_text('#!/bin/sh\nexit 1\n')
        (scripts/'check.sh').write_text('#!/bin/bash -p\nprintf \'{"reason":"disabled: fixture"}\\n\' >"$DIR/evidence/eligibility.json"\n')
        import shlex
        (scripts/'install.sh').write_text('#!/bin/bash -p\ncp '+shlex.quote(str(self.binary))+' "$DIR/bin/tego"\nsha256sum "$DIR/bin/tego" | cut -d\' \' -f1 >"$DIR/state/binary-sha256"\n')
        (scripts/'prepare.sh').write_text('#!/bin/bash -p\nmkdir "$DIR/ledger"\n: >"$DIR/state/runs-before.txt"\n')
        workspace=self.root/'caller'
        git_env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
        subprocess.run(['/usr/bin/git','-c','init.templateDir=','init','-q',str(workspace)],env=git_env,check=True)
        subprocess.run(['/usr/bin/git','-C',str(workspace),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                        '-c','core.hooksPath=/dev/null','commit','--quiet','--allow-empty','--no-gpg-sign','-m','fixture'],env=git_env,check=True)
        outputs=self.root/'agent-outputs'
        env=dict(self.env,HOME=str(self.root/'original-home'),RUNNER_TEMP=str(self.root/'runtime'),
                 GITHUB_RUN_ID='42',GITHUB_RUN_ATTEMPT='1',GITHUB_WORKSPACE=str(workspace),IN_USE_SUDO='true',
                 GITHUB_OUTPUT=str(outputs),GITHUB_SHA='a'*40)
        result=subprocess.run([str(scripts/'agent.sh')],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        values=dict(line.split('=',1) for line in outputs.read_text().splitlines())
        self.assertEqual(values['agent-exit-code'],'unknown')
        self.assertNotEqual(values['evidence-exit'],'0')
        self.assertEqual(len(values['inventory-sha256']),64)
        evidence=Path(values['dir'])/'evidence'
        self.assertIn('No receipt',(evidence/'receipt.md').read_text())
        self.assertFalse((evidence/'receipt.json').exists())
        self.assertFalse(self.log.exists())

    def test_reader_accepts_normal_private_status(self):
        file=self.status_file()
        self.assertEqual(S.read_status(str(file)),file.read_bytes())

    def test_reader_refuses_wrong_owner_or_modes(self):
        file=self.status_file()
        with patch.object(S.os,'geteuid',return_value=os.geteuid()+1),self.assertRaisesRegex(ValueError,'launcher-owned'):
            S.read_status(str(file))
        for mode in (0o644,0o666,0o400):
            file.chmod(mode)
            with self.subTest(file_mode=oct(mode)),self.assertRaises(ValueError):S.read_status(str(file))
        file.chmod(0o600)
        file.parent.chmod(0o755)
        with self.assertRaises(ValueError):S.read_status(str(file))

    def test_reader_refuses_links_specials_oversize_and_unclean_paths(self):
        file=self.status_file()
        for special in ('hardlink','symlink','fifo','oversize'):
            with self.subTest(special=special):
                file.unlink()
                if special=='hardlink':
                    original=self.root/'original';original.write_bytes(b'{}');original.chmod(0o600);os.link(original,file)
                elif special=='symlink':file.symlink_to(self.root/'original')
                elif special=='fifo':os.mkfifo(file,0o600)
                else:file.write_bytes(b'x'*4097);file.chmod(0o600)
                with self.assertRaises((ValueError,OSError)):S.read_status(str(file))
        link=self.root/'alias';link.symlink_to(file.parent,target_is_directory=True)
        with self.assertRaises(OSError):S.read_status(str(link/'run-status.json'))
        for bad in (str(self.run)+'/status/../status/run-status.json', '/'+str(file)):
            with self.subTest(path=bad),self.assertRaises(ValueError):S.read_status(bad)

    def test_collector_copy_is_exclusive_private_and_same_bytes(self):
        file=self.status_file()
        result=self.copy()
        self.assertEqual(result.returncode,0,result.stderr)
        dest=self.run/'run-status.json'
        self.assertEqual(dest.read_bytes(),file.read_bytes())
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode),0o600)
        self.assertEqual(dest.stat().st_uid,os.geteuid())
        dest.write_bytes(b'retained')
        self.assertEqual(self.copy().returncode,125)
        self.assertEqual(dest.read_bytes(),b'retained')

    def test_sudo_reader_writes_only_stdout_collector_owns_copy(self):
        file=self.status_file()
        self.env['IN_USE_SUDO']='true'
        result=self.copy()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.run/'run-status.json').read_bytes(),file.read_bytes())
        self.assertEqual(json.loads(self.log.read_text().splitlines()[0]),
                         ['-n','--','/usr/bin/python3','-I',str(self.scripts/'status.py'),'read',str(file)])

    def test_missing_status_refuses_collection_historical_no_directory_survives(self):
        self.assertEqual(self.copy().returncode,0)
        (self.run/'status').mkdir(mode=0o700)
        self.assertEqual(self.copy().returncode,125)

    def test_stale_unimplemented_display_removed(self):
        result=subprocess.run(['/usr/bin/python3','-I',str(A/'scripts/eligibility.py')],
                              env=dict(self.env,GITHUB_EVENT_NAME='push',VISIBILITY='public',IN_SIGN='auto'),
                              capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout)
        self.assertTrue(value['signing_implemented'])
        self.assertIn('separate signing job',value['reason'])
        self.assertNotIn('not implemented',value['reason'])


if __name__=='__main__':unittest.main(verbosity=2)
