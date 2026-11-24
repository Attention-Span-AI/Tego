#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Data transport tests; no Tego binary or WSL instance is executed."""
import base64
import configparser
import importlib.util
import json
import contextlib
import hashlib
import io
from types import SimpleNamespace
from unittest import mock
import os
import subprocess
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('entry', Path(__file__).with_name('windows-entry.py'))
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)

class EntryTests(unittest.TestCase):
    def test_hostile_arguments_are_data(self):
        args = ['', '--', '--flag=value with spaces', 'quote"and\\backslash', '雪 café', '$(touch SHOULD_NOT_EXIST)', '; & | > <', '$HOME', "a'b", 'line\nbreak']
        payload = base64.b64encode(json.dumps(args, ensure_ascii=False).encode()).decode()
        self.assertEqual(entry.invocation(payload), args)

    def test_guest_provisioning_with_windows_pipeline_newline(self):
        # Execute the real provisioning shell with all machine-changing paths
        # redirected into fixtures and apt/id replaced. Windows PowerShell's
        # text pipeline appends CRLF even when the release script uses LF.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root/'bin').mkdir()
            (root/'etc/profile.d').mkdir(parents=True)
            (root/'bin/id').write_text('#!/bin/sh\necho 26743\n')
            (root/'bin/apt-get').write_text('#!/bin/sh\nexit 0\n')
            for command in (root/'bin').iterdir():
                command.chmod(0o755)
            source = Path(__file__).with_name('windows-provision.sh').read_text()
            for folder in ['/usr/local/', '/etc/', '/var/lib/']:
                source = source.replace(folder, str(root)+folder)
            payload = base64.b64encode(b'verified entry fixture').decode()
            result = subprocess.run(['bash','-s','--',payload], input=source+'\r\n', text=True, capture_output=True,
                                    env=dict(os.environ, PATH=str(root/'bin')+os.pathsep+os.environ['PATH']))
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual((root/'usr/local/lib/tego/windows-entry').read_bytes(), b'verified entry fixture')
            config = (root/'etc/wsl.conf').read_text()
            parsed = configparser.ConfigParser()
            parsed.read_string(config)
            for section, key, value in [('boot','systemd','true'), ('automount','enabled','false'),
                                        ('automount','mountFsTab','false'), ('automount','ldconfig','false'),
                                        ('interop','enabled','false'), ('interop','appendWindowsPath','false'),
                                        ('general','guiApplications','false'), ('gpu','enabled','false'),
                                        ('gpu','appendLibPath','false'), ('user','default','tego')]:
                self.assertEqual(parsed[section][key], value)
            checked = subprocess.run(['bash','-s','--',payload,'check'], input=source+'\r\n', text=True, capture_output=True,
                                     env=dict(os.environ, PATH=str(root/'bin')+os.pathsep+os.environ['PATH']))
            self.assertEqual(checked.returncode, 0, checked.stdout+checked.stderr)
            # Positive control: changing the closure really requests a restart.
            (root/'etc/wsl.conf').write_text(config.replace('[interop]\nenabled=false', '[interop]\nenabled=true'))
            checked = subprocess.run(['bash','-s','--',payload,'check'], input=source+'\r\n', text=True, capture_output=True,
                                     env=dict(os.environ, PATH=str(root/'bin')+os.pathsep+os.environ['PATH']))
            self.assertEqual(checked.returncode, 10, checked.stdout+checked.stderr)

    def test_non_array_and_nul_refused(self):
        for value in ['text', {'arg':'x'}, [None], ['nul\0']]:
            with self.assertRaises(ValueError):
                entry.invocation(base64.b64encode(json.dumps(value).encode()).decode())

    def test_shell_banner_is_reserved_for_interactive_shell(self):
        with tempfile.TemporaryDirectory() as name:
            home = Path(name)
            runtime = home/'proc/self'
            runtime.mkdir(parents=True)
            (runtime/'cgroup').write_text('0::/user@' + str(os.getuid()) + '.service/app.slice')
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                if str(path) == '/proc/self/cgroup':
                    return original_read(runtime/'cgroup', *args, **kwargs)
                return original_read(path, *args, **kwargs)
            with mock.patch.dict(os.environ), mock.patch.object(Path, 'home', return_value=home), mock.patch.object(Path, 'read_text', read), \
                    mock.patch.object(entry.os, 'execv'), mock.patch.object(entry.os, 'chdir'):
                for command, banner in [([], True), (['shell'], True), (['shell', '-c', 'exit 37'], False)]:
                    out = io.StringIO()
                    payload = base64.b64encode(json.dumps(command).encode()).decode()
                    with contextlib.redirect_stdout(out):
                        entry.main(['--scoped', payload])
                    self.assertEqual("Tego's Linux, inside Windows" in out.getvalue(), banner)

    def test_protection_failure_is_not_installer_repair_advice(self):
        script = b'#!/bin/sh\n'
        values = ['v0.2.0', 'https://mirror.invalid', 'a'*64, hashlib.sha256(script).hexdigest(), 'False']
        values = [base64.b64encode(value.encode()).decode() for value in values]
        for tier, expected in [('', 211), ('landlock', 0)]:
            report = SimpleNamespace(returncode=0 if tier else 1, stdout=json.dumps({'tier': tier}), stderr='D5 unavailable' if not tier else '')
            with mock.patch.object(entry.urllib.request, 'urlopen', return_value=io.BytesIO(script)), \
                    mock.patch.object(entry.subprocess, 'run', side_effect=[SimpleNamespace(returncode=0), report, SimpleNamespace(returncode=0)]):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = entry.install_release(values)
                self.assertEqual(code, expected)
                self.assertNotIn('rerun', out.getvalue())
                if not tier:
                    self.assertIn('D5 unavailable', out.getvalue())
                else:
                    self.assertIn('Basic protection is available here', out.getvalue())

    def test_available_tier_does_not_hide_refused_setup(self):
        script = b'#!/bin/sh\n'
        values = ['v0.2.0', 'https://mirror.invalid', 'a'*64, hashlib.sha256(script).hexdigest(), 'False']
        values = [base64.b64encode(value.encode()).decode() for value in values]
        installed = SimpleNamespace(returncode=0, stdout='', stderr='')
        machine = SimpleNamespace(returncode=0, stdout='{"tier":"landlock"}', stderr='')
        refused = SimpleNamespace(returncode=125, stdout='', stderr='private cgroup namespace [governed]')
        with mock.patch.object(entry.urllib.request, 'urlopen', return_value=io.BytesIO(script)), \
                mock.patch.object(entry.subprocess, 'run', side_effect=[installed, machine, refused]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = entry.install_release(values)
            self.assertEqual(code, 212)
            self.assertNotIn('protecting', out.getvalue())
            self.assertIn('guide', out.getvalue())

    def test_private_ready_handshake_requires_the_user_scope(self):
        with tempfile.TemporaryDirectory() as name:
            with mock.patch.dict(os.environ), mock.patch.object(Path, 'home', return_value=Path(name)), \
                    mock.patch.object(entry.os, 'chdir'), mock.patch.object(entry.os, 'execv') as execute, \
                    mock.patch.object(entry.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(b''))):
                for scoped in [False, True]:
                    cgroup = '0::/user@' + str(os.getuid()) + '.service/app.slice' if scoped else '0::/non-systemd'
                    out = io.StringIO()
                    with mock.patch.object(Path, 'read_text', return_value=cgroup), contextlib.redirect_stdout(out):
                        if scoped:
                            self.assertEqual(entry.main(['--scoped', '--ready']), 0)
                        else:
                            with self.assertRaisesRegex(RuntimeError, 'scope entry'):
                                entry.main(['--scoped', '--ready'])
                    self.assertEqual(out.getvalue(), 'TEGO_SCOPE_READY\n' if scoped else '')
                    execute.assert_not_called()

    def test_cold_start_waits_for_user_bus(self):
        with mock.patch.object(Path, 'is_socket', side_effect=[False, False, True]) as ready, \
                mock.patch.object(entry.time, 'monotonic', return_value=0), \
                mock.patch.object(entry.time, 'sleep') as pause:
            self.assertTrue(entry.wait_for_user_bus('/run/user/26743'))
            self.assertEqual(ready.call_count, 3)
            self.assertEqual(pause.call_args_list, [mock.call(0.1), mock.call(0.1)])
        with mock.patch.object(Path, 'is_socket', return_value=False), \
                mock.patch.object(entry.time, 'monotonic', side_effect=[0, 60]), \
                mock.patch.object(entry.time, 'sleep') as pause:
            self.assertFalse(entry.wait_for_user_bus('/run/user/26743'))
            pause.assert_not_called()

    def test_scope_starts_only_after_user_bus_is_ready(self):
        payload = base64.b64encode(b'["version"]').decode()
        with tempfile.TemporaryDirectory() as name:
            with mock.patch.dict(os.environ), mock.patch.object(Path, 'home', return_value=Path(name)), \
                    mock.patch.object(entry.os, 'chdir'), mock.patch.object(entry.os, 'execv', return_value=None) as execute:
                for ready in [False, True]:
                    execute.reset_mock()
                    err = io.StringIO()
                    with mock.patch.object(entry, 'wait_for_user_bus', return_value=ready) as wait, \
                            contextlib.redirect_stderr(err):
                        result = entry.main([payload])
                    wait.assert_called_once_with('/run/user/' + str(os.getuid()))
                    if ready:
                        self.assertIsNone(result)
                        execute.assert_called_once()
                        self.assertEqual(execute.call_args.args[0], '/usr/bin/systemd-run')
                        self.assertEqual(execute.call_args.args[1][-1], payload)
                        self.assertEqual(err.getvalue(), '')
                    else:
                        self.assertEqual(result, 125)
                        execute.assert_not_called()
                        self.assertEqual(len(err.getvalue().splitlines()), 1)
                        self.assertNotIn('installer', err.getvalue())

    def test_relay_modes_run_fixed_commands_in_the_scope(self):
        # The relay's Linux modes take no caller data, run only inside the user scope, print nothing before the
        # exec (their standard output is the relay's pipe) and never say they were started by the Windows command.
        with tempfile.TemporaryDirectory() as name:
            home = Path(name)
            for scoped, mode, want in [(True, '--relay', 'serve'), (True, '--dashboard-open', 'open'), (False, '--relay', None)]:
                cgroup = '0::/user@' + str(os.getuid()) + '.service/app.slice/run-u1.scope' if scoped else '0::/init.scope'
                with mock.patch.dict(os.environ, {'TEGO_WINDOWS_NATIVE': '1'}), mock.patch.object(Path, 'home', return_value=home), \
                        mock.patch.object(Path, 'read_text', return_value=cgroup), mock.patch.object(entry.os, 'chdir'), \
                        mock.patch.object(entry.os, 'execv', return_value=0) as execute:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        if want:
                            entry.main(['--scoped', mode])
                        else:
                            with self.assertRaisesRegex(RuntimeError, 'scope entry'):
                                entry.main(['--scoped', mode])
                    self.assertEqual(out.getvalue(), '')
                    if want:
                        execute.assert_called_once_with(str(home/'.local/bin/tego'), ['tego', 'dashboard-relay', want])
                        self.assertNotIn('TEGO_WINDOWS_NATIVE', os.environ)
                    else:
                        execute.assert_not_called()

    def test_native_marker_reaches_commands_not_the_shell(self):
        with tempfile.TemporaryDirectory() as name:
            home = Path(name)
            cgroup = '0::/user@' + str(os.getuid()) + '.service/app.slice/run-u1.scope'
            for command, native in [(['dashboard'], '1'), (['serve', '--open'], '1'), (['shell'], None), ([], None)]:
                seen = {}
                def execv(path, argv):
                    seen['native'] = os.environ.get('TEGO_WINDOWS_NATIVE')
                    seen['argv'] = argv
                    return 0
                payload = base64.b64encode(json.dumps(command).encode()).decode()
                with mock.patch.dict(os.environ, {'TEGO_WINDOWS_NATIVE': 'stale'}), mock.patch.object(Path, 'home', return_value=home), \
                        mock.patch.object(Path, 'read_text', return_value=cgroup), mock.patch.object(entry.os, 'chdir'), \
                        mock.patch.object(entry.os, 'execv', side_effect=execv), contextlib.redirect_stdout(io.StringIO()):
                    entry.main(['--scoped', payload])
                self.assertEqual(seen['native'], native, command)
                if command == ['serve', '--open']:
                    self.assertEqual(seen['argv'], ['tego', 'dashboard'])

    def test_last_project_or_home(self):
        with tempfile.TemporaryDirectory() as name:
            home = Path(name)
            self.assertEqual(entry.working_folder(home), name)
            (home/'.config/tego').mkdir(parents=True)
            (home/'app').mkdir()
            (home/'.config/tego/last-project').write_text(str(home/'app'))
            self.assertEqual(entry.working_folder(home), str(home/'app'))
            (home/'.config/tego/last-project').write_text('relative')
            self.assertEqual(entry.working_folder(home), name)

if __name__ == '__main__':
    unittest.main()
