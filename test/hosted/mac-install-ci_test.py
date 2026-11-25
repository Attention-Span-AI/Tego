#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Infrastructure contracts only; these never start Lima or a product binary (the uninstall phase runs against stand-ins)."""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io

HELPER = Path(__file__).with_name('mac') / 'mac-install-ci.py'
spec = importlib.util.spec_from_file_location('macci', HELPER)
macci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(macci)


class PureInfrastructure(unittest.TestCase):
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
            with patch.dict(os.environ, env, clear=True):
                macci.collect(root/'safe')
            artifacts = list((root/'safe').rglob('*'))
            self.assertEqual(3, sum(p.is_file() for p in artifacts))
            for p in artifacts:
                if p.is_file():
                    self.assertNotIn(b'secret', p.read_bytes())
                    self.assertNotIn(b'PRIVATE KEY', p.read_bytes())

    def test_command_modes_refuse_before_side_effects(self):
        # No hosted facts are invented: exercise the refusal on a developer machine.
        for facts in ({}, {'GITHUB_ACTIONS': 'true'}, {'RUNNER_ENVIRONMENT': 'github-hosted'},
                      {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted'},
                      {'GITHUB_ACTIONS': 'false', 'RUNNER_ENVIRONMENT': 'github-hosted'}):
            env = {k: v for k, v in os.environ.items() if k not in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT')}
            env.update(facts)
            with self.subTest(facts=facts), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp)/'must-not-exist'
                for op, args in (('bound', ['1', str(log), '/must/not/run']),
                                 ('terminal', ['1', str(log), 'install', '/must/not/run']),
                                 ('dispatch', ['start']), ('collect', [str(log)])):
                    p = subprocess.run([sys.executable, str(HELPER), op, *args], env=env,
                                       capture_output=True, timeout=5)
                    self.assertEqual(2, p.returncode, p.stderr)
                    self.assertEqual(REFUSAL, p.stderr.decode().strip())
                    self.assertEqual(b'', p.stdout)
                    self.assertFalse(log.exists())
                for script in ('mac-install-assets.sh', 'mac-install-ci.sh'):
                    p = subprocess.run(['bash', str(HELPER.with_name(script))], env=env,
                                       capture_output=True, timeout=5)
                    self.assertEqual(2, p.returncode, p.stderr)
                    self.assertEqual(REFUSAL, p.stderr.decode().strip())
                    self.assertEqual(b'', p.stdout)

    def test_imported_command_functions_also_refuse(self):
        with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stderr(io.StringIO()), \
                patch.object(macci.pty, 'fork', side_effect=AssertionError('opened a terminal')), \
                patch.object(macci.subprocess, 'Popen', side_effect=AssertionError('started a command')), \
                patch.object(macci.os, 'execv', side_effect=AssertionError('dispatched a command')):
            for function, args in ((macci.bound, (1, Path('/must/not/open'), [])),
                                   (macci.terminal, (1, Path('/must/not/open'), 'install', [])),
                                   (macci.dispatch, ([],))):
                with self.subTest(function=function.__name__):
                    with self.assertRaises(SystemExit) as raised:
                        function(*args)
                    self.assertEqual(2, raised.exception.code)


REFUSAL = 'this script installs the real product and is only for GitHub-hosted machines'
HOSTED = os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'


@unittest.skipUnless(HOSTED, 'command and terminal checks run only on GitHub-hosted machines')
class HostedInfrastructure(unittest.TestCase):
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
            p = self.helper('terminal', 3, Path(tmp)/'pty.log', 'install', '/bin/sh', '-c', 'test -t 0 || exit 42; test "$HISTFILE" = /dev/null || exit 43; exit 8')
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



REPO = HELPER.parents[3]
SCRIPT = HELPER.with_name('mac-install-ci.sh')
PATH_LINE = 'export PATH="$HOME/.local/bin:$PATH" # added by the Tego installer'

FAKE_LIMACTL = r"""#!/bin/sh
# Stand-in for Lima: one instance "tego" whose state is a file; its guest is a folder.
st=$FAKE_STATE
case "$1" in
list)
	shift
	format='' name=''
	while [ $# -gt 0 ]; do
		case "$1" in --format) format=$2; shift 2 ;; *) name=$1; shift ;; esac
	done
	if [ ! -f "$st/vm" ]; then
		[ -z "$name" ] || { echo "no instance $name" >&2; exit 1; }
		exit 0
	fi
	case "$format" in
	'{{.Status}}') cat "$st/vm" ;;
	'{{.Dir}}') echo "$HOME/.lima/tego" ;;
	'{{.Name}}') echo tego ;;
	'{{.Name}} {{.Status}}') echo "tego $(cat "$st/vm")" ;;
	*) echo "fake limactl: format $format" >&2; exit 2 ;;
	esac ;;
shell)
	shift
	[ "$1" != --workdir ] || shift 2
	shift # the instance name
	case "$*" in
	*'uninstall "$@"'*)
		g=$st/guest
		rm -f "$g/.local/bin/tego" "$g/.local/bin/tego-control" "$g/.config/systemd/user/tego-dashboard.service" "$g/.tego/dashboard.log"
		grep -vF '# added by tego start' "$g/.bashrc" >"$g/.bashrc.new" || :
		mv "$g/.bashrc.new" "$g/.bashrc"
		[ "${FAKE_WIPE_RECORDS:-}" != 1 ] || rm -rf "$g/.tego" "$g/.config/tego"
		exit 0 ;;
	esac
	exec env HOME="$st/guest" "$@" ;;
stop) echo Stopped >"$st/vm" ;;
start) echo Running >"$st/vm" ;;
delete) rm -f "$st/vm"; rm -rf "$HOME/.lima/tego" ;;
*) echo "fake limactl: $*" >&2; exit 2 ;;
esac
"""
FAKE_SSH = r"""#!/bin/sh
# Stand-in for ssh: "-S SOCKET -O exit" ends the master, which removes its control socket.
[ "${FAKE_SSH_KEEP:-}" != 1 ] || exit 0
while [ $# -gt 0 ]; do
	case "$1" in -S) rm -f "$2"; shift 2 ;; *) shift ;; esac
done
"""
FAKE_CURL = """#!/bin/sh
[ "${FAKE_CURL_OK:-}" = 1 ] && exit 0
exit 7
"""


def mac_command():
    """The Mac command exactly as install.sh writes it (its quoted part), for the stand-in Lima below."""
    text = (REPO/'scripts'/'install.sh').read_text()
    body = re.search(r'cat >>"\$shim" <<\'EOF\'\n(.*?)\nEOF\n', text, re.S)
    assert body, 'install.sh no longer writes the Mac command the way this test reads it'
    return "#!/bin/sh\nvm=tego\ninstall_line='true'\n" + body.group(1) + '\n'


@unittest.skipUnless(os.name == 'posix' and shutil.which('python3'), 'needs a POSIX shell and a pseudo-terminal')
class UninstallPhase(unittest.TestCase):
    """The uninstall phase of mac-install-ci.sh against the real Mac command and a stand-in Lima.

    The stand-ins supply only Lima, ssh and curl. The controls break one promise at a time and the phase must say which."""

    def run_phase(self, command=None, fake=None, marker=True, other_tool=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        home, state, fakebin = root/'home', root/'state', root/'fakebin'
        logs, work, assets = root/'logs', root/'work', root/'assets'
        for d in (home/'.local/bin', home/'.lima/tego', state/'guest/.local/bin', state/'guest/.config/systemd/user',
                  state/'guest/.tego', fakebin, logs, work, assets):
            d.mkdir(parents=True)
        for name, text in (('limactl', FAKE_LIMACTL), ('ssh', FAKE_SSH), ('curl', FAKE_CURL)):
            (fakebin/name).write_text(text)
            (fakebin/name).chmod(0o755)
        (home/'.local/bin/tego').write_text(command or mac_command())
        (home/'.local/bin/tego').chmod(0o755)
        (home/'.zshrc').write_text('# mine\n' + PATH_LINE + '\n')
        if other_tool:
            (home/'.local/bin/othertool').write_text('x\n')
        (home/'.lima/tego/lima.yaml').write_text(('# tego-mac-provisioning: 1\n' if marker else '') + 'mounts: []\n')
        (home/'.lima/tego/tego-dashboard.sock').write_text('master\n')
        (state/'vm').write_text('Running\n')
        guest = state/'guest'
        for f in ('.local/bin/tego', '.local/bin/tego-control', '.config/systemd/user/tego-dashboard.service', '.tego/dashboard.log'):
            (guest/f).write_text('x\n')
            (guest/f).chmod(0o755)
        (guest/'.bashrc').write_text('# mine\n[ -f x ] && . x # added by tego start\n')
        (logs/'selected-driver.txt').write_text('vz\n')
        (logs/'browser-links.txt').write_text('http://127.0.0.1:8484/?t=one-time\n')
        env = {'HOME': str(home), 'PATH': f'{fakebin}:/usr/bin:/bin', 'GITHUB_ACTIONS': 'true',
               'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'macOS', 'RUNNER_TEMP': str(root),
               'MAC_CI_LOGS': str(logs), 'MAC_CI_TMP': str(work), 'MAC_CI_ASSETS': str(assets),
               'FAKE_STATE': str(state), **(fake or {})}
        self.assertTrue(str(home).startswith(tempfile.gettempdir()) or str(home).startswith(str(root)))
        p = subprocess.run(['bash', str(SCRIPT), 'uninstall'], env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        self.state, self.home = state, home
        return p.returncode, p.stdout.decode(errors='replace')

    def assert_stops(self, out, rc, check):
        self.assertNotEqual(0, rc, out)
        self.assertIn('CHECK FAILED: ' + check, out)

    def test_the_promised_behaviour_passes_every_check(self):
        rc, out = self.run_phase()
        self.assertEqual(0, rc, out)
        self.assertIn('MAC_UNINSTALL_PROVEN=', out)
        self.assertNotIn('CHECK FAILED', out)
        self.assertFalse((self.home/'.local/bin/tego').exists())
        self.assertFalse((self.state/'vm').exists())
        self.assertEqual('# mine\n', (self.home/'.zshrc').read_text())

    def test_other_files_in_the_command_folder_keep_the_path_line(self):
        # The documented other branch: the line stays while another program in ~/.local/bin may need it.
        rc, out = self.run_phase(other_tool=True)
        self.assertEqual(0, rc, out)
        self.assertIn('kept: the PATH line stays while other files need it', out)
        self.assertIn(PATH_LINE, (self.home/'.zshrc').read_text())
        self.assertFalse((self.home/'.zshrc.tego-backup').exists())

    def test_control_a_command_left_behind_is_caught(self):
        rc, out = self.run_phase(command=mac_command().replace('rm -f "$bin/tego" &&', ': &&'))
        self.assert_stops(out, rc, 'kept: the command is gone')

    def test_control_a_vm_deleted_without_being_asked_is_caught(self):
        rc, out = self.run_phase(command=mac_command().replace('\twith_vm=0\n', '\twith_vm=1\n'))
        self.assertNotEqual(0, rc, out)
        self.assertIn('CHECK FAILED', out)
        self.assertNotIn('MAC_UNINSTALL_PROVEN', out)

    def test_control_records_wiped_by_the_default_are_caught(self):
        rc, out = self.run_phase(fake={'FAKE_WIPE_RECORDS': '1'})
        self.assert_stops(out, rc, 'kept: the record under ~/.tego is still in the VM')

    def test_control_an_unmarked_vm_stops_the_phase_before_it_asks(self):
        rc, out = self.run_phase(marker=False)
        self.assert_stops(out, rc, "before: the instance's lima.yaml carries the installer's marker")

    def test_control_a_tunnel_left_open_is_caught(self):
        rc, out = self.run_phase(fake={'FAKE_SSH_KEEP': '1'})
        self.assert_stops(out, rc, "kept: the tunnel's control socket is gone")

    def test_control_a_dashboard_still_answering_is_caught(self):
        rc, out = self.run_phase(fake={'FAKE_CURL_OK': '1'})
        self.assert_stops(out, rc, 'kept: the dashboard no longer answers on the Mac')

    def test_control_a_path_line_left_in_the_profile_is_caught(self):
        rc, out = self.run_phase(command=mac_command().replace('remove_line "$f" "$path_line" &&', ': &&'))
        self.assert_stops(out, rc, 'kept: the installer PATH line is gone from .zshrc')

    def test_control_a_delete_records_that_deletes_nothing_is_caught(self):
        rc, out = self.run_phase(command=mac_command().replace('limactl delete -f "$vm" >/dev/null 2>&1', 'false'))
        self.assert_stops(out, rc, 'deleted: exit status 0')

    def test_control_a_no_that_still_removes_is_caught(self):
        rc, out = self.run_phase(command=mac_command().replace(
            'echo "  Nothing was changed."; exit 0;', 'echo "  Nothing was changed."; rm -f "$bin/tego"; exit 0;'))
        self.assert_stops(out, rc, 'declined: the Mac command is still there')

    def test_the_questions_the_phase_answers_are_the_ones_the_command_asks(self):
        text = (REPO/'scripts'/'install.sh').read_text()
        self.assertIn("uninstall_ask '" + macci.UNINSTALL_FIRST.decode() + "'", text)
        self.assertIn('uninstall_ask "' + macci.UNINSTALL_SECOND.decode(), text)

    def test_no_vm_means_nothing_to_uninstall(self):
        # A hosted Mac that cannot boot a VM leaves no Mac command: the phase says so and passes.
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp)/'logs'
            logs.mkdir()
            (logs/'selected-driver.txt').write_text('\n')
            env = {'HOME': tmp, 'PATH': '/usr/bin:/bin', 'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                   'RUNNER_OS': 'macOS', 'RUNNER_TEMP': tmp, 'MAC_CI_LOGS': str(logs), 'MAC_CI_TMP': tmp + '/work'}
            p = subprocess.run(['bash', str(SCRIPT), 'uninstall'], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            self.assertEqual(0, p.returncode, p.stdout)
            self.assertIn(b'no VM booted', p.stdout)


if __name__ == '__main__':
    unittest.main()
