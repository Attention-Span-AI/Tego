#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Exercise the actual cleanup function, pair judgement and pair loop with harmless waited children and private
# files. A concurrent writer makes the real rm return ENOTEMPTY; other injected failures test the final gate. Each
# stand-in launcher (a shell function run in the background, as the real launcher is) writes a run directory whose
# events.jsonl says what the case needs (the plane it ran on, its own pid as launcher_pid, its refusal of the
# secret, its run_end) and an output (the agent's word on its read), and can leave a stand-in reaper that writes
# later, so the pair loop's judgement (ADR 0021's per-pair proof) and the self-deny run before it are run as written.
# judge's table is held whole: every combination of one launcher's evidence is run through assert_pair and compared
# with the table as ADR 0021's 2026-10-19 note states it. So are the setup functions: COPY_B's two inodes and the
# third-party listener's ready handshake and stop, against stand-in listeners.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python3 -B - "$here/tier2-pairs.sh" "$@" <<'PY'
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap

parser = argparse.ArgumentParser()
parser.add_argument('source')
parser.add_argument('--original')
args = parser.parse_args()
source = Path(args.original or args.source).read_text()
# From the self-deny run on: the pair loop as written, with SELF_DENY's run before it.
loop = source[source.index('cd "$w" || exit 1\n'):]


def extract(*names):
    out = ''
    for name in names:
        matches = re.findall(r'^' + name + r'\(\) \{\n.*?^\}', source, re.M | re.S)
        if len(matches) != 1:
            raise SystemExit('FAIL expected one ' + name + ' function')
        out += matches[0] + '\n'
    return out


functions = extract('pcat', 'cleanup_pair', 'by_mechanism', 'ledger_facts', 'read_effect', 'settle', 'judge',
                    'assert_pair', 'stop_listener', 'abort', 'self_deny')
setup_functions = extract('pcat', 'setup_copy_b', 'setup_self_link', 'start_listener', 'stop_listener', 'launcher_names', 'launchers')

# A permission-error control must run under ordinary credentials even when the host gate is root.
if os.geteuid() == 0:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)


def check(ok, message):
    if not ok:
        raise AssertionError(message)
    print('ok   ' + message, flush=True)


with tempfile.TemporaryDirectory(prefix='tego-pair-cleanup.', dir='/tmp') as name:
    base = Path(name)
    real_rm = shutil.which('rm')
    tools = base / 'tools'
    tools.mkdir()
    wrapper = tools / 'rm'
    wrapper.write_text('#!' + sys.executable + '\n' + textwrap.dedent(r'''
        import errno, json, os, subprocess, sys, threading
        from pathlib import Path
        sys.dont_write_bytecode = True
        root = Path(os.environ['PAIR_TEST_ROOT'])
        count = root / 'calls'
        n = int(count.read_text()) + 1 if count.exists() else 1
        count.write_text(str(n))
        mode = os.environ['PAIR_TEST_MODE']
        targets = sys.argv[sys.argv.index('--') + 1:] if '--' in sys.argv else sys.argv[2:]
        target = next((p for p in targets if '/runs/' in p), None)
        if mode == 'false-zero':
            raise SystemExit(0)
        if mode == 'warning':
            result = subprocess.run(['rm', *sys.argv[1:]], executable=os.environ['PAIR_REAL_RM'])
            print('unexpected rm warning', file=sys.stderr)
            raise SystemExit(result.returncode)
        if mode == 'missing-diagnostic':
            raise SystemExit(1)
        if mode in ('persistent', 'deadline'):
            try:
                os.rmdir(target)
            except OSError as e:
                if e.errno != errno.ENOTEMPTY:
                    raise
                print("rm: cannot remove '%s': Directory not empty" % target, file=sys.stderr)
                raise SystemExit(1)
            raise SystemExit('FAIL persistent fixture unexpectedly empty')
        if mode == 'race' and n == 1:
            # Keep the directory held while a real separate rm enumerates/unlinks it. New names
            # appear after that enumeration; rm itself supplies the actual ENOTEMPTY diagnostic.
            fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            stop = threading.Event()
            writes = [0]
            def writer():
                while not stop.is_set() and writes[0] < 5000:
                    try:
                        f = os.open('late-%d' % writes[0], os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=fd)
                        os.close(f)
                        writes[0] += 1
                    except FileNotFoundError:
                        return
            task = threading.Thread(target=writer)
            task.start()
            try:
                result = subprocess.run(['rm', *sys.argv[1:]], executable=os.environ['PAIR_REAL_RM'],
                                        capture_output=True, text=True, timeout=5)
            finally:
                stop.set()
                task.join(2)
                os.close(fd)
            if task.is_alive():
                raise SystemExit('FAIL concurrent writer did not join')
            (root / 'race.json').write_text(json.dumps({'rc': result.returncode,
                'stderr': result.stderr, 'writes': writes[0], 'writer_joined': True}))
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit(result.returncode)
        os.execv(os.environ['PAIR_REAL_RM'], ['rm', *sys.argv[1:]])
    '''))
    wrapper.chmod(0o755)

    secret = '/var/lib/tego-pairs/secret'
    self_link = '/var/lib/tego-pairs/tego-self'
    secret_text = 'PAIRS-SECRET-CONTENT do-not-print'

    def ledger(defect, plane, path=secret):
        """One run's events.jsonl as the launcher leaves it: run_start with its decision_plane and its launcher_pid
        (@PID@, which the stand-in launcher replaces with its own pid), the agent's one refused open of path by the
        plane's mechanism, run_end with reason exit. defect names what differs, several joined by '+': orphaned and
        oom are run_end's reason (the reaper's, and tego's own cgroup kill's), allowed-line an fs line that lets path
        through, stage-exec:<path> an exec line of the stage, and the rest what they say."""
        ds = set(defect.split('+'))
        line = lambda d: json.dumps(d, separators=(',', ':'))
        out = []
        if 'no-start' not in ds:
            start = {'v': 1, 'seq': 0, 'kind': 'run_start', 'source': 'supervisor', 'launcher_pid': '@PID@',
                     'launcher_start_ns': 1234}
            if 'foreign-pid' in ds:
                start['launcher_pid'] = 1
            start['capture'] = 'uprobe'
            if 'no-plane' not in ds:
                start['decision_plane'] = 'lsm' if 'mismatch' in ds else plane
            start['tier'] = 'cgroup'
            out.append(line(start).replace('"@PID@"', '@PID@'))
        out.append(line({'v': 1, 'seq': 1, 'kind': 'exec', 'source': 'supervisor', 'verdict': 'allow',
                         'argv': ['sh', '-c', 'cat'], 'path': '/usr/bin/dash'}))
        for d in sorted(ds):
            if d.startswith('stage-exec:'):
                # The stage's exec of the launcher's own binary, which is never decided nor recorded (ADR 0021 (2)).
                out.append(line({'v': 1, 'seq': 1, 'kind': 'exec', 'source': 'fanotify', 'verdict': 'allow',
                                 'argv': ['tego'], 'path': d.split(':', 1)[1]}))
        refusal = {'v': 1, 'seq': 2, 'kind': 'fs', 'source': 'fanotify', 'rule': 'fs.deny_read[' + path + ']',
                   'verdict': 'refused', 'authority': 'rule', 'reason': 'read-denied'}
        if plane != 'fanotify':
            refusal['source'] = 'kernel'
            refusal['decision_plane'] = plane
            refusal['mechanism'] = 'plane'
        if 'wrong-mechanism' in ds:
            refusal['source'] = 'landlock'
            refusal.pop('decision_plane', None)
            refusal.pop('mechanism', None)
        refusal['op'] = 'open'
        refusal['path'] = '/etc/other' if 'other-path' in ds else path
        if 'no-refusal' not in ds:
            out.append(line(refusal))
        if 'two-refusals' in ds:
            out.append(line(refusal))
        # A refused open of something else, and an allowed one of the secret's directory, count for nothing.
        out.append(line({**refusal, 'path': path + '-not'}))
        out.append(line({'v': 1, 'seq': 3, 'kind': 'fs', 'source': 'landlock', 'verdict': 'allow', 'op': 'open',
                         'path': path.rpartition('/')[0] + '/'}))
        if 'allowed-line' in ds:
            out.append(line({'v': 1, 'seq': 3, 'kind': 'fs', 'source': 'fanotify', 'verdict': 'allow', 'op': 'open',
                             'path': path}))
        if 'no-end' not in ds:
            reason = 'orphaned' if 'orphaned' in ds else 'oom' if 'oom' in ds else 'exit'
            out.append(line({'v': 1, 'seq': 4, 'kind': 'run_end', 'source': 'supervisor', 'reason': reason}))
        return '\n'.join(out) + '\n'

    def output(tag, effect):
        """A launcher's output: what its agent's read did, as the agent says it ('PAIRS-READ refused' or 'opened',
        after the secret's content cat printed) or cut short (cut: the content and no word after it; none: nothing).
        said is the word 'opened' alone, as the self-deny agent, which prints none of the binary, says it."""
        text = 'launcher ' + tag + '\n'
        if effect in ('opened', 'cut'):
            text += 'agent output: ' + secret_text + '\n'
        if effect in ('refused', 'opened', 'said'):
            text += 'PAIRS-READ ' + ('opened' if effect == 'said' else effect) + '\n'
        return text

    def invoke(label, mode='ordinary', actor_a=0, actor_b=0, pair_mode='plain', defect='ok', defect_run='a',
               plane='fanotify', run_plane=None, self_deny=False, actor_self=0, kill_min=0, kill_target=None,
               pairs=1, effect='refused', late=None, settle=0):
        """Runs the pair loop as written over stand-in launchers. defect and effect are what defect_run's ledger and
        output differ in (effect: output()'s); late, for defect_run, is what its run's reaper stand-in writes 0.5 s
        after the launcher exited: (effect, run_end reason), the output's lines and then the run_end, which the
        loop waits for up to settle seconds."""
        root = base / label
        (root / 'runs').mkdir(parents=True)
        # What each launcher leaves, written by the stand-in launcher when it runs (so its launcher_pid is the pid
        # the pair loop has for it): a run directory, the first of which (a's) the rm stand-in's injected failures
        # act on, and its output. A run whose defect is 'none' leaves no run directory. The ledger root holds
        # nothing else a pair's judgement would read: a previous pair's runs are gone, and .live is hidden.
        tmpl = root / 'tmpl'
        tmpl.mkdir()
        for tag in ('a', 'b', 'self'):
            d = defect if tag == defect_run else 'ok'
            if d != 'none' and (tag != 'self' or self_deny):
                if mode in ('permission', 'race') and tag != 'self':
                    # The directory now, so the permission case's read-only runs/ still holds it and the race case
                    # can seed it; otherwise the stand-in makes it.
                    (root / 'runs' / ('r-zz-1-' + tag)).mkdir()
                (tmpl / (tag + '.jsonl')).write_text(ledger(d, run_plane or plane,
                                                            self_link if tag == 'self' else secret))
            (tmpl / (tag + '.out')).write_text(output(tag, effect if tag == defect_run else 'refused'))
            if late and tag == defect_run:
                (tmpl / (tag + '.late')).write_text(output(tag, late[0]).split('\n', 1)[1])
                (tmpl / (tag + '.end')).write_text(json.dumps(
                    {'v': 1, 'seq': 9, 'kind': 'run_end', 'source': 'supervisor', 'reason': late[1]},
                    separators=(',', ':')) + '\n')
        live = root / 'runs' / '.live'
        live.mkdir()
        (live / 'keep').write_text('bookkeeping\n')
        out = root / 'out'
        out.mkdir()
        for f in ('a.0', 'b.0'):
            (out / f).write_text('previous pair\n')
        if mode == 'race':
            for i in range(5000):
                (root / 'runs' / 'r-zz-1-a' / ('seed-%05d' % i)).touch()
        outside = root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('external sentinel\n')
        os.symlink(outside, root / 'runs' / 'r-zz-symlink')
        if mode == 'permission':
            (root / 'runs').chmod(0o555)
        driver = root / 'driver.sh'
        driver.write_text('set -u\nw=$1\nN=$PAIR_N\nMODE=$2\nTEGO=A\nTEGO_B=B\nPLANE=$5\nwant_plane=$6\n'
            'SELF_DENY=$7\nactor_self=$8\nKILL_MIN=$9\nSETTLE=$PAIR_SETTLE\n'
            'SECRET=' + secret + '\nSELF_LINK=' + self_link + '\nsecret_text=\'' + secret_text + '\'\nCOPY_B=0\nLISTENER=\nlpid=\n'
            # The stand-in launcher: its ledger and output from the case's templates, then its status. A case with
            # a late part leaves a stand-in reaper behind, which writes the output's late lines and then the run_end.
            'stub() { local t; [ ! -e "$w/tmpl/$1.jsonl" ] || { mkdir -p "$w/runs/r-zz-1-$1"; '
            't=$(<"$w/tmpl/$1.jsonl"); printf "%s\\n" "${t//@PID@/$BASHPID}" >"$w/runs/r-zz-1-$1/events.jsonl"; }; '
            'printf "%s\\n" "$(<"$w/tmpl/$1.out")"; '
            '[ ! -e "$w/tmpl/$1.late" ] || { ( /bin/sleep 0.5; [ ! -s "$w/tmpl/$1.late" ] || '
            'printf "%s\\n" "$(<"$w/tmpl/$1.late")"; '
            'printf "%s\\n" "$(<"$w/tmpl/$1.end")" >>"$w/runs/r-zz-1-$1/events.jsonl" ) & }; exit "$2"; }\n'
            'A() { stub self "$actor_self"; }\n'
            # Kill-mode controls check aggregation of known waited statuses, with each harmless child
            # already settled before the fixture's signal attempt. They do not test kernel killing. A case that
            # waits for a late part sleeps as nap would.
            'actor_a=$3\nactor_b=$4\nnap() { [ "$PAIR_TEST_MODE" != deadline ] || SECONDS=$((SECONDS + 5)); '
            '[ "$MODE" != kill ] || { wait "$!" 2>/dev/null || :; }; [ "$SETTLE" = 0 ] || /bin/sleep "$1"; }\n'
            # The kill point: the case's target, no delay; what the loop drew from is kept for the span check.
            'kill_draw() { echo "$1" >>"$w/draws"; kd=0.000; kt=$PAIR_KILL; }\n'
            # Those actor PIDs have been reaped and may be reused: validate but do not signal them.
            # Watchdog TERM and the EXIT cleanup still use the actual builtin kill and wait.
            'kill() { if [ "$1" = -KILL ]; then '
            '[ "$MODE" = kill ] && { { [ "${kt-}" = a ] && [ "$2" = "$pa" ]; } || '
            '{ [ "${kt-}" = b ] && [ "$2" = "$pb" ]; }; } || '
            '{ echo "kill of $2 is not the target ${kt-}" >>"$w/kill-wrong"; return 2; }; '
            'return 0; fi; [ "$1" = "$wd" ] || return 2; '
            'local job; for job in $(jobs -pr); do [ "$job" != "$wd" ] || { builtin kill "$@"; return; }; done; '
            'return 0; }\n'
            # Under MODE=timeout the launcher is a child of what $! names, as under timeout(1), and says its pid
            # in pid.<a|b>: a loop that tied runs to $! there would find them foreign.
            'launch() { local rc=$actor_a; [ "$1" = a ] || rc=$actor_b; if [ "$MODE" = timeout ]; then '
            '{ ( echo "$BASHPID" >"$w/pid.$1"; stub "$1" "$rc" ); } >"$w/out/$1.$i" 2>&1 & '
            'else stub "$1" "$rc" >"$w/out/$1.$i" 2>&1 & fi; }\n'
            '/bin/sleep 60 &\nwd=$!\ntrap \'kill "$wd" 2>/dev/null; wait "$wd" 2>/dev/null || :\' EXIT\n'
            + functions + loop)
        try:
            command = ['bash', str(driver), str(root), pair_mode, str(actor_a), str(actor_b), plane,
                       '' if plane == 'auto' else plane, '1' if self_deny else '0', str(actor_self), str(kill_min)]
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True,
                env={**os.environ, 'PATH': str(tools) + ':' + os.environ['PATH'],
                     'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1', 'PAIR_TEST_ROOT': str(root),
                     'PAIR_N': str(pairs), 'PAIR_SETTLE': str(settle),
                     # The launcher the kill targets: the case's, else the one that exited 137 (a by default).
                     'PAIR_KILL': kill_target or ('b' if actor_b == 137 and actor_a != 137 else 'a'),
                     'PAIR_REAL_RM': real_rm, 'PAIR_TEST_MODE': mode})
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except BaseException:
                # A timeout leaves the private session leader unreaped. KeyboardInterrupt can
                # instead make communicate reap it: never signal a released numeric group ID.
                if proc.returncode is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                proc.communicate(timeout=2)
                raise
            result = subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)
        finally:
            (root / 'runs').chmod(0o700)
        check((live / 'keep').read_text() == 'bookkeeping\n'
              and (outside / 'keep').read_text() == 'external sentinel\n',
              label + ': hidden bookkeeping and external symlink target untouched')
        check(not (root / 'kill-wrong').exists(), label + ': kill mode SIGKILLs the launcher kill_draw drew')
        return root, result

    root, r = invoke('ordinary')
    check(r.returncode == 0 and 'PAIR-CLEANUP 1 attempts=1 status=removed' in r.stdout
          and 'PAIRS-DONE 1/1' in r.stdout and not r.stderr
          and not (root / 'runs' / 'r-zz-1-a').exists()
          and not (root / 'out' / 'a.0').exists() and (root / 'out' / 'a.1').exists(),
          'real external rm removes only selected ledgers and previous outputs: ' + r.stdout + r.stderr)

    root, r = invoke('concurrent-writer', 'race')
    race = json.loads((root / 'race.json').read_text())
    check(race['rc'] == 1 and 'Directory not empty' in race['stderr']
          and race['writes'] > 0 and race['writer_joined'],
          'concurrent filesystem writer makes real rm return ENOTEMPTY: ' + repr(race))
    check(r.returncode == 0 and 'status=retry reason=enotempty rm_status=1' in r.stderr
          and 'Directory not empty' in r.stderr
          and 'PAIR-CLEANUP 1 attempts=2 status=removed' in r.stdout
          and 'PAIRS-DONE 1/1' in r.stdout and not (root / 'runs' / 'r-zz-1-a').exists(),
          'exact ENOTEMPTY is visible and a later real rm proves completed cleanup')

    for mode in ('persistent', 'deadline', 'permission', 'false-zero', 'warning', 'missing-diagnostic'):
        root, r = invoke(mode, mode)
        count = int((root / 'calls').read_text())
        check(r.returncode == 1 and 'PAIRS-CLEANUP-FAIL pair=1' in r.stderr
              and 'PAIRS-DONE' not in r.stdout and '1-waited' not in (root / 'hb').read_text(),
              mode + ': actual loop cannot count failed cleanup as progress or success')
        check(count == (50 if mode == 'persistent' else 1),
              mode + ': retry only exact ENOTEMPTY and bounded attempts; calls=' + str(count))

    # The pair's verdict comes from judge's table alone (ADR 0021's 2026-10-19 note): both launchers exited 0,
    # but in kill mode the one the SIGKILL targeted, which may exit 137 (or 0, when the kill came after it exited).
    # Any other status, the target's included, and a 137 of the launcher that was not killed (tego's own exit when
    # its agent was cgroup-killed, pkg/spec/identity/exit.go) fail the pair. The stand-ins leave whole runs, so a
    # killed one is killed-in-run.
    for mode, a, b, target, expected in (('plain', 0, 7, None, 1), ('timeout', 8, 0, None, 1),
                                         ('kill', 0, 0, 'a', 0), ('kill', 0, 0, 'b', 0),
                                         ('kill', 0, 137, 'b', 0), ('kill', 137, 0, 'a', 0),
                                         ('kill', 7, 8, 'a', 1), ('kill', 0, 7, 'a', 1), ('kill', 7, 0, 'a', 1),
                                         ('kill', 0, 7, 'b', 1), ('kill', 7, 0, 'b', 1),
                                         ('kill', 0, 137, 'a', 1), ('kill', 137, 0, 'b', 1),
                                         ('kill', 137, 137, 'a', 1)):
        label = 'actors-%s-%d-%d-%s' % (mode, a, b, target)
        root, r = invoke(label, actor_a=a, actor_b=b, pair_mode=mode, kill_target=target)
        check(r.returncode == expected and 'PAIRS-DONE %d/1' % (1 - expected) in r.stdout
              and not (root / 'kill-wrong').exists(),
              label + ': final exit reflects waited actor statuses and kill-mode surviving success: '
              + r.stdout + r.stderr)
        if mode == 'kill':
            # A kill landed when its target exited 137; another launcher's 137 is no kill of this script's.
            landed = int((a if target == 'a' else b) == 137)
            check('PAIR 1 rc=%d,%d kill=%s' % (a, b, target) in r.stdout
                  and ' kills=%d kills_started=%d' % (landed, landed) in r.stdout,
                  label + ': kills counts the target alone: ' + r.stdout)

    # A launcher that failed without being killed fails its pair, whatever its run holds (R2-1); a refusal by another
    # mechanism than the plane's fails any run's proof, a failed launcher's too.
    for defect, want in (('no-refusal', 'PAIRS-DONE 0/1'), ('none', 'PAIRS-DONE 0/1'),
                         ('wrong-mechanism', 'PAIRS-ASSERT-FAIL pair=1 what=refusal-mechanism')):
        label = 'kill-survivor-failed-' + defect
        root, r = invoke(label, actor_b=1, pair_mode='kill', kill_target='a', defect=defect, defect_run='b')
        check(r.returncode == 1 and want in r.stdout + r.stderr and 'PAIRS-DONE 1/1' not in r.stdout,
              label + ': a launcher that failed without being killed fails the pair: ' + r.stdout + r.stderr)

    # The per-pair proof (ADR 0021, A-0021-1): each run's ledger is read before cleanup removes it. A run that
    # started on another decision plane than the one pinned stops the script; on the first pair with 2, since
    # that is the binary or the host (a build without tegotesthooks ignores the pin), not a pair.
    root, r = invoke('ledger-plane-mismatch', defect='mismatch')
    check(r.returncode == 2 and 'PAIRS-ASSERT-FAIL pair=1 what=decision_plane want=fanotify got=lsm' in r.stderr
          and 'PAIRS-DONE' not in r.stdout and '1-waited' not in (root / 'hb').read_text(),
          'plane mismatch on the first pair: exit 2, no PAIRS-DONE: ' + r.stderr)
    check((root / 'runs' / 'r-zz-1-a' / 'events.jsonl').exists() and not (root / 'calls').exists(),
          'the assertion runs before cleanup: a failed pair keeps its ledgers and rm never ran')
    root, r = invoke('ledger-no-plane', defect='no-plane', defect_run='b')
    check(r.returncode == 2 and 'what=decision_plane want=fanotify got=none run=r-zz-1-b' in r.stderr,
          'a run_start with no decision_plane is a mismatch too: ' + r.stderr)

    # A launcher that exited 0 is owed all of it: its run, one refusal by the plane's mechanism, run_end with its
    # agent's exit, and its agent's word that the read was refused.
    for defect, effect, what in (('no-refusal', 'refused', 'refusal launcher=a'),
                                 ('other-path', 'refused', 'refusal launcher=a'),
                                 ('wrong-mechanism', 'refused', 'refusal-mechanism'),
                                 ('no-end', 'refused', 'run_end launcher=a'),
                                 ('orphaned', 'refused', 'run_end-reason launcher=a'),
                                 ('oom', 'refused', 'run_end-reason launcher=a'),
                                 ('no-start', 'refused', 'no-run launcher=a'),
                                 ('two-refusals', 'refused', 'refusals=2'),
                                 ('allowed-line', 'refused', 'unrefused-lines=1'),
                                 ('ok', 'none', 'read-unseen launcher=a'),
                                 ('ok', 'opened', 'secret-read launcher=a'),
                                 ('ok', 'cut', 'secret-read launcher=a'),
                                 ('ok', 'said', 'secret-read launcher=a')):
        label = 'ledger-%s-%s' % (defect, effect)
        root, r = invoke(label, defect=defect, effect=effect)
        check(r.returncode == 1 and 'PAIRS-ASSERT-FAIL pair=1 what=' + what in r.stderr
              and 'PAIRS-DONE' not in r.stdout and '1-waited' not in (root / 'hb').read_text()
              and (root / 'runs' / 'r-zz-1-a').exists(),
              label + ': the pair fails like a cleanup failure, its ledgers kept: ' + r.stderr)
    root, r = invoke('ledger-plain-incomplete', defect='no-refusal', defect_run='b')
    check(r.returncode == 1 and 'what=refusal launcher=b rc=0 target=0 run=r-zz-1-b' in r.stderr,
          'plain: both runs are owed: ' + r.stderr)

    # A run is its launcher's by run_start's launcher_pid. The killed launcher's run never stands in for the
    # survivor's: a survivor whose run failed open, was refused by another mechanism, or left nothing fails.
    for defect, what in (('no-refusal', 'refusal launcher=b'),
                         ('wrong-mechanism', 'refusal-mechanism path=' + secret + ' run=r-zz-1-b'),
                         ('none', 'no-run launcher=b')):
        root, r = invoke('kill-masking-' + defect, actor_a=137, pair_mode='kill', defect=defect, defect_run='b')
        check(r.returncode == 1 and 'PAIRS-ASSERT-FAIL pair=1 what=' + what in r.stderr and 'PAIRS-DONE' not in r.stdout,
              'kill: the killed launcher\'s complete run does not cover the survivor\'s (' + defect + '): '
              + r.stdout + r.stderr)
    root, r = invoke('ledger-foreign-pid', defect='foreign-pid')
    check(r.returncode == 1 and 'PAIRS-ASSERT-FAIL pair=1 what=foreign-run launcher_pid=1 run=r-zz-1-a' in r.stderr,
          'a run whose launcher_pid is no launcher of the pair fails it: ' + r.stderr)
    # Under MODE=timeout $! is timeout's pid; the launcher's is the one it wrote to pid.<a|b> (launch), and its run
    # is held to it like any other.
    root, r = invoke('timeout-own-pid', pair_mode='timeout')
    check(r.returncode == 0 and 'PAIRS-DONE 1/1 plane=fanotify copy_b=0 listener=0 mode=timeout' in r.stdout
          and not r.stderr, 'timeout: each run is its launcher\'s by the pid the launcher wrote: ' + r.stdout + r.stderr)
    root, r = invoke('timeout-no-refusal', actor_a=124, pair_mode='timeout', defect='no-refusal', defect_run='b')
    check(r.returncode == 1 and 'PAIRS-ASSERT-FAIL pair=1 what=refusal launcher=b rc=0' in r.stderr,
          'timeout: a run with no refusal fails beside a failed launcher: ' + r.stderr)

    # The stage's exec (of either launcher's binary, or of /proc/self/exe) is never recorded (ADR 0021 (2)).
    for exe in ('A', 'B', '/proc/self/exe'):
        root, r = invoke('stage-exec-' + exe.replace('/', '_'), defect='stage-exec:' + exe, defect_run='b')
        check(r.returncode == 1 and 'PAIRS-ASSERT-FAIL pair=1 what=stage-exec-recorded lines=1' in r.stderr
              and 'run=r-zz-1-b' in r.stderr, 'an exec line for ' + exe + ' fails the pair: ' + r.stderr)

    # The effect, not only the ledger's word. On the fallback the agent of the launcher the SIGKILL ended runs
    # undecided by fanotify until the reaper kills it (E15's stated window, enforce-cgroup-observe §6 E15, ADR 0020):
    # its read is that residual, counted and disclosed (killed_reads), never a pass of its check, and only when its
    # run shows the window: no refusal of the path (the listener records one only after its FAN_DENY) and a run its
    # reaper closed (run_end reason orphaned). A read beside the run's refusal is a ledger that says refused of a
    # read that went through (R3-1); one in a run its launcher closed was decided by a live listener.
    for label, defect, effect in (('killed-read', 'no-refusal+orphaned', 'opened'),
                                  ('killed-read-cut', 'no-refusal+orphaned', 'cut')):
        root, r = invoke(label, actor_b=137, pair_mode='kill', defect=defect, effect=effect, defect_run='b')
        check(r.returncode == 0 and 'PAIRS-KILLED-READ pair=1 launcher=b plane=fanotify' in r.stdout
              and 'PAIRS-DONE 1/1 plane=fanotify copy_b=0 listener=0 mode=kill kills=1 kills_started=1 killed_reads=1'
              in r.stdout and not r.stderr,
              label + ': the fallback: a killed launcher\'s unrefused read in its orphaned run is E15\'s window, '
              'counted: ' + r.stdout + r.stderr)
    for label, kw, what in (
            ('killed-read-after-refusal', dict(actor_b=137, defect='orphaned'), 'secret-read-after-refusal launcher=b'),
            ('killed-read-refused-launcher-end', dict(actor_b=137), 'secret-read launcher=b'),
            ('killed-read-launcher-end', dict(actor_b=137, defect='no-refusal'), 'refusal launcher=b'),
            ('killed-read-open', dict(actor_b=137, defect='no-refusal+no-end'), 'run_end launcher=b'),
            ('killed-read-no-run', dict(actor_b=137, defect='none'), 'read-without-run launcher=b'),
            ('killed-read-lsm', dict(actor_b=137, defect='no-refusal+orphaned', plane='lsm'), 'secret-read launcher=b'),
            ('killed-read-fmod_ret', dict(actor_b=137, defect='no-refusal+orphaned', plane='fmod_ret'),
             'secret-read launcher=b'),
            ('secret-leak-survivor', dict(actor_b=137, defect_run='a'), 'secret-read launcher=a'),
            ('secret-leak-kill-missed', dict(kill_target='b'), 'secret-read launcher=b'),
            ('secret-leak-not-target', dict(actor_b=137, kill_target='a', defect='no-refusal+orphaned'),
             'secret-read launcher=b'),
            ('secret-leak-target-failed', dict(actor_b=9, kill_target='b', defect='no-refusal+orphaned'),
             'secret-read launcher=b')):
        kw.setdefault('defect_run', 'b')
        root, r = invoke(label, pair_mode='kill', effect='opened', **kw)
        check(r.returncode == 1 and 'PAIRS-ASSERT-FAIL pair=1 what=' + what in r.stderr
              and 'PAIRS-KILLED-READ' not in r.stdout and 'PAIRS-DONE' not in r.stdout,
              label + ': a read the table does not explain fails the pair: ' + r.stdout + r.stderr)
    root, r = invoke('secret-leak-plain-137', actor_b=137, defect='no-refusal+orphaned', effect='opened',
                     defect_run='b')
    check(r.returncode == 1 and 'what=secret-read launcher=b rc=137 target=0' in r.stderr,
          'outside kill mode a 137 explains no read: ' + r.stdout + r.stderr)

    # The pair is judged once it settled: a killed launcher's run is closed by its reaper after the launcher's wait
    # returned (ADR 0020 (3)), and until then its agent may still write to the launcher's output. The stand-in reaper
    # writes the agent's late lines 0.5 s after its launcher exited, then run_end.
    for label, defect, late, ok, want in (
            ('late-killed-read', 'no-refusal+no-end', ('cut', 'orphaned'), True, 'PAIRS-KILLED-READ pair=1 launcher=b'),
            ('late-read-after-refusal', 'no-end', ('cut', 'orphaned'), False,
             'what=secret-read-after-refusal launcher=b'),
            ('late-killed-in-run', 'no-end', ('none', 'orphaned'), True, 'killed_reads=0')):
        root, r = invoke(label, actor_b=137, pair_mode='kill', defect=defect, effect='none', defect_run='b',
                         late=late, settle=3)
        check(r.returncode == (0 if ok else 1) and want in r.stdout + r.stderr
              and ('PAIRS-DONE 1/1' in r.stdout) == ok,
              label + ': the pair is judged on what its reaper left: ' + r.stdout + r.stderr)
    root, r = invoke('late-unsettled', actor_b=137, pair_mode='kill', defect='no-refusal+no-end', effect='none',
                     defect_run='b', late=('cut', 'orphaned'), settle=0)
    check(r.returncode == 1 and 'what=run_end launcher=b rc=137 target=1' in r.stderr,
          'a killed run its reaper has not closed within SETTLE fails: ' + r.stdout + r.stderr)

    # SELF_DENY (ADR 0021 (4)): one run before the pairs, of a contract that denies reading TEGO itself, judged as a
    # launcher of a pair; it must be complete.
    root, r = invoke('self-deny', self_deny=True)
    check(r.returncode == 0 and 'PAIRS-SELF-DENY ok path=' + self_link + ' plane=fanotify' in r.stdout
          and 'PAIRS-DONE 1/1' in r.stdout and not r.stderr, 'self-deny: a clean run passes: ' + r.stdout + r.stderr)
    for label, kw, want_rc, what in (
            ('self-deny-exit', {'actor_self': 3}, 1, 'self-deny-exit rc=3'),
            ('self-deny-no-refusal', {'defect': 'no-refusal'}, 1, 'refusal launcher=self'),
            ('self-deny-mechanism', {'defect': 'wrong-mechanism'}, 1, 'refusal-mechanism path=' + self_link + ' run=r-zz-1-self'),
            ('self-deny-mismatch', {'defect': 'mismatch'}, 2, 'decision_plane want=fanotify got=lsm'),
            ('self-deny-stage', {'defect': 'stage-exec:A'}, 1, 'stage-exec-recorded'),
            ('self-deny-proc-exe', {'defect': 'stage-exec:/proc/self/exe'}, 1, 'stage-exec-recorded'),
            ('self-deny-opened', {'effect': 'said'}, 1, 'secret-read launcher=self'),
            ('self-deny-unseen', {'effect': 'none'}, 1, 'read-unseen launcher=self'),
            ('self-deny-none', {'defect': 'none'}, 1, 'no-run launcher=self')):
        root, r = invoke(label, self_deny=True, defect_run='self', **kw)
        check(r.returncode == want_rc and 'PAIRS-ASSERT-FAIL pair=0 what=' + what in r.stderr
              and 'PAIRS-SELF-DENY' not in r.stdout and 'PAIRS-DONE' not in r.stdout
              and (root / 'hb').read_text().strip() == 'done',
              label + ': the self-deny run fails before any pair: ' + r.stdout + r.stderr)

    # Kill mode counts the kills that landed (the target's verdict is killed-*) and those whose run had started, and
    # fails a phase where fewer than KILL_MIN percent of the pairs lost a launcher.
    root, r = invoke('kills-counted', actor_b=137, pair_mode='kill', kill_min=50)
    check(r.returncode == 0 and 'mode=kill kills=1 kills_started=1' in r.stdout, 'kill: a landed kill: ' + r.stdout + r.stderr)
    for label, defect in (('kills-unstarted', 'none'), ('kills-unstarted-dir', 'no-start')):
        root, r = invoke(label, actor_a=137, pair_mode='kill', defect=defect, effect='none', kill_min=50)
        check(r.returncode == 0 and 'mode=kill kills=1 kills_started=0' in r.stdout,
              label + ': kill: a launcher killed before its run started: ' + r.stdout + r.stderr)
    # kills_started is the target's run, not the other launcher's.
    root, r = invoke('kills-unstarted-b', actor_b=137, pair_mode='kill', defect='none', effect='none', defect_run='b',
                     kill_min=50)
    check(r.returncode == 0 and 'mode=kill kills=1 kills_started=0' in r.stdout,
          'kill: b killed before its run started, a\'s run started: ' + r.stdout + r.stderr)
    root, r = invoke('kills-short', pair_mode='kill', kill_min=50)
    check(r.returncode == 1 and 'PAIRS-DONE 1/1 plane=fanotify copy_b=0 listener=0 mode=kill kills=0 kills_started=0'
          in r.stdout and 'PAIRS-KILLS-SHORT landed=0 want=1 pairs=1 kill_min=50' in r.stderr,
          'kill: too few landed kills fail the phase: ' + r.stdout + r.stderr)

    # judge's table, all of it: every combination of one launcher's evidence (its exit status, whether the kill
    # targeted it, its run's ledger, its agent's output) beside another launcher, whole or killed, on the fallback
    # and on a plane, run through assert_pair as written in one shell and held to the table as the ADR states it,
    # written out once more below. A combination the table does not name fails; nothing else passes.
    grid_ledgers = {
        # name: (ledger() defect, or None for no run directory; the table's view: None, 'unstarted' or
        # (refusals, by the plane's mechanism, other lines on the path, exec lines of the stage, run_end's reason))
        'none': (None, None), 'unstarted': ('no-start', 'unstarted'),
        'whole': ('ok', (1, True, 0, 0, 'exit')), 'orphaned': ('orphaned', (1, True, 0, 0, 'orphaned')),
        'open': ('no-end', (1, True, 0, 0, None)), 'oom': ('oom', (1, True, 0, 0, 'oom')),
        'unrefused': ('no-refusal', (0, True, 0, 0, 'exit')),
        'unrefused-orphaned': ('no-refusal+orphaned', (0, True, 0, 0, 'orphaned')),
        'unrefused-open': ('no-refusal+no-end', (0, True, 0, 0, None)),
        'unrefused-oom': ('no-refusal+oom', (0, True, 0, 0, 'oom')),
        'landlock': ('wrong-mechanism', (1, False, 0, 0, 'exit')),
        'landlock-orphaned': ('wrong-mechanism+orphaned', (1, False, 0, 0, 'orphaned')),
        'two': ('two-refusals', (2, True, 0, 0, 'exit')),
        'allowed': ('allowed-line', (1, True, 1, 0, 'exit')),
        'allowed-unrefused': ('allowed-line+no-refusal+orphaned', (0, True, 1, 0, 'orphaned')),
        'stage': ('stage-exec:A', (1, True, 0, 1, 'exit')),
    }

    def table(mode, kt, plane, launchers):
        """The verdict as ADR 0021's 2026-10-19 note states it: None for a PAIRS-ASSERT-FAIL, else (pair_ok,
        outcomes)."""
        unstarted = sum(1 for _, _, name, _ in launchers if grid_ledgers[name][1] == 'unstarted')
        for _, _, name, _ in launchers:
            run = grid_ledgers[name][1]
            if isinstance(run, tuple) and (run[0] > 1 or not run[1] or run[2] or run[3]):
                return None
        outcomes, spare = [], 0
        for tag, rc, name, effect in launchers:
            run = grid_ledgers[name][1]
            started = isinstance(run, tuple)
            refusals, end = (run[0], run[4]) if started else (0, None)
            opened = effect in ('opened', 'cut', 'said')
            killed = mode == 'kill' and tag == kt and rc == 137
            if rc == 0 or (killed and end == 'exit'):
                # Exited 0, or killed after it closed its run: the run is whole.
                if not (started and refusals == 1 and end == 'exit' and effect == 'refused'):
                    return None
                outcomes.append('complete' if rc == 0 else 'killed-in-run')
            elif killed:
                if not started:
                    if effect != 'none':
                        return None
                    outcomes.append('killed-early')
                elif end != 'orphaned':
                    return None
                elif not opened:
                    outcomes.append('killed-in-run')
                elif plane == 'fanotify' and refusals == 0 and end == 'orphaned':
                    outcomes.append('killed-read')
                else:
                    return None
            elif opened:
                return None
            else:
                outcomes.append('failed')
            spare += int(not started and rc != 0)
        if unstarted > spare:
            return None
        return ('failed' not in outcomes, outcomes)

    grid = base / 'grid'
    grid.mkdir()
    rows, combos = [], []
    others = {'whole': (0, 'whole', 'refused'), 'killed': (137, 'orphaned', 'none')}
    for mode, kt in (('plain', '-'), ('kill', 'a'), ('kill', 'b')):
        for plane in ('fanotify', 'lsm'):
            for side in ('a', 'b'):
                for other in (('whole',) if mode == 'plain' else ('whole', 'killed')):
                    for rc in (0, 1, 137):
                        for name in grid_ledgers:
                            for effect in ('refused', 'opened', 'cut', 'said', 'none'):
                                d = grid / str(len(combos))
                                (d / 'runs').mkdir(parents=True)
                                (d / 'out').mkdir()
                                pids = {'a': 1001, 'b': 1002}
                                launchers = []
                                for tag in ('a', 'b'):
                                    l_rc, l_name, l_effect = (rc, name, effect) if tag == side else others[other]
                                    launchers.append((tag, l_rc, l_name, l_effect))
                                    defect = grid_ledgers[l_name][0]
                                    if defect is not None:
                                        (d / 'runs' / ('r-' + tag)).mkdir()
                                        (d / 'runs' / ('r-' + tag) / 'events.jsonl').write_text(
                                            ledger(defect, plane).replace('@PID@', str(pids[tag])))
                                    (d / 'out' / tag).write_text(output(tag, l_effect))
                                combos.append((mode, kt, plane, launchers))
                                rows.append('%s %s %s %s 1001 %d 1002 %d' % (d, mode, kt, plane, launchers[0][1],
                                                                              launchers[1][1]))
    (grid / 'combos').write_text('\n'.join(rows) + '\n')
    grid_functions = extract('pcat', 'by_mechanism', 'ledger_facts', 'read_effect', 'settle', 'judge', 'assert_pair')
    result = subprocess.run(
        ['bash', '-c', 'set -u\nTEGO=A TEGO_B=B SETTLE=0\nsecret_text=\'' + secret_text + '\'\nnap() { :; }\n'
         + grid_functions + 'while read -r w MODE kt want_plane pa ra pb rb; do\n[ "$kt" != - ] || kt=""\n'
         'assert_pair 1 ' + secret + ' a "$pa" "$ra" "$w/out/a" b "$pb" "$rb" "$w/out/b" 2>"$w/err"\nst=$?\n'
         'echo "$st ${pair_ok} ${outcome[0]-} ${outcome[1]-}"\ndone <"$1"\n', 'grid', str(grid / 'combos')],
        capture_output=True, text=True, timeout=300, env={**os.environ, 'LC_ALL': 'C'})
    got = result.stdout.splitlines()
    wrong = []
    for i, (combo, line) in enumerate(zip(combos, got)):
        want = table(*combo)
        parts = line.split()
        err = (grid / str(i) / 'err').read_text()
        if want is None:
            good = parts[0] == '1' and err.startswith('PAIRS-ASSERT-FAIL pair=1 what=')
        else:
            good = (parts == ['0', str(int(want[0]))] + want[1]) and not err
        if not good:
            wrong.append('%r: got %r %r, want %r' % (combo, line, err.strip(), want))
    passes = sum(1 for c in combos if table(*c) is not None)
    check(result.returncode == 0 and not result.stderr and len(got) == len(combos) and not wrong,
          'judge: %d combinations of a launcher\'s evidence, %d passing, each as the table says (%d differ): %s %s'
          % (len(combos), passes, len(wrong), '\n'.join(wrong[:8]), result.stderr[-2000:]))
    shutil.rmtree(grid)

    # A run directory is one launcher's: two runs naming one launcher, one naming none, and a directory with no
    # run_start beside launchers that all wrote theirs, each fail the pair.
    def structure(label, dirs, rcs=(0, 0), mode='plain', kt=''):
        d = base / label
        (d / 'out').mkdir(parents=True)
        for name, pid, defect in dirs:
            (d / 'runs' / name).mkdir(parents=True)
            (d / 'runs' / name / 'events.jsonl').write_text(ledger(defect, 'fanotify').replace('@PID@', str(pid)))
        for tag in ('a', 'b'):
            (d / 'out' / tag).write_text(output(tag, 'refused' if rcs['ab'.index(tag)] == 0 else 'none'))
        return subprocess.run(
            ['bash', '-c', 'set -u\nTEGO=A TEGO_B=B SETTLE=0 want_plane=fanotify MODE=' + mode + ' kt=' + kt
             + '\nsecret_text=\'' + secret_text + '\'\nnap() { :; }\nw=' + str(d) + '\n' + grid_functions
             + 'assert_pair 1 ' + secret + ' a 1001 %d "$w/out/a" b 1002 %d "$w/out/b"\n' % rcs
             + 'echo "st=$? ok=${pair_ok} ${outcome[*]-}"\n'],
            capture_output=True, text=True, timeout=30, env={**os.environ, 'LC_ALL': 'C'})

    for label, dirs, rcs, mode, kt, want in (
            ('two-runs', (('r-a', 1001, 'ok'), ('r-a2', 1001, 'ok'), ('r-b', 1002, 'ok')), (0, 0), 'plain', '',
             'what=two-runs launcher=a runs=r-a,r-a2'),
            ('stray-unstarted', (('r-a', 1001, 'ok'), ('r-b', 1002, 'ok'), ('r-c', 1003, 'no-start')), (0, 0),
             'plain', '', 'what=unstarted-runs runs=1 launchers=0'),
            ('two-unstarted', (('r-a', 1001, 'ok'), ('r-c', 1003, 'no-start'), ('r-d', 1004, 'no-start')), (0, 137),
             'kill', 'b', 'what=unstarted-runs runs=2 launchers=1'),
            ('one-unstarted', (('r-a', 1001, 'ok'), ('r-c', 1003, 'no-start')), (0, 137), 'kill', 'b',
             'st=0 ok=1 complete killed-early'),
            ('foreign', (('r-a', 1001, 'ok'), ('r-b', 1002, 'ok'), ('r-c', 1003, 'ok')), (0, 0), 'plain', '',
             'what=foreign-run launcher_pid=1003 run=r-c')):
        r = structure('structure-' + label, dirs, rcs, mode, kt)
        check(want in r.stdout + r.stderr and (('st=0' in r.stdout) == want.startswith('st=0')),
              label + ': ' + r.stdout + r.stderr)

    # The kill point (R2-2): the loop draws it from the previous pair's length, 900 ms for the first pair, and the
    # draw is a delay in [0, span) ms written as seconds with three decimals (nap's argument) and a target, a or b.
    root, r = invoke('kill-draw-span', pair_mode='kill', pairs=2)
    draws = (root / 'draws').read_text().split() if (root / 'draws').exists() else []
    check(r.returncode == 0 and 'PAIRS-DONE 2/2' in r.stdout and len(draws) == 2 and draws[0] == '900'
          and re.fullmatch(r'\d+', draws[1]) and int(draws[1]) < 900,
          'kill: the first pair draws from 900 ms, the next from the first one\'s length: %r %s%s'
          % (draws, r.stdout, r.stderr))
    spans = (0, 1, 2, 7, 900, 1000, 12345, 3600000)
    draw = subprocess.run(['bash', '-c', extract('kill_draw') + 'set -u\nfor s in ' + ' '.join(map(str, spans))
                           + ' x ""; do for ((j = 0; j < 400; j++)); do\nkill_draw "$s"; echo "$s $kd $kt"\n'
                           'done; done\n'],
                          capture_output=True, text=True, timeout=60, env={**os.environ, 'LC_ALL': 'C'})
    seen = {}
    bad = []
    for line in draw.stdout.splitlines():
        parts = line.split(' ')
        span, kd, kt = parts if len(parts) == 3 else ['', '', '']
        m = re.fullmatch(r'(\d+)\.(\d{3})', kd)
        limit = int(span) if re.fullmatch(r'\d+', span) and int(span) >= 1 else 1
        ms = int(m.group(1)) * 1000 + int(m.group(2)) if m else -1
        if not m or not 0 <= ms < limit or kt not in ('a', 'b'):
            bad.append(line)
        seen.setdefault(span, []).append((ms, kt))
    check(draw.returncode == 0 and not draw.stderr and not bad and len(seen) == len(spans) + 2
          and all(len(v) == 400 for v in seen.values()),
          'kill_draw: every delay is in [0, span) ms as s.mmm, every target a or b: %r %r' % (bad[:5], draw.stderr))
    for span in ('900', '12345', '3600000'):
        ms = [d for d, _ in seen.get(span, [])]
        kts = {t for _, t in seen.get(span, [])}
        # 400 uniform draws: each quarter of the span holds some, and both launchers are targeted.
        check(len(ms) == 400 and kts == {'a', 'b'}
              and all(any(q * int(span) // 4 <= d < (q + 1) * int(span) // 4 for d in ms) for q in range(4)),
              'kill_draw: span %s is covered and both launchers drawn: %r' % (span, sorted(ms)[:3] + sorted(ms)[-3:]))

    # A plane mode's refusal is the plane's line (mechanism plane, the mode as decision_plane); the listener's
    # is not, and the other way round.
    root, r = invoke('ledger-lsm', plane='lsm')
    check(r.returncode == 0 and 'PAIRS-DONE 1/1 plane=lsm copy_b=0 listener=0 mode=plain' in r.stdout,
          'lsm: the plane\'s refusal line passes: ' + r.stdout + r.stderr)
    root, r = invoke('ledger-lsm-by-fanotify', plane='lsm', run_plane='fanotify')
    check(r.returncode == 2 and 'what=decision_plane want=lsm got=fanotify' in r.stderr,
          'lsm pinned, the run fell back to fanotify: exit 2: ' + r.stderr)
    # PLANE=auto takes the mode the first run reports and holds every later run to it.
    root, r = invoke('ledger-auto', plane='auto', run_plane='fmod_ret')
    check(r.returncode == 0 and 'PAIRS-PLANE fmod_ret' in r.stdout
          and 'PAIRS-DONE 1/1 plane=fmod_ret' in r.stdout, 'auto adopts the probe\'s mode: ' + r.stdout + r.stderr)
    root, r = invoke('ledger-auto-split', plane='auto', run_plane='fmod_ret', defect='mismatch', defect_run='b')
    check(r.returncode == 2 and 'what=decision_plane want=fmod_ret got=lsm run=r-zz-1-b' in r.stderr,
          'auto: a second run on another mode fails: ' + r.stderr)

    # The setup: COPY_B's second inode, and the third-party listener's ready handshake and stop.
    def setup(label, script, env=None, timeout=20):
        root = base / label
        root.mkdir()
        driver = root / 'setup.sh'
        driver.write_text('set -u\nw=$1\nTEGO=$w/tego\nCOPY_B_PATH=$w/tego-b\nlpid=\n'
                          'printf "#!/bin/sh\\n" >"$TEGO"\nchmod 755 "$TEGO"\n'
                          + setup_functions + script)
        proc = subprocess.run(['bash', str(driver), str(root)], capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, 'LC_ALL': 'C', **(env or {})})
        return root, proc

    root, r = setup('copy-b', 'COPY_B=1 TEGO_B=$TEGO b_given=\nsetup_copy_b; echo "rc=$? b=$TEGO_B"\n')
    m = re.search(r'^PAIRS-INODES a=(\S+) b=(\S+)$', r.stdout, re.M)
    check(r.returncode == 0 and 'rc=0 b=' + str(root / 'tego-b') in r.stdout and m and m.group(1) != m.group(2)
          and (root / 'tego-b').exists(), 'COPY_B=1: a copy at a second inode, both printed: ' + r.stdout + r.stderr)
    # A phase after the first finds COPY_B_PATH still executing: the last launcher out of the previous phase left its
    # build's linger timer running from it (ADR 0022), and writing over a busy executable is ETXTBSY. The copy goes in
    # by rename, so the timer keeps its inode and the new phase gets a fresh one with TEGO's bytes.
    root, r = setup('copy-b-busy', 'cp -- "$(command -v bash)" "$COPY_B_PATH"\n"$COPY_B_PATH" -c "read -r -t 30 _" </dev/zero &\nbusy=$!\n'
                    'while [ "$(readlink /proc/$busy/exe)" != "$COPY_B_PATH" ]; do :; done\n'
                    'busy_ino=$(stat -c %i "$COPY_B_PATH")\n'
                    'COPY_B=1 TEGO_B=$TEGO b_given=\nsetup_copy_b; echo "rc=$? b=$TEGO_B"\n'
                    'cmp -s "$TEGO" "$COPY_B_PATH" && echo same-bytes\n'
                    '[ "$(stat -c %i "$COPY_B_PATH")" != "$busy_ino" ] && echo fresh-inode\n'
                    'kill "$busy"; wait "$busy" 2>/dev/null\nls "$w"\n')
    check(r.returncode == 0 and 'rc=0 b=' + str(root / 'tego-b') in r.stdout and 'same-bytes' in r.stdout
          and 'fresh-inode' in r.stdout and 'PAIRS-INODES' in r.stdout and 'tego-b.new' not in r.stdout,
          'COPY_B=1 over a busy copy: renamed in, no temporary left: ' + r.stdout + r.stderr)
    for label, b in (('copy-b-hardlink', 'ln "$TEGO" "$w/hard"; TEGO_B=$w/hard'), ('copy-b-same', 'TEGO_B=$TEGO')):
        root, r = setup(label, 'COPY_B=1\n' + b + '\nb_given=1\nsetup_copy_b; echo "rc=$?"\n')
        check('rc=2' in r.stdout and 'PAIRS-SETUP-FAIL what=copy_b-same-inode' in r.stderr,
              label + ': COPY_B with the second launcher at the first one\'s inode is refused: ' + r.stdout + r.stderr)
    root, r = setup('copy-b-off', 'COPY_B=0 TEGO_B=$TEGO b_given=\nsetup_copy_b; echo "rc=$?"\n')
    check('rc=0' in r.stdout and 'PAIRS-INODES' not in r.stdout and not (root / 'tego-b').exists(),
          'COPY_B=0: nothing copied')

    # SELF_DENY's second name for TEGO's file: the one inode, made again by a later phase of the guest, and a failure
    # that ends the setup. SELF_DENY=0 leaves the launcher's file with its one name.
    root, r = setup('self-link', 'SELF_DENY=1 SELF_LINK=$w/d/tego-self\nmkdir "$w/d"\nsetup_self_link; echo "rc=$?"\n'
                    'setup_self_link; echo "again=$?"\n')
    check('rc=0' in r.stdout and 'again=0' in r.stdout and not r.stderr
          and os.path.samefile(root / 'tego', root / 'd' / 'tego-self'),
          'SELF_DENY=1: the link names TEGO\'s inode, and a later phase makes it again: ' + r.stdout + r.stderr)
    root, r = setup('self-link-fail', 'SELF_DENY=1 SELF_LINK=$w/no-such-dir/tego-self\nsetup_self_link; echo "rc=$?"\n')
    check('rc=2' in r.stdout and 'PAIRS-SETUP-FAIL what=self-link' in r.stderr,
          'a link that cannot be made ends the setup: ' + r.stdout + r.stderr)
    root, r = setup('self-link-off', 'SELF_DENY=0 SELF_LINK=$w/tego-self\nsetup_self_link; echo "rc=$?"\n')
    check('rc=0' in r.stdout and not (root / 'tego-self').exists(), 'SELF_DENY=0: no link')

    silent = base / 'silent-listener'
    silent.write_text('#!/bin/sh\necho $$ >"$PAIR_TEST_PIDFILE"\nexec sleep 60\n')
    silent.chmod(0o755)
    pidfile = base / 'silent.pid'
    root, r = setup('listener-timeout', 'LISTENER=' + str(silent) + ' LISTENER_READY=1 LISTENER_ARGS=\n'
                    'start_listener; echo "rc=$? lpid=$lpid"\n', env={'PAIR_TEST_PIDFILE': str(pidfile)})
    pid = int(pidfile.read_text())
    check('rc=2 lpid=\n' in r.stdout and 'PAIRS-LISTENER-FAIL what=ready-timeout' in r.stderr,
          'a listener that never says ready fails the setup with 2: ' + r.stdout + r.stderr)
    alive = True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        alive = False
    check(not alive, 'the silent listener was killed, not left holding marks')

    good = base / 'good-listener'
    good.write_text('#!/bin/bash\n'
                    'trap \'echo "PERMLISTENER-STATS events=9 tego=4 self=1 late=0 denied=0 exec=2 failed=0 '
                    'malformed=0 mode=allow-touch"; exit "${PAIR_TEST_LISTENER_RC:-0}"\' TERM\n'
                    'echo "args=$*" >&2\necho PERMLISTENER-READY\nwhile :; do sleep 0.05; done\n')
    good.chmod(0o755)
    root, r = setup('listener-ok', 'LISTENER=' + str(good) + ' LISTENER_READY=5 LISTENER_ARGS="-workers 2"\n'
                    'start_listener; echo "start=$?"\nstop_listener; echo "stop=$?"\n')
    check('start=0' in r.stdout and 'stop=0' in r.stdout
          and 'PAIRS-LISTENER rc=0 PERMLISTENER-STATS events=9 tego=4' in r.stdout
          and 'args=-mode allow-touch -workers 2' in (root / 'listener.err').read_text(),
          'a listener that says ready is started, then stopped with its stats kept: ' + r.stdout + r.stderr)
    root, r = setup('listener-fails', 'LISTENER=' + str(good) + ' LISTENER_READY=5 LISTENER_ARGS=\n'
                    'start_listener; echo "start=$?"\nstop_listener; echo "stop=$?"\n',
                    env={'PAIR_TEST_LISTENER_RC': '1'})
    check('start=0' in r.stdout and 'stop=1' in r.stdout and 'PAIRS-LISTENER-FAIL what=exit rc=1' in r.stderr,
          'a listener that exits non-zero at its stop fails the run: ' + r.stdout + r.stderr)
    root, r = setup('listener-died', 'LISTENER=' + str(good) + ' LISTENER_READY=5 LISTENER_ARGS=\n'
                    'start_listener; echo "start=$?"\nkill -KILL "$lpid"; wait "$lpid" 2>/dev/null\n'
                    'stop_listener; echo "stop=$?"\n')
    check('start=0' in r.stdout and 'stop=1' in r.stdout and 'PAIRS-LISTENER-FAIL what=died' in r.stderr,
          'a listener that died during the run fails it: ' + r.stdout + r.stderr)

    # The watchdog signals the launchers by their names: COPY_B's copy and the PIE are launchers too, and a launcher
    # a launcher started (any of the names) is not one. Stand-ins: scripts, whose comm is their file's name; TEGO
    # waits on a fifo with a builtin (no child), and TEGO_B starts TEGO as its child.
    root, r = setup('launchers', 'mkfifo "$w/f"\nprintf "#!/bin/bash\\nread -r -t \\"\\$1\\" _ <>\\"%s\\"\\n" "$w/f" >"$TEGO"\n'
                    'TEGO_B=$w/tego-pie\n'
                    'printf "#!/bin/bash\\n\\"%s\\" 30 &\\nwait\\n" "$TEGO" >"$TEGO_B"\nchmod 755 "$TEGO_B"\n'
                    '"$TEGO" 30 & a=$!\n"$TEGO_B" & b=$!\n'
                    'for _ in 1 2 3 4 5 6 7 8 9 10; do c=$(pgrep -P "$b"); [ -n "$c" ] && break; sleep 0.1; done\n'
                    'launcher_names\nl=" $(launchers | tr "\\n" " ")"\n'
                    'echo "a=$a b=$b c=$c l=$l"\ncase $l in *" $a "*) echo has-a ;; esac\n'
                    'case $l in *" $b "*) echo has-b ;; esac\ncase $l in *" $c "*) echo has-c ;; esac\n'
                    'kill $c $a $b 2>/dev/null\n')
    check('has-a' in r.stdout and 'has-b' in r.stdout and 'has-c' not in r.stdout and 'c=\n' not in r.stdout + '\n'
          and 'c= ' not in r.stdout,
          'launchers names TEGO\'s and TEGO_B\'s processes, not a launcher\'s child: ' + r.stdout + r.stderr)

    # The watchdog: the invocation's first run (pair 1, or the self-deny run) has COLD_STALL, every later pair STALL;
    # and recovery counts a heartbeat that moved before its check (the loop went on while the report was written).
    watch_functions = extract('watch', 'recovery')

    def watchdog(label, script):
        root = base / label
        root.mkdir()
        driver = root / 'watch.sh'
        driver.write_text('set -u\nw=$1\nnap() { sleep 0.1; }\nstacks() { echo STACKS; }\n'
                          'report() { echo "REPORT $1 $2 $3"; }\n' + watch_functions + script)
        return subprocess.run(['bash', str(driver), str(root)], capture_output=True, text=True, timeout=30,
                              env={**os.environ, 'LC_ALL': 'C'})

    r = watchdog('watch-cold', 'echo 1-start >"$w/hb"\nSTALL=1 COLD_STALL=3\nwatch\n')
    m = re.search(r'^REPORT 1 (\d+) 1-start$', r.stdout, re.M)
    check(m and int(m.group(1)) >= 3, 'pair 1 is held to COLD_STALL, not STALL: ' + r.stdout + r.stderr)
    r = watchdog('watch-self', 'echo 0-self >"$w/hb"\nSTALL=1 COLD_STALL=3\nwatch\n')
    m = re.search(r'^REPORT 0 (\d+) 0-self$', r.stdout, re.M)
    check(m and int(m.group(1)) >= 3, 'the self-deny run is held to COLD_STALL: ' + r.stdout + r.stderr)
    r = watchdog('watch-warm', 'echo 2-start >"$w/hb"\nSTALL=1 COLD_STALL=20\nwatch\n')
    m = re.search(r'^REPORT 2 (\d+) 2-start$', r.stdout, re.M)
    check(m and 1 <= int(m.group(1)) < 20, 'a later pair is held to STALL: ' + r.stdout + r.stderr)
    r = watchdog('recovery-moved', 'echo abort >"$w/hb"\nrecovery "SIGKILL to the launchers" 1-start; echo "rc=$?"\n')
    check('RECOVERED 0s after SIGKILL to the launchers (heartbeat 1-start -> abort' in r.stdout and 'rc=0' in r.stdout,
          'a heartbeat that moved before the check is a recovery: ' + r.stdout + r.stderr)
    r = watchdog('recovery-held', 'echo 1-start >"$w/hb"\nrecovery "SIGKILL to the launchers" 1-start; echo "rc=$?"\n')
    check('NOT RECOVERED 15s after SIGKILL to the launchers' in r.stdout and 'STACKS' in r.stdout and 'rc=1' in r.stdout,
          'a heartbeat that never moves is not: ' + r.stdout + r.stderr)

    # The report prints the pair's ledgers as they stand, then asks the launchers for their goroutines with SIGABRT,
    # the Go runtime's own: tego run forwards SIGQUIT to its agent and lives on (launch.HandledSignals). The
    # stand-in launcher says which signal it got and ends on SIGABRT, as the runtime does.
    stand = base / 'abrt-launcher'
    stand.write_text('#!/bin/bash\ntrap \'echo QUIT >>"$1/signals"\' QUIT\n'
                     'trap \'echo ABRT >>"$1/signals"; exit 2\' ABRT\necho ready >"$1/ready"\n'
                     'while :; do /bin/sleep 0.05; done\n')
    stand.chmod(0o755)
    root = base / 'report-abrt'
    (root / 'runs' / 'r-1').mkdir(parents=True)
    (root / 'out').mkdir()
    (root / 'runs' / 'r-1' / 'events.jsonl').write_text('{"kind":"run_start","launcher_pid":7}\n')
    driver = root / 'report.sh'
    driver.write_text('set -u\nw=$1\nlpid=\nnap() { /bin/sleep 0.1; }\nstacks() { echo STACKS; }\n'
                      + extract('pcat', 'report', 'recovery') + 'echo 3-start >"$w/hb"\n'
                      + '"' + str(stand) + '" "$w" &\nL=$!\nwhile [ ! -e "$w/ready" ]; do /bin/sleep 0.05; done\n'
                      'launchers() { echo "$L"; }\nreport 3 20 3-start\n')
    r = subprocess.run(['bash', str(driver), str(root)], capture_output=True, text=True, timeout=60,
                       env={**os.environ, 'LC_ALL': 'C'})
    signals = (root / 'signals').read_text().split() if (root / 'signals').exists() else []
    ledger_at = r.stdout.find('    {"kind":"run_start","launcher_pid":7}')
    abrt_at = r.stdout.find('=== WATCHDOG: SIGABRT to the launchers (')
    check(signals == ['ABRT'] and 0 <= ledger_at < abrt_at and 'SIGQUIT' not in r.stdout,
          'the report prints the ledgers, then asks for goroutines with SIGABRT: %r %s%s' % (signals, r.stdout, r.stderr))
PY
