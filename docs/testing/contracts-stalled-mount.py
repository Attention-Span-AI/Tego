#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Real stopped-FUSE acceptance, owed in a guest; see contracts-stuck-mount.md."""

import atexit
import ast
import hashlib
import html
import http.cookiejar
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).absolute().parent
WORDS = 'cannot tell: this location does not answer (a disconnected or stuck mount?)'
NAME_WORDS = ("discovery is incomplete, so that name cannot be proven unambiguous; "
              "give the rules file's path")
BOUND = 70
PAGE_BOUND = 20
# A page that has to wait for a helper slot held by other commands' stuck helpers waits for its request's whole bound
# (25 s: the server's 30 s write deadline less a 5 s margin, ADR 0144, 2026-11-21), then is answered with the capacity
# words. The recipe's client makes two requests, the sign-in, which lands on the overview, and the page: 2 * 25 s and a
# margin. (40 s killed a page that the dashboard answered at 25 s and 50 s, 2026-11-21.)
CAPACITY_PAGE_BOUND = 60
WORKERS = 32
CAPACITY = '32 filesystem helpers are still alive'
# The longest a healthy helper lives (ADR 0144, 2026-11-21, fix29): the start-up budget 30 s, the location cap 20 s, the
# paused compile allowance 55 s and a 10 s margin. A pool whose every holder is older than that is stuck by definition,
# and a command or a page is refused at once, naming them: the answer needs no 25 s or 30 s wait.
HELPER_MAX_LIFETIME = 30 + 20 + 55 + 10
STUCK = f'{WORKERS} earlier checks are still stuck on a location that does not answer'
# A refusal at once: well inside a request's wait, and a page's sign-in landing and its page together.
AGED_BOUND = 10
AGED_PAGE_BOUND = 20


def check_identity(identity, uids, gids, sudo_lines, uid, gid, name, other_uid=54320):
    expected_uid = {'user': uid, 'real-root': 0, 'sudo': 0, 'other-uid': other_uid}[identity]
    expected_gid = {'user': gid, 'real-root': 0, 'sudo': 0, 'other-uid': other_uid}[identity]
    assert uids == [expected_uid] * 4, (identity, uids)
    assert gids == [expected_gid] * 4, (identity, gids)
    if identity == 'sudo':
        assert f'{uid}:{gid}:{name}' in sudo_lines, sudo_lines
    else:
        assert sudo_lines == [], (identity, sudo_lines)


def check_command(rc, elapsed, bound, want):
    assert rc is not None, 'command was not reaped before its bound'
    assert elapsed < bound, (elapsed, bound)
    if want is not None:
        assert rc == want, (rc, want)


def check_http(status, elapsed, bound=PAGE_BOUND):
    assert status == 200, status
    assert elapsed < bound, ('complete dashboard response exceeded bound', elapsed)


def check_host_status(wrapper, harness, qemu, console):
    assert wrapper == '0', ('wrapper status', wrapper)
    assert harness == 'guest 0', ('harness status', harness)
    assert qemu == '0', ('QEMU status', qemu)
    assert 'CONTRACTS-STALLED-MOUNT-GUEST PASS' in console.splitlines(), 'missing final sentinel'


def check_catalog(identity, catalog, source, healthy):
    entries = {entry['path']: entry for entry in catalog['contracts']}
    if identity == 'other-uid':
        assert catalog['incomplete'] is True
        assert source not in entries and healthy not in entries, entries
        assert any(issue['code'] == 'other-owner' for issue in catalog['issues'])
    else:
        expected = 'unsafe' if identity == 'real-root' else 'compiles'
        assert catalog['incomplete'] is (identity == 'real-root'), catalog
        for path in (source, healthy):
            assert path in entries, ('recorded entry disappeared', identity, path)
            assert entries[path]['state'] == expected, (identity, entries[path])
            if identity == 'real-root':
                assert any(d['code'] == 'source-unreadable' and 'untrusted' in d['message']
                           for d in entries[path]['diagnostics']), entries[path]


def check_stalled_catalog(identity, catalog, source, healthy):
    if identity == 'other-uid':
        check_catalog(identity, catalog, source, healthy)
        return
    assert catalog['incomplete'] is True, 'stalled catalogue claims completeness'
    assert any(entry['path'] == source and entry['state'] == 'incomplete'
               for entry in catalog['contracts']), 'stalled source missing or not incomplete'
    if identity == 'user':
        assert any(entry['path'] == healthy and entry['state'] == 'compiles'
                   for entry in catalog['contracts']), 'healthy source missing or no longer compiles'


def check_source_owner(observed_uid, expected_uid):
    assert observed_uid == expected_uid, ('mount changed the source owner boundary', observed_uid, expected_uid)


def check_stopped_server(returncode, status):
    assert returncode is None, ('server exited before abort', returncode)
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    state = fields.get('State', '').strip().split()
    assert state and state[0] == 'T', ('server resumed before abort', status)


def check_source_control(identity, text):
    if identity != 'user':
        assert 'owned by uid' in text and 'rulefile: refused' in text, text
    else:
        assert 'compiles' in text, text
    check_answered(text)


def check_answered(text):
    assert WORDS not in text, 'normally answering source reports unavailable'


# The words of a checker that was starved or still working, or that did not start in time (ADR 0144, 2026-11-20): none
# of them may be said about a stuck mount, and none may be said about a healthy location on a loaded machine.
BUSY_WORDS = ("Tego's checker was too slow to finish", 'the check was still working when its time ran out',
              'the check did not finish in time', "Tego's checker did not start in time")


def check_loaded_healthy(text):
    assert 'compiles' in text, text
    check_answered(text)
    assert not any(words in text for words in BUSY_WORDS), ('a healthy location on a loaded guest said busy words', text)


def check_loaded_stuck(text, elapsed):
    assert WORDS in text, ('a stuck mount on a loaded guest did not say the mount words', text)
    assert not any(words in text for words in BUSY_WORDS), ('a stuck mount on a loaded guest said busy words', text)
    assert 4.5 <= elapsed < 20, ('the mount words came outside five seconds of location time (a starved helper is given more)', elapsed)


def check_unavailable(text, name_selector=False):
    expected = NAME_WORDS if name_selector else WORDS
    assert expected in text, 'missing CLI name refusal' if name_selector else 'missing CLI cannot-tell reason'


def check_root_refusal(text):
    assert 'never as root' in text, text


def check_page(route, text, ref, unavailable, capacity, aged=False):
    if unavailable and capacity:
        # While the helpers are young no checker could start and no location was asked: the page says what is known (the
        # capacity words, below), and never that a location does not answer (ADR 0144, 2026-11-20 and 2026-11-21). Once
        # every holder is older than any check can live, they are stuck on a location, and the page says that (fix29).
        assert 'cannot tell' in text, 'missing cannot-tell reason'
        assert STUCK in text or WORDS not in text, 'a page whose checker could not start blames a location'
    elif unavailable:
        assert WORDS in text, 'missing cannot-tell reason'
    if unavailable:
        assert ref in text, 'the recorded entry disappeared'
        if route.startswith('/rules/change?'):
            assert 'method="post"' not in text, 'unavailable file offers a write form'
        if route.startswith('/rules?'):
            assert f'href="/rules/change?c={ref}"' not in text
            assert 'disabled' in text
            if not capacity:
                assert 'Can run true' in text, 'recorded rule disappeared'
                assert "The run's copy" in text and 'name: deadproj' in text, 'recorded YAML disappeared'
                assert 'run copy line ' in text, 'recorded copy positions disappeared'
    if capacity and aged:
        assert STUCK in text, 'missing stuck-helpers reason'
    elif capacity:
        # The pool ages while the recipe's pages are made: a later page can already be refused as stuck.
        assert CAPACITY in text or STUCK in text, 'missing shared-capacity reason'


def check_recovered_page(text, ref):
    assert WORDS not in text, 'dashboard did not recover after the mount was detached'
    assert ref in text, 'recovered recorded entry disappeared'


def check_workers(found, expected_uid=None, require_blocked=False):
    assert len(found) <= WORKERS, len(found)
    if expected_uid is not None:
        for item in found.values():
            for task in item['tasks']:
                assert task['uid'] == [str(expected_uid)] * 4, task
    if require_blocked:
        assert found, 'no actual helper remained blocked'
        # Kernel FUSE waits can be killable/interruptible. A ptrace stop is not
        # evidence, and no particular D/S state is promised across kernels.
        assert any('fuse' in task['wchan'] or 'request_wait_answer' in task['wchan']
                   for item in found.values() for task in item['tasks']), found


def check_aged_refusal(text):
    assert STUCK in text, 'a pool of helpers older than any check can live was not refused as stuck'
    assert CAPACITY not in text, 'an aged pool still waited for a slot'


def check_capacity(before, after):
    assert len(before) == WORKERS and after == before, (before, after)


def check_gone(found, remaining):
    assert not found and not remaining, ('helpers survived or were not reaped', found, remaining)


def check_exit(status, exists, exited_early):
    assert not exited_early, 'dashboard exited before cleanup was requested'
    assert status in (0, -signal.SIGTERM), ('dashboard cleanup status', status)
    assert not exists, 'dashboard still exists in /proc after wait'


def check_server_exit(abort, status, exists):
    assert status == (-signal.SIGKILL if abort == 'kill' else 0), (abort, status)
    assert not exists, 'FUSE server still exists in /proc after wait'


def check_driver_wiring(source):
    """Keep phase controls and the final sentinel bound to their real actions."""
    tree = ast.parse(source)
    phase = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                 and node.name == 'phase')
    expected_controls = {'mounted-healthy', 'mounted-owner-boundary', 'mounted-own-source', 'healthy-source-still-checks',
                         'recovered-list', 'recovered-explicit-source', 'recovered-own-source'}
    controls = set()
    for node in ast.walk(phase):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in ('invoke', 'catalog_control') or len(node.args) < 2:
            continue
        label = ast.unparse(node.args[0])
        for suffix in expected_controls:
            if suffix in label:
                assert isinstance(node.args[1], ast.Name) and node.args[1].id == 'identity', label
                controls.add(suffix)
    assert controls == expected_controls, controls
    catalog_control = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                           and node.name == 'catalog_control')
    for scope, called in ((catalog_control, 'check_catalog'), (phase, 'check_stalled_catalog'),
                          (phase, 'check_source_control')):
        calls = [node for node in ast.walk(scope) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == called]
        assert calls, ('phase acceptance validator was removed', called)
        for call in calls:
            assert isinstance(call.args[0], ast.Name) and call.args[0].id == 'identity', called
    for suffix in ('-capacity-page-', '-recovered-page-'):
        calls = [node for node in ast.walk(phase) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'page'
                 and suffix in ast.unparse(node.args[0])]
        assert calls, ('phase page control was removed', suffix)
        for call in calls:
            assert isinstance(call.args[1], ast.Name) and call.args[1].id == 'identity', suffix
    unavailable = [node for node in ast.walk(phase) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == 'check_unavailable'
                   and isinstance(node.args[0], ast.Name) and node.args[0].id == 'text']
    assert len(unavailable) == 1
    assert len(unavailable[0].args) == 2 and ast.unparse(unavailable[0].args[1]) == "args == ['show', 'deadproj']", 'name-selector refusal is not checked separately'
    assert 'capacity=True' in ast.unparse(phase), 'shared capacity never checked by a page'
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    phase_calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == 'phase']
    assert phase_calls, 'identity phase matrix was removed'
    for call in phase_calls:
        assert isinstance(call.args[1], ast.Name) and call.args[1].id == 'identity', 'phase matrix identity'
    final = ast.unparse(main.body[-1])
    cleanup = ast.unparse(main.body[-3])
    assert 'CONTRACTS-STALLED-MOUNT-GUEST PASS' in final
    assert 'finally:' in cleanup and 'stop_services()' in cleanup
    assert 'gone(' in ast.unparse(main.body[-2])


def http_client(link, route, bound=PAGE_BOUND):
    # Run this subprocess as the service uid: the real peer-uid guard stays on.
    started = time.monotonic()
    deadline = started + bound

    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError(f'dashboard sign-in and page exceeded {bound} seconds')
        return budget

    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    with opener.open(link, timeout=remaining()) as response:
        response.read()
    origin = link.split('/?t=', 1)[0]
    with opener.open(origin + route, timeout=remaining()) as response:
        body = response.read().decode()
        check_http(response.status, time.monotonic() - started, bound)
    remaining()  # Include both authentication and the complete response body.
    sys.stdout.write(body)


def main():
    assert os.getuid() == 0
    assert os.environ.get('TEGO_DISPOSABLE_HOST') == 'kvm', 'disposable guest only'
    uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    assert uid != 0
    account = pwd.getpwuid(uid)
    root = Path('/vm/contracts-stalled-mount')
    root.mkdir(mode=0o755)  # Fresh evidence only. Never reuse a prior ledger.
    binary, control = '/vm/tego', '/vm/tego-control'
    assert Path(binary).is_file() and Path(control).is_file()
    assert Path('/dev/fuse').exists()
    # Install only staged, hashed host-userland files into this disposable guest.
    # The driver itself remains root, and every sudo cell starts from the user.
    sudo_stage = Path('/vm/sudo-support')
    manifest = json.loads((sudo_stage / 'manifest.json').read_text())
    for target, facts in manifest.items():
        staged = sudo_stage / target.lstrip('/')
        assert hashlib.sha256(staged.read_bytes()).hexdigest() == facts['sha256']
        destination = Path(target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + '.contracts-stage')
        shutil.copyfile(staged, temporary)
        os.chown(temporary, 0, 0)
        temporary.chmod(0o4755 if target == '/usr/bin/sudo' else facts['mode'])
        temporary.replace(destination)  # Never truncate a library this driver maps.
    Path('/etc/sudoers').write_text(
        'Defaults env_reset\nDefaults secure_path="/usr/local/bin:/usr/bin:/bin"\n'
        + account.pw_name + ' ALL=(root) NOPASSWD: ALL\n')
    Path('/etc/sudoers').chmod(0o440)
    Path('/etc/pam.d').mkdir(exist_ok=True)
    Path('/etc/pam.d/sudo').write_text(
        'auth required pam_permit.so\naccount required pam_permit.so\n'
        'session required pam_permit.so\n')
    pending, services = [], []
    serial = 0

    def stop_services():
        failures = []
        for child, log, err in services:
            try:
                exited_early = child.poll() is not None
                if not exited_early:
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=10)
                print('DASHBOARD STATUS', child.pid, child.returncode, flush=True)
                check_exit(child.returncode, Path(f'/proc/{child.pid}').exists(), exited_early)
            except (AssertionError, subprocess.TimeoutExpired) as error:
                failures.append(str(error))
            finally:
                for name, handle in (('STDOUT', log), ('STDERR', err)):
                    handle.flush()
                    handle.seek(0)
                    print('DASHBOARD', name, child.pid, handle.read(), flush=True)
                log.close()
                err.close()
        services.clear()
        assert not failures, failures

    atexit.register(stop_services)

    def put(path, text, owner=uid, group=gid, mode=0o644):
        path.write_text(text)
        os.chown(path, owner, group)
        path.chmod(mode)
        return path

    def directory(path, owner=uid, group=gid, mode=0o755):
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, owner, group)
        path.chmod(mode)
        return path

    ledger = directory(root / 'ledger')
    healthy = directory(root / 'healthy')
    mount = directory(root / 'mounted')
    project = directory(mount / 'project')
    source = str(project / 'agent.yaml')
    contract = ('version: 0\nname: deadproj\ncommand: [/bin/true]\n'
                'tier: landlock\ncapture: off\nexec:\n  allow: [/bin/true]\n')
    put(project / 'agent.yaml', contract)
    backing = put(root / 'fuse-agent.yaml', contract)
    put(healthy / 'agent.yaml', contract.replace('deadproj', 'healthy'))

    other_uid = 54320
    try:
        pwd.getpwuid(other_uid)
        raise AssertionError('uid 54320 must be unused in this disposable guest')
    except KeyError:
        pass
    with open('/etc/passwd', 'a') as out:
        out.write('contracts-other:x:54320:54320::/home/contracts-other:/bin/sh\n')
    with open('/etc/group', 'a') as out:
        out.write('contracts-other:x:54320:\n')
    directory(Path('/home/contracts-other'), other_uid, other_uid)

    identities, controls = {}, {}
    for name, owner, group in (
            ('user', uid, gid), ('real-root', 0, 0),
            ('sudo', 0, 0), ('other-uid', other_uid, other_uid)):
        state = directory(root / name, owner, group)
        own = directory(state / 'own', owner, group, 0o700)
        runtime = directory(state / 'runtime', owner, group, 0o700)
        config = put(state / 'config.yaml', f'version: 0\nledger_root: {ledger}\n',
                     owner, group, 0o600)
        control_dir = directory(state / 'healthy', owner, group)
        controls[name] = put(control_dir / 'agent.yaml',
                             contract.replace('deadproj', 'control-' + name), owner, group)
        env = dict(PATH='/usr/local/bin:/usr/bin:/bin', TEGO_CONFIG=str(config),
                   TEGO_TEST_CHAIN_ANCHOR=str(own / 'chain.log'),
                   TEGO_TEST_OWN_LOG_HOME=str(own), XDG_RUNTIME_DIR=str(runtime),
                   HOME=pwd.getpwuid(owner).pw_dir, USER=pwd.getpwuid(owner).pw_name)
        identities[name] = (owner, group, env)

    def command(identity, argv):
        owner, group, env = identities[identity]
        if identity == 'sudo':
            # Real setuid sudo creates the SUDO metadata. env adds the selected
            # fixture paths after sudo's normal environment sanitization; it
            # does not clear or fabricate sudo's own variables.
            user_env = identities['user'][2]
            return ['setpriv', f'--reuid={uid}', f'--regid={gid}', '--clear-groups',
                    'env', '-i', *[f'{key}={value}' for key, value in user_env.items()],
                    '/usr/bin/sudo', '-n', '-u', 'root', '--', '/usr/bin/env',
                    *[f'{key}={value}' for key, value in env.items()], *argv]
        return ['setpriv', f'--reuid={owner}', f'--regid={group}', '--clear-groups',
                'env', '-i', *[f'{key}={value}' for key, value in env.items()], *argv]

    def invoke(label, identity, argv, want=None, cwd=healthy, bound=BOUND):
        nonlocal serial
        serial += 1
        label = f'{serial:03d}-{label}'
        stdout = open(root / (label + '.stdout'), 'w+')
        stderr = open(root / (label + '.stderr'), 'w+')
        start = time.monotonic()
        cmd = command(identity, argv)
        child = subprocess.Popen(cmd, cwd=str(cwd), stdout=stdout, stderr=stderr)
        while child.poll() is None and time.monotonic() - start < bound:
            time.sleep(0.02)
        elapsed = time.monotonic() - start
        stdout.seek(0)
        stderr.seek(0)
        text, errors = stdout.read(), stderr.read()
        stdout.close()
        stderr.close()
        print(json.dumps(dict(label=label, argv=cmd, pid=child.pid, rc=child.returncode,
                              elapsed=elapsed, stdout=text, stderr=errors)), flush=True)
        if child.returncode is None:
            child.kill()  # Never wait here: abort FUSE first, in finally below.
            pending.append(child)
            raise AssertionError(f'{label}: command was not reaped before {bound}s')
        check_command(child.returncode, elapsed, bound, want)
        return child.returncode, html.unescape(text + errors)

    for identity in identities:
        # /proc reports real/effective/saved/fs ids; real root has no fabricated
        # sudo environment, while the sudo cell starts as the delegated uid.
        probe = ('import json, os; from pathlib import Path; '
                 's=dict(line.split(":",1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line); '
                 'print(json.dumps(dict(uids=[int(x) for x in s["Uid"].split()], '
                 'gids=[int(x) for x in s["Gid"].split()], '
                 'sudo=[":".join(os.environ[k] for k in ("SUDO_UID","SUDO_GID","SUDO_USER"))] '
                 'if "SUDO_UID" in os.environ else [])))')
        _, text = invoke(identity + '-actual-provenance', identity, ['python3', '-I', '-c', probe], 0)
        facts = json.loads(text)
        check_identity(identity, facts['uids'], facts['gids'], facts['sudo'], uid, gid, account.pw_name)

    # The harness's delegated cgroup is inherited by this child. Recording from
    # each real cwd matters: an absolute source from healthy would record it wrong.
    invoke('record-healthy', 'user', [binary, 'run', 'agent.yaml'], 0)
    invoke('record-dead', 'user', [binary, 'run', 'agent.yaml'], 0, cwd=project)
    # Root/other uid read exactly the user's ledger; source ownership stays user.
    for folder, dirs, files in os.walk(ledger):
        Path(folder).chmod(0o755)
        for name in files:
            (Path(folder) / name).chmod(0o644)

    def workers():
        found = {}
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                argv = (path / 'cmdline').read_bytes().split(b'\0')
                if b'__contracts-check' not in argv:
                    continue
                status = (path / 'status').read_text()
                tasks = []
                for task in (path / 'task').iterdir():
                    fields = dict(line.split(':', 1) for line in
                                  (task / 'status').read_text().splitlines() if ':' in line)
                    tasks.append(dict(tid=int(task.name), state=fields['State'].strip(),
                                      uid=fields['Uid'].split(), gid=fields['Gid'].split(),
                                      wchan=(task / 'wchan').read_text().strip()))
                found[int(path.name)] = dict(argv=[os.fsdecode(a) for a in argv if a],
                                            status=status, tasks=tasks)
            except (FileNotFoundError, ProcessLookupError):
                continue
        return found

    def snapshot(label, expected_uid=None, require_blocked=False):
        found = workers()
        (root / (label + '-helpers.json')).write_text(json.dumps(found, indent=2))
        print('HELPERS', label, len(found), json.dumps(found), flush=True)
        check_workers(found, expected_uid, require_blocked)
        return set(found)

    def gone(known):
        limit = time.monotonic() + 15
        while time.monotonic() < limit:
            found = workers()
            remaining = {pid for pid in known if (Path('/proc') / str(pid)).exists()}
            if not found and not remaining:
                check_gone(found, remaining)
                print('HELPERS EXITED AND REAPED', sorted(known), flush=True)
                return
            time.sleep(0.02)
        check_gone(workers(), {pid for pid in known if (Path('/proc') / str(pid)).exists()})

    def start_dashboard(identity):
        log = open(root / (identity + '-serve.stdout'), 'w+')
        err = open(root / (identity + '-serve.stderr'), 'w+')
        child = subprocess.Popen(command(identity, [control, 'serve', '--addr',
                                                    '127.0.0.1:0', '--ledger', str(ledger)]),
                                 cwd=str(healthy), stdout=log, stderr=err)
        services.append((child, log, err))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            log.seek(0)
            match = re.search(r'Tego dashboard: (http://[^\s]+)', log.read())
            if match:
                return match[1]
            assert child.poll() is None, 'dashboard failed before printing its link'
            time.sleep(0.02)
        raise AssertionError('dashboard startup exceeded 15s')

    def page(label, identity, link, route, unavailable=False, capacity=False, aged=False):
        bound = AGED_PAGE_BOUND if aged else CAPACITY_PAGE_BOUND if capacity else PAGE_BOUND
        rc, text = invoke(label, identity,
                          ['python3', '-I', str(Path(__file__).absolute()),
                           '--http', link, route, str(bound)], 0, bound=bound)
        check_page(route, text, ref, unavailable, capacity, aged)
        return text

    def catalog_control(label, identity):
        want = 125 if identity in ('real-root', 'other-uid') else 0
        _, text = invoke(label, identity, [binary, 'contracts', '--json'], want,
                         cwd=controls[identity].parent)
        catalog, _ = json.JSONDecoder().raw_decode(text.lstrip())
        check_catalog(identity, catalog, source, str(healthy / 'agent.yaml'))
        check_answered(text)

    ref = hashlib.sha256(source.encode()).hexdigest()[:16]
    user_link = start_dashboard('user')
    other_link = start_dashboard('other-uid')
    for identity in ('real-root', 'sudo'):
        _, text = invoke(identity + '-serve-refuses-root', identity,
                         [control, 'serve', '--addr', '127.0.0.1:0'], want=125)
        check_root_refusal(text)
    page('healthy-rules', 'user', user_link, '/rules?c=' + ref)
    page('healthy-change', 'user', user_link, '/rules/change?c=' + ref)

    def phase(label, identity, exhaustion=False, abort='kill'):
        gone(set(workers()))  # Healthy workers may still be finishing pipe EOF.
        log = open(root / (label + '-fuse.log'), 'w+')
        server = subprocess.Popen(['python3', '-I', str(HERE / 'contracts-fuse-server.py'),
                                   str(mount), str(uid), str(gid), str(backing)],
                                  stdout=log, stderr=subprocess.STDOUT)
        known = set()
        connection = None

        def stopped():
            rc = server.poll()
            status = Path(f'/proc/{server.pid}/status').read_text() if rc is None else ''
            check_stopped_server(rc, status)

        try:
            limit = time.monotonic() + 10
            while f' {mount} ' not in Path('/proc/self/mountinfo').read_text():
                assert server.poll() is None and time.monotonic() < limit
                time.sleep(0.02)
            # Find this fixture's FUSE connection from the mount major:minor.
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                fields = line.split()
                if fields[4] == str(mount):
                    connection = fields[2].split(':')[1]
            check_source_owner(Path(source).stat().st_uid, uid)
            _, text = invoke(label + '-mounted-healthy', identity,
                             [binary, 'contracts', 'show', source],
                             0 if identity == 'user' else 125, cwd=controls[identity].parent)
            check_source_control(identity, text)
            catalog_control(label + '-mounted-owner-boundary', identity)
            invoke(label + '-mounted-own-source', identity,
                   [binary, 'contracts', 'show', str(controls[identity])], 0,
                   cwd=controls[identity].parent)
            gone(set(workers()))
            os.kill(server.pid, signal.SIGSTOP)
            limit = time.monotonic() + 5
            while '\nState:\tT' not in Path(f'/proc/{server.pid}/status').read_text():
                assert time.monotonic() < limit
                time.sleep(0.01)
            stopped()
            (root / (label + '-mountinfo')).write_text(Path('/proc/self/mountinfo').read_text())
            print('MOUNTINFO', label, Path('/proc/self/mountinfo').read_text(), flush=True)
            variants = [[], ['--json'], ['show', 'deadproj'], ['show', source],
                        ['show', str(project) + '/../project/agent.yaml']]
            for index, args in enumerate(variants if not exhaustion else [['show', source]] * (WORKERS + 1)):
                before = set(workers())
                _, text = invoke(label + '-cli-' + str(index), identity,
                                 [binary, 'contracts', *args], 125, cwd=controls[identity].parent)
                stopped()
                if exhaustion and CAPACITY in text:
                    check_capacity(before, set(workers()))
                    known |= before
                    full_at = time.monotonic()  # every holder started before this
                    print('CROSS-COMMAND EXHAUSTION REFUSES WITHOUT NEW HELPER', flush=True)
                    break
                if identity == 'other-uid' and not exhaustion and index < 3:
                    # The CLI deliberately excludes another uid's recorded
                    # sources before touching them. Name lookup must not bypass
                    # that boundary merely to demonstrate a mount timeout.
                    check_answered(text)
                    if args == ['--json']:
                        catalog, _ = json.JSONDecoder().raw_decode(text.lstrip())
                        check_stalled_catalog(identity, catalog, source, str(healthy / 'agent.yaml'))
                    # A healthy request's worker can still be consuming pipe
                    # EOF after the CLI was reaped. Wait for that lifecycle to
                    # finish; a worker blocked on the foreign source cannot.
                    gone(set(workers()))
                    continue
                check_unavailable(text, args == ['show', 'deadproj'])
                if args == ['--json']:
                    catalog, _ = json.JSONDecoder().raw_decode(text.lstrip())
                    check_stalled_catalog(identity, catalog, source, str(healthy / 'agent.yaml'))
                known |= snapshot(label + '-cli-' + str(index), identities[identity][0], True)
            else:
                assert not exhaustion, 'shared budget did not refuse at its documented bound'
            if exhaustion and identity in ('user', 'other-uid'):
                # The dashboard and fresh CLI commands share the same uid/netns
                # reservation pool. Exercise every recorded-path page at its
                # actual service uid while all 32 reservations are held.
                link = other_link if identity == 'other-uid' else user_link
                for route in ('/rules?c=' + ref, '/rules/change', '/rules/change?c=' + ref):
                    before = set(workers())
                    page(label + '-capacity-page-' + route.split('?')[0].replace('/', '-'),
                         identity, link, route, unavailable=True, capacity=True)
                    stopped()
                    check_capacity(before, set(workers()))
                    known |= snapshot(label + '-capacity-page', identities[identity][0], True)
                print('DASHBOARD SHARED-CAPACITY REFUSES WITHOUT NEW HELPER', identity, flush=True)
            elif exhaustion:
                # Root has no dashboard service. Its existing privilege refusal
                # must still precede helper dispatch when its shared pool is full.
                before = set(workers())
                _, text = invoke(label + '-capacity-root-service-refusal', identity,
                                 [control, 'serve', '--addr', '127.0.0.1:0'], 125)
                check_root_refusal(text)
                check_capacity(before, set(workers()))
            if exhaustion:
                # Once every holder is older than any check can live (ADR 0144, fix29) the pool is stuck by definition: a
                # command and a page are refused at once, naming the stuck checks, with no new helper.
                wait = full_at + HELPER_MAX_LIFETIME + 5 - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                before = set(workers())
                _, text = invoke(label + '-aged-cli', identity, [binary, 'contracts', 'show', source], 125,
                                 cwd=controls[identity].parent, bound=AGED_BOUND)
                stopped()
                check_aged_refusal(text)
                check_capacity(before, set(workers()))
                if identity in ('user', 'other-uid'):
                    link = other_link if identity == 'other-uid' else user_link
                    page(label + '-aged-page', identity, link, '/rules?c=' + ref, unavailable=True, capacity=True, aged=True)
                    stopped()
                    check_capacity(before, set(workers()))
                print('AGED POOL REFUSES AT ONCE AS STUCK', identity, flush=True)
            if not exhaustion:
                invoke(label + '-healthy-source-still-checks', identity,
                       [binary, 'contracts', 'show', str(controls[identity])], 0,
                       cwd=controls[identity].parent)
                stopped()
                # Root cannot serve; its CLI is tested above. The user/other uid
                # services remain unprivileged and their actual peer checks run.
                page_identity = 'other-uid' if identity == 'other-uid' else 'user'
                link = other_link if page_identity == 'other-uid' else user_link
                for route in ('/rules?c=' + ref, '/rules/change', '/rules/change?c=' + ref):
                    page(label + '-page-' + route.split('?')[0].replace('/', '-'),
                         page_identity, link, route, unavailable=True)
                    stopped()
                known |= snapshot(label + '-after-pages', require_blocked=True)
            stopped()
            print('ALL COMMANDS REAPED AND PAGES RETURNED BEFORE ABORT', label, flush=True)
        finally:
            known |= set(workers())
            if abort == 'connection' and connection is not None:
                Path('/sys/fs/fuse/connections/' + connection + '/abort').write_text('1\n')
                os.kill(server.pid, signal.SIGCONT)
            elif abort == 'unmount':
                # A lazy detach alone need not abort an open FUSE connection.
                # Use fusermount first, then the connection abort to release it.
                subprocess.run(['fusermount', '-u', '-z', str(mount)], check=True, timeout=10)
                if connection is not None:
                    abort_file = Path('/sys/fs/fuse/connections/' + connection + '/abort')
                    if abort_file.exists():
                        abort_file.write_text('1\n')
                os.kill(server.pid, signal.SIGCONT)
            else:
                server.kill()  # SIGKILL closes /dev/fuse and aborts its connection.
            try:
                gone(known)
                if abort == 'kill':
                    # SIGKILL has aborted the connection, but its disconnected mount
                    # is still attached. Check ENOTCONN/EIO before detaching it.
                    _, killed_plain = invoke(label + '-killed-cli', identity,
                                             [binary, 'contracts', 'show', source], 125)
                    check_unavailable(killed_plain)
                    _, killed_text = invoke(label + '-killed-cli-json', identity,
                                            [binary, 'contracts', 'show', source, '--json'], 125)
                    check_unavailable(killed_text)
                    page_identity = 'other-uid' if identity == 'other-uid' else 'user'
                    link = other_link if page_identity == 'other-uid' else user_link
                    for route in ('/rules?c=' + ref, '/rules/change', '/rules/change?c=' + ref):
                        page(label + '-killed-page-' + route.split('?')[0].replace('/', '-'),
                             page_identity, link, route, unavailable=True)
                    gone(set(workers()))
            finally:
                try:
                    status = server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=10)
                    raise AssertionError('FUSE server did not exit after its connection was aborted')
                print('FUSE SERVER STATUS', label, status, flush=True)
                print('FUSE REQUEST LOG', label,
                      (root / (label + '-fuse.log')).read_text(), flush=True)
                if f' {mount} ' in Path('/proc/self/mountinfo').read_text():
                    subprocess.run(['fusermount', '-u', '-z', str(mount)], check=True, timeout=10)
                log.close()
                for child in pending:
                    print('FAILED COMMAND REAPED AFTER ABORT', child.pid, child.wait(timeout=10), flush=True)
                pending.clear()
                check_server_exit(abort, status, Path(f'/proc/{server.pid}').exists())
        catalog_control(label + '-recovered-list', identity)
        _, text = invoke(label + '-recovered-explicit-source', identity,
                         [binary, 'contracts', 'show', source],
                         0 if identity == 'user' else 125, cwd=controls[identity].parent)
        check_source_control(identity, text)
        invoke(label + '-recovered-own-source', identity,
               [binary, 'contracts', 'show', str(controls[identity])], 0,
               cwd=controls[identity].parent)
        if identity in ('user', 'other-uid'):
            link = other_link if identity == 'other-uid' else user_link
            for route in ('/rules?c=' + ref, '/rules/change', '/rules/change?c=' + ref):
                text = page(label + '-recovered-page-' + route.split('?')[0].replace('/', '-'),
                            identity, link, route)
                check_recovered_page(text, ref)
        gone(known)

    def loaded_phase():
        # Eight runnable busy loops per CPU beside the checks: a healthy location must still be answered, and a really
        # stuck one (the server stopped, the helper in a FUSE wait) must still get the mount words, never the busy ones.
        gone(set(workers()))
        log = open(root / 'loaded-fuse.log', 'w+')
        server = subprocess.Popen(['python3', '-I', str(HERE / 'contracts-fuse-server.py'),
                                   str(mount), str(uid), str(gid), str(backing)],
                                  stdout=log, stderr=subprocess.STDOUT)
        burners, connection = [], None
        try:
            limit = time.monotonic() + 10
            while f' {mount} ' not in Path('/proc/self/mountinfo').read_text():
                assert server.poll() is None and time.monotonic() < limit
                time.sleep(0.02)
            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                fields = line.split()
                if fields[4] == str(mount):
                    connection = fields[2].split(':')[1]
            for _ in range(8 * (os.cpu_count() or 1)):
                burners.append(subprocess.Popen(['python3', '-I', '-c', 'while True: pass']))
            time.sleep(1)
            print('LOADED loadavg', Path('/proc/loadavg').read_text().strip(), 'cpus', os.cpu_count(),
                  'burners', len(burners), flush=True)
            for n in range(3):
                started = time.monotonic()
                _, text = invoke(f'loaded-healthy-{n}', 'user', [binary, 'contracts', 'show', source], 0,
                                 cwd=controls['user'].parent)
                print('LOADED healthy', n, 'seconds', time.monotonic() - started, flush=True)
                check_loaded_healthy(text)
            os.kill(server.pid, signal.SIGSTOP)
            limit = time.monotonic() + 5
            while '\nState:\tT' not in Path(f'/proc/{server.pid}/status').read_text():
                assert time.monotonic() < limit
                time.sleep(0.01)
            started = time.monotonic()
            _, text = invoke('loaded-stuck', 'user', [binary, 'contracts', 'show', source], 125,
                             cwd=controls['user'].parent)
            elapsed = time.monotonic() - started
            print('LOADED stuck seconds', elapsed, 'loadavg', Path('/proc/loadavg').read_text().strip(), flush=True)
            check_loaded_stuck(text, elapsed)
            stopped_known = set(workers())
        finally:
            for burner in burners:
                burner.kill()
            for burner in burners:
                burner.wait(timeout=10)
            if connection is not None:
                abort_file = Path('/sys/fs/fuse/connections/' + connection + '/abort')
                if abort_file.exists():
                    abort_file.write_text('1\n')
            os.kill(server.pid, signal.SIGCONT)
            try:
                status = server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
                raise AssertionError('FUSE server did not exit after its connection was aborted')
            print('FUSE SERVER STATUS loaded', status, flush=True)
            if f' {mount} ' in Path('/proc/self/mountinfo').read_text():
                subprocess.run(['fusermount', '-u', '-z', str(mount)], check=True, timeout=10)
            log.close()
            for child in pending:
                print('FAILED COMMAND REAPED AFTER ABORT', child.pid, child.wait(timeout=10), flush=True)
            pending.clear()
        gone(stopped_known)

    try:
        for identity in identities:
            phase(identity, identity)
            phase(identity + '-exhaustion-and-lazy-abort', identity, True, 'unmount')
            phase(identity + '-connection-abort', identity, False, 'connection')
        loaded_phase()
    finally:
        stop_services()
        atexit.unregister(stop_services)
    gone(set(workers()))
    print('CONTRACTS-STALLED-MOUNT-GUEST PASS', flush=True)


if __name__ == '__main__':
    if len(sys.argv) in (4, 5) and sys.argv[1] == '--http':
        http_client(sys.argv[2], sys.argv[3], *([int(sys.argv[4])] if len(sys.argv) == 5 else []))
    elif len(sys.argv) == 3 and sys.argv[1] == '--host-status':
        evidence = Path(sys.argv[2])
        check_host_status(*[(evidence / name).read_text().strip() for name in
                            ('wrapper.status', 'harness.status', 'qemu.status')],
                          (evidence / 'console.log').read_text())
    else:
        main()
