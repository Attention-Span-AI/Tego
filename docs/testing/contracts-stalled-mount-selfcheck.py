#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Host-safe negative controls for the guest driver's evidence assertions.

Imports the driver without running it. Never starts a product binary or a guest.
"""

import ast
import copy
import contextlib
import errno
import importlib.util
import io
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True


def main(recipe_path):
    spec = importlib.util.spec_from_file_location('recipe', recipe_path)
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    server_spec = importlib.util.spec_from_file_location(
        'fuse_server', Path(recipe_path).with_name('contracts-fuse-server.py'))
    server = importlib.util.module_from_spec(server_spec)
    server_spec.loader.exec_module(server)

    def check(name, function, good, bad):
        function(*good)
        try:
            function(*bad)
        except AssertionError:
            print(name + ': correct accepted; deliberately wrong rejected')
        else:
            raise AssertionError(name + ': deliberately wrong evidence accepted')

    check('actual-identity', recipe.check_identity,
          ('sudo', [0] * 4, [0] * 4, ['1000:1000:owner'], 1000, 1000, 'owner'),
          ('sudo', [1000] * 4, [1000] * 4, ['1000:1000:owner'], 1000, 1000, 'owner'))
    check('sudo-provenance', recipe.check_identity,
          ('sudo', [0] * 4, [0] * 4, ['1000:1000:owner'], 1000, 1000, 'owner'),
          ('sudo', [0] * 4, [0] * 4, ['0:0:root'], 1000, 1000, 'owner'))
    check('actual-gid', recipe.check_identity,
          ('sudo', [0] * 4, [0] * 4, ['1000:1000:owner'], 1000, 1000, 'owner'),
          ('sudo', [0] * 4, [1000] * 4, ['1000:1000:owner'], 1000, 1000, 'owner'))
    check('real-root-has-no-sudo', recipe.check_identity,
          ('real-root', [0] * 4, [0] * 4, [], 1000, 1000, 'owner'),
          ('real-root', [0] * 4, [0] * 4, ['1000:1000:owner'], 1000, 1000, 'owner'))
    for identity, actual_id in (('user', 1000), ('real-root', 0), ('other-uid', 54320)):
        correct = (identity, [actual_id] * 4, [actual_id] * 4, [], 1000, 1000, 'owner')
        check('actual-uid-' + identity, recipe.check_identity, correct,
              (identity, [actual_id + 1] * 4, [actual_id] * 4, [], 1000, 1000, 'owner'))
        check('actual-gid-' + identity, recipe.check_identity, correct,
              (identity, [actual_id] * 4, [actual_id + 1] * 4, [], 1000, 1000, 'owner'))
    check('root-dashboard-refusal', recipe.check_root_refusal,
          ('never as root',), ('dashboard is serving',))
    check('command-reaped', recipe.check_command, (0, 1, 70, 0), (None, 1, 70, 0))
    check('command-bound', recipe.check_command, (0, 1, 70, 0), (0, 71, 70, 0))
    check('command-status', recipe.check_command, (0, 1, 70, 0), (125, 1, 70, 0))
    check('refusal-command-status', recipe.check_command, (125, 1, 70, 125), (0, 1, 70, 125))
    check('http-status', recipe.check_http, (200, 1), (500, 1))
    check('http-complete-body-bound', recipe.check_http, (200, 1), (200, 21))
    check('loaded-healthy-words', recipe.check_loaded_healthy, ('Check: compiles',), ("Check: compiles\n" + recipe.WORDS,))
    check('loaded-healthy-busy-words', recipe.check_loaded_healthy, ('Check: compiles',), ("Check: compiles\nTego's checker was too slow to finish",))
    check('loaded-stuck-mount-words', recipe.check_loaded_stuck, (recipe.WORDS, 5.1), ('Check: incomplete', 5.1))
    check('loaded-stuck-busy-words', recipe.check_loaded_stuck, (recipe.WORDS, 5.1), (recipe.WORDS + ' the check was still working when its time ran out', 5.1))
    check('loaded-stuck-bound', recipe.check_loaded_stuck, (recipe.WORDS, 5.1), (recipe.WORDS, 21))
    check('loaded-stuck-too-early', recipe.check_loaded_stuck, (recipe.WORDS, 5.1), (recipe.WORDS, 1))
    check('http-capacity-body-bound', recipe.check_http, (200, 50, recipe.CAPACITY_PAGE_BOUND), (200, 61, recipe.CAPACITY_PAGE_BOUND))
    check('aged-pool-stuck-words', recipe.check_aged_refusal, (recipe.STUCK,), (recipe.CAPACITY,))
    check('aged-pool-no-wait', recipe.check_aged_refusal, (recipe.STUCK,), (recipe.STUCK + ' ' + recipe.CAPACITY,))
    check('aged-page-stuck-words', recipe.check_page,
          ('/rules?c=REF', 'cannot tell: ' + recipe.WORDS + ' REF ' + recipe.STUCK + ' disabled', 'REF', True, True, True),
          ('/rules?c=REF', 'cannot tell: REF ' + recipe.CAPACITY + ' disabled', 'REF', True, True, True))
    check('aged-page-bound', recipe.check_http, (200, 5, recipe.AGED_PAGE_BOUND), (200, 21, recipe.AGED_PAGE_BOUND))
    assert recipe.HELPER_MAX_LIFETIME == 115, recipe.HELPER_MAX_LIFETIME
    statuses = ['0', 'guest 0', '0', 'CONTRACTS-STALLED-MOUNT-GUEST PASS\n']
    for index, name in enumerate(('wrapper', 'harness', 'qemu', 'sentinel')):
        wrong = statuses.copy()
        wrong[index] = 'failed'
        check('host-status-' + name, recipe.check_host_status, statuses, wrong)
    source, healthy = '/mounted/project/agent.yaml', '/healthy/agent.yaml'
    def catalog(state='compiles', diagnostics=None):
        return dict(incomplete=state == 'incomplete', issues=[], contracts=[
            dict(path=path, state=state, diagnostics=copy.deepcopy(diagnostics) if diagnostics else [])
            for path in (source, healthy)])
    owner = catalog()
    root = catalog('unsafe', [dict(code='source-unreadable', message='source untrusted: uid=1000')])
    root['incomplete'] = True
    other = dict(incomplete=True, issues=[dict(code='other-owner')], contracts=[])
    for identity, correct in [('user', owner), ('sudo', owner), ('real-root', root),
                              ('other-uid', other)]:
        wrong = copy.deepcopy(correct)
        if identity == 'other-uid':
            wrong['contracts'] = owner['contracts']
        else:
            wrong['contracts'][0]['state'] = 'missing'
        check('owner-boundary-' + identity, recipe.check_catalog,
              (identity, correct, source, healthy), (identity, wrong, source, healthy))
        wrong = copy.deepcopy(correct)
        wrong['incomplete'] = not correct['incomplete']
        check('catalog-incomplete-' + identity, recipe.check_catalog,
              (identity, correct, source, healthy), (identity, wrong, source, healthy))
        if identity != 'other-uid':
            for entry_index, entry_name in enumerate(('source', 'healthy')):
                wrong = copy.deepcopy(correct)
                wrong['contracts'].pop(entry_index)
                check('catalog-entry-retained-' + identity + '-' + entry_name, recipe.check_catalog,
                      (identity, correct, source, healthy), (identity, wrong, source, healthy))
            wrong = copy.deepcopy(correct)
            wrong['contracts'][1]['state'] = 'missing'
            check('catalog-healthy-state-' + identity, recipe.check_catalog,
                  (identity, correct, source, healthy), (identity, wrong, source, healthy))
    for entry_index, entry_name in enumerate(('source', 'healthy')):
        for field, wrong_value in (('code', 'compile-context'), ('message', 'permission denied')):
            wrong = copy.deepcopy(root)
            wrong['contracts'][entry_index]['diagnostics'][0][field] = wrong_value
            check('catalog-root-diagnostic-' + entry_name + '-' + field, recipe.check_catalog,
                  ('real-root', root, source, healthy), ('real-root', wrong, source, healthy))
    for exposed in (source, healthy):
        wrong = copy.deepcopy(other)
        wrong['contracts'] = [dict(path=exposed, state='compiles')]
        check('catalog-other-excludes-' + ('source' if exposed == source else 'healthy'), recipe.check_catalog,
              ('other-uid', other, source, healthy), ('other-uid', wrong, source, healthy))
    wrong = copy.deepcopy(other)
    wrong['issues'] = []
    check('catalog-other-owner-reason', recipe.check_catalog,
          ('other-uid', other, source, healthy), ('other-uid', wrong, source, healthy))

    stalled = catalog()
    stalled['incomplete'] = True
    stalled['contracts'][0]['state'] = 'incomplete'
    for identity in ('user', 'real-root', 'sudo'):
        for predicate in ('incomplete', 'dead-entry', 'dead-state'):
            wrong = copy.deepcopy(stalled)
            if predicate == 'incomplete':
                wrong['incomplete'] = False
            elif predicate == 'dead-entry':
                wrong['contracts'].pop(0)
            else:
                wrong['contracts'][0]['state'] = 'compiles'
            check('stalled-json-' + identity + '-' + predicate, recipe.check_stalled_catalog,
                  (identity, stalled, source, healthy), (identity, wrong, source, healthy))
    for predicate in ('healthy-entry', 'healthy-state'):
        wrong = copy.deepcopy(stalled)
        if predicate == 'healthy-entry':
            wrong['contracts'].pop(1)
        else:
            wrong['contracts'][1]['state'] = 'incomplete'
        check('stalled-json-user-' + predicate, recipe.check_stalled_catalog,
              ('user', stalled, source, healthy), ('user', wrong, source, healthy))
    for predicate in ('incomplete', 'source-exposed', 'healthy-exposed', 'other-owner-reason'):
        wrong = copy.deepcopy(other)
        if predicate == 'incomplete':
            wrong['incomplete'] = False
        elif predicate == 'other-owner-reason':
            wrong['issues'] = []
        else:
            wrong['contracts'] = [dict(path=source if predicate == 'source-exposed' else healthy,
                                       state='compiles')]
        check('stalled-json-other-' + predicate, recipe.check_stalled_catalog,
              ('other-uid', other, source, healthy), ('other-uid', wrong, source, healthy))
    check('mounted-source-owner', recipe.check_source_owner, (1000, 1000), (0, 1000))
    stopped_status = 'Name:\tpython3\nState:\tT (stopped)\n'
    for predicate, observed in [('alive', (0, stopped_status)), ('stopped', (None, 'State:\tS (sleeping)\n')),
                                ('state-present', (None, 'Name:\tpython3\n'))]:
        check('fuse-server-before-abort-' + predicate, recipe.check_stopped_server,
              (None, stopped_status), observed)
    check('explicit-source-owner', recipe.check_source_control,
          ('user', 'state: compiles'), ('user', 'state: unsafe'))
    for identity in ('real-root', 'sudo', 'other-uid'):
        check('explicit-source-foreign-' + identity, recipe.check_source_control,
              (identity, 'rulefile: refused: folder is owned by uid 1000'),
              (identity, 'state: compiles'))
        check('explicit-source-foreign-guard-reason-' + identity, recipe.check_source_control,
              (identity, 'rulefile: refused: folder is owned by uid 1000'),
              (identity, 'folder is owned by uid 1000'))
        check('explicit-source-foreign-owner-reason-' + identity, recipe.check_source_control,
              (identity, 'rulefile: refused: folder is owned by uid 1000'),
              (identity, 'rulefile: refused: cannot open'))
    check('answered-source-availability', recipe.check_answered, ('compiles',), (recipe.WORDS,))
    check('unavailable-cli-reason', recipe.check_unavailable, (recipe.WORDS,), ('permission denied',))
    # Literal observations keep the name refusal independent of recipe constants.
    name_refusal = ("tego contracts: discovery is incomplete, so that name cannot be proven "
                    "unambiguous; give the contract's path [io]\n")
    for wrong in ('permission denied', recipe.WORDS, 'state: compiles',
                  name_refusal.replace('discovery is incomplete', 'discovery is complete'),
                  name_refusal.replace('cannot be proven unambiguous', 'is unambiguous'),
                  name_refusal.replace("give the contract's path", 'retry')):
        check('unavailable-name-refusal', recipe.check_unavailable,
              (name_refusal, True), (wrong, True))
    check('unavailable-path-rejects-name-refusal', recipe.check_unavailable,
          (recipe.WORDS,), (name_refusal,))

    ref = 'f00d'
    body = (recipe.WORDS + ' ' + ref + ' disabled ' + recipe.CAPACITY +
            " Can run true The run's copy name: deadproj run copy line 7")
    check('page-unavailable-reason', recipe.check_page,
          ('/rules?c=' + ref, body, ref, True, False),
          ('/rules?c=' + ref, ref + ' disabled', ref, True, False))
    check('page-entry-retained', recipe.check_page,
          ('/rules?c=' + ref, body, ref, True, False),
          ('/rules?c=' + ref, recipe.WORDS + ' disabled', ref, True, False))
    check('page-edit-disabled', recipe.check_page,
          ('/rules?c=' + ref, body, ref, True, False),
          ('/rules?c=' + ref, body + ' href="/rules/change?c=f00d"', ref, True, False))
    check('page-disabled-control', recipe.check_page,
          ('/rules?c=' + ref, body, ref, True, False),
          ('/rules?c=' + ref, body.replace('disabled', ''), ref, True, False))
    for predicate, missing in [('rule', 'Can run true'), ('yaml', 'name: deadproj'),
                               ('copy-panel', "The run's copy"), ('positions', 'run copy line ')]:
        check('page-recorded-' + predicate, recipe.check_page,
              ('/rules?c=' + ref, body, ref, True, False),
              ('/rules?c=' + ref, body.replace(missing, ''), ref, True, False))
    check('page-write-form-disabled', recipe.check_page,
          ('/rules/change?c=' + ref, body, ref, True, False),
          ('/rules/change?c=' + ref, body + ' method="post"', ref, True, False))
    capacity_body = body.replace(recipe.WORDS, "cannot tell: Tego's checker could not start")
    check('page-capacity-reason', recipe.check_page,
          ('/rules?c=' + ref, capacity_body, ref, True, True),
          ('/rules?c=' + ref, capacity_body.replace(recipe.CAPACITY, ''), ref, True, True))
    check('page-capacity-cannot-tell', recipe.check_page,
          ('/rules?c=' + ref, capacity_body, ref, True, True),
          ('/rules?c=' + ref, capacity_body.replace('cannot tell', ''), ref, True, True))
    check('page-capacity-no-mount-words', recipe.check_page,
          ('/rules?c=' + ref, capacity_body, ref, True, True),
          ('/rules?c=' + ref, capacity_body + ' ' + recipe.WORDS, ref, True, True))
    check('page-recovered', recipe.check_recovered_page,
          (ref + ' compiles', ref), (ref + recipe.WORDS, ref))
    check('page-recovered-entry-retained', recipe.check_recovered_page,
          (ref + ' compiles', ref), ('compiles', ref))
    worker = {1: dict(tasks=[dict(uid=['1000'] * 4, wchan='fuse_wait_answer')])}
    check('worker-real-fuse-wait', recipe.check_workers, (worker, 1000, True),
          ({1: dict(tasks=[dict(uid=['1000'] * 4, wchan='ptrace_stop')])}, 1000, True))
    check('worker-present-in-fuse-wait', recipe.check_workers, (worker, 1000, True), ({}, 1000, True))
    check('worker-uid', recipe.check_workers, (worker, 1000, True), (worker, 0, True))
    check('worker-bound', recipe.check_workers, (worker, 1000, True),
          ({i: worker[1] for i in range(33)}, 1000, True))
    full = set(range(32))
    check('capacity-no-replacement', recipe.check_capacity, (full, full),
          (full, set(range(1, 33))))
    check('capacity-full', recipe.check_capacity, (full, full), ({1}, {1}))
    check('service-status', recipe.check_exit, (-15, False, False), (7, False, False))
    check('service-disappearance', recipe.check_exit, (-15, False, False), (-15, True, False))
    check('service-unexpected-early-exit', recipe.check_exit,
          (-15, False, False), (0, False, True))
    check('helpers-disappearance', recipe.check_gone, ({}, set()), (worker, set()))
    check('zombie-disappearance', recipe.check_gone, ({}, set()), ({}, {1}))
    check('fuse-server-status', recipe.check_server_exit,
          ('kill', -9, False), ('kill', 1, False))
    check('fuse-server-disappearance', recipe.check_server_exit,
          ('kill', -9, False), ('kill', -9, True))
    for abort in ('connection', 'unmount'):
        check('fuse-server-abort-status-' + abort, recipe.check_server_exit,
              (abort, 0, False), (abort, -9, False))

    # These checks bind the validators to the phase orchestration as well. An
    # accurate validator is useless if the fixture always runs a different uid.
    source = Path(recipe_path).read_text()
    recipe.check_driver_wiring(source)
    for suffix in ('mounted-healthy', 'mounted-owner-boundary', 'mounted-own-source', 'healthy-source-still-checks',
                   'recovered-list', 'recovered-explicit-source', 'recovered-own-source'):
        wrong = source.replace("label + '-" + suffix + "', identity",
                               "label + '-" + suffix + "', 'user'")
        assert wrong != source, suffix
        check('phase-identity-' + suffix, recipe.check_driver_wiring, (source,), (wrong,))

    def wrong_identity(scope_name, function_name, argument, label=None, index=0):
        tree = ast.parse(source)
        scope = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                     and node.name == scope_name)
        calls = [node for node in ast.walk(scope) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == function_name
                 and (label is None or label in ast.unparse(node.args[0]))]
        call = calls[index]
        call.args[argument] = ast.Constant(value='user')
        return ast.unparse(tree)

    for scope, called in (('catalog_control', 'check_catalog'), ('phase', 'check_stalled_catalog'),
                          ('phase', 'check_source_control')):
        check('validator-actual-identity-' + called, recipe.check_driver_wiring,
              (source,), (wrong_identity(scope, called, 0),))
    for label in ('-capacity-page-', '-recovered-page-'):
        check('page-actual-identity' + label, recipe.check_driver_wiring,
              (source,), (wrong_identity('phase', 'page', 1, label),))
    for index, name in enumerate(('normal', 'exhaustion', 'connection-abort')):
        check('phase-matrix-actual-identity-' + name, recipe.check_driver_wiring,
              (source,), (wrong_identity('main', 'phase', 1, index=index),))
    check('name-selector-refusal-wired', recipe.check_driver_wiring, (source,),
          (source.replace("check_unavailable(text, args == ['show', 'deadproj'])",
                          'check_unavailable(text)'),))
    check('capacity-page-wired', recipe.check_driver_wiring, (source,),
          (source.replace('capacity=True', 'capacity=False'),))
    pass_line = "    print('CONTRACTS-STALLED-MOUNT-GUEST PASS', flush=True)"
    wrong = source.replace(pass_line, '')
    wrong = wrong.replace('    finally:\n        stop_services()',
                          '    ' + pass_line + '\n    finally:\n        stop_services()')
    check('cleanup-before-pass', recipe.check_driver_wiring, (source,), (wrong,))

    # Exercise actual fixture protocol replies with only the device and mount
    # syscalls replaced. No host mount, privilege change or product process.
    request = struct.pack('<IIQQ', 40, 99, 1, 1) + bytes(16)
    for failure_errno in (errno.ENOENT, errno.ENODEV, errno.ECONNABORTED, errno.EIO):
        with mock.patch.object(server.ctypes, 'CDLL', return_value=SimpleNamespace(mount=lambda *args: 0)), \
                mock.patch.object(server.os, 'open', return_value=11), \
                mock.patch.object(server.os, 'read', side_effect=[request, OSError(errno.ENODEV, 'aborted')]), \
                mock.patch.object(server.os, 'write', side_effect=OSError(failure_errno, 'reply')), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                server.serve('/fixture-mount', 1000, 1000, recipe_path)
            except OSError as error:
                assert failure_errno == errno.EIO and error.errno == errno.EIO, error
            else:
                assert failure_errno != errno.EIO, 'unexpected I/O failure was hidden'
        print(f'fuse-reply-errno-{failure_errno}: cancelled/aborted accepted; unexpected I/O rejected')


if __name__ == '__main__':
    main(sys.argv[1])
