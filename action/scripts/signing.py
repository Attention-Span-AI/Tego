#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Signer inputs from authenticated runner channels. Never execute evidence."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.parse
import urllib.request

CONSENT = 'I consent to publish repository and workflow names in the permanent public Sigstore log'
CORE = ('anchor-line.txt', 'contract.yaml', 'receipt.json', 'run-status.json', 'run/events.jsonl')


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key: ' + key)
        value[key] = item
    return value


def strict(data):
    def invalid(value):
        raise ValueError('non-JSON value: ' + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def load(path, limit=64*1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('expected bounded regular input: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError('input exceeds limit')
        return strict(data)
    finally:
        os.close(fd)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def api(path):
    return strict(subprocess.check_output(['/usr/bin/gh', 'api', path], timeout=60))


def eligibility(sign, consent, event, visibility, fork):
    if sign not in ('auto', 'true', 'false'):
        raise ValueError('sign must be auto, true or false')
    if event == 'pull_request_target':
        raise ValueError('pull_request_target is refused')
    if sign == 'false':
        return False, 'disabled: sign is false'
    if fork is True:
        return False, 'fork: another repository'
    if event not in ('push', 'schedule', 'workflow_dispatch', 'pull_request'):
        return False, 'trigger: event is ineligible'
    if visibility not in ('public', 'private', 'internal') or (event == 'pull_request' and fork is None):
        if sign == 'true':
            raise ValueError('requested signing cannot authenticate repository visibility or fork identity')
        return False, 'unknown: API visibility or fork identity unavailable'
    if sign == 'auto' and visibility != 'public':
        return False, 'private: private/internal auto is unsigned'
    if consent != CONSENT:
        raise ValueError('signing requires explicit consent: ' + CONSENT)
    return True, 'requested with explicit public-log consent'


def repository():
    repo = os.environ['GITHUB_REPOSITORY']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('invalid repository')
    data = api('repos/' + repo)
    if data.get('full_name', '').lower() != repo.lower():
        raise ValueError('API repository differs')
    for field in ('id', 'owner'):
        if field not in data:
            raise ValueError('missing authenticated repository ID')
    fork = None
    if os.environ['GITHUB_EVENT_NAME'] == 'pull_request':
        event = load(os.environ['GITHUB_EVENT_PATH'], 4*1024*1024)
        number = event['number']
        if type(number) is not int or number <= 0:
            raise ValueError('invalid PR number')
        pull = api(f'repos/{repo}/pulls/{number}')
        fork = pull['head']['repo']['id'] != data['id']
        if pull['base']['repo']['id'] != data['id']:
            raise ValueError('PR base differs')
    return data, fork


def attempt_jobs():
    path = 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/actions/runs/' + os.environ['GITHUB_RUN_ID'] + '/attempts/' + os.environ['ARTIFACT_ATTEMPT'] + '/jobs?per_page=100'
    pages = strict(subprocess.check_output(['/usr/bin/gh', 'api', '--paginate', '--slurp', path], timeout=120))
    return [job for page in pages for job in page['jobs']]


def decision():
    sign = os.environ.get('IN_SIGN', 'auto')
    consent = os.environ.get('IN_SIGN_CONSENT', '')
    event = os.environ['GITHUB_EVENT_NAME']
    # Validate the selection and exclusions before touching the API. Disabled
    # reports and unsupported triggers do not depend on repository metadata.
    if sign not in ('auto', 'true') or event not in ('push', 'schedule', 'workflow_dispatch', 'pull_request'):
        should, reason = eligibility(sign, consent, event, 'unknown', None)
        return dict(sign=should, reason=reason, repository={})
    try:
        data, fork = repository()
    except (OSError, subprocess.SubprocessError):
        # An unavailable API authenticates neither visibility nor PR identity.
        # Auto remains unsigned; an eligible explicit request still refuses.
        data, fork = {}, None
    should, reason = eligibility(sign, consent, event, data.get('visibility', 'unknown'), fork)
    return dict(sign=should, reason=reason, repository=data)


def teardown(path, run):
    status = load(path, 4096)
    if set(status) != {'schema', 'run', 'scope', 'cgroup_id', 'removed', 'deferred'}:
        raise ValueError('unexpected teardown keys')
    scope = status['scope']
    if (status['schema'] != 'tego.run-status/1' or status['run'] != run or
            status['removed'] is not True or status['deferred'] is not False or
            not isinstance(status['cgroup_id'], str) or not re.fullmatch('[1-9][0-9]*', status['cgroup_id']) or
            not isinstance(scope, str) or not scope.startswith('/sys/fs/cgroup/') or
            Path(scope).resolve() != Path(scope)):
        raise ValueError('teardown is not a confirmed exact scope removal')
    try:
        os.stat(scope)
    except FileNotFoundError:
        # Also require the parent to be inspectable: ENOENT from an inaccessible
        # hierarchy must never be interpreted as successful removal.
        parent = Path(scope).parent
        while not parent.exists() and parent != Path('/sys/fs/cgroup'):
            parent = parent.parent
        os.listdir(parent)
    else:
        raise ValueError('governed cgroup still exists')
    return status


def producer(root):
    root = Path(root)
    return dict(asset=(root/'state/binary-asset').read_text().strip(),
                binary_sha256=(root/'state/binary-sha256').read_text().strip())


def core_inventory(root):
    return ''.join(f'{digest(root/name)} {(root/name).stat().st_size} {name}\n' for name in sorted(CORE)).encode('ascii')


def check_core_outputs(root):
    root = Path(root)
    for label, name in zip(('receipt','record','anchor','contract','status'),
                           ('receipt.json','run/events.jsonl','anchor-line.txt','contract.yaml','run-status.json')):
        prefix = 'CORE_' + label.upper()
        if (os.environ.get(prefix+'_SHA256') != digest(root/name) or
                os.environ.get(prefix+'_BYTES') != str((root/name).stat().st_size)):
            raise ValueError('out-of-band core file digest/size differs: ' + name)
    if os.environ.get('CORE_INVENTORY_SHA256') != hashlib.sha256(core_inventory(root)).hexdigest():
        raise ValueError('out-of-band core inventory differs')


def full_check(path):
    value = load(path, 4*1024*1024)
    required = {'receipt', 'binding', 'made_by', 'run', 'chain', 'head', 'bytes', 'facts', 'ended', 'teardown', 'coverage'}
    steps = value.get('checks', [])
    names = [s.get('name') for s in steps]
    if (value.get('check_v') != 1 or type(value.get('binding_v')) is not int or value['binding_v'] != 2 or
            value.get('result') != 'match' or value.get('ended') is not True or
            value.get('coverage_complete') is not True or value.get('complete') is not True or
            len(names) != len(set(names)) or not required.issubset(names) or
            any(not isinstance(n, str) or not n for n in names) or any(s.get('result') != 'pass' for s in steps)):
        raise ValueError('signing requires a complete binding-2 ended match')
    return value


def token(repo):
    # Consent and authenticated API policy are checked before this first OIDC call.
    url = os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.actions.githubusercontent.com'):
        raise ValueError('unexpected OIDC endpoint')
    url += ('&' if '?' in url else '?') + 'audience=sigstore'
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError('OIDC response too large')
    jwt = strict(raw)['value']
    encoded = jwt.split('.')[1]
    claims = strict(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    expected = dict(repository=os.environ['GITHUB_REPOSITORY'], repository_id=str(repo['id']),
                    repository_owner_id=str(repo['owner']['id']), repository_visibility=repo['visibility'],
                    sha=os.environ['GITHUB_SHA'], ref=os.environ['GITHUB_REF'], run_id=os.environ['GITHUB_RUN_ID'],
                    run_attempt=os.environ['GITHUB_RUN_ATTEMPT'], event_name=os.environ['GITHUB_EVENT_NAME'],
                    workflow_ref=os.environ['GITHUB_WORKFLOW_REF'], workflow_sha=os.environ['GITHUB_WORKFLOW_SHA'],
                    runner_environment='github-hosted', job_workflow_sha=os.environ['TEGO_CODE_SHA'],
                    iss='https://token.actions.githubusercontent.com', aud='sigstore')
    for key, value in expected.items():
        if claims.get(key) != value:
            raise ValueError('OIDC claim disagrees with authenticated context: ' + key)
    # Claims are received directly over authenticated GitHub HTTPS, not evidence.
    # The reader still requires Fulcio's signed extensions from the actual bundle.
    workflow = claims.get('job_workflow_ref', '')
    if workflow != 'Attention-Span-AI/Tego/.github/workflows/ci-receipt-sign.yml@' + os.environ['TEGO_CODE_SHA']:
        raise ValueError('unexpected reusable signer workflow')
    return jwt, claims


def manifest(root, repo, claims):
    root = Path(root)
    receipt = load(root/'receipt.json', 64*1024*1024)
    full_check(root/'signer-check.json')
    binding, chain = receipt['binding'], receipt['binding']['chain']
    if binding['v'] != 2:
        raise ValueError('binding 2 required')
    producer_data = load(root/'producer.json')
    assets = {}
    for line in (Path(os.environ['DIR'])/'state/release-checksums.txt').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match or match[2] in assets:
            raise ValueError('invalid or duplicate authenticated checksum asset')
        assets[match[2]] = match[1]
    for item in (producer_data, producer(os.environ['DIR'])):
        if (not re.fullmatch('tego_' + re.escape(os.environ['IN_VERSION'].removeprefix('v')) + r'_linux_(amd64|arm64)', item['asset']) or
                assets.get(item['asset']) != item['binary_sha256']):
            raise ValueError('executable is outside authenticated release checksums')
    if binding['receipt_by'] != dict(tego_version=os.environ['IN_VERSION'], commit=os.environ['IN_RELEASE_COMMIT']):
        raise ValueError('receipt is outside authenticated release identity')
    # The exact producing attempt is queried independently; artifact metadata is
    # never authority for a self-hosted agent runner.
    jobs = attempt_jobs()
    if producer_data['binary_sha256'] != binding['binary_sha256']:
        raise ValueError('producer differs from binding')
    meta = load(root/'tego-ci.json')
    # The copied first-job provenance must agree with trusted contexts. The
    # producing attempt remains explicit when only the signing job is rerun.
    for key, value in dict(repository=os.environ['GITHUB_REPOSITORY'], checkout_sha=os.environ['GITHUB_SHA'],
                           action_sha=os.environ['TEGO_CODE_SHA'], sha=os.environ['GITHUB_SHA'],
                           workflow_sha=os.environ['GITHUB_WORKFLOW_SHA'], workflow_ref=os.environ['GITHUB_WORKFLOW_REF'],
                           run_id=os.environ['GITHUB_RUN_ID'], run_attempt=os.environ['ARTIFACT_ATTEMPT'],
                           ref=os.environ['GITHUB_REF'], event=os.environ['GITHUB_EVENT_NAME']).items():
        if meta['github'].get(key) != value:
            raise ValueError('agent provenance differs: ' + key)
    agent_jobs = [job for job in jobs if job.get('runner_name') == meta['github'].get('runner_name') and
                  (job.get('name') == 'agent' or job.get('name', '').endswith(' / agent'))]
    if (len(agent_jobs) != 1 or agent_jobs[0].get('status') != 'completed' or
            'self-hosted' in agent_jobs[0].get('labels', []) or
            type(agent_jobs[0].get('runner_group_id')) is not int or agent_jobs[0]['runner_group_id'] != 0 or
            agent_jobs[0].get('runner_group_name') != 'GitHub Actions' or
            not agent_jobs[0].get('runner_name', '').startswith('GitHub Actions ')):
        raise ValueError('API does not establish one completed GitHub-hosted agent job')
    for runner in (meta['github']['agent_runner'],):
        if (runner.get('environment') != 'github-hosted' or runner.get('arch') not in ('X64', 'ARM64') or
                any(not isinstance(runner.get(k), str) or not runner[k] for k in ('image', 'version'))):
            raise ValueError('invalid agent runner image assertion')
    event = load(os.environ['GITHUB_EVENT_PATH'], 4*1024*1024)
    def hashed(name):
        return dict(file=name, sha256=digest(root/name))
    github = dict(server_url='https://github.com', repository=os.environ['GITHUB_REPOSITORY'],
                  repository_id=str(repo['id']), repository_owner_id=str(repo['owner']['id']), visibility=repo['visibility'],
                  source_sha=os.environ['GITHUB_SHA'], source_ref=os.environ['GITHUB_REF'],
                  workflow_ref=os.environ['GITHUB_WORKFLOW_REF'], workflow_sha=os.environ['GITHUB_WORKFLOW_SHA'],
                  job_workflow_ref=claims['job_workflow_ref'], job_workflow_sha=claims['job_workflow_sha'],
                  event=os.environ['GITHUB_EVENT_NAME'], run_id=os.environ['GITHUB_RUN_ID'], run_attempt=os.environ['GITHUB_RUN_ATTEMPT'],
                  agent_job='agent', signing_job='sign', step='collect', matrix_key=os.environ['CANONICAL_MATRIX_KEY'],
                  action_sha=os.environ['TEGO_CODE_SHA'], checkout_sha=os.environ['GITHUB_SHA'],
                  pull_request_head_sha=event['pull_request']['head']['sha'] if os.environ['GITHUB_EVENT_NAME']=='pull_request' else None,
                  agent_runner=meta['github']['agent_runner'],
                  signer_runner=dict(environment='github-hosted', image=os.environ['ImageOS'], version=os.environ['ImageVersion'], arch='X64'))
    return dict(schema='tego.ci-receipt/1',
                receipt=dict(**hashed('receipt.json'), bytes=(root/'receipt.json').stat().st_size),
                record=dict(**hashed('run/events.jsonl'), run=chain['run'], bytes=chain['bytes'], lines=chain['lines'], head=chain['head'], ended=chain['ended']),
                anchor=hashed('anchor-line.txt'), contract=dict(file='contract.yaml', file_sha256=digest(root/'contract.yaml'), compiled_hash=binding['contract_hash']),
                teardown=hashed('run-status.json'), signer_check=hashed('signer-check.json'),
                tego=dict(version=os.environ['IN_VERSION'], commit=os.environ['IN_RELEASE_COMMIT'], checksums_sha256=digest(Path(os.environ['DIR'])/'state/release-checksums.txt'),
                          producer=producer_data, signer=producer(os.environ['DIR'])),
                artifact=dict(agent_id=os.environ['ARTIFACT_ID'], inventory_sha256=hashlib.sha256(core_inventory(root)).hexdigest()), github=github)


def main():
    mode = sys.argv[1]
    if mode == 'decision':
        print(json.dumps(decision()))
    elif mode == 'teardown':
        teardown(sys.argv[2], sys.argv[3])
    elif mode == 'producer':
        print(json.dumps(producer(sys.argv[2])))
    elif mode == 'core-outputs':
        root = Path(sys.argv[2])
        for label, name in zip(('receipt','record','anchor','contract','status'),
                               ('receipt.json','run/events.jsonl','anchor-line.txt','contract.yaml','run-status.json')):
            print(label+'-sha256='+digest(root/name))
            print(label+'-bytes='+str((root/name).stat().st_size))
        print('core-inventory-sha256='+hashlib.sha256(core_inventory(root)).hexdigest())
    elif mode == 'core-check':
        check_core_outputs(sys.argv[2])
    elif mode == 'complete':
        full_check(sys.argv[2])
    elif mode == 'snapshot':
        root = Path(sys.argv[2])
        print(json.dumps({p.relative_to(root).as_posix(): digest(p) for p in sorted(root.rglob('*')) if p.is_file()}))
    elif mode == 'unchanged':
        root = Path(sys.argv[2])
        original = load(sys.argv[3])
        for name, checksum in original.items():
            if digest(root/name) != checksum:
                raise ValueError('evidence changed during signing: ' + name)
    elif mode == 'sign-inputs':
        selected = decision()
        if not selected['sign']:
            raise ValueError('signer refuses unsigned selection: ' + selected['reason'])
        full_check(Path(sys.argv[2])/'signer-check.json')
        jwt, claims = token(selected['repository'])
        value = manifest(sys.argv[2], selected['repository'], claims)
        Path(sys.argv[2], 'manifest.json').write_text(json.dumps(value, separators=(',', ':'))+'\n')
        Path(os.environ['DIR'], 'state/identity-token').write_text(jwt)
    else:
        raise ValueError('unknown signer operation')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError, subprocess.SubprocessError) as error:
        sys.exit('tego-ci: ' + str(error))
