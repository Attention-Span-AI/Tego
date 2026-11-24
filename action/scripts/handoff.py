#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, regular-file-only evidence transfer. Never execute evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
FILES = {'agent-check.json', 'eligibility.json', 'doctor.json', 'compile.json', 'compile.txt',
         'contract.yaml', 'run/events.jsonl', 'receipt.json', 'receipt.md', 'run_start.json',
         'tego-ci.json', 'verify.json', 'anchor-line.txt', 'run-status.json', 'producer.json'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    result, total = [], 0
    for p in sorted(root.rglob('*')):
        name = p.relative_to(root).as_posix()
        if p.is_symlink() or not (p.is_file() or p.is_dir()):
            raise ValueError('evidence contains a link or special file')
        if p.is_dir():
            if name != 'run':
                raise ValueError('unexpected directory')
            continue
        if name not in FILES or p.stat().st_size > MAX_FILE:
            raise ValueError('unexpected or oversized evidence file')
        data = p.read_bytes()
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError('evidence exceeds 256 MiB')
        result.append(f'{sha(data)} {len(data)} {name}\n')
    if not result:
        raise ValueError('empty evidence')
    return ''.join(result).encode('ascii')


def extract(archive, root, digest, expected):
    if not re.fullmatch('[0-9a-f]{64}', digest) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('missing out-of-band digest')
    if archive.stat().st_size > MAX_TOTAL or sha(archive.read_bytes()) != digest:
        raise ValueError('artifact archive digest or size mismatch')
    root.mkdir(mode=0o700)  # preexisting state is refused
    total, seen = 0, set()
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            name = info.filename
            mode = info.external_attr >> 16
            if info.is_dir():
                if name != 'run/':
                    raise ValueError('unexpected archive directory')
                continue
            if name not in FILES or name in seen or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                raise ValueError('archive contains an unexpected name, duplicate or non-regular file')
            seen.add(name)
            total += info.file_size
            if info.file_size > MAX_FILE or total > MAX_TOTAL:
                raise ValueError('archive expansion limit')
            dest = root / name
            dest.parent.mkdir(mode=0o700, exist_ok=True)
            # Exclusive creation plus allowlisted paths: no traversal or links.
            with z.open(info) as src, dest.open('xb') as out:
                left = info.file_size
                while left:
                    data = src.read(min(left, 1024 * 1024))
                    if not data:
                        raise ValueError('short archive entry')
                    out.write(data)
                    left -= len(data)
                if src.read(1):
                    raise ValueError('archive entry exceeds declared size')
            dest.chmod(0o600)
    if sha(inventory(root)) != expected:
        raise ValueError('evidence inventory digest mismatch')


def check_display(root):
    # The receipt checker recomputes receipt facts. Bind the separate display
    # sidecars to those same copied bytes as well.
    receipt = json.loads((root / 'receipt.json').read_text())
    start = json.loads((root / 'run_start.json').read_text())
    first = json.loads((root / 'run/events.jsonl').read_text().splitlines()[0])
    meta = json.loads((root / 'tego-ci.json').read_text())
    compiled = json.loads((root / 'compile.json').read_text())
    if first != start or start.get('kind') != 'run_start':
        raise ValueError('display run_start differs from the copied record')
    for key, path in [('receipt_sha256', 'receipt.json'), ('events_sha256', 'run/events.jsonl'),
                      ('contract_file_sha256', 'contract.yaml')]:
        if meta.get(key) != sha((root / path).read_bytes()):
            raise ValueError('display digest mismatch')
    if not (receipt['run'] == start['run'] == meta['run'] and
            start['contract_hash'] == meta['contract_hash'] == compiled['contract_hash']):
        raise ValueError('display run or compiled contract hash mismatch')


def decisions(root):
    """Read gate facts only after receipt --check and the sidecar binding pass."""
    check_display(root)
    receipt = json.loads((root / 'receipt.json').read_text())
    meta = json.loads((root / 'tego-ci.json').read_text())
    run, refusals = receipt['run'], receipt['refusals']['total']
    code = receipt.get('exit_code')
    if code is None and receipt.get('end_reason') != 'exit':
        # Receipt v1 publishes exit_code only for reason=exit. Other ended
        # outcomes retain their status in the freshly checked record. Match
        # the receipt reader's first-run_end rule, never a later appended end.
        for line in (root / 'run/events.jsonl').read_text().splitlines():
            event = json.loads(line)
            if event.get('kind') == 'run_end':
                code = event.get('exit_code')
                break
    if not isinstance(run, str) or not re.fullmatch('r-[0-9a-z-]+', run):
        raise ValueError('invalid checked run id')
    if receipt.get('ended') is not True or type(code) is not int or not 0 <= code <= 255:
        raise ValueError('checked receipt has no ended agent exit code')
    if type(refusals) is not int or refusals < 0:
        raise ValueError('invalid checked refusal count')
    if type(meta.get('agent_exit_code')) is not int or meta['agent_exit_code'] != code:
        raise ValueError('agent exit metadata differs from checked receipt')
    return dict(run_id=run, agent_exit=code, refusals=refusals, verified=True,
                prepare_exit=0, evidence_exit=0)


def diagnostic(root, tier):
    """A copied doctor refusal cannot stand in for an available run receipt."""
    if tier not in ('landlock', 'cgroup') or (root / 'receipt.json').exists():
        raise ValueError('invalid diagnostic tier or unexpected receipt')
    doctor = json.loads((root / 'doctor.json').read_text())
    missing = doctor.get('missing', {}).get(tier, [])
    unavailable = doctor.get('tiers', {}).get(tier) is False
    setup_failure = (doctor.get('diagnostic_source') == 'runner-setup' and
                     isinstance(missing, list) and bool(missing) and
                     all(isinstance(item, str) and item for item in missing))
    if not unavailable and not setup_failure:
        raise ValueError('diagnostic does not establish requested tier refusal')
    return 211


def pull_request():
    # The fresh job owns this event file. No artifact or agent output selects
    # the comment target, including on an evidence-download failure.
    if os.environ.get('GITHUB_EVENT_NAME') != 'pull_request':
        return ''
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    number = event.get('number')
    if type(number) is not int or number < 1 or not isinstance(event.get('pull_request'), dict):
        raise ValueError('invalid fresh-job pull request event')
    if event['pull_request'].get('number', number) != number:
        raise ValueError('inconsistent fresh-job pull request event')
    return str(number)


def download(dest):
    artifact = os.environ['ARTIFACT_ID']
    repo = os.environ['GITHUB_REPOSITORY']
    run = os.environ['GITHUB_RUN_ID']
    if not re.fullmatch('[1-9][0-9]*', artifact) or not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('bad artifact ID or repository')
    api = f'repos/{repo}/actions/artifacts/{artifact}'
    key = os.environ['MATRIX_SHA256']
    attempt = os.environ['ARTIFACT_ATTEMPT']
    if (not re.fullmatch('[0-9a-f]{64}', key) or not re.fullmatch('[1-9][0-9]*', attempt)
            or not re.fullmatch('[1-9][0-9]*', run)):
        raise ValueError('bad matrix or attempt')
    expected_name = f'tego-receipt-{run}-{attempt}-{key}'
    if os.environ['ARTIFACT_NAME'] != expected_name:
        raise ValueError('artifact name differs from agent attempt and matrix')
    metadata = json.loads(subprocess.check_output(['/usr/bin/gh', 'api', api], timeout=60))
    if (str(metadata.get('id')) != artifact or str(metadata.get('workflow_run', {}).get('id')) != run
            or metadata.get('name') != expected_name or metadata.get('expired') is not False or not 0 < metadata['size_in_bytes'] <= MAX_TOTAL):
        raise ValueError('artifact metadata mismatch, expiry or size limit')
    # Bound the stream too; do not trust size metadata to bound a disk write.
    proc = subprocess.Popen(['/usr/bin/gh', 'api', api + '/zip'], stdout=subprocess.PIPE)
    try:
        total = 0
        with dest.open('xb') as out:
            while True:
                data = proc.stdout.read(1024 * 1024)
                if not data:
                    break
                total += len(data)
                if total > MAX_TOTAL:
                    raise ValueError('artifact download size limit')
                out.write(data)
        if proc.wait(timeout=60):
            raise ValueError('artifact download failed')
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


if __name__ == '__main__':
    try:
        mode = sys.argv[1]
        if mode == 'inventory':
            print(sha(inventory(Path(sys.argv[2]))))
        elif mode == 'extract':
            extract(Path(sys.argv[2]), Path(sys.argv[3]), os.environ['ARTIFACT_DIGEST'], os.environ['INVENTORY_SHA256'])
        elif mode == 'display':
            check_display(Path(sys.argv[2]))
        elif mode == 'decisions':
            print(json.dumps(decisions(Path(sys.argv[2]))))
        elif mode == 'diagnostic':
            print(diagnostic(Path(sys.argv[2]), sys.argv[3]))
        elif mode == 'pull-request':
            print(pull_request())
        elif mode == 'download':
            download(Path(sys.argv[2]))
        else:
            raise ValueError('unknown handoff operation')
    except (ValueError, KeyError, OSError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(125)
