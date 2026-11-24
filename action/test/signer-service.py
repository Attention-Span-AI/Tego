#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Offline transport/tool doubles for the real sign.sh and signing.py paths.

The test copies this file to signing.py and bin/cosign in a scratch action.
Only GitHub transport and the cosign executable are substituted. Production
claim, manifest, trust, environment, signing-loop and publication code runs.
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys


def append(path, value):
    with path.open('a') as out:
        out.write(json.dumps(value) + '\n')


def cosign():
    root = Path(__file__).resolve().parents[1]
    args = sys.argv[1:]
    blob = Path(args[-1])
    value = dict(args=args, blob=str(blob), sha256=hashlib.sha256(blob.read_bytes()).hexdigest(),
                 token=os.environ.get('SIGSTORE_ID_TOKEN'), environment=dict(os.environ))
    append(root/'state/cosign-calls.jsonl', value)
    if (root/'state/mutate-blob').exists():
        (root/'evidence/receipt.json').write_text('substituted after signing')
    bundle = Path(args[args.index('--bundle') + 1])
    bundle.write_text(json.dumps(dict(fixture_bundle=True, blob_sha256=value['sha256'])) + '\n')
    # A failed cosign can leave output behind. Exit status must still refuse.
    if (root/'state/fail-blob').exists() and (root/'state/fail-blob').read_text() == blob.name:
        sys.exit(42)


def signing():
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('production_signing', here/'signing-implementation.py')
    implementation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(implementation)
    fixture = Path(os.environ['SIGNER_FIXTURE'])
    data = json.loads((fixture/'service.json').read_text())

    def request_json(args, **kwargs):
        # Exercise production api() and attempt_jobs() through their real gh
        # argument parsing boundary, without invoking any network-capable tool.
        append(fixture/'api-calls.jsonl', args)
        if args == ['/usr/bin/gh', 'api', 'repos/example/app']:
            value = data['repository']
        elif args == ['/usr/bin/gh', 'api', '--paginate', '--slurp',
                      'repos/example/app/actions/runs/42/attempts/1/jobs?per_page=100']:
            value = [dict(jobs=data['jobs'])]
        else:
            raise AssertionError('unexpected offline API request: ' + repr(args))
        return json.dumps(value).encode()

    def token_service(request, timeout):
        append(fixture/'token-calls.jsonl', dict(url=request.full_url,
                                               authorization=request.get_header('Authorization'), timeout=timeout))
        raw = json.dumps(data['claims'], separators=(',', ':')).encode()
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip('=')
        return io.BytesIO(json.dumps(dict(value='header.' + encoded + '.signature')).encode())

    implementation.subprocess.check_output = request_json
    implementation.urllib.request.urlopen = token_service
    try:
        implementation.main()
    except (ValueError, KeyError, OSError, TypeError, implementation.subprocess.SubprocessError) as error:
        sys.exit('tego-ci: ' + str(error))


if __name__ == '__main__':
    if Path(__file__).name == 'cosign':
        cosign()
    else:
        signing()
