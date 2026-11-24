#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Canonical matrix identity, shared by paths and comment markers."""
import hashlib
import json
import os


def matrix():
    raw = os.environ.get('IN_MATRIX_KEY', 'single')
    if len(raw.encode()) > 8192:
        raise ValueError('matrix-key exceeds 8 KiB')
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = raw
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def identity():
    key = matrix()
    digest = hashlib.sha256(key.encode()).hexdigest()
    marker = hashlib.sha256(json.dumps([
        os.environ.get('GITHUB_WORKFLOW_REF', 'local'),
        os.environ.get('GITHUB_JOB', 'agent'), 'collect', key
    ], separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    return {'matrix_key': key, 'matrix_sha256': digest, 'marker': f'<!-- tego-receipt:{marker} -->'}


if __name__ == '__main__':
    print(json.dumps(identity()))
