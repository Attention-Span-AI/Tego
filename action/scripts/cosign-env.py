#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Exec cosign with only reviewed state and an explicitly supplied signing token."""
import os
import sys

clean = {'PATH': '/usr/bin:/bin', 'HOME': os.environ['DIR'] + '/sigstore/home',
         'TUF_ROOT': os.environ['DIR'] + '/sigstore/tuf'}
args = sys.argv[1:]
if args[0] == '--identity-token':
    clean['SIGSTORE_ID_TOKEN'] = os.environ['SIGSTORE_ID_TOKEN']
    args = args[1:]
os.execve(args[0], args, clean)
