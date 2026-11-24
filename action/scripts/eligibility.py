#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Agent-phase display selection. Only the separate consent-checked job signs."""
import json
import os
import sys

event = os.environ.get('GITHUB_EVENT_NAME', '')
visibility = os.environ.get('VISIBILITY', 'unknown')
sign = os.environ.get('IN_SIGN', 'auto')
if event == 'pull_request_target':
    print('pull_request_target is refused before launch', file=sys.stderr)
    sys.exit(125)
if sign not in {'auto', 'true', 'false'}:
    sys.exit(125)
if sign == 'false':
    reason = 'disabled: sign is false'
elif os.environ.get('IS_FORK', 'unknown') == 'true':
    reason = 'fork: pull request from another repository'
elif event not in {'push', 'schedule', 'workflow_dispatch', 'pull_request'}:
    reason = 'trigger: this event is not eligible for signing'
elif visibility not in {'public', 'private', 'internal'}:
    reason = 'unknown: repository visibility could not be authenticated'
elif event == 'pull_request' and os.environ.get('IS_FORK', 'unknown') != 'false':
    reason = 'unknown: pull request repository IDs could not be authenticated'
elif visibility != 'public' and sign == 'auto':
    reason = 'private: private/internal repositories default to unsigned'
else:
    reason = 'pending: separate signing job requires explicit public-log consent and complete verification'
print(json.dumps({'reason': reason, 'signing_implemented': True, 'requested': sign}))
