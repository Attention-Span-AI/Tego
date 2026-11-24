#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


# The product owns the full check list. Require the version's minimum and accept
# additional checks only when each one explicitly passed. This is a generic
# ended comparison, not B1-3's complete coverage/teardown acceptance.
set -euo pipefail
# jq keeps the last duplicate key. Validate one complete document first, then
# forward those same bytes so no key is silently discarded before the checks.
/usr/bin/python3 -I - "$1" <<'PY' | /usr/bin/jq -e '
  .check_v == 1 and .result == "match" and .ended == true and
  (.binding_v == 1 or .binding_v == 2 or .binding_v == 3) and
  (.checks | type == "array") and
  (all(.checks[]; (.name | type == "string" and length > 0) and .result == "pass")) and
  ([.checks[].name] | length == (unique | length)) and
  (((["receipt", "made_by", "run", "chain", "head", "bytes", "facts"] +
     (if .binding_v >= 2 then ["binding"] else [] end)) - [.checks[].name]) | length == 0)
' >/dev/null
import json
import sys


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError("non-JSON constant: " + value)


try:
    with open(sys.argv[1], 'rb') as source:
        data = source.read()
    parsed = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if not isinstance(parsed, dict) or type(parsed.get('binding_v')) is not int:
        raise ValueError("binding_v must be an integer")
except (OSError, ValueError, RecursionError) as err:
    sys.exit("tego-ci: invalid receipt check: " + str(err))
sys.stdout.buffer.write(data)
PY
