#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# procself_probe.sh <path of tego> — run.sh, L2: started under a contract whose only exec.allow entry is "/proc/self/exe",
# the entry `tego learn` proposed from a Codex session (Codex starts itself by that name). It says whether the agent can
# start the tego binary, which is what the entry compiles to: the launcher's own executable, not Codex's.
out=$("$1" version 2>&1)
rc=$?
first=${out%%$'\n'*}
echo "start tego:        exit=$rc ${first:0:60}"
out=$(/usr/bin/id 2>&1)
rc=$?
echo "start /usr/bin/id:  exit=$rc ${out}"
