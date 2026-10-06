#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# unattended.sh — the other half of the 'tego watch' demo (README.md): one write that asks a person, with nobody there
# to answer. It says whether the write was allowed and how long the agent waited.
start=${EPOCHREALTIME/./}
if echo night >held/a.txt; then result=allowed; else result=refused; fi
echo "write held/a.txt with nobody there: $result after $(((${EPOCHREALTIME/./} - start) / 1000000)) s"
