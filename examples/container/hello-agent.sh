#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# hello-agent.sh: the example agent hello.yaml governs. It writes one file where the contract lets it, then tries one
# write the contract does not allow and checks that it was refused. Exit 0 when both happened as the contract says.
set -u
when=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "hello from an agent under tego, $when" >/work/out/hello.txt || exit 1
echo "wrote /work/out/hello.txt"
if (echo "not allowed" >/work/outside.txt) 2>/dev/null; then
	echo "UNEXPECTED: a write outside /work/out went through" >&2
	exit 1
fi
echo "refused, as the contract says: a write to /work/outside.txt"
