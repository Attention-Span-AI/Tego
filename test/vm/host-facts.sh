#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# host-facts.sh prints the version of each host package the guest image copies (kvm-run.sh's HOST_PKGS), one line a
# package: "<package> <version>", or "<package> absent" where this host has none installed. The guest runs the host's
# own python3, git and nodejs; they are not pinned or verified by hash, so a root-suite run records them
# (root-suites.sh, host-packages.txt) and two machines' runs can be compared.
#
# Usage: host-facts.sh PACKAGE...
set -uo pipefail

for pkg in "$@"; do
	line="$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$pkg" 2>/dev/null)"
	case "$line" in
	ii*) echo "$pkg $(awk '{print $2}' <<<"$line")" ;;
	*) echo "$pkg absent" ;;
	esac
done
