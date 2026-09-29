# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# python_host_pkgs [INTERPRETER]: the Debian packages that hold the host's own python3 and its stdlib, named
# from the interpreter /usr/bin/python3 resolves to (python3.13 on a dev box, python3.12 on the hosted
# ubuntu-24.04 runner), so a guest built there has an interpreter that starts. Sourced by kvm-run.sh; prints
# nothing when the interpreter's name is not pythonX.Y (kvm-run.sh's list still carries python3-minimal, and
# the guest's own self-check in run-matrix-row.sh then fails by name).
python_host_pkgs() {
	local py
	py="$(basename "$(readlink -f "${1:-/usr/bin/python3}" 2>/dev/null)")"
	case "$py" in
	python3.[0-9] | python3.[0-9][0-9]) echo "$py-minimal lib$py-minimal lib$py-stdlib" ;;
	esac
}
