#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests vm-matrix.yml's "enable KVM for the runner user" step, the gate every guest step of a hosted runner
# passes first, against the race it once lost: `udevadm trigger` without --settle returns once the change
# event is queued, systemd-udevd applies the rule's MODE=0666 later in a worker, and the step's own check of
# /dev/kvm ran in between and failed the row, blaming a device that was about to be usable.
#
# The step's script is taken from the workflow as written and run with stand-ins: sudo runs its command
# (and swallows the rule `tee` would install), apt-get does nothing, /dev/kvm is a file of mode 000 here, and
# udevadm applies mode 0666 to it the way udevd does: at once for `trigger --settle` or a later `udevadm
# settle`, and a second after a bare `trigger` otherwise. The step must pass. The same script with --settle
# taken out must fail, which is what shows the stand-in reproduces the race rather than hiding it.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
workflow="$here/../../.github/workflows/vm-matrix.yml"
if [ "$(id -u)" = 0 ]; then
	echo "skip kvm-step_test.sh: root reads and writes a mode-000 file, so the check it tests cannot fail"
	exit 0
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-kvm-step-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

# The run block of the step, its indentation removed; /dev/kvm becomes this test's device file.
awk '
	/- name: enable KVM for the runner user$/ { step = 1; next }
	step && !block && /^ *run: [|]$/ { block = 1; match($0, /^ */); indent = RLENGTH; next }
	block {
		if ($0 ~ /^ *$/) { print; next }
		match($0, /^ */)
		if (RLENGTH <= indent) exit
		sub(/^ +/, "")
		print
	}' "$workflow" | sed "s#/dev/kvm#$tmp/kvm#g" >"$tmp/step.sh"
grep -q 'udevadm trigger' "$tmp/step.sh" || { echo "FAIL the step's script was not found in $workflow" >&2; exit 1; }

mkdir "$tmp/bin"
cat >"$tmp/bin/sudo" <<'EOF'
#!/bin/sh
if [ "$1" = tee ]; then
	cat >/dev/null
	exit 0
fi
exec "$@"
EOF
cat >"$tmp/bin/apt-get" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$tmp/bin/udevadm" <<'EOF'
#!/bin/sh
case "$1" in
trigger)
	case " $* " in
	*" --settle "* | *" -w "*) chmod 666 "$KVMDEV" ;;
	*)
		: >"$KVMDEV.pending"
		(sleep 1 && chmod 666 "$KVMDEV" && rm -f "$KVMDEV.pending") >/dev/null 2>&1 &
		;;
	esac
	;;
settle) [ ! -e "$KVMDEV.pending" ] || chmod 666 "$KVMDEV" ;;
esac
exit 0
EOF
chmod +x "$tmp/bin/sudo" "$tmp/bin/apt-get" "$tmp/bin/udevadm"

fail=0
# step NAME WANT SCRIPT: runs SCRIPT against a fresh mode-000 device and wants exit WANT.
step() {
	: >"$tmp/kvm"
	chmod 000 "$tmp/kvm"
	rm -f "$tmp/kvm.pending"
	set +e
	PATH="$tmp/bin:$PATH" KVMDEV="$tmp/kvm" bash -e "$3" >"$tmp/out" 2>&1
	got=$?
	set -e
	if [ "$got" = "$2" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: exit $got, want $2" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
	sleep 1.2 # the bare trigger's background chmod finishes before the next case resets the device
}

step "the step as vm-matrix.yml writes it passes once udev has applied the rule" 0 "$tmp/step.sh"
sed 's/ --settle//' "$tmp/step.sh" >"$tmp/unsettled.sh"
step "the same step without --settle loses the race (the stand-in reproduces it)" 1 "$tmp/unsettled.sh"
grep -q '::error::' "$tmp/out" || { echo "FAIL the unsettled step failed without its ::error:: line" >&2; fail=1; }
exit "$fail"
