#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# go-shim.sh — installed as /usr/local/bin/go inside the kvm-run.sh guest by test/vm/root-suites.sh.
#
# Why it exists: a few integration tests build a helper at run time with `go build -o OUT PKG`
# (internal/runtime builds cmd/tego and test/workloads/model-agent, internal/runtime/cgroup builds its
# memhog). The guest has no Go toolchain, module cache or build cache, and carrying them in would
# triple the initramfs for three binaries. root-suites.sh builds exactly those packages on the host
# from the same tree, CGO_ENABLED=0 like the tests ask, into /vm/prebuilt/<last path element>, and
# this shim hands the test that file. It serves nothing else: any other go command fails loudly, so
# a test that grows a new `go` call shows up as a failure here rather than as a silent skip.
#
# The tags decide the variant, exactly as they would for a real `go build` the test starts with its own
# environment: GOFLAGS or a -tags flag naming tegobpf gets <name>.tegobpf (built with the objects
# embedded), one naming tegotesthooks gets <name>.testhooks, and both get <name>.tegobpf.testhooks; any
# other build flag is accepted and ignored, since the helpers are prebuilt. The testhooks variant is what
# internal/runtime's CLI tests build to point tego's chain anchor and own log into their own directories
# (internal/cli/anchor_testhook.go, ownlog_testhook.go); served the plain build instead, their tego
# ignores both variables and those tests read the wrong log.
set -eu

die() {
	echo "go (tego-vm shim): $*" >&2
	exit 1
}

[ "${1:-}" = build ] || die "only 'go build -o OUT PKG' is served in the guest, not: go $*"
shift
out=""
pkg=""
tags="${GOFLAGS:-}"
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out="$2"; shift 2 ;;
	-o=*) out="${1#-o=}"; shift ;;
	-tags) tags="$tags ${2:-}"; shift 2 ;;
	-tags=*) tags="$tags ${1#-tags=}"; shift ;;
	-ldflags | -gcflags | -asmflags | -mod | -p | -buildmode | -modfile | -overlay | -pgo) shift 2 ;;
	-*) shift ;;
	*)
		[ -z "$pkg" ] || die "one package per build, got $pkg and $1"
		pkg="$1"
		shift
		;;
	esac
done
[ -n "$pkg" ] || die "no package named"
[ -n "$out" ] || die "no -o given for $pkg"

dir="${TEGO_VM_PREBUILT:-/vm/prebuilt}"
name="${pkg##*/}"
src="$dir/$name"
case " $tags " in
*tegobpf*) src="$src.tegobpf" ;;
esac
case " $tags " in
*tegotesthooks*) src="$src.testhooks" ;;
esac
[ -f "$src" ] || die "no prebuilt binary for $pkg at $src (root-suites.sh builds cmd/tego, memhog and model-agent)"
case "$out" in */) out="$out$name" ;; esac
cp "$src" "$out"
chmod 0755 "$out"
