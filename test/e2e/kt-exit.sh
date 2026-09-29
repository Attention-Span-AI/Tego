# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# kt-exit.sh — the exit codes every script under test/e2e returns, and how the kernel matrix reads one. Sourced
# by lib.sh and by test/vm/run-matrix-row.sh; it makes nothing and sets no trap.
#
# "A distinct exit code for pass, fail, and skip". The skip is 77 (automake's), not 2: bash exits
# 2 on a syntax error and several scripts exit 2 on a usage error, and neither may read as a named skip.
KT_PASS=0
# shellcheck disable=SC2034 # Sourced callers use this shared failure code.
KT_FAIL=1
KT_SKIP=77

# kt_verdict names a kill test's exit code: 0 PASS, KT_SKIP SKIP, anything else (1, a bash or usage error's 2, a
# timeout's 124) FAIL.
kt_verdict() {
	case "$1" in
	"$KT_PASS") echo PASS ;;
	"$KT_SKIP") echo SKIP ;;
	*) echo FAIL ;;
	esac
}
