// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"slices"
	"testing"
)

// minLandlockTruncateABI is the first Landlock ABI that can deny a truncation (kernel 6.2). Below it the tier-1
// seccomp filter notifies truncate(2) (internal/runtime/enforce/landlock, truncateTest, R2 and E31) and the supervisor
// answers it EPERM, with a refused line, before the plane's path_truncate hook is reached; the filter keeps that arm when
// the decision plane is loaded (TestPlaneFilterKeepsTheErrnoArms), so the agent sees EPERM and not the plane's EACCES. The
// plane stays the decider of everything else on those kernels, ftruncate(2) and an O_TRUNC open included (the 6.1 row gave
// EACCES for both).
const minLandlockTruncateABI = 3

// planeBlockRefusals is the errnos a refused change of a live block's phase 1 may carry on a machine whose Landlock
// ABI is abi: the plane's EACCES for every change, and also EPERM for truncate(2) below ABI 3, from the filter's arm.
// The errno is tied to the probed ABI, never to a version string, and no other pair is accepted.
func planeBlockRefusals(op string, abi int) []string {
	if op == "truncate" && abi < minLandlockTruncateABI {
		return []string{"EACCES", "EPERM"}
	}
	return []string{"EACCES"}
}

// planeBlockRefused reports whether got, a probe's answer for op, is a refusal the plane's design allows.
func planeBlockRefused(op string, got any, abi int) bool {
	s, ok := got.(string)
	return ok && slices.Contains(planeBlockRefusals(op, abi), s)
}

func TestPlaneBlockRefusals(t *testing.T) {
	for _, tc := range []struct {
		op   string
		abi  int
		got  any
		want bool
	}{
		{"truncate", 2, "EPERM", true},   // al2023, kernel 6.1: the filter's arm
		{"truncate", 2, "EACCES", true},  // the plane, should the arm be left out
		{"truncate", 1, "EPERM", true},   // Landlock ABI 1 (5.13)
		{"truncate", 3, "EACCES", true},  // 6.2 and later: the plane or Landlock
		{"truncate", 3, "EPERM", false},  // nothing at ABI 3 and later answers EPERM
		{"truncate", 2, "ok", false},     // an allowed truncate is never a refusal
		{"truncate", 2, "ENOENT", false}, // nor is an unrelated errno
		{"truncate", 2, nil, false},
		{"ftruncate_early", 2, "EPERM", false}, // only truncate(2) has the arm; ftruncate is the plane's on 6.1
		{"ftruncate_early", 2, "EACCES", true},
		{"trunc_open", 2, "EPERM", false},
		{"setxattr", 2, "EACCES", true},
		{"setxattr", 2, "skipped", false}, // the hook precedes the filesystem's own answer: skipped is a miss
		{"removexattr", 7, "skipped", false},
		{"mnt_setxattr", 7, "EACCES", true},
		{"unlink", 2, "EPERM", false},
	} {
		if got := planeBlockRefused(tc.op, tc.got, tc.abi); got != tc.want {
			t.Errorf("%s at ABI %d answered %v: refused = %v, want %v", tc.op, tc.abi, tc.got, got, tc.want)
		}
	}
}

// TestPlaneBlockRefusalsAL2023Row is the Amazon Linux 2023 row's own answers (kernel 6.1, Landlock ABI 2, no user
// xattrs on the run's filesystem or the tmpfs, both plane modes of both boots): every refusal the test lists is
// accepted at ABI 2, and the same answers do not pass on a machine at ABI 3 or later, where truncate(2) is the
// plane's or Landlock's EACCES.
func TestPlaneBlockRefusalsAL2023Row(t *testing.T) {
	row := map[string]any{"truncate": "EPERM", "ftruncate_early": "EACCES", "trunc_open": "EACCES",
		"setxattr": "EACCES", "removexattr": "EACCES", "mnt_setxattr": "EACCES", "unlink": "EACCES", "chmod": "EACCES"}
	for op, got := range row {
		if !planeBlockRefused(op, got, 2) {
			t.Errorf("%s = %v at ABI 2 is not accepted", op, got)
		}
	}
	if planeBlockRefused("truncate", row["truncate"], 3) {
		t.Error("truncate = EPERM is accepted at ABI 3")
	}
}
