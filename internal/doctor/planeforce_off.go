// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package doctor

import bpfobj "github.com/attention-span-ai/tego/internal/bpf"

// planeTestOutcome is the seam of planeforce_testhook.go: in a product build it returns the outcome it was given, so
// a row's outside leg is what doctor's own syscall answered and no switch, variable or key of a test reaches it.
func planeTestOutcome(_ bpfobj.PlaneMode, _, outcome string) string { return outcome }
