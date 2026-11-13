// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"fmt"
	"testing"
)

type skipProofRecorder struct {
	skipped bool
	cleanup func()
	fatal   string
}

func (*skipProofRecorder) Helper()            {}
func (r *skipProofRecorder) Cleanup(f func()) { r.cleanup = f }
func (r *skipProofRecorder) Skipped() bool    { return r.skipped }
func (r *skipProofRecorder) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
}
func (r *skipProofRecorder) Skipf(format string, args ...any) { r.skipped = true }

func TestSkippedDecidingProofRejectsSkippedPreconditions(t *testing.T) {
	for _, reason := range []string{"python3 missing", "no plane mode passes"} {
		t.Run(reason, func(t *testing.T) {
			r := new(skipProofRecorder)
			failSkippedDecidingProof(r)
			r.Skipf("%s", reason)
			if r.cleanup == nil {
				t.Fatal("the proof did not install its skip guard")
			}
			r.cleanup()
			if r.fatal == "" {
				t.Fatalf("a required proof skipped successfully: %s", reason)
			}
		})
	}
}

func TestSkippedDecidingProofNeedsRecordedSkip(t *testing.T) {
	// An outside snapshot can count a shared skip after the run's final reading.
	// Such a counter movement does not establish a forced skip in this run.
	r := new(skipProofRecorder)
	requireDecidingSkipProof(r, true, 0, 1, 100)
	if r.fatal == "" {
		t.Fatal("an external skip alone passed the required forced proof")
	}
	r = new(skipProofRecorder)
	requireDecidingSkipProof(r, true, 1, 1, 100)
	if r.fatal != "" || r.skipped {
		t.Fatalf("a recorded deciding skip was rejected: %+v", r)
	}
}
