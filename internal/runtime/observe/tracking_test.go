// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
)

func TestTrackingFailureSurvivesRecordOff(t *testing.T) {
	for _, silent := range []bool{false, true} {
		r := &Recorder{silent: silent, gaps: map[string]int64{}, scoped: true, slot: 9, gen: 7}
		calls := 0
		r.SetTrackingFailure(func(err error) {
			calls++
			if !strings.Contains(err.Error(), "cgroup 42 under 7") {
				t.Error(err)
			}
		})
		rec := &Record{Header: Header{Kind: KindCgroupMkdir, RunIdx: 9, Gen: 7}, Cgroup: CgroupBody{ParentCgroupID: 7, ChildCgroupID: 42}}
		r.handle(rec)
		if calls != 0 || len(r.gaps) != 0 {
			t.Fatal("successful insertion reported a failure")
		}
		h := sample{Kind: KindCgroupMkdir, RunIdx: 9, Gen: 7}
		decoded, err := Decode(wire(&bpf.CgroupEvent{Hdr: h.header(CgroupSize), ParentCgroupID: 7, ChildCgroupID: 42, Err: -7}))
		if err != nil {
			t.Fatal(err)
		}
		rec = &decoded
		rec.RunIdx = 10
		r.handle(rec)
		if calls != 0 {
			t.Fatal("another run's tracking failure ended this run")
		}
		rec.RunIdx = 9
		r.handle(rec)
		r.handle(rec)
		if calls != 1 || r.gaps[GapCgroupTrackingFailed] != 2 {
			t.Fatalf("silent=%v: callbacks=%d gaps=%v", silent, calls, r.gaps)
		}
	}
}
