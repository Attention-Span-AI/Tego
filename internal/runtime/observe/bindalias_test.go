// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Prepared facts take precedence over a different table at recorder construction or Start.
func TestRecorderUsesPreparedMountFacts(t *testing.T) {
	saved := readRecorderMounts
	reads := 0
	readRecorderMounts = func(string) (*agent.MountTable, []byte, error) {
		reads++
		return nil, nil, errors.New("unexpected recorder mount read")
	}
	t.Cleanup(func() { readRecorderMounts = saved })
	f := newFixture(t)
	secret := filepath.Join(f.out, "secret")
	sub := filepath.Join(secret, "sub")
	f.rules = &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: f.out, Resolved: f.out, Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: secret, Resolved: secret, Raw: "./secret/", Unenforced: true},
	}}
	// No NameDeny: the different-device submount lies outside every name-rule scope.
	prepared, err := agent.ParseMountTableStrict([]byte("1 0 8:1 / / rw - ext4 dev rw\n2 1 0:77 / " + sub + " rw - tmpfs tmpfs rw\n"))
	if err != nil {
		t.Fatal(err)
	}
	stale := writeMountinfo(t, "1 0 8:1 / / rw - ext4 dev rw\n")
	r, err := New(Options{Rules: f.rules, Reader: newFakeRing(), Proc: f.procFS, mountinfo: stale, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	r.SetMountTable(prepared, nil)
	sink := &fakeSink{}
	if err := r.Start(context.Background(), source.RunRef{ID: "run", CgroupID: 99, Contract: f.rules}, sink); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if reads != 0 {
		t.Fatalf("recorder acquired mount facts %d times after Prepare", reads)
	}
	if _, ok := r.rules.marked[77]; !ok {
		t.Fatalf("prepared submount device omitted: %v", r.rules.marked)
	}
}

func TestRecorderUsesActualMarkedDevices(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.out, "secret")
	f.rules = &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: f.out, Resolved: f.out, Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: secret, Resolved: secret, Raw: "./secret/", Unenforced: true},
	}}
	samples := [][]byte{fsSample(sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 1, Start: 900, RetOK: true}, 0, 1, 77, filepath.Join(secret, "sub", "x"), "")}
	_, sink := runRecorder(t, f, Options{FlushInterval: time.Hour, listener: func(dev uint64) bool { return dev == 77 }}, samples...)
	if n := len(sink.byKind(record.KindFS)); n != 0 {
		t.Fatalf("%d recorder lines for listener's refused read", n)
	}
}
