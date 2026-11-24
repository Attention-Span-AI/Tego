// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"errors"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"slices"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
)

func TestCaptureCollectionReadback(t *testing.T) {
	prev := checkCaptureStack
	t.Cleanup(func() { checkCaptureStack = prev })
	denied := errors.New("cannot verify capture stack safety: read translated instructions: permission denied")
	for _, names := range [][]string{bpf.SSLSinglePrograms, bpf.SSLPrograms, append(append([]string{}, bpf.SSLPrograms...), "future_capture")} {
		coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
		for _, name := range names {
			coll.Programs[name] = &ebpf.Program{}
		}
		var checked []string
		checkCaptureStack = func(name string, _ *ebpf.Program) error { checked = append(checked, name); return nil }
		if err := checkCaptureCollection(coll); err != nil {
			t.Fatal(err)
		}
		slices.Sort(checked)
		want := slices.Sorted(slices.Values(names))
		if !slices.Equal(checked, want) {
			t.Fatalf("checked %v, want %v", checked, names)
		}
		for _, name := range names {
			checkCaptureStack = func(got string, _ *ebpf.Program) error {
				if got == name {
					return denied
				}
				return nil
			}
			if err := checkCaptureCollection(coll); !errors.Is(err, denied) {
				t.Fatalf("read-back failure in %s did not make capture unavailable: %v", name, err)
			}
		}
	}
}

func TestCaptureLoaderRequiresReadback(t *testing.T) {
	prev := loadCaptureCollection
	t.Cleanup(func() { loadCaptureCollection = prev })
	loadCaptureCollection = func(string, string) (*ebpf.Collection, error) { return &ebpf.Collection{}, nil }
	if coll, err := LoadCollection("", ""); coll != nil || err == nil {
		t.Fatalf("loader offered a collection without checked capture programs: coll=%v err=%v", coll, err)
	}
}

// Inject the read-back failure at the kernel-opening boundary: the real reader
// and program-info calls need privilege and are separately covered in a guest.
func TestCaptureReadbackFailureIsMechanismUnavailable(t *testing.T) {
	previousOpen, previousCheck := startKernel, checkCaptureStack
	t.Cleanup(func() { startKernel, checkCaptureStack = previousOpen, previousCheck })
	denied := errors.New("uprobe: cannot verify capture stack safety: read translated instructions: injected permission denied")
	checkCaptureStack = func(string, *ebpf.Program) error { return denied }
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}}
	for _, name := range bpf.SSLSinglePrograms {
		coll.Programs[name] = &ebpf.Program{}
	}
	opened := 0
	startKernel = func(u *Uprobe, hash string, cg uint64, ring bool) error {
		opened++
		if hash != "capture-test" || cg != 41 || !ring {
			t.Errorf("kernel opening: hash=%q cg=%d ring=%v", hash, cg, ring)
		}
		if err := checkCaptureCollection(coll); err != nil {
			return err
		}
		// If the check is removed, let Start complete rather than panic on a nil
		// reader: the assertions must detect the lost unavailable transition.
		u.reader = &fakeRing{}
		return nil
	}
	att := &fakeAttacher{}
	u, err := New(Options{Kernel: true, Attacher: att, Preattach: func() []string { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	u.FollowKernel("capture-test")
	sink := &fakeSink{}
	if err := u.Start(context.Background(), source.RunRef{ID: "r-stack", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatalf("source Start: %v", err)
	}
	if err := u.Stop(); err != nil {
		t.Fatalf("source Stop: %v", err)
	}
	if opened != 1 || u.UnavailableCause() != denied.Error() {
		t.Errorf("opened %d, cause %q, want exact read-back error %q", opened, u.UnavailableCause(), denied)
	}
	gaps := u.Gaps()
	if len(gaps) != 1 {
		t.Fatalf("gaps %+v, want exactly one unavailable mechanism", gaps)
	}
	if gaps[0].What != "capture" || gaps[0].Why != GapMechanismUnavailable || gaps[0].Binary != Name || gaps[0].Count != 0 {
		t.Errorf("gaps %+v, want capture/mechanism-unavailable/uprobe count 0", gaps)
	}
	if att.count() != 0 || len(sink.events()) != 0 {
		t.Errorf("unavailable source attached %d probes and emitted %d events", att.count(), len(sink.events()))
	}
}
