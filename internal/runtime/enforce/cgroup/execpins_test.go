// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// fakePinMap is a slot's pin map holding at most limit pins (0: no limit).
type fakePinMap struct {
	pins   map[ebpfbindings.PinKey][]byte
	limit  int
	closed int
}

func (m *fakePinMap) put(k ebpfbindings.PinKey, pin []byte) error {
	if m.pins == nil {
		m.pins = map[ebpfbindings.PinKey][]byte{}
	}
	if _, ok := m.pins[k]; !ok && m.limit > 0 && len(m.pins) >= m.limit {
		return ErrPinsFull
	}
	m.pins[k] = pin
	return nil
}

func (m *fakePinMap) del(k ebpfbindings.PinKey) error { delete(m.pins, k); return nil }

func (m *fakePinMap) keys() ([]ebpfbindings.PinKey, error) {
	var out []ebpfbindings.PinKey
	for k := range m.pins {
		out = append(out, k)
	}
	return out, nil
}

func (m *fakePinMap) close() error { m.closed++; return nil }

// TestSlotHeaderCarriesExecPin (ADR 0048 (3) P2): a pinned run's header carries PlaneSlotExecPin and the pid namespace
// its pins' keys number threads in; an unpinned run's carries neither.
func TestSlotHeaderCarriesExecPin(t *testing.T) {
	req := planeFillRequest{Gen: 3}
	if h := slotHeader(req, false, 0, 0); h.Flags&ebpfbindings.PlaneSlotExecPin != 0 || h.PidnsDev != 0 || h.PidnsIno != 0 {
		t.Fatalf("an unpinned run's header %+v", h)
	}
	req.Pin = &planePin{PidnsDev: 4<<20 | 300, PidnsIno: 0xeffffffc}
	if h := slotHeader(req, false, 0, 0); h.Flags&ebpfbindings.PlaneSlotExecPin == 0 || h.PidnsDev != 4<<20|300 || h.PidnsIno != 0xeffffffc {
		t.Fatalf("a pinned run's header %+v", h)
	}
}

// TestBootOffsetZero: pins stay off when the launcher's /proc start times are shifted by its time namespace, or its
// children's namespace is another one; a kernel without time namespaces has no offset.
func TestBootOffsetZero(t *testing.T) {
	setup := func(t *testing.T, offsets string, sameNS bool) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"time", "time_for_children"} {
			if err := os.WriteFile(filepath.Join(dir, "ns", n), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if sameNS {
			_ = os.Remove(filepath.Join(dir, "ns", "time_for_children"))
			if err := os.Link(filepath.Join(dir, "ns", "time"), filepath.Join(dir, "ns", "time_for_children")); err != nil {
				t.Fatal(err)
			}
		}
		if offsets != "" {
			if err := os.WriteFile(filepath.Join(dir, "timens_offsets"), []byte(offsets), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		old := procSelf
		procSelf = dir
		t.Cleanup(func() { procSelf = old })
	}
	for _, c := range []struct {
		name    string
		offsets string
		same    bool
		ok      bool
	}{
		{"no time namespaces", "", true, true},
		{"zero", "monotonic           0         0\nboottime            0         0\n", true, true},
		{"numbered zero", "1 5 0\n7 0 0\n", true, true},
		{"boottime offset", "monotonic 0 0\nboottime 3600 0\n", true, false},
		{"nanoseconds", "boottime 0 1\n", true, false},
		{"children elsewhere", "boottime 0 0\n", false, false},
		{"no boottime line", "monotonic 0 0\n", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			setup(t, c.offsets, c.same)
			if err := BootOffsetZero(); (err == nil) != c.ok {
				t.Fatalf("BootOffsetZero = %v, want ok %v", err, c.ok)
			}
		})
	}
}

// TestLaunchPidnsIsTheKernelsEncoding: the header's pid namespace device is MKDEV's encoding of nsfs's device, which
// bpf_get_ns_current_pid_tgid compares, not stat's st_dev.
func TestLaunchPidnsIsTheKernelsEncoding(t *testing.T) {
	dev, ino, err := launcherPidns()
	if err != nil {
		t.Skipf("no pid namespace to read: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		t.Fatal(err)
	}
	if dev != uint64(unix.Major(st.Dev))<<20|uint64(unix.Minor(st.Dev)) || ino != st.Ino {
		t.Fatalf("pidns %#x %d, stat %#x %d", dev, ino, st.Dev, st.Ino)
	}
}

// TestPinExecWritesGenAndSeq: each pin the supervisor hands over is written with the run's gen and the run's next seq,
// keyed by its thread and start time; a full map says ErrPinsFull, and a sweep deletes only the pins whose thread is
// gone.
func TestPinExecWritesGenAndSeq(t *testing.T) {
	m := &fakePinMap{limit: 2}
	h := &Handle{gen: 9}
	if _, ok := h.ExecPins(); ok {
		t.Fatal("an unpinned handle reports pins")
	}
	if _, err := h.PinExec(1, 1, make([]byte, execpin.Size)); err == nil {
		t.Fatal("an unpinned handle wrote a pin")
	}
	h.pinMap, h.pinKey = m, execpin.Key{1}
	if k, ok := h.ExecPins(); !ok || k != (execpin.Key{1}) {
		t.Fatalf("ExecPins = %v %v", k, ok)
	}
	pin := make([]byte, execpin.Size)
	pin[8] = execpin.FormDirect
	for i, key := range []ebpfbindings.PinKey{{TID: 40, Start: 100}, {TID: 41, Start: 101}} {
		seq, err := h.PinExec(key.TID, key.Start, pin)
		if err != nil || seq != uint32(i+1) {
			t.Fatalf("PinExec %d = %d, %v", i, seq, err)
		}
		got := m.pins[key]
		if binary.LittleEndian.Uint32(got) != 9 || binary.LittleEndian.Uint32(got[4:]) != seq || got[8] != execpin.FormDirect {
			t.Fatalf("pin % x: want gen 9, seq %d, the form kept", got[:12], seq)
		}
	}
	if pin[0] != 0 || pin[4] != 0 {
		t.Fatal("PinExec wrote into the caller's bytes")
	}
	if _, err := h.PinExec(42, 102, pin); !errors.Is(err, ErrPinsFull) {
		t.Fatalf("a full map: %v", err)
	}
	if err := h.SweepExecPins(func(tid uint32, start uint64) bool { return tid == 41 }); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.pins[ebpfbindings.PinKey{TID: 40, Start: 100}]; ok || len(m.pins) != 1 {
		t.Fatalf("after the sweep: %v", m.pins)
	}
	if seq, err := h.PinExec(42, 102, pin); err != nil || seq != 4 {
		t.Fatalf("after the sweep: %d, %v (a failed write still took its seq)", seq, err)
	}
}

// TestPreparePinsAPinnedRun: a run asked to be pinned, on a plane with pin maps, is filled with a key and the
// launcher's pid namespace, and its handle reports pins; a plane without the maps, a kernel recorder without exec
// outcomes (no line could carry a kill), or a run not asked, is filled without, and its handle reports none. Detach closes the pin map.
func TestPreparePinsAPinnedRun(t *testing.T) {
	for _, c := range []struct {
		name      string
		ask, maps bool
		noOutcome bool
		pinned    bool
	}{
		{"pinned", true, true, false, true},
		{"no maps", true, false, false, false},
		{"not asked", false, true, false, false},
		{"no exec outcomes", true, true, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, plane := planeFixture(t, ebpfbindings.PlaneLSM)
			if c.maps {
				plane.pins = &fakePinMap{}
			}
			f.kernel.noExecOutcomes = c.noOutcome
			f.run.ExecPin = c.ask
			h, err := f.backend.Prepare(context.Background(), f.table, f.run)
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			if len(plane.fills) != 1 {
				t.Fatalf("%d fills", len(plane.fills))
			}
			req := plane.fills[0]
			key, ok := h.ExecPins()
			if (req.Pin != nil) != c.pinned || ok != c.pinned {
				t.Fatalf("fill pin %+v, ExecPins %v: want pinned %v", req.Pin, ok, c.pinned)
			}
			if !c.pinned {
				return
			}
			dev, ino, err := launcherPidns()
			if err != nil || req.Pin.PidnsDev != dev || req.Pin.PidnsIno != ino || req.Pin.Key != key || key == (execpin.Key{}) {
				t.Fatalf("fill pin %+v: want the launcher's pid namespace %#x %d and the handle's key (%v)", req.Pin, dev, ino, err)
			}
			if err := h.Detach(); err != nil {
				t.Fatal(err)
			}
			if plane.pins.closed != 1 {
				t.Fatalf("the pin map was closed %d times by Detach", plane.pins.closed)
			}
			if _, ok := h.ExecPins(); ok {
				t.Fatal("a detached handle reports pins")
			}
		})
	}
}

// TestExecPinClaim is ADR 0048 (7), (9): a run's handle claims that the kernel holds its execs to the decided facts
// only where a plane mode decides it, doctor's exec pin cell passed in that mode, and, for a run that asked to be
// pinned, its slot is pinned; only then do the exec.command_argv row and (with an escalating exec gate) the gate exec
// row hold. Each refusal says why.
func TestExecPinClaim(t *testing.T) {
	cell := PlaneSetup{Mode: ebpfbindings.PlaneLSM, ExecPins: true}
	for _, c := range []struct {
		name   string
		h      *Handle
		claim  bool
		reason string
	}{
		{"no plane", &Handle{opts: Options{Plane: cell}, run: Run{ExecPin: true}}, false, "no decision plane"},
		{"cell not passed", &Handle{planeMode: ebpfbindings.PlaneLSM, opts: Options{Plane: PlaneSetup{Mode: ebpfbindings.PlaneLSM}},
			run: Run{ExecPin: true}, handlePins: handlePins{pinMap: &fakePinMap{}}}, false, "exec pin cell"},
		{"cell of another mode", &Handle{planeMode: ebpfbindings.PlaneFmodRet, opts: Options{Plane: cell},
			run: Run{ExecPin: true}, handlePins: handlePins{pinMap: &fakePinMap{}}}, false, "exec pin cell"},
		{"slot not pinned", &Handle{planeMode: ebpfbindings.PlaneLSM, opts: Options{Plane: cell}, run: Run{ExecPin: true},
			handlePins: handlePins{pinOff: "the kernel recorder has no exec outcomes"}}, false, "no exec outcomes"},
		{"pinned", &Handle{planeMode: ebpfbindings.PlaneLSM, opts: Options{Plane: cell}, run: Run{ExecPin: true},
			handlePins: handlePins{pinMap: &fakePinMap{}}}, true, ""},
		{"nothing to pin", &Handle{planeMode: ebpfbindings.PlaneLSM, opts: Options{Plane: cell}}, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			claim, why := c.h.ExecPinClaim()
			if claim != c.claim || !strings.Contains(why, c.reason) || claim && why != "" {
				t.Fatalf("ExecPinClaim = %t %q, want %t and a reason with %q", claim, why, c.claim, c.reason)
			}
			caps := c.h.Capabilities()
			if want := c.claim && c.h.pinMap != nil; caps.Has(backend.CapExecCommandArgv) != want {
				t.Fatalf("exec.command_argv %t, want %t", caps.Has(backend.CapExecCommandArgv), want)
			}
			if caps.Has(backend.CapGateExecCompletion) {
				t.Fatal("gate.exec_completion without an exec gate")
			}
		})
	}
}
