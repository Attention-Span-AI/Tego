// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/execpin"
)

// Exec pins (ADR 0048 (3) P2, enforce-plane §2.22). A run Prepare is asked to pin (Run.ExecPin) gets, in its slot, a
// pin map (the slot's inner hash of bpf.MapPlaneExecPins, created once per slot and kept like the row maps), the run's
// MAC key with its gen (bpf.MapPlanePinKeys), and a header that names the launcher's pid namespace and carries
// PlaneSlotExecPin. The supervisor then writes each continued exec's pin through the Handle (PinExec), and the plane
// holds the exec to it. A run Prepare cannot pin is a run without pins, never one whose every exec is refused: its
// handle reports no pins (ExecPins), and the reason is in the run's log.

// ErrPinsFull is PinExec's answer when the slot's pin map has no room.
var ErrPinsFull = errors.New("cgroup: the slot's exec pin map is full")

// planePin is what a pinned slot's fill writes beyond the rows: the run's key and the launcher's pid namespace, in which
// a pin's key numbers its thread (bpf_get_ns_current_pid_tgid's dev, in the kernel's encoding, and inode).
type planePin struct {
	Key                execpin.Key
	PidnsDev, PidnsIno uint64
}

// slotPinMap is a slot's pin map as the Handle writes it.
type slotPinMap interface {
	// put writes pin at key, ErrPinsFull when the map has no room.
	put(key ebpfbindings.PinKey, pin []byte) error
	del(key ebpfbindings.PinKey) error
	keys() ([]ebpfbindings.PinKey, error)
	close() error
}

// execPinRequest is the pin a run asked to be pinned gets, or why it gets none: a plane whose object has no pin maps,
// a kernel recorder without exec outcomes (a kill's line is the recorder's exec record folded with the plane's kill
// sample, ADR 0048 (8): with no record of the run's execs a kill would have no line, and the supervisor's allow would
// stand for an exec the plane killed), a launcher in a time namespace that shifts /proc's start times (the
// supervisor's key would never match the plane's), or a pid namespace that cannot be named.
func (h *Handle) execPinRequest() (*planePin, error) {
	if !h.run.ExecPin || h.plane == nil {
		return nil, nil
	}
	if !h.plane.pinsReady() {
		return nil, errors.New("the plane object has no exec pin maps")
	}
	if !h.ExecOutcomes() {
		return nil, errors.New("the kernel recorder has no exec outcomes, so a kill would have no line")
	}
	if err := BootOffsetZero(); err != nil {
		return nil, err
	}
	dev, ino, err := launcherPidns()
	if err != nil {
		return nil, err
	}
	pin := &planePin{PidnsDev: dev, PidnsIno: ino}
	if _, err := unix.Getrandom(pin.Key[:], 0); err != nil {
		return nil, fmt.Errorf("getrandom: %w", err)
	}
	return pin, nil
}

// procSelf is the procfs directory this launcher reads its own namespaces from; a variable for the tests.
var procSelf = "/proc/self"

// launcherPidns names this launcher's pid namespace as bpf_get_ns_current_pid_tgid compares it: nsfs's device in the
// kernel's encoding (MKDEV, not stat's st_dev; ADR 0048's K0 note) and the namespace's inode. The supervisor reads
// thread ids in this namespace, so it is the one a pin's key numbers its thread in.
func launcherPidns() (dev, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Stat(procSelf+"/ns/pid", &st); err != nil {
		return 0, 0, fmt.Errorf("the launcher's pid namespace: %w", err)
	}
	return execpin.KernelDev(unix.Major(st.Dev), unix.Minor(st.Dev)), st.Ino, nil
}

// BootOffsetZero is nil when /proc's start times read by this launcher are the plane's: /proc/<tid>/stat's start time
// is shifted by the reading process's time namespace's boottime offset, while the plane reads the raw
// start_boottime (ADR 0048 (3) "Time namespaces"). timens_offsets shows the namespace this process's children get, so
// the two must also be one namespace. A kernel without time namespaces has no offset.
func BootOffsetZero() error {
	b, err := os.ReadFile(procSelf + "/timens_offsets")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the launcher's time namespace offsets: %w", err)
	}
	var cur, kids unix.Stat_t
	if err := unix.Stat(procSelf+"/ns/time", &cur); err != nil {
		return fmt.Errorf("the launcher's time namespace: %w", err)
	}
	if err := unix.Stat(procSelf+"/ns/time_for_children", &kids); err != nil {
		return fmt.Errorf("the launcher's children's time namespace: %w", err)
	}
	if cur.Ino != kids.Ino || cur.Dev != kids.Dev {
		return errors.New("the launcher's children enter another time namespace than its own")
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := bytes.Fields(sc.Bytes())
		// The clock is named (5.6 and later print "boottime") or numbered (CLOCK_BOOTTIME, 7).
		if len(f) != 3 || string(f[0]) != "boottime" && string(f[0]) != strconv.Itoa(unix.CLOCK_BOOTTIME) {
			continue
		}
		if string(f[1]) != "0" || string(f[2]) != "0" {
			return fmt.Errorf("the launcher's time namespace offsets boottime by %s s %s ns", f[1], f[2])
		}
		return nil
	}
	return errors.New("the launcher's time namespace offsets name no boottime clock")
}

// ExecPins reports whether this run's slot is pinned (ADR 0048 (3) P2), and the run's MAC key, which the supervisor's
// pins are under. The key is the launcher's and the supervisor's alone: it is never logged or written to the ledger.
func (h *Handle) ExecPins() (execpin.Key, bool) {
	if h.pinMap == nil {
		return execpin.Key{}, false
	}
	return h.pinKey, true
}

// ExecPinClaim reports whether the kernel holds this run's execs to the facts that were decided (ADR 0048 (7), (9)),
// and why not when it does not: a plane mode decides the run, doctor's exec pin cell passed in that mode
// (PlaneSetup.ExecPins), and a run that asked to be pinned (command rules, or an exec gate that can escalate) has its
// slot pinned. A run with nothing to pin on such a plane rests on no copied exec fact, so it claims as well. Only a
// claim drops the exec.rules/argv and gate.exec cells from run_start.best_effort, sets the run's
// exec.command_argv capability, and lets an exec.assurance: kernel run start.
func (h *Handle) ExecPinClaim() (bool, string) {
	switch {
	case h.planeMode == "":
		return false, "no decision plane decides the run"
	case !h.opts.Plane.ExecPins || h.opts.Plane.Mode != h.planeMode:
		return false, fmt.Sprintf("doctor's exec pin cell (plane.exec_pin) has not passed in plane mode %s", h.planeMode)
	case h.run.ExecPin && h.pinMap == nil:
		why := h.pinOff
		if why == "" {
			why = "Prepare did not pin it"
		}
		return false, "the run's plane slot is not pinned: " + why
	}
	return true, ""
}

// PinExec writes one continued exec's pin for the thread tid (in the launcher's pid namespace) started at startTicks,
// with the run's gen and its next seq, which it returns (ADR 0048 (3) "Write"). ErrPinsFull when the map is full.
func (h *Handle) PinExec(tid uint32, startTicks uint64, pin []byte) (uint32, error) {
	if h.pinMap == nil || len(pin) != execpin.Size {
		return 0, errors.New("cgroup: this run is not pinned")
	}
	seq := h.pinSeq.Add(1)
	b := append([]byte(nil), pin...)
	execpin.SetGenSeq(b, h.gen, seq)
	if err := h.pinMap.put(ebpfbindings.PinKey{TID: tid, Start: startTicks}, b); err != nil {
		return 0, err
	}
	return seq, nil
}

// SweepExecPins deletes the slot's pins whose thread live reports gone: an exec that failed before bprm_check leaves its
// pin until the same thread's next exec overwrites it, or this sweep, which a full map triggers.
func (h *Handle) SweepExecPins(live func(tid uint32, startTicks uint64) bool) error {
	if h.pinMap == nil {
		return nil
	}
	keys, err := h.pinMap.keys()
	if err != nil {
		return err
	}
	var errs []error
	for _, k := range keys {
		if !live(k.TID, k.Start) {
			if err := h.pinMap.del(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// openPins opens the slot's pin map for PinExec once the fill wrote a pinned header.
func (h *Handle) openPins(pin *planePin) error {
	m, err := h.plane.slotPins(h.slot)
	if err != nil {
		return err
	}
	h.pinMap, h.pinKey = m, pin.Key
	return nil
}

// closePins releases the pin map's descriptor.
func (h *Handle) closePins() error {
	if h.pinMap == nil {
		return nil
	}
	err := h.pinMap.close()
	h.pinMap = nil
	return err
}

// handlePins is the Handle's pin state: the slot's pin map (nil in a run that is not pinned), the run's key, and its
// last seq.
type handlePins struct {
	pinMap slotPinMap
	pinKey execpin.Key
	pinSeq atomic.Uint32
	// pinOff is why a run that asked to be pinned is not (execPinRequest's error), "" otherwise.
	pinOff string
}

// ebpfPinMap is a slot's pin map in the kernel.
type ebpfPinMap struct{ m *ebpf.Map }

func (p ebpfPinMap) put(key ebpfbindings.PinKey, pin []byte) error {
	if err := p.m.Put(key, pin); err != nil {
		if errors.Is(err, unix.E2BIG) || errors.Is(err, unix.ENOMEM) {
			return fmt.Errorf("%w: %w", ErrPinsFull, err)
		}
		return fmt.Errorf("cgroup: write an exec pin: %w", err)
	}
	return nil
}

func (p ebpfPinMap) del(key ebpfbindings.PinKey) error { return p.m.Delete(key) }

func (p ebpfPinMap) keys() ([]ebpfbindings.PinKey, error) {
	var (
		out []ebpfbindings.PinKey
		k   ebpfbindings.PinKey
		v   = make([]byte, execpin.Size)
	)
	it := p.m.Iterate()
	for it.Next(&k, v) {
		out = append(out, k)
	}
	return out, it.Err()
}

func (p ebpfPinMap) close() error { return p.m.Close() }

// pinsReady reports whether the plane holds the pin maps a pinned slot needs: both maps open, and the pin map's inner
// definition loaded or loadable (an adopted plane's compact load restores it when a slot's map is first made,
// innerSpec).
func (p *bpfPlane) pinsReady() bool {
	return p.execPins != nil && p.pinKeys != nil && (p.pinsInner != nil || p.loadInner != nil)
}

// slotPins opens the slot's pin map.
func (p *bpfPlane) slotPins(slot uint32) (slotPinMap, error) {
	m, err := innerOf(p.execPins, slot, ebpfbindings.MapPlaneExecPins)
	if err != nil {
		return nil, err
	}
	return ebpfPinMap{m}, nil
}

// putPins makes a pinned slot's pin map exist and empty and writes the run's key with its gen, before the header that
// makes the plane read them (fill). A slot whose run is not pinned writes nothing here: its header's flag is clear, and
// the plane reads neither map for it.
func (p *bpfPlane) putPins(req planeFillRequest) error {
	if req.Pin == nil {
		return nil
	}
	if !p.pinsReady() {
		return fmt.Errorf("cgroup: the %s plane has no exec pin maps", p.mode)
	}
	if err := makeSlotMap(p.execPins, ebpfbindings.MapPlaneExecPins, p.innerSpec, req.Slot); err != nil {
		return err
	}
	if err := p.clearPins(req.Slot); err != nil {
		return err
	}
	k0, k1 := req.Pin.Key.Halves()
	if err := p.pinKeys.Put(req.Slot, &ebpfbindings.PinKeyval{Gen: req.Gen, K0: k0, K1: k1}); err != nil {
		return fmt.Errorf("cgroup: write slot %d's %s: %w", req.Slot, ebpfbindings.MapPlanePinKeys, err)
	}
	return nil
}

// clearPins zeroes the slot's key and deletes every pin the slot's map holds, of any gen (Detach, the reaper's purge
// and the next Prepare, ADR 0048 (7)). A plane without the maps, or a slot never pinned, has nothing to clear.
func (p *bpfPlane) clearPins(slot uint32) error {
	var errs []error
	if p.pinKeys != nil {
		if err := p.pinKeys.Put(slot, &ebpfbindings.PinKeyval{}); err != nil {
			errs = append(errs, fmt.Errorf("cgroup: clear slot %d's %s: %w", slot, ebpfbindings.MapPlanePinKeys, err))
		}
	}
	if p.execPins == nil {
		return errors.Join(errs...)
	}
	inner, ok, err := ebpfbindings.OpenInner(p.execPins, slot)
	if err != nil || !ok {
		return errors.Join(append(errs, err)...)
	}
	defer func() { _ = inner.Close() }()
	pins := ebpfPinMap{inner}
	keys, err := pins.keys()
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("cgroup: read slot %d's %s: %w", slot, ebpfbindings.MapPlaneExecPins, err))...)
	}
	for _, k := range keys {
		if err := pins.del(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: clear slot %d's %s: %w", slot, ebpfbindings.MapPlaneExecPins, err))
		}
	}
	return errors.Join(errs...)
}
