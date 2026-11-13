// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The plane's answer in a build's pin directory (ADR 0024 (3); docs/p0/enforce-plane.md R21): the mode and build
// the probe selected, which the backend that loads the build (TIER3-PLAN T6) pins beside its programs, so that a
// run adopting the pinned build probes nothing. bpffs holds no regular file, so the answer is a one-entry array
// map, pinned by name. doctor itself never pins it (I7): PinPlaneAnswer is the backend's, adoptPinnedPlane the
// run's.

// PlanePinMap is the pinned map in a plane build's pin directory that holds the probe's answer.
const PlanePinMap = "tego_plane_probe"

// planePinMagic ("TGPL") and planePinVersion identify the value's layout; any other is no answer. Version 2 added the
// flags byte (ADR 0048 (7)): an answer of version 1 cannot say whether the mode's exec pin cell passed, so a run
// probes rather than adopt it.
const (
	planePinMagic   = 0x4c504754
	planePinVersion = 2
)

// planePinValueSize is the value's size: magic (4), version (2), mode (1), build (1), flags (1), three reserved zero
// bytes.
const planePinValueSize = 12

// planePinExecPins is the flags bit that says the mode's exec pin cell passed (PlaneChoice.ExecPins).
const planePinExecPins = 0x01

// planePinBPFFS is the bpf filesystem the plane's pins live under (cgroupenforce.DefaultBPFFS; doctor does not
// import the backend).
const planePinBPFFS = "/sys/fs/bpf"

// PlanePinDir is a plane build's pin directory, /sys/fs/bpf/tego/<bpf_hash>-<mode> (ADR 0024 (2): the mode is in
// the name, so two modes never share maps).
func PlanePinDir(bpffs, hash string, m bpfobj.PlaneMode) string {
	if bpffs == "" {
		bpffs = planePinBPFFS
	}
	return filepath.Join(bpffs, "tego", hash+"-"+string(m))
}

// encodePlanePin is the pinned value for c.
func encodePlanePin(c PlaneChoice) ([]byte, error) {
	b := make([]byte, planePinValueSize)
	binary.LittleEndian.PutUint32(b[0:], planePinMagic)
	binary.LittleEndian.PutUint16(b[4:], planePinVersion)
	switch c.Mode {
	case bpfobj.PlaneLSM:
		b[6] = 1
	case bpfobj.PlaneFmodRet:
		b[6] = 2
	default:
		return nil, fmt.Errorf("doctor: no plane mode to pin (%q)", c.Mode)
	}
	switch c.Build {
	case bpfobj.ObjectPlaneRdonly:
		b[7] = 1
	case bpfobj.ObjectPlaneProbe:
		b[7] = 2
	default:
		return nil, fmt.Errorf("doctor: no plane build to pin (%q)", c.Build)
	}
	if c.ExecPins {
		b[8] = planePinExecPins
	}
	return b, nil
}

// decodePlanePin reads a pinned value, false for anything but this layout.
func decodePlanePin(b []byte) (PlaneChoice, bool) {
	if len(b) != planePinValueSize || binary.LittleEndian.Uint32(b[0:]) != planePinMagic ||
		binary.LittleEndian.Uint16(b[4:]) != planePinVersion || b[8]&^planePinExecPins != 0 || b[9]|b[10]|b[11] != 0 {
		return PlaneChoice{}, false
	}
	c := PlaneChoice{ExecPins: b[8]&planePinExecPins != 0}
	switch b[6] {
	case 1:
		c.Mode = bpfobj.PlaneLSM
	case 2:
		c.Mode = bpfobj.PlaneFmodRet
	default:
		return PlaneChoice{}, false
	}
	switch b[7] {
	case 1:
		c.Build = bpfobj.ObjectPlaneRdonly
	case 2:
		c.Build = bpfobj.ObjectPlaneProbe
	default:
		return PlaneChoice{}, false
	}
	return c, true
}

// PinPlaneAnswer pins c, the answer the build in dir was loaded by, as dir/PlanePinMap. It is the backend's call
// (T6) after it loaded and pinned the build in c's mode; the directory must exist.
func PinPlaneAnswer(dir string, c PlaneChoice) error {
	v, err := encodePlanePin(c)
	if err != nil {
		return err
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: PlanePinMap, Type: ebpf.Array, KeySize: 4,
		ValueSize: planePinValueSize, MaxEntries: 1})
	if err != nil {
		return fmt.Errorf("doctor: plane answer map: %w", err)
	}
	defer func() { _ = m.Close() }()
	if err := m.Put(uint32(0), v); err != nil {
		return fmt.Errorf("doctor: plane answer: %w", err)
	}
	if err := m.Pin(filepath.Join(dir, PlanePinMap)); err != nil {
		return fmt.Errorf("doctor: pin the plane answer: %w", err)
	}
	return nil
}

// readPlanePin reads the answer pinned in dir, false when there is none or it is not this layout.
func readPlanePin(dir string) (PlaneChoice, bool) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(dir, PlanePinMap), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return PlaneChoice{}, false
	}
	defer func() { _ = m.Close() }()
	info, err := m.Info()
	if err != nil || info.Type != ebpf.Array || info.ValueSize != planePinValueSize {
		return PlaneChoice{}, false
	}
	v := make([]byte, planePinValueSize)
	if err := m.Lookup(uint32(0), &v); err != nil {
		return PlaneChoice{}, false
	}
	return decodePlanePin(v)
}

// errNoPlanePin is adoption finding no usable answer.
var errNoPlanePin = errors.New("no pinned plane answer")

// adoptPlaneFrom is adoption over a pin reader: the mode the machine's bpf.plane would select, when its build's pin
// directory records that very mode. Under auto only LSM mode's answer is taken where bpf is an active LSM (LSM mode
// is then the one a probe would prefer); fmod_ret's is taken only where it is not. Anything else probes.
func adoptPlaneFrom(pin string, lsm LSMState, hash string, read func(dir string) (PlaneChoice, bool)) (*PlaneState, error) {
	var want bpfobj.PlaneMode
	switch pin {
	case config.PlaneLSM:
		want = bpfobj.PlaneLSM
	case config.PlaneFmodRet:
		want = bpfobj.PlaneFmodRet
	default:
		want = bpfobj.PlaneFmodRet
		if lsm.BPFActive {
			want = bpfobj.PlaneLSM
		}
	}
	dir := PlanePinDir("", hash, want)
	c, ok := read(dir)
	if !ok || c.Mode != want {
		return nil, errNoPlanePin
	}
	st := &PlaneState{Pin: pin, Build: c.Build, BuildHash: hash, BuildWhy: "recorded by the pinned build", Source: planeSourcePin,
		Modes: []PlaneModeResult{{Mode: want, OK: true, Tested: true,
			Detail: "adopted: the pinned build " + dir + " was loaded in this mode after its probe passed"}}}
	if c.ExecPins {
		st.Modes[0].ExecPin = &PlaneExecPinCell{OK: true, Detail: "adopted: the pinned answer says the exec pin cell passed"}
	}
	selectPlane(st)
	return st, nil
}

// adoptPinnedPlane is scope.adopt in production: this build's pin directory, read through bpffs. An fmod_ret answer
// is adopted only while this kernel's preemption model, read afresh, still admits the mode (adoptStillAdmitted): the
// build may have been pinned by a test build that waived it, or before the mode was changed in debugfs.
func adoptPinnedPlane(pin string) (*PlaneState, bool) {
	hash, err := bpfobj.Hash()
	if err != nil {
		return nil, false
	}
	lsm, err := ReadLSMState()
	if err != nil {
		return nil, false
	}
	st, err := adoptPlaneFrom(pin, lsm, hash, readPlanePin)
	if err != nil {
		return nil, false
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return nil, false
	}
	env, _ := fmodRetAdmittedNow(unix.ByteSliceToString(u.Release[:]), lsm)
	if !adoptStillAdmitted(st, env, lsm) {
		return nil, false
	}
	return st, true
}

// adoptStillAdmitted reports whether an adopted answer's mode passes its preconditions on this kernel now; the
// adopted state then carries the preemption reading. An fmod_ret answer on a kernel that preempts kernel code is
// not adopted: the run probes, and the probe rules the mode out with the reason.
func adoptStillAdmitted(st *PlaneState, env PlaneEnv, lsm LSMState) bool {
	for i, r := range st.Modes {
		switch r.Mode {
		case bpfobj.PlaneFmodRet:
			if why, _ := fmodRetPreemptRefusal(env, lsm); why != "" {
				return false
			}
		case bpfobj.PlaneLSM:
			if why, _ := lsmRecursionRefusal(env); why != "" {
				return false
			}
		}
		// The pinned answer's exec pin cell is held to this reading too (ADR 0148).
		st.Modes[i].ExecPin = execPinWhereSkippable(r.ExecPin, env)
	}
	st.Env.LSMRecursionExempt, st.Env.LSMRecursionSource = env.LSMRecursionExempt, env.LSMRecursionSource
	st.Env.Preempt, st.Env.PreemptSource, st.Env.PreemptWaived = env.Preempt, env.PreemptSource, env.PreemptWaived
	return true
}
