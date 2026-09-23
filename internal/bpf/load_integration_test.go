// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// requireBPF skips unless this process holds the capabilities loading these objects needs: CAP_BPF with
// CAP_PERFMON (the tracing programs) and CAP_NET_ADMIN (the cgroup ones), or CAP_SYS_ADMIN, which the kernel
// accepts in place of each. An unprivileged run of the suite must skip, not fail, and say so
// (CONTRIBUTING.md: "Anything that needs root or a specific kernel").
//
// The decision is read from the effective capability set and never from a load's error. The verifier
// rejects a program with EACCES, "permission denied", which is also what a missing capability produces, so a
// skip keyed on the load's errno turned a program the verifier refused into a skipped test — the exact
// failure this suite exists to report. Once the capabilities are there, every load failure is a failure.
func requireBPF(t *testing.T) {
	t.Helper()
	if missing := missingBPFCaps(); missing != "" {
		t.Skipf("this process lacks %s; run as root or grant cap_bpf,cap_perfmon,cap_net_admin", missing)
	}
	// Kernels from 5.11 account BPF memory to the cgroup and need no memlock headroom, so a failure here is
	// informational: the loads below are what decide.
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("could not raise the memlock rlimit (%v); relying on memcg accounting", err)
	}
}

// missingBPFCaps names the capabilities the effective set lacks for loading every object, or "" when none.
func missingBPFCaps() string {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return "a readable capability set (" + err.Error() + ")"
	}
	eff := uint64(data[0].Effective) | uint64(data[1].Effective)<<32
	has := func(c int) bool { return eff&(1<<uint(c)) != 0 }
	if has(unix.CAP_SYS_ADMIN) {
		return ""
	}
	var missing []string
	for _, c := range []struct {
		n    int
		name string
	}{{unix.CAP_BPF, "cap_bpf"}, {unix.CAP_PERFMON, "cap_perfmon"}, {unix.CAP_NET_ADMIN, "cap_net_admin"}} {
		if !has(c.n) {
			missing = append(missing, c.name)
		}
	}
	return strings.Join(missing, ",")
}

// unixConnectAttachType reports whether this kernel accepts BPF_CGROUP_UNIX_CONNECT as a program's expected
// attach type, which it checks at load. EINVAL is the answer of a kernel below 6.7; anything else is a failure.
func unixConnectAttachType(t *testing.T) bool {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.CGroupSockAddr, AttachType: ebpf.AttachCgroupUnixConnect, License: "Dual BSD/GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Logf("this kernel does not know BPF_CGROUP_UNIX_CONNECT: %v", err)
			return false
		}
		t.Fatalf("probe BPF_CGROUP_UNIX_CONNECT: %v", err)
	}
	p.Close()
	return true
}

// unpin clears the pin-by-name declaration so a load test needs no bpffs directory; the pin protocol itself
// is exercised by internal/runtime/enforce/cgroup's own integration tests.
// dropOptionalWhereAbsent leaves out of spec each OptionalTracePrograms program whose kernel function this kernel's BTF
// lacks (security_file_truncate below 6.2), as the backend does (enforce/cgroup kernel.go dropTraceWhereAbsent): the
// loader resolves an fexit target when it loads the program, so trace_proc does not load whole on such a kernel.
func dropOptionalWhereAbsent(t *testing.T, spec *ebpf.CollectionSpec) (dropped []string) {
	t.Helper()
	kspec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil
	}
	for name, fn := range OptionalTracePrograms {
		var f *btf.Func
		if _, ok := spec.Programs[name]; ok && kspec.TypeByName(fn, &f) != nil {
			delete(spec.Programs, name)
			dropped = append(dropped, name)
		}
	}
	return dropped
}

func unpin(spec *ebpf.CollectionSpec) {
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
}

// Capture selects optional TLS dispatchers by the actual multi link interface;
// loading a Kprobe program alone does not prove that the kernel can attach it.
// A measured unsupported probe removes only those programs; unexpected probe
// errors remain failures so a broken verifier cannot become an allowed skip.
func dropSSLMultiWhereUnsupported(spec *ebpf.CollectionSpec, probe func() error) ([]string, error) {
	err := probe()
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return nil, err
	}
	var dropped []string
	for _, name := range []string{ProgSSLMultiEnter, ProgSSLMultiReturn} {
		if _, ok := spec.Programs[name]; ok {
			delete(spec.Programs, name)
			dropped = append(dropped, name)
		}
	}
	return dropped, nil
}

func TestObjectLoadMultiSelectionIsMeasuredAndNarrow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		dropped int
	}{
		{"available", nil, 0}, {"unsupported", ebpf.ErrNotSupported, 2},
		{"permission-error", unix.EPERM, 0}, {"verifier-error", unix.EACCES, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			programs := map[string]*ebpf.ProgramSpec{}
			for _, name := range SSLPrograms {
				programs[name] = &ebpf.ProgramSpec{Name: name}
			}
			spec := &ebpf.CollectionSpec{Programs: programs}
			dropped, err := dropSSLMultiWhereUnsupported(spec, func() error { return tc.err })
			if len(dropped) != tc.dropped || len(spec.Programs) != len(SSLPrograms)-tc.dropped {
				t.Fatalf("wrong optional selection: dropped=%v programs=%v", dropped, spec.Programs)
			}
			if tc.err != nil && tc.dropped == 0 && !errors.Is(err, tc.err) || tc.dropped != 0 && err != nil {
				t.Fatalf("probe failure hidden or unsupported path rejected: %v", err)
			}
			for _, name := range SSLSinglePrograms {
				if spec.Programs[name] == nil {
					t.Fatalf("required %s removed", name)
				}
			}
		})
	}
}

// TestObjectsLoadOnThisKernel loads every program of every object into the running kernel. It is the check
// the ticket's acceptance criterion names: the verifier accepts each program, every fentry and tp_btf attach
// target resolves in this kernel's BTF, and every CO-RE relocation of this component's own structs succeeds
// (§6 E31).
//
// Each program is loaded on its own before the whole object is, so a rejection names the one program the
// verifier refused and carries that program's own log, instead of stopping the object at the first program
// the loader happened to reach. That is how connect6 and sendmsg6 were found refused while the other five
// cgroup programs loaded ("dereference of modified ctx ptr", common.h tego_addr_v6).
func TestObjectsLoadOnThisKernel(t *testing.T) {
	requireBPF(t)
	unixConnect := unixConnectAttachType(t)
	for _, o := range Objects() {
		t.Run(o.String(), func(t *testing.T) {
			spec, err := Load(o)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			names := make([]string, 0, len(spec.Programs))
			for name := range spec.Programs {
				names = append(names, name)
			}
			slices.Sort(names)
			// The unix programs' attach types are checked when a program is loaded, and below 6.7 the kernel
			// does not know them; the backend leaves both out there (enforce/cgroup kernel.go, §5 R7), so this
			// test loads what the backend loads.
			if !unixConnect {
				for _, name := range UnixPrograms {
					delete(spec.Programs, name)
				}
			}
			absent := dropOptionalWhereAbsent(t, spec)
			var absentMulti []string
			if o == ObjectUprobeSSL {
				absentMulti, err = dropSSLMultiWhereUnsupported(spec, features.HaveBPFLinkUprobeMulti)
				if err != nil {
					t.Fatalf("probe optional TLS multi attach interface: %v", err)
				}
			}
			for _, name := range names {
				t.Run(name, func(t *testing.T) {
					if slices.Contains(UnixPrograms, name) && !unixConnect {
						t.Skip("this kernel predates the unix sockaddr attach types (6.7); the backend does not load it here")
					}
					if slices.Contains(absent, name) {
						t.Skipf("this kernel has no %s; the backend does not load it here", OptionalTracePrograms[name])
					}
					if slices.Contains(absentMulti, name) {
						t.Skip("actual uprobe_multi feature probe is unsupported; capture loads the required individual programs")
					}
					one := spec.Copy()
					unpin(one)
					for other := range one.Programs {
						if other != name {
							delete(one.Programs, other)
						}
					}
					coll, err := ebpf.NewCollection(one)
					if err != nil {
						t.Fatalf("the verifier refused %s on its own: %+v", name, err)
					}
					defer coll.Close()
					if p := coll.Programs[name]; p == nil || p.FD() < 0 {
						t.Fatalf("program %s loaded without a descriptor", name)
					}
					t.Logf("%s: loaded", name)
				})
			}

			whole := spec.Copy()
			unpin(whole)
			coll, err := ebpf.NewCollection(whole)
			if err != nil {
				t.Fatalf("load %s into the kernel: %v", o, err)
			}
			defer coll.Close()
			for name, p := range coll.Programs {
				if p.FD() < 0 {
					t.Errorf("program %s has no fd", name)
				}
			}
		})
	}
}

// TestRingsOfAnySizeGoInTheOuter is ADR 0026's first measurement, kept as a test for every row of the kernel
// matrix: the record's ring outer, loaded from the object, takes inner rings of 64 KiB, 1 MiB and 8 MiB at once
// (its prototype is 64 KiB), and each is read back at its slot with its own size.
func TestRingsOfAnySizeGoInTheOuter(t *testing.T) {
	requireBPF(t)
	spec, err := Load(ObjectTraceProc)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	unpin(spec)
	dropOptionalWhereAbsent(t, spec)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load %s: %v", ObjectTraceProc, err)
	}
	defer coll.Close()
	outer := coll.Maps[MapEvents]
	// What a build holds with no run: its ring outers and per-run counters (ADR 0026's idle-build figure).
	for _, name := range append(append([]string{}, RingMaps...), SlotCounters...) {
		if m, err := Memlock(coll.Maps[name]); err == nil {
			t.Logf("%s charges %d B of memlock with no ring in it", name, m)
		}
	}
	sizes := []uint32{1 << 16, 1 << 20, 2 << 20, 8 << 20}
	for slot, size := range sizes {
		ring, err := NewRing(RingRecord, size)
		if err != nil {
			t.Fatal(err)
		}
		if err := InsertRing(outer, uint32(slot), ring); err != nil {
			t.Fatalf("insert a %d-byte ring: %v", size, err)
		}
		m, err := Memlock(ring)
		if err != nil || m < uint64(size) {
			t.Errorf("a %d-byte ring charges %d B of memlock (%v)", size, m, err)
		}
		t.Logf("a %d-byte ring charges %d B of memlock", size, m)
		_ = ring.Close()
	}
	for slot, size := range sizes {
		ring, ok, err := RingOf(outer, uint32(slot))
		if err != nil || !ok {
			t.Fatalf("RingOf(%d) = %v, %v", slot, ok, err)
		}
		if ring.MaxEntries() != size {
			t.Errorf("slot %d holds %d bytes, want %d", slot, ring.MaxEntries(), size)
		}
		_ = ring.Close()
	}
	if got, err := RingIDs(outer); err != nil || len(got) != len(sizes) {
		t.Errorf("RingIDs = %v, %v", got, err)
	}
}
