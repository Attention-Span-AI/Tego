// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestHookTableIsWellFormed guards the D7 table itself: every entry names a tier, every tracing and
// LSM entry names both a symbol and the BTF type that proves it exists, a cgroup entry names no
// symbol, and every tier-2 entry names the embedded program that runs there in production, which is
// what D7 loads whenever the binary carries it (R27 D7). Tier 3's rows are no longer in the table: they are
// the plane's, one per decide.bpf.c hook per mode (TestPlaneParamsMatchTheSource, enforce-plane.md R21).
func TestHookTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	var tier2, tier3 int
	for _, h := range hooks {
		if seen[h.Name] {
			t.Errorf("%s appears twice", h.Name)
		}
		seen[h.Name] = true
		switch h.Tier {
		case backend.TierCgroup:
			tier2++
			if h.object == "" || h.program == "" {
				t.Errorf("%s is a tier-2 hook with no embedded program; D7 would always load a stand-in "+
					"the verifier judges instead of the program a run loads", h.Name)
			}
		case backend.TierBPFLSM:
			tier3++
		case backend.TierLandlock, backend.TierObserve, backend.TierAuto:
			fallthrough
		default:
			t.Errorf("%s names tier %q", h.Name, h.Tier)
		}
		switch h.kind {
		case hookFEntry, hookFExit, hookRawTP:
			if h.attachTo == "" || h.btfName == "" {
				t.Errorf("%s has no attach symbol or BTF name", h.Name)
			}
		case hookCgroupAddr, hookCgroupSKB, hookSockOps, hookCgroupSock, hookCgroupSockopt:
			if h.attachTo != "" {
				t.Errorf("%s names a symbol; a cgroup program attaches to a cgroup, not a symbol", h.Name)
			}
		}
		if (h.object == "") != (h.program == "") {
			t.Errorf("%s names half an embedded program: object %q program %q", h.Name, h.object, h.program)
		}
		if !strings.Contains(h.Name, "/") && h.kind != hookSockOps {
			t.Errorf("%s is not spelled the way its SEC() is", h.Name)
		}
	}
	if tier2 == 0 || tier3 != 0 {
		t.Fatalf("the table covers %d tier-2 and %d tier-3 hooks; tier 3's are the plane's", tier2, tier3)
	}
}

// TestHookTableCoversEveryTierTwoProgram: D7 is "every tier-2 program load test" (P0-DESIGN §2.13),
// so every program the three tier-2 objects carry has exactly one hook row, in the object that
// carries it. A program with no row is one a run loads and doctor never asked the verifier about;
// cgroup_rmdir and the two bind placeholders were such programs.
func TestHookTableCoversEveryTierTwoProgram(t *testing.T) {
	want := map[string]bpfobj.Object{}
	for obj, progs := range map[bpfobj.Object][]string{
		bpfobj.ObjectCgroupNet: append(append(append([]string{}, bpfobj.CgroupPrograms...), bpfobj.NetControlPrograms...),
			bpfobj.SocketPrograms...),
		bpfobj.ObjectCgroupTrack: bpfobj.TrackPrograms,
		bpfobj.ObjectTraceProc:   bpfobj.TracePrograms,
	} {
		for _, p := range progs {
			want[p] = obj
		}
	}
	got := map[string]int{}
	for _, h := range hooks {
		if h.program == "" {
			continue
		}
		got[h.program]++
		if obj, ok := want[h.program]; !ok {
			t.Errorf("%s names program %s, which no tier-2 object lists", h.Name, h.program)
		} else if obj != h.object {
			t.Errorf("%s names program %s in %s; it is %s's", h.Name, h.program, h.object, obj)
		}
	}
	for p, obj := range want {
		if got[p] != 1 {
			t.Errorf("%s's program %s has %d hook rows, want 1", obj, p, got[p])
		}
	}
}

// TestSockCreateRowIsRequired is A-0018-6: cgroup/sock_create's and cgroup/setsockopt's D7 rows gate tier cgroup like
// connect4's. Every run with a net: section attaches both programs (enforce/cgroup attachSocketPrograms), on every
// kernel of the floor, so a machine where either does not load or attach offers no tier cgroup, rather than a run
// that fails at Attach. cgroup/setsockopt is ADR 0018 (7)'s.
func TestSockCreateRowIsRequired(t *testing.T) {
	for _, want := range []struct {
		name    string
		kind    hookKind
		attach  ebpf.AttachType
		program string
	}{
		{"cgroup/sock_create", hookCgroupSock, ebpf.AttachCGroupInetSockCreate, bpfobj.ProgSockCreate},
		{"cgroup/setsockopt", hookCgroupSockopt, ebpf.AttachCGroupSetsockopt, bpfobj.ProgSetsockopt},
	} {
		found := false
		for _, h := range hooks {
			if h.Name != want.name {
				continue
			}
			found = true
			if h.Tier != backend.TierCgroup || h.optional || h.capabilityOnly || h.since != (Version{}) || h.kind != want.kind ||
				h.attachType != want.attach || h.object != bpfobj.ObjectCgroupNet || h.program != want.program {
				t.Fatalf("the %s row is %+v", want.name, h)
			}
			st := probeState{hooks: []HookResult{{Hook: h.Name, Tier: h.Tier, Detail: "attach: operation not permitted"}}}
			if got := st.missingHooks(backend.TierCgroup); len(got) != 1 || !strings.Contains(got[0], want.name) {
				t.Fatalf("a failed %s row withholds tier cgroup with %v", want.name, got)
			}
		}
		if !found {
			t.Errorf("D7 has no %s row", want.name)
		}
	}
}

// TestCgroupAttachRefusalNamesTheConflict (§6 E36) in D7: an EPERM from a cgroup row's attach
// names the cause an operator acts on, in the very words a run's Attach refusal uses (cgroup.AttachConflictHint), so
// doctor and tego run cannot describe one host two ways. Any other errno keeps its own detail.
func TestCgroupAttachRefusalNamesTheConflict(t *testing.T) {
	const path = "/sys/fs/cgroup/user.slice/.tego-doctor-progs-1"
	for _, h := range hooks {
		if h.kind != hookCgroupAddr && h.kind != hookCgroupSock && h.kind != hookCgroupSKB && h.kind != hookSockOps &&
			h.kind != hookCgroupSockopt {
			continue
		}
		out := cgroupAttachFailure(h, HookResult{Hook: h.Name, Tier: h.Tier, BTF: true, Loaded: true},
			fmt.Errorf("attach cgroup: %w", unix.EPERM), path)
		if out.Attached || !strings.Contains(out.Detail, cgroupenforce.AttachConflictHint(path)) {
			t.Errorf("%s: EPERM detail %q does not name the conflict", h.Name, out.Detail)
		}
		out = cgroupAttachFailure(h, HookResult{Hook: h.Name, Tier: h.Tier, BTF: true, Loaded: true}, unix.EINVAL, path)
		if strings.Contains(out.Detail, "bpftool cgroup tree") {
			t.Errorf("%s: EINVAL is no hierarchy conflict: %q", h.Name, out.Detail)
		}
	}
}

// TestHookTableMatchesTheObjects holds each tier-2 row to the object it names: the SEC() spelling,
// the attach type the program was compiled for and the kernel symbol it attaches to. It parses the
// embedded ELF only, so it needs no privilege, and it needs a binary that carries the objects.
func TestHookTableMatchesTheObjects(t *testing.T) {
	if !bpfobj.Available() {
		t.Skip("this build carries no BPF objects (build with -tags tegobpf after go generate ./internal/bpf/...)")
	}
	for _, h := range hooks {
		if h.object == "" {
			continue
		}
		spec, err := bpfobj.Load(h.object)
		if err != nil {
			t.Fatalf("%s: %v", h.Name, err)
		}
		ps := spec.Programs[h.program]
		if ps == nil {
			t.Errorf("%s: %s has no program %s", h.Name, h.object, h.program)
			continue
		}
		if ps.SectionName != h.Name {
			t.Errorf("%s: %s is SEC(%q)", h.Name, h.program, ps.SectionName)
		}
		if ps.AttachType != h.attachType {
			t.Errorf("%s: %s was compiled for attach type %s, the row attaches it as %s", h.Name, h.program,
				ps.AttachType, h.attachType)
		}
		if ps.AttachTo != h.attachTo {
			t.Errorf("%s: %s attaches to %q, the row resolves %q in BTF", h.Name, h.program, ps.AttachTo, h.attachTo)
		}
	}
}

// TestHookBTFNamesResolveHere is I2's pre-load check against this kernel's own BTF, which needs no
// privilege. It is the regression test for a check that declared every BTF-named hook absent on
// every kernel: it passed a pointer to a nil btf.Type interface, which btf.Spec.TypeByName refuses
// for any name ("points to a nil Type"), so a 6.17 kernel with all of them was told to "boot a kernel
// with the listed hooks". hookInBTF's answer must agree with a plain lookup of the name, and the
// tier-2 names — kernel functions and tracepoints any BTF kernel has — must all resolve.
func TestHookBTFNamesResolveHere(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF here: %v", err)
	}
	for _, h := range hooks {
		if h.btfName == "" {
			continue
		}
		types, _ := spec.AnyTypesByName(h.btfName)
		present := false
		for _, typ := range types {
			switch typ.(type) {
			case *btf.Func:
				present = present || h.kind != hookRawTP
			case *btf.Typedef:
				present = present || h.kind == hookRawTP
			}
		}
		err := hookInBTF(spec, h)
		if (err == nil) != present {
			t.Errorf("%s: hookInBTF(%s) = %v, but a lookup of the name finds it=%v", h.Name, h.btfName, err, present)
		}
		// An optional hook a kernel below its version does not have is absent by design (RHEL 9's 5.14 carries
		// security_file_truncate in its BTF and not the version doctor allows it; 6.1 carries neither).
		if _, _, kernel := probeKernelVersion(); h.Tier == backend.TierCgroup && err != nil && !(h.optional && !kernel.AtLeast(h.since)) {
			t.Errorf("%s: %s does not resolve in this kernel's BTF: %v", h.Name, h.btfName, err)
		}
		if err == nil {
			t.Logf("%s: %s resolves", h.Name, h.btfName)
		}
	}
}

// TestProbeProgramsWithoutRoot is E18's wording rule for D7.
// (limits-check-doctor-cli.md E18: doctor without root skips the functional half and says so.)
func TestProbeProgramsWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test describes the unprivileged answer")
	}
	r, results := probePrograms(false, os.Getuid(), Version{6, 17, 0})
	if r.OK || len(results) != 0 {
		t.Fatalf("result %+v, %d hooks", r, len(results))
	}
	if !strings.Contains(r.Detail, "requires root") || r.Fix == "" {
		t.Errorf("detail %q fix %q", r.Detail, r.Fix)
	}
}

func TestHookResultOK(t *testing.T) {
	cases := []struct {
		name string
		h    HookResult
		want bool
	}{
		{"all three", HookResult{BTF: true, Loaded: true, Attached: true}, true},
		{"no btf", HookResult{Loaded: true, Attached: true}, false},
		{"loaded but not attached", HookResult{BTF: true, Loaded: true}, false},
		{"nothing", HookResult{}, false},
		// A capture row has no BTF attach point (a uprobe sits at a file offset): load and attach are all.
		{"a capture row that attached", HookResult{Capture: true, Loaded: true, Attached: true}, true},
		{"a capture row that only loaded", HookResult{Capture: true, Loaded: true, LoadOnly: true}, false},
	}
	for _, tc := range cases {
		if got := tc.h.OK(); got != tc.want {
			t.Errorf("%s: OK = %v", tc.name, got)
		}
	}
}

func TestVerifierTail(t *testing.T) {
	short := errors.New("one line")
	if got := verifierTail(short); got != "one line" {
		t.Errorf("short error rendered as %q", got)
	}
	long := errors.New("a\nb\nc\nd\ne")
	got := verifierTail(long)
	if !strings.HasPrefix(got, "... ") || !strings.Contains(got, "e") || strings.Contains(got, "a;") {
		t.Errorf("long error rendered as %q; want the last lines", got)
	}
	if got := verifierTail(errors.New("a\nb\n")); got != "a; b" {
		t.Errorf("trailing newline rendered as %q", got)
	}
}

// TestSinceGatedHookSkipsOnAnOldKernel is R7: connect_unix is 6.7+, and doctor's answer must come
// from the version gate plus a real attach, never from a guess.
func TestSinceGatedHookSkipsOnAnOldKernel(t *testing.T) {
	var unixHook hook
	for _, h := range hooks {
		if h.Name == "cgroup/connect_unix" {
			unixHook = h
		}
	}
	if unixHook.since != (Version{6, 7, 0}) {
		t.Fatalf("connect_unix is gated at %s, want 6.7.0", unixHook.since)
	}
	withUnixSupport(t, false)
	got := testHook(unixHook, nil, nil, nil, Version{6, 1, 0})
	if got.BTF || got.Loaded || got.Attached {
		t.Errorf("a hook below its minimum kernel must not be probed: %+v", got)
	}
	if !got.Absent || !strings.Contains(got.Detail, "needs kernel >= 6.7.0") {
		t.Errorf("detail %q", got.Detail)
	}
}

// hookNamed returns the table row for one hook.
func hookNamed(t *testing.T, name string) hook {
	t.Helper()
	for _, h := range hooks {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("no hook %s", name)
	return hook{}
}

// TestTestHookStandsInForAMissingObject: a binary built without the objects has nothing of its own
// to load at a tier-2 hook, and still runs on a kernel worth describing. D7 then tests the attach
// point with a minimal program and says so (StandIn), and the tier it cannot build is the tier
// derivation's answer (enforce.Buildable), not one "not built" line per hook. The loader is supplied
// so the answer is the same in a build that does carry the objects.
func TestTestHookStandsInForAMissingObject(t *testing.T) {
	missing := func(o bpfobj.Object) (*ebpf.CollectionSpec, error) {
		return nil, fmt.Errorf("%w: %s", bpfobj.ErrNotGenerated, o)
	}
	h := hookNamed(t, "cgroup/connect4")
	got := testHookWith(h, nil, nil, nil, Version{6, 17, 0}, missing)
	if !got.StandIn || got.Object != string(bpfobj.ObjectCgroupNet) {
		t.Fatalf("a hook whose object this binary lacks = %+v, want a stand-in for %s", got, bpfobj.ObjectCgroupNet)
	}
	if os.Geteuid() != 0 && got.Loaded {
		t.Errorf("an unprivileged stand-in loaded: %+v", got)
	}
	r := programsVerdict([]HookResult{{Hook: h.Name, Object: string(h.object), StandIn: true, BTF: true, Loaded: true, Attached: true}})
	if !r.OK || !strings.Contains(r.Detail, "this binary carries no BPF objects") {
		t.Errorf("D7 over stand-ins for a missing object = %+v, want the missing objects said on the line", r)
	}

	// An object that does not carry the row's program is a build defect, reported as a load failure
	// before any bpf(2) call, never as a stand-in and never as success.
	empty := func(bpfobj.Object) (*ebpf.CollectionSpec, error) {
		return &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}, Maps: map[string]*ebpf.MapSpec{}}, nil
	}
	got = testHookWith(h, nil, nil, nil, Version{6, 17, 0}, empty)
	if got.Loaded || got.StandIn || !strings.Contains(got.Detail, "has no program "+bpfobj.ProgConnect4) {
		t.Errorf("an object without the program = %+v", got)
	}
}

// TestProgramsVerdict pins D7's line: the count, the stand-in disclosure for a binary without objects, and a fix only when a hook failed.
func TestProgramsVerdict(t *testing.T) {
	ok := HookResult{Hook: "cgroup/connect4", Object: "cgroup_net", BTF: true, Loaded: true, Attached: true}
	refused := HookResult{Hook: "cgroup/connect6", Object: "cgroup_net", BTF: true, Detail: "load: permission denied"}

	if r := programsVerdict([]HookResult{ok}); !r.OK || r.Fix != "" || strings.Contains(r.Detail, "minimal") {
		t.Errorf("all real programs = %+v", r)
	}
	// The verifier refusing a program of this build at a hook the kernel has is not cured by "a kernel
	// with the listed hooks": 6.17 has cgroup/connect6 and refused tego_cg_connect6 itself.
	r := programsVerdict([]HookResult{ok, refused})
	if r.OK || !strings.Contains(r.Detail, "missing: cgroup/connect6") || !strings.Contains(r.Fix, "verifier refuses") {
		t.Errorf("a refused program = %+v, want the verifier named in the fix", r)
	}
	absent := HookResult{Hook: "fentry/security_file_open", Object: "trace_proc", Detail: "not in the kernel's BTF"}
	if r := programsVerdict([]HookResult{refused, absent}); !strings.Contains(r.Fix, "boot a kernel with the listed hooks") {
		t.Errorf("a hook missing from the kernel = %+v, want the kernel fix", r)
	}
}

// TestProbeCgroupPathNeverDereferencesNil: testHook is driven with no probe cgroup and no error
// (TestTestHookWithoutBTF passes nil for both). As root a cgroup program loads and the attach step
// used to read cg.path from the nil pointer, and the SIGSEGV took the whole doctor test binary down
// with it in the KVM guest.
func TestProbeCgroupPathNeverDereferencesNil(t *testing.T) {
	if _, err := probeCgroupPath(nil, nil); err == nil {
		t.Error("no cgroup and no error must still be an error")
	}
	cause := errors.New("no delegated subtree")
	if _, err := probeCgroupPath(nil, cause); !errors.Is(err, cause) {
		t.Errorf("the cgroup's own error was lost: %v", err)
	}
	if p, err := probeCgroupPath(&scratchCgroup{path: "/sys/fs/cgroup/x"}, nil); err != nil || p != "/sys/fs/cgroup/x" {
		t.Errorf("probeCgroupPath = %q, %v", p, err)
	}
}

// TestTestHookWithoutAProbeCgroup is the same case end to end, as root: every cgroup hook loads its
// program (when this build carries the objects) and must answer "no probe cgroup", not panic.
func TestTestHookWithoutAProbeCgroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("reaching the attach step needs a program the kernel loaded, which needs root")
	}
	_, _, kernel := probeKernelVersion()
	for _, h := range hooks {
		if h.kind != hookCgroupAddr {
			continue
		}
		got := testHook(h, nil, nil, nil, kernel)
		t.Logf("%s: %+v", h.Name, got)
		if got.Attached {
			t.Errorf("%s attached with no cgroup to attach to: %+v", h.Name, got)
		}
		if got.Loaded && !strings.Contains(got.Detail, "no probe cgroup") {
			t.Errorf("%s: detail %q, want the missing probe cgroup named", h.Name, got.Detail)
		}
	}
}

// TestMinimalProgramReturnsTheNeutralValue: the stand-in D7 loads at a hook no object carries must
// never refuse anything while it is attached — 0 allows for tracing and LSM, and the
// cgroup address/socket and packet admission programs allow with 1 (R1).
func TestMinimalProgramReturnsTheNeutralValue(t *testing.T) {
	for _, h := range hooks {
		ps := minimalProgram(h)
		want := int64(0)
		if h.kind == hookCgroupAddr || h.kind == hookCgroupSock || h.kind == hookCgroupSKB || h.kind == hookCgroupSockopt {
			want = 1
		}
		if len(ps.Instructions) != 2 || ps.Instructions[0].Constant != want || ps.Instructions[1].OpCode != asm.Return().OpCode {
			t.Errorf("%s: the stand-in is %v, want r0 = %d; exit", h.Name, ps.Instructions, want)
		}
		if ps.AttachType != h.attachType {
			t.Errorf("%s: stand-in attach type %s, want %s", h.Name, ps.AttachType, h.attachType)
		}
	}
}

// TestCaptureHookTableCoversUprobeSSL: every program of uprobe_ssl has exactly one capture row, so a
// program capture loads is a program D7 has loaded (R27 D7). A row has no tier, which is what keeps
// it out of every tier's missing list (derive.go keeps a tier's own rows only), and the entry rows
// try the symbols capture itself hooks, in capture's order (capture-derive.md R1-R3).
func TestCaptureHookTableCoversUprobeSSL(t *testing.T) {
	got := map[string]int{}
	for _, h := range captureHooks {
		got[h.program]++
		if h.Tier != "" || h.object != bpfobj.ObjectUprobeSSL || len(h.symbols) == 0 {
			t.Errorf("%s: tier %q object %q symbols %v, want no tier, %s and a symbol", h.Name, h.Tier, h.object,
				h.symbols, bpfobj.ObjectUprobeSSL)
		}
		if h.kind != hookUprobe && h.kind != hookUretprobe {
			t.Errorf("%s is not a uprobe row", h.Name)
		}
		if want, entry := bpfobj.SSLEntryPrograms[h.program]; entry && strings.Join(h.symbols, ",") != strings.Join(want, ",") {
			t.Errorf("%s tries %v, capture hooks %v", h.Name, h.symbols, want)
		}
		if (h.program == bpfobj.ProgSSLReadReturn) != (h.kind == hookUretprobe) {
			t.Errorf("%s: program %s as kind %d; only the read return is a uretprobe", h.Name, h.program, h.kind)
		}
	}
	// Doctor's required capture rows exercise the individual fallback on every
	// admitted kernel. Optional multi dispatch is probed by the capture loader.
	for _, p := range bpfobj.SSLSinglePrograms {
		if got[p] != 1 {
			t.Errorf("uprobe_ssl's program %s has %d capture rows, want 1", p, got[p])
		}
	}
	for _, h := range hooks {
		if h.object == bpfobj.ObjectUprobeSSL {
			t.Errorf("%s: a uprobe_ssl program in the tier table would gate tier %s", h.Name, h.Tier)
		}
	}
}

// TestCaptureHookTableMatchesTheObject holds each capture row to the program it names: a KPROBE
// program in a uprobe or uretprobe section of the kind the row attaches it as.
func TestCaptureHookTableMatchesTheObject(t *testing.T) {
	spec, err := bpfobj.Load(bpfobj.ObjectUprobeSSL)
	if errors.Is(err, bpfobj.ErrNotGenerated) {
		t.Skip("this build carries no uprobe_ssl object (build with -tags tegobpf on amd64 or arm64)")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range captureHooks {
		ps := spec.Programs[h.program]
		if ps == nil {
			t.Errorf("%s: uprobe_ssl has no program %s", h.Name, h.program)
			continue
		}
		want := "uprobe"
		if h.kind == hookUretprobe {
			want = "uretprobe"
		}
		if ps.Type != ebpf.Kprobe || ps.SectionName != want {
			t.Errorf("%s: %s is %s in SEC(%q), the row attaches it as a %s", h.Name, h.program, ps.Type,
				ps.SectionName, want)
		}
	}
}

// TestSystemLibSSLFindsARegularLibssl: the first directory with a regular file named like a libssl
// wins, the highest-sorting name first; names capture does not match and dangling links are passed
// over, and no library at all is an error naming where D7 looked.
func TestSystemLibSSLFindsARegularLibssl(t *testing.T) {
	empty, other, lib := t.TempDir(), t.TempDir(), t.TempDir()
	for _, name := range []string{"libssl3.so", "libssl.so.x"} { // NSS's libssl3.so is not OpenSSL
		if err := os.WriteFile(filepath.Join(other, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"libssl.so", "libssl.so.1.1", "libssl.so.3"} {
		if err := os.WriteFile(filepath.Join(lib, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(lib, "gone"), filepath.Join(lib, "libssl.so.9")); err != nil {
		t.Fatal(err)
	}
	got := systemLibSSL([]string{filepath.Join(empty, "absent"), empty, other, lib})
	if got.err != nil || got.path != filepath.Join(lib, "libssl.so.3") {
		t.Fatalf("systemLibSSL = %+v, want %s", got, filepath.Join(lib, "libssl.so.3"))
	}
	none := systemLibSSL([]string{empty, other})
	if none.err == nil || !strings.Contains(none.err.Error(), other) {
		t.Fatalf("no libssl = %+v, want an error naming %s", none, other)
	}
}

// TestLibsslDirsLookOnlyAtThisArchitecture: the multiarch directory D7 searches is this binary's
// own, never another architecture's, whose libssl no agent of this binary maps.
func TestLibsslDirsLookOnlyAtThisArchitecture(t *testing.T) {
	for _, dir := range libsslDirs() {
		for _, triplet := range []string{"x86_64-linux-gnu", "aarch64-linux-gnu", "i386-linux-gnu"} {
			if strings.HasSuffix(dir, "/"+triplet) && triplet != multiarchTriplet {
				t.Errorf("%s is another architecture's directory", dir)
			}
		}
	}
}

// TestCaptureRowsNeverGateATier is R27 D7's decision for capture's rows. A uprobe_ssl program that
// fails is said on D7's line and in capture.model_traffic's note, and changes nothing else: every
// tier stays reachable, no tier's missing list names it, D7 stays OK with no fix, and the fix line
// is the one the next tier needs. D7 failing on it would have put a capture remedy on that line
// ahead of D6's, which derive.go's fix reads after D7's.
func TestCaptureRowsNeverGateATier(t *testing.T) {
	refused := HookResult{Hook: "uretprobe/SSL_read", Object: "uprobe_ssl", Capture: true,
		Detail: "load: program tego_ssl_read_return: invalid argument"}
	attached := HookResult{Hook: "uprobe/SSL_write", Object: "uprobe_ssl", Capture: true, Loaded: true,
		Attached: true, Target: "/usr/lib/libssl.so.3", Detail: "attached at SSL_write"}
	healthy := state(nil)
	st := state(func(st *probeState) {
		st.hooks = append(st.hooks, attached, refused)
		r := programsVerdict(st.hooks)
		st.byID[CheckPrograms] = r
		// A BPF LSM the functional probe could not confirm: tier 3's fix is D6's, not a capture one.
		st.lsm.Functional = "the counter did not move"
		fail(st, CheckLSM, "bpf listed but the functional probe did not confirm it", "check the lsm= line")
	})
	d7 := st.byID[CheckPrograms]
	if !d7.OK || d7.Fix != "" {
		t.Fatalf("D7 over a failing capture row = %+v, want OK with no fix", d7)
	}
	for _, want := range []string{"1 of 2 programs load and attach at /usr/lib/libssl.so.3",
		"failed: uretprobe/SSL_read", "does not fail D7", fmt.Sprintf("%d of %d hooks", len(hooks), len(hooks))} {
		if !strings.Contains(d7.Detail, want) {
			t.Errorf("D7's line %q does not say %q", d7.Detail, want)
		}
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		if st.probe()[tier] != healthy.probe()[tier] {
			t.Errorf("a capture row changed tier %s: %v", tier, st.probe()[tier])
		}
	}
	for tier, reasons := range st.missing(backend.TierCgroup) {
		for _, r := range reasons {
			if strings.Contains(r, "SSL") || strings.Contains(r, "uprobe") {
				t.Errorf("tier %s lists capture's row: %s", tier, r)
			}
		}
	}
	if fix := st.fix(backend.TierCgroup); fix != "check the lsm= line" {
		t.Errorf("tier 3's fix line is %q, want D6's", fix)
	}
	_, notes := st.machineMatrix(backend.TierCgroup)
	if note := notes[backend.CapCaptureModel]; !strings.Contains(note, "uretprobe/SSL_read") ||
		!strings.Contains(note, "forwarder") {
		t.Errorf("capture.model_traffic's note is %q, want the failed row and the forwarder named", note)
	}
	if set, _ := st.machineMatrix(backend.TierCgroup); !set.Has(backend.CapCaptureModel) || !set[backend.CapCaptureModel] {
		t.Errorf("a failed uprobe row turned capture.model_traffic off, but the forwarder still captures")
	}
	if _, notes := healthy.machineMatrix(backend.TierCgroup); notes[backend.CapCaptureModel] != "" {
		t.Errorf("no capture rows, but a capture note: %q", notes[backend.CapCaptureModel])
	}
}

// TestCaptureSummarySaysWhatWasNotTested: an attach D7 had no library for, a symbol the library does
// not export, and a stand-in are each said on the line, never counted as attached, and never failed.
func TestCaptureSummarySaysWhatWasNotTested(t *testing.T) {
	noLib := HookResult{Hook: "uprobe/SSL_write", Capture: true, Loaded: true, LoadOnly: true,
		Detail: "attach not tested: no system libssl found in /usr/lib"}
	if got := captureSummary([]HookResult{noLib}); !strings.Contains(got, "1 of 1 programs load, attach not tested") ||
		strings.Contains(got, "failed") {
		t.Errorf("no system libssl = %q", got)
	}
	if captureFailed(noLib) || noLib.OK() {
		t.Errorf("an untested attach is neither a failure nor OK: %+v", noLib)
	}
	missingSym := HookResult{Hook: "uprobe/SSL_read_ex", Capture: true, Loaded: true, LoadOnly: true,
		Target: "/lib/libssl.so.1.0.0"}
	written := HookResult{Hook: "uprobe/SSL_write", Capture: true, Loaded: true, Attached: true,
		Target: "/lib/libssl.so.1.0.0", StandIn: true}
	got := captureSummary([]HookResult{written, missingSym})
	for _, want := range []string{"1 of 2 programs load and attach at /lib/libssl.so.1.0.0",
		"not exported there: uprobe/SSL_read_ex", "tested with a minimal program"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q does not say %q", got, want)
		}
	}
	st := state(func(st *probeState) { st.hooks = append(st.hooks, noLib) })
	if _, notes := st.machineMatrix(backend.TierCgroup); !strings.Contains(notes[backend.CapCaptureModel], "load only") {
		t.Errorf("an untested attach's note is %q", notes[backend.CapCaptureModel])
	}

	// Every load failed on a host that has a libssl: a kernel without the KPROBE program type, or a CO-RE
	// relocation uprobe_ssl needs. The attach was not tested because nothing loaded, and the line must not
	// send the operator looking for a library that is there.
	refused := func(bpfobj.Object) (*ebpf.CollectionSpec, error) {
		return nil, errors.New("load program: invalid argument")
	}
	lib := libTarget{path: "/usr/lib/x86_64-linux-gnu/libssl.so.3"}
	var rows []HookResult
	for _, h := range captureHooks {
		rows = append(rows, testCaptureHook(h, nil, lib, refused))
	}
	got = captureSummary(rows)
	if strings.Contains(got, "no system libssl") {
		t.Errorf("summary %q claims no libssl on a host where one was found", got)
	}
	for _, want := range []string{"0 of 6 programs load", "attach at /usr/lib/x86_64-linux-gnu/libssl.so.3 not tested",
		"no program loaded", "failed: uprobe/SSL_write"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q does not say %q", got, want)
		}
	}
}

// TestCaptureUprobeIsScopedToDoctor pins R27 D7's scope: the capture rows attach to doctor's own pid. Without
// it the uprobe PMU would put a breakpoint in every process on the host that maps the system libssl, live
// agents included, for the length of the probe.
func TestCaptureUprobeIsScopedToDoctor(t *testing.T) {
	if opts := captureUprobeOptions(); opts == nil || opts.PID != os.Getpid() {
		t.Fatalf("capture's uprobe options %+v, want PID %d (doctor's own)", opts, os.Getpid())
	}
}

// TestCaptureHookAnswersWithoutTheObjectOrALibrary drives testCaptureHook unprivileged: a binary
// without uprobe_ssl stands in a minimal KPROBE program, which an unprivileged process cannot load,
// and the row still answers as a capture row. As root the stand-in loads and, with no library, the
// attach is reported untested rather than failed.
func TestCaptureHookAnswersWithoutTheObjectOrALibrary(t *testing.T) {
	missing := func(o bpfobj.Object) (*ebpf.CollectionSpec, error) {
		return nil, fmt.Errorf("%w: %s", bpfobj.ErrNotGenerated, o)
	}
	noLib := libTarget{err: errors.New("no system libssl found in /nowhere")}
	for _, h := range captureHooks {
		got := testCaptureHook(h, nil, noLib, missing)
		if !got.Capture || !got.StandIn || got.Tier != "" || got.Attached {
			t.Errorf("%s = %+v, want an unattached capture stand-in", h.Name, got)
		}
		if got.Loaded && (!got.LoadOnly || !strings.Contains(got.Detail, "attach not tested")) {
			t.Errorf("%s loaded with no library, but %+v does not say the attach was not tested", h.Name, got)
		}
		if ps := minimalProgram(h); ps.Type != ebpf.Kprobe || ps.Instructions[0].Constant != 0 {
			t.Errorf("%s: the stand-in is %s returning %d, want a KPROBE returning 0", h.Name, ps.Type,
				ps.Instructions[0].Constant)
		}
	}
}

// TestProgramsVerdictNamesTheReaderBuild: D7's line says which build of trace_proc it loaded and why, and when
// lockdown=confidentiality leaves no build this kernel loads, the line and the fix say that rather than the
// verifier's "cannot use helper" (ADR 0024's tier-2 note).
func TestProgramsVerdictNamesTheReaderBuild(t *testing.T) {
	obj := string(bpfobj.ObjectTraceProc)
	ok := []HookResult{
		{Hook: "fexit/security_file_open", Tier: backend.TierCgroup, Object: obj, BTF: true, Loaded: true, Attached: true,
			Reader: "rdonly", ReaderWhy: "the kernel's BTF has bpf_rdonly_cast and bpf_loop"},
		{Hook: "tp_btf/sched_process_exec", Tier: backend.TierCgroup, Object: obj, BTF: true, Loaded: true, Attached: true,
			Reader: "rdonly", ReaderWhy: "the kernel's BTF has bpf_rdonly_cast and bpf_loop"},
	}
	r := programsVerdict(ok)
	if !r.OK || strings.Count(r.Detail, "trace_proc is its rdonly build (the kernel's BTF has bpf_rdonly_cast and bpf_loop)") != 1 {
		t.Errorf("D7 with the rdonly build = %+v", r)
	}
	refused := []HookResult{{Hook: "fexit/security_file_open", Tier: backend.TierCgroup, Object: obj, BTF: true,
		Reader: "probe", ReaderWhy: "the kernel's BTF has no bpf_rdonly_cast", Lockdown: true}}
	r = programsVerdict(refused)
	if r.OK || !strings.Contains(r.Detail, "trace_proc has no build this kernel loads under lockdown=confidentiality") ||
		!strings.Contains(r.Fix, "boot without lockdown=confidentiality") {
		t.Errorf("D7 under confidentiality without the rdonly build = %+v", r)
	}
}
