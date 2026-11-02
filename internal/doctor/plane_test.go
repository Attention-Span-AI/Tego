// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/btf"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// planeArity is each hook's parameter count in 6.17's BTF, bpf_lsm_ and security_ alike but for planeArityFmodRet's.
var planeArity = map[string]int{"file_open": 1, "bprm_check": 1, "path_rename": 5, "path_link": 3, "path_unlink": 2,
	"path_rmdir": 2, "path_mknod": 4, "path_mkdir": 3, "path_symlink": 3, "path_truncate": 1, "file_truncate": 1,
	"path_chmod": 2, "path_chown": 3, "inode_setxattr": 6, "inode_removexattr": 3, "inode_set_acl": 4,
	"inode_remove_acl": 3, "socket_create": 4,
	"socket_connect": 3, "socket_sendmsg": 3, "mmap_file": 4, "file_mprotect": 3,
	"socket_bind": 3, "socket_listen": 2, "ptrace_access_check": 2, "ptrace_traceme": 1, "bpf": 4, "key_permission": 3}

// planeArityFmodRet is the security_ function's count where it differs from the LSM hook's.
var planeArityFmodRet = map[string]int{"mmap_file": 3}

// planeArityOf is hook h's parameter count in mode m.
func planeArityOf(h bpfobj.PlaneHook, m bpfobj.PlaneMode) int {
	if n, ok := planeArityFmodRet[h.Name]; ok && m == bpfobj.PlaneFmodRet {
		return n
	}
	return planeArity[h.Name]
}

// passingPlaneRows is every plane hook in every mode, loaded, attached, run, and answering as its body does.
func passingPlaneRows() []HookResult {
	var rows []HookResult
	for _, m := range bpfobj.PlaneModes {
		for _, h := range bpfobj.PlaneHooks {
			inside := planePassed
			if h.Decides {
				inside = planeRefused
			}
			rows = append(rows, HookResult{Hook: planeRowName(h, m), Plane: m, Function: planeTarget(h, m),
				Arity: planeArityOf(h, m), Object: string(bpfobj.ObjectPlaneRdonly), Decides: h.Decides, BTF: true,
				Loaded: true, Attached: true, Ran: true, Inside: inside, Outside: planePassed})
		}
	}
	return rows
}

// passingPlane is a machine on which both modes pass the probe with the rd build, under bpf.plane pin.
func passingPlane(pin string) *PlaneState {
	if pin == "" {
		pin = config.PlaneAuto
	}
	rows := passingPlaneRows()
	st := &PlaneState{Env: PlaneEnv{BPFLoop: true, RdonlyCast: true, Lockdown: "none", LTO: ltoNone,
		LTOSource: "/boot/config-6.17.0-test"}, Build: bpfobj.ObjectPlaneRdonly, BuildWhy: "bpf_rdonly_cast is in BTF",
		BuildHash: "0123abcd4567ef890123abcd4567ef89", Pin: pin, Source: planeSourceProbed}
	for _, m := range bpfobj.PlaneModes {
		var mine []HookResult
		for _, r := range rows {
			if r.Plane == m {
				mine = append(mine, r)
			}
		}
		st.Modes = append(st.Modes, planeModeVerdict(m, mine, planeScope{Inside: 1}, passingKnown()))
	}
	selectPlane(st)
	return st
}

// defaultBootPlane is the guest's default boot: bpf not an active LSM, so LSM mode is ruled out before any load and
// fmod_ret mode passes.
func defaultBootPlane() *PlaneState {
	st := passingPlane("")
	lsm := LSMState{Modules: []string{"lockdown", "capability", "landlock", "yama", "apparmor"}}
	detail, fix := modePrecondition(bpfobj.PlaneLSM, st.Env, lsm)
	st.Modes[0] = PlaneModeResult{Mode: bpfobj.PlaneLSM, Detail: detail, Fix: fix}
	selectPlane(st)
	return st
}

func TestChoosePlaneBuild(t *testing.T) {
	all := func(bpfobj.Object) bool { return true }
	none := func(bpfobj.Object) bool { return false }
	cases := []struct {
		name string
		env  PlaneEnv
		have func(bpfobj.Object) bool
		want bpfobj.Object
		fix  string
	}{
		{"6.17: bpf_rdonly_cast", PlaneEnv{BPFLoop: true, RdonlyCast: true, Lockdown: "none"}, all, bpfobj.ObjectPlaneRdonly, ""},
		{"6.17 under confidentiality: the rd build still loads",
			PlaneEnv{BPFLoop: true, RdonlyCast: true, Lockdown: "confidentiality"}, all, bpfobj.ObjectPlaneRdonly, ""},
		{"AL2023 6.1: probe reads", PlaneEnv{BPFLoop: true, Lockdown: "integrity"}, all, bpfobj.ObjectPlaneProbe, ""},
		{"AL2023 6.1 under confidentiality: no build",
			PlaneEnv{BPFLoop: true, Lockdown: "confidentiality"}, all, "", "boot without lockdown=confidentiality"},
		{"no bpf_loop: no build", PlaneEnv{RdonlyCast: true}, all, "", "boot a kernel >= 5.17"},
		{"an untagged binary", PlaneEnv{BPFLoop: true, RdonlyCast: true}, none, "", ""},
	}
	for _, tc := range cases {
		got, why, fix := choosePlaneBuild(tc.env, tc.have)
		if got != tc.want || why == "" || !strings.HasPrefix(fix, tc.fix) || (tc.fix == "" && fix != "") {
			t.Errorf("%s: build %q (%s), fix %q; want %q, fix %q", tc.name, got, why, fix, tc.want, tc.fix)
		}
	}
}

func TestModePrecondition(t *testing.T) {
	inactive := LSMState{Modules: []string{"capability", "landlock"}}
	active := LSMState{Modules: []string{"capability", "landlock", "bpf"}, BPFActive: true}
	if d, fix := modePrecondition(bpfobj.PlaneLSM, PlaneEnv{}, inactive); !strings.Contains(d, "bpf is not in the active LSM list") ||
		!strings.Contains(fix, "lsm=capability,landlock,bpf") {
		t.Errorf("LSM mode without bpf: %q, fix %q", d, fix)
	}
	if d, _ := modePrecondition(bpfobj.PlaneLSM, PlaneEnv{LTO: ltoClang}, active); d != "" {
		t.Errorf("LTO rules LSM mode out: %q", d)
	}
	if d, fix := modePrecondition(bpfobj.PlaneFmodRet, PlaneEnv{LTO: ltoClang, LTOSource: "/proc/config.gz"}, active); !strings.Contains(d, "Clang LTO") ||
		!strings.Contains(fix, "CONFIG_LTO_CLANG") {
		t.Errorf("fmod_ret under Clang LTO: %q, fix %q", d, fix)
	}
	for _, lto := range []string{ltoNone, ltoUnknown} {
		if d, _ := modePrecondition(bpfobj.PlaneFmodRet, PlaneEnv{LTO: lto}, inactive); d != "" {
			t.Errorf("fmod_ret with LTO %s ruled out: %q", lto, d)
		}
	}
}

// TestTransientAttachFaultsTheProbe: an attach errno that can pass on its own (memory pressure, a full trampoline, a
// busy or interrupted call) faults the mode's probe, so the run-probe cache does not keep it for the boot; one that
// repeats stays a failed row the mode fails on.
func TestTransientAttachFaultsTheProbe(t *testing.T) {
	for _, e := range []syscall.Errno{syscall.ENOMEM, syscall.E2BIG, syscall.EBUSY, syscall.EAGAIN, syscall.EINTR, syscall.EPERM} {
		err := attachFault("lsm/file_open", fmt.Errorf("attach lsm link: %w", e))
		if !errors.Is(err, errAttachTransient) || !strings.Contains(err.Error(), "lsm/file_open") {
			t.Errorf("%v: %v, want a transient fault", e, err)
		}
	}
	for _, e := range []syscall.Errno{syscall.EINVAL, syscall.ENOENT, syscall.EOPNOTSUPP} {
		if err := attachFault("lsm/file_open", fmt.Errorf("attach lsm link: %w", e)); err != nil {
			t.Errorf("%v: %v, want a row failure", e, err)
		}
	}
}

// TestUnreadLSMListIsNotAnInactiveBPF: when no mechanism could read the active LSM list (ReadLSMState's error),
// LSM mode is ruled out as unknown, never as "bpf is not in the active LSM list ()" with a bare lsm=bpf GRUB fix
// that would switch off every LSM the machine runs, and the answer is Faulted so the run-probe cache does not keep
// a transient read failure; fmod_ret mode does not read the list.
func TestUnreadLSMListIsNotAnInactiveBPF(t *testing.T) {
	unread := LSMState{Source: LSMSourceNone}
	d, fix := modePrecondition(bpfobj.PlaneLSM, PlaneEnv{}, unread)
	if !strings.Contains(d, "cannot read the active LSM list") || strings.Contains(fix, "lsm=") ||
		!strings.Contains(fix, "securityfs") {
		t.Errorf("LSM mode on an unread list: %q, fix %q", d, fix)
	}
	if d, _ := modePrecondition(bpfobj.PlaneFmodRet, PlaneEnv{}, unread); d != "" {
		t.Errorf("fmod_ret ruled out by an unread LSM list: %q", d)
	}
	rep := state(func(st *probeState) {
		st.lsm = unread
		st.plane = defaultBootPlane()
	}).report(nil, "")
	_, err := rep.PlaneFor(backend.TierBPFLSM)
	var pe *PlaneUnavailableError
	if !errors.As(err, &pe) || strings.Contains(pe.Fix, "lsm=") || strings.Contains(pe.Why, "not in the active") {
		t.Errorf("bpflsm on an unread list: %v", err)
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	res, _ := probePlaneMode(bpfobj.PlaneLSM, spec, PlaneEnv{}, unread, bpfobj.ObjectPlaneRdonly, "", "", 0, &planeKnownRows{}, &planeImage{fd: -1})
	if res.OK || !res.Faulted || strings.Contains(res.Fix, "lsm=") {
		t.Errorf("LSM mode's result on an unread list: %+v; want not OK, Faulted, no GRUB fix", res)
	}
	st := &PlaneState{Modes: []PlaneModeResult{res}}
	if !st.faulted() {
		t.Error("a plane whose LSM list was unread is kept by the run-probe cache")
	}
}

func TestParseLockdownAndLTO(t *testing.T) {
	for in, want := range map[string]string{"none [integrity] confidentiality\n": "integrity",
		"[none] integrity confidentiality": "none", "none integrity [confidentiality]\n": "confidentiality"} {
		if got := parseLockdown(in); got != want {
			t.Errorf("parseLockdown(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"CONFIG_LTO_NONE=y\n# CONFIG_LTO_CLANG is not set\n": ltoNone,
		"CONFIG_LTO=y\nCONFIG_LTO_CLANG=y\nCONFIG_LTO_CLANG_THIN=y\n": ltoClang} {
		if got, ok := scanConfigLTO(strings.NewReader(in)); !ok || got != want {
			t.Errorf("scanConfigLTO(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	// A config with no CONFIG_ line (empty, a stub, a placeholder) is no answer: readLTO then tries the next config
	// and kallsyms, rather than reading "no Clang LTO" off a file that says nothing.
	for _, in := range []string{"", "\n", "# placeholder\n", "stub"} {
		if got, ok := scanConfigLTO(strings.NewReader(in)); ok {
			t.Errorf("scanConfigLTO(%q) = %q, answered; want no answer", in, got)
		}
	}
	dir := t.TempDir()
	syms := filepath.Join(dir, "kallsyms")
	if err := os.WriteFile(syms, []byte("0 t foo\n0 t bar.llvm.123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := kallsymsLTO(syms); !ok || got != ltoClang {
		t.Errorf("kallsyms with a .llvm. suffix: %q %v", got, ok)
	}
	if _, ok := kallsymsLTO(filepath.Join(dir, "none")); ok {
		t.Error("a missing kallsyms answered")
	}
}

// TestSelectPlane is R18/R19's choice for tier cgroup.
func TestSelectPlane(t *testing.T) {
	both := passingPlane("")
	onlyFmod := defaultBootPlane()
	neither := defaultBootPlane()
	neither.Modes[1].OK = false
	cases := []struct {
		name  string
		st    *PlaneState
		pin   string
		want  string
		whyIn string
	}{
		{"auto prefers LSM mode", both, config.PlaneAuto, "lsm", ""},
		{"auto takes fmod_ret where LSM mode is out", onlyFmod, config.PlaneAuto, "fmod_ret", ""},
		{"auto without a mode falls back", neither, config.PlaneAuto, PlaneFanotify, "no plane mode passed"},
		{"a pin takes its mode although LSM passed", both, config.PlaneFmodRet, "fmod_ret", ""},
		{"a pin that failed is the fallback, said so", onlyFmod, config.PlaneLSM, PlaneFanotify, "bpf.plane pins lsm"},
		{"a test build pinned to the listener takes it where both passed", both, PlaneFanotify, PlaneFanotify, "pinned to fanotify"},
	}
	for _, tc := range cases {
		st := *tc.st
		st.Pin = tc.pin
		selectPlane(&st)
		if st.Selected != tc.want || !strings.Contains(st.SelectedWhy, tc.whyIn) || (tc.whyIn == "" && st.SelectedWhy != "") {
			t.Errorf("%s: %q (%s), want %q (%s)", tc.name, st.Selected, st.SelectedWhy, tc.want, tc.whyIn)
		}
	}
}

// TestPlaneRowOK is R21's per-hook rule: a row counts when it loaded, attached, ran, passed outside every run, and
// in the scratch cgroup was refused where its body decides and passed where it is a stub.
func TestPlaneRowOK(t *testing.T) {
	base := HookResult{Plane: bpfobj.PlaneLSM, BTF: true, Loaded: true, Attached: true, Ran: true, Outside: planePassed}
	cases := []struct {
		name    string
		decides bool
		inside  string
		edit    func(*HookResult)
		want    bool
	}{
		{"a stub that passes", false, planePassed, nil, true},
		{"a stub that refuses", false, planeRefused, nil, false},
		{"a body that refuses", true, planeRefused, nil, true},
		{"a body that does not refuse", true, planePassed, nil, false},
		{"another errno", true, "failed: operation not permitted", nil, false},
		{"never ran", false, planePassed, func(r *HookResult) { r.Ran = false }, false},
		{"refused outside every run", true, planeRefused, func(r *HookResult) { r.Outside = planeRefused }, false},
		{"not in BTF", false, planePassed, func(r *HookResult) { r.BTF = false }, false},
		{"an optional hook this kernel predates", true, "", func(r *HookResult) {
			*r = HookResult{Plane: bpfobj.PlaneLSM, Decides: true, Absent: true}
		}, true},
	}
	for _, tc := range cases {
		r := base
		r.Decides, r.Inside = tc.decides, tc.inside
		if tc.edit != nil {
			tc.edit(&r)
		}
		if r.OK() != tc.want {
			t.Errorf("%s: OK() = %v", tc.name, r.OK())
		}
		if !r.OK() && r.BTF && planeRowFault(r) == "" {
			t.Errorf("%s: a failing row has no fault to name", tc.name)
		}
	}
}

func TestPlaneModeVerdict(t *testing.T) {
	rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
	scoped := planeScope{Inside: 1}
	all := fmt.Sprintf("%d of %d hooks load, attach and run", len(rows), len(rows))
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, scoped, passingKnown()); !v.OK || !strings.HasPrefix(v.Detail, all) {
		t.Errorf("passing rows: %+v", v)
	}
	// An optional hook this kernel predates (enforce-plane R3, §6 E14) is no failure: the mode is selected without
	// it, and the line names it apart.
	absent := slices.Clone(rows)
	for i, h := range bpfobj.PlaneHooks {
		if h.Optional {
			absent[i] = HookResult{Hook: absent[i].Hook, Plane: absent[i].Plane, Function: absent[i].Function,
				Decides: true, Absent: true}
		}
	}
	if v := planeModeVerdict(bpfobj.PlaneLSM, absent, scoped, passingKnown()); !v.OK || !strings.Contains(v.Detail, "not in this kernel") ||
		strings.HasPrefix(v.Detail, all) {
		t.Errorf("rows with optional hooks absent: %+v", v)
	}
	// Scope (R1): file_open's walk must meet the probe row in the scratch cgroup, and nothing outside it may.
	for name, sc := range map[string]planeScope{"never met": {}, "met outside the run": {Inside: 1, Outside: 1}} {
		if v := planeModeVerdict(bpfobj.PlaneLSM, rows, sc, passingKnown()); v.OK || !strings.Contains(v.Detail, "not scoped") {
			t.Errorf("%s: %+v", name, v)
		}
	}
	rows[2].Ran = false
	if v := planeModeVerdict(bpfobj.PlaneLSM, rows, scoped, passingKnown()); v.OK || !strings.Contains(v.Detail, "failed: "+rows[2].Hook) || v.Fix == "" {
		t.Errorf("a row that never ran: %+v", v)
	}
}

// TestPlaneParamsMatchTheSource holds planeParams, what the prototype check asks of the kernel, to decide.bpf.c's
// TEGO_PLANE_HOOK parameters, and covers every plane hook.
func TestPlaneParamsMatchTheSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "bpf", "decide.bpf.c"))
	if err != nil {
		t.Fatal(err)
	}
	// The step files decide.bpf.c includes carry their own hooks (decide_stepc.h).
	for _, m := range regexp.MustCompile(`(?m)^#include "(decide_[a-z0-9_]+\.h)"`).FindAllSubmatch(src, -1) {
		step, err := os.ReadFile(filepath.Join("..", "..", "bpf", string(m[1])))
		if err != nil {
			t.Fatal(err)
		}
		src = append(src, step...)
	}
	for name, fmr := range planeParamsFmodRet {
		if lsm := planeParams[name]; len(fmr) > len(lsm) || !reflect.DeepEqual(fmr, lsm[:len(fmr)]) {
			t.Errorf("%s: fmod_ret mode's parameters %v are not a prefix of the program's %v", name, fmr, lsm)
		}
	}
	inv := regexp.MustCompile(`(?m)^TEGO_PLANE_HOOK\(\s*([a-z_]+)\s*,[^(]*\(([^)]*)\)`)
	param := regexp.MustCompile(`(?:struct|union)\s+([a-z_]+)\s*\*`)
	seen := map[string]bool{}
	for _, m := range inv.FindAllStringSubmatch(string(src), -1) {
		var got []string
		for _, p := range strings.Split(m[2], ",") {
			if pm := param.FindStringSubmatch(p); pm != nil {
				got = append(got, pm[1])
			} else {
				typ := strings.Fields(p)[0]
				switch typ {
				case "unsigned", "enum":
					typ = "int"
				}
				got = append(got, typ)
			}
		}
		seen[m[1]] = true
		if !reflect.DeepEqual(got, planeParams[m[1]]) {
			t.Errorf("%s: decide.bpf.c declares %v, planeParams says %v", m[1], got, planeParams[m[1]])
		}
	}
	for _, h := range bpfobj.PlaneHooks {
		if !seen[h.Name] {
			t.Errorf("no TEGO_PLANE_HOOK parameters read for %s", h.Name)
		}
	}
}

// TestPlanePrototypesResolveHere is the prototype check on this machine's own BTF: every hook's LSM and fmod_ret
// target exists with the parameters the program reads, and a wrong expectation is caught.
func TestPlanePrototypesResolveHere(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	_, release, _ := probeKernelVersion()
	t.Logf("this kernel's plane environment: %+v", readPlaneEnv(spec, release))
	for _, m := range bpfobj.PlaneModes {
		rows, ok := planeStaticRows(m, spec)
		for i, r := range rows {
			if r.Absent {
				// An optional hook this kernel predates (enforce-plane R3): the row names the hook that decides
				// its rule here, and the mode is checked without it.
				t.Logf("%s: %s", r.Hook, r.Detail)
				continue
			}
			if !r.BTF || r.Arity < len(planeParamsFor(bpfobj.PlaneHooks[i], m)) {
				t.Errorf("%s: %s", r.Hook, r.Detail)
			}
		}
		if !ok {
			t.Errorf("mode %s: the prototype check failed on this kernel", m)
		}
	}
	if _, err := checkPrototype(spec, "security_file_open", []string{"dentry"}); err == nil ||
		!strings.Contains(err.Error(), "argument 1 is file") {
		t.Errorf("a wrong parameter passed: %v", err)
	}
	if _, err := checkPrototype(spec, "security_file_open", []string{"file", "file", "file", "file"}); err == nil ||
		!strings.Contains(err.Error(), "takes 1 arguments") {
		t.Errorf("too many parameters passed: %v", err)
	}
	// mmap_file's LSM hook takes reqprot beside prot; security_mmap_file does not (planeParamsFmodRet).
	if _, err := checkPrototype(spec, "security_mmap_file", planeParams["mmap_file"]); err == nil ||
		!strings.Contains(err.Error(), "takes 3 arguments") {
		t.Errorf("the LSM hook's four parameters passed on security_mmap_file: %v", err)
	}
	if _, err := checkPrototype(spec, "security_file_mprotect", []string{"vm_area_struct", "int"}); err == nil ||
		!strings.Contains(err.Error(), "8-byte") && !strings.Contains(err.Error(), "4-byte") {
		t.Errorf("an unsigned long read as an int passed: %v", err)
	}
	if _, err := checkPrototype(spec, "security_no_such_hook", nil); err == nil {
		t.Error("a function the kernel lacks passed")
	}
}

// TestBPFLSMNeedsLSMMode is enforce-plane.md R19: tier bpflsm is the plane in LSM mode, so it is missing wherever LSM mode did not
// pass, with LSM mode's own fix; where bpf is not active, the lsm line and the GRUB fix say it once.
func TestBPFLSMNeedsLSMMode(t *testing.T) {
	ok := state(func(st *probeState) { st.plane = passingPlane("") })
	if p := ok.probe(); !p[backend.TierBPFLSM] {
		t.Fatalf("both modes pass and tier bpflsm is missing: %v", ok.missingFor(backend.TierBPFLSM))
	}
	failing := state(func(st *probeState) {
		st.plane = passingPlane("")
		st.plane.Modes[0] = PlaneModeResult{Mode: bpfobj.PlaneLSM, Tested: true,
			Detail: "5 of 6 hooks load, attach and run; failed: lsm/path_link", Fix: "report it"}
		selectPlane(st.plane)
	})
	if failing.probe()[backend.TierBPFLSM] || !failing.probe()[backend.TierCgroup] {
		t.Errorf("LSM mode failed: offered %v", failing.probe())
	}
	if why := failing.whyNot()[backend.TierBPFLSM]; !strings.Contains(why, "plane: LSM mode: 5 of 6 hooks") ||
		!strings.HasSuffix(why, "fix: report it") {
		t.Errorf("tier bpflsm explained as %q", why)
	}
	if failing.plane.Selected != string(bpfobj.PlaneFmodRet) {
		t.Errorf("tier cgroup decides by %q, want fmod_ret", failing.plane.Selected)
	}
	pinned := state(func(st *probeState) { st.plane = passingPlane(config.PlaneFmodRet) })
	if why := pinned.whyNot()[backend.TierBPFLSM]; !strings.Contains(why, "bpf.plane pins fmod_ret") ||
		!strings.Contains(why, "fix: set bpf.plane: auto or lsm") {
		t.Errorf("a fmod_ret pin explains tier bpflsm as %q", why)
	}
	inactive := state(func(st *probeState) {
		st.lsm = LSMState{Modules: []string{"capability", "landlock"}, Source: LSMSourceSyscall}
		st.plane = defaultBootPlane()
	})
	why := inactive.whyNot()[backend.TierBPFLSM]
	if strings.Contains(why, "plane:") || !strings.Contains(why, "lsm=capability,landlock,bpf") {
		t.Errorf("bpf inactive explains tier bpflsm as %q", why)
	}
	notProbed := state(func(st *probeState) { st.plane = nil })
	if notProbed.probe()[backend.TierBPFLSM] {
		t.Error("tier bpflsm offered with no plane answer")
	}
}

// TestPlaneFor is the seam the backends read their mode from (T6, T7): bpflsm gets LSM mode or a refusal with the
// fix, never another mode; cgroup gets the selected mode or the fallback.
func TestPlaneFor(t *testing.T) {
	rep := state(func(st *probeState) { st.plane = passingPlane("") }).report(nil, "")
	if c, err := rep.PlaneFor(backend.TierBPFLSM); err != nil || c != (PlaneChoice{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneRdonly}) {
		t.Errorf("bpflsm: %+v %v", c, err)
	}
	if c, err := rep.PlaneFor(backend.TierCgroup); err != nil || c.Mode != bpfobj.PlaneLSM {
		t.Errorf("cgroup: %+v %v", c, err)
	}
	def := state(func(st *probeState) {
		st.lsm = LSMState{Modules: []string{"capability", "landlock"}, Source: LSMSourceSyscall}
		st.plane = defaultBootPlane()
	}).report(nil, "")
	_, err := def.PlaneFor(backend.TierBPFLSM)
	var pe *PlaneUnavailableError
	if !errors.As(err, &pe) || !errors.Is(err, ErrPlaneUnavailable) || !strings.Contains(pe.Fix, "lsm=capability,landlock,bpf") {
		t.Errorf("bpflsm without bpf: %v", err)
	}
	if c, err := def.PlaneFor(backend.TierCgroup); err != nil || c.Mode != bpfobj.PlaneFmodRet {
		t.Errorf("cgroup on the default boot: %+v %v", c, err)
	}
	none := state(func(st *probeState) {
		st.plane = defaultBootPlane()
		st.plane.Modes[1].OK = false
		selectPlane(st.plane)
	}).report(nil, "")
	if c, err := none.PlaneFor(backend.TierCgroup); err != nil || c.Mode != "" {
		t.Errorf("cgroup with no mode: %+v %v, want the fanotify fallback", c, err)
	}
	if _, err := (&Report{}).PlaneFor(backend.TierBPFLSM); !errors.Is(err, ErrPlaneUnavailable) {
		t.Errorf("bpflsm with no probe: %v", err)
	}
}

func TestPlanePinCodec(t *testing.T) {
	for _, c := range []PlaneChoice{{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneRdonly}, {Mode: bpfobj.PlaneFmodRet, Build: bpfobj.ObjectPlaneProbe},
		{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneProbe, ExecPins: true}} {
		b, err := encodePlanePin(c)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := decodePlanePin(b); !ok || got != c {
			t.Errorf("round trip of %+v: %+v %v", c, got, ok)
		}
		b[0] ^= 1
		if _, ok := decodePlanePin(b); ok {
			t.Error("a value of another magic decoded")
		}
	}
	if _, err := encodePlanePin(PlaneChoice{}); err == nil {
		t.Error("the fallback encoded as a pinned mode")
	}
	// The layout before ADR 0048 (7)'s exec pin bit (version 1, eight bytes) is no answer: a run probes rather than
	// adopt an answer that cannot say whether the mode's exec pin cell passed.
	if _, ok := decodePlanePin([]byte{0x45, 0x59, 0x50, 0x4c, 1, 0, 1, 1}); ok {
		t.Error("a version 1 answer decoded")
	}
	b, _ := encodePlanePin(PlaneChoice{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneRdonly})
	b[len(b)-1] = 1
	if _, ok := decodePlanePin(b); ok {
		t.Error("an answer with a reserved byte set decoded")
	}
}

// TestAdoptedPlaneCarriesExecPins is ADR 0048 (7) through adoption: a run that adopts a pinned build claims exec pins
// exactly when the pinned answer says the mode's exec pin cell passed.
func TestAdoptedPlaneCarriesExecPins(t *testing.T) {
	for _, pins := range []bool{false, true} {
		st, err := adoptPlaneFrom(config.PlaneLSM, LSMState{BPFActive: true}, "h", func(string) (PlaneChoice, bool) {
			return PlaneChoice{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneRdonly, ExecPins: pins}, true
		})
		if err != nil || len(st.Modes) != 1 {
			t.Fatalf("adopt: %+v %v", st, err)
		}
		if got := st.Modes[0].execPinsPass(); got != pins {
			t.Errorf("a pinned answer with exec pins %t adopted as %t (%+v)", pins, got, st.Modes[0].ExecPin)
		}
	}
	if got := PlanePinDir("", "0123456789abcdef", bpfobj.PlaneFmodRet); got != "/sys/fs/bpf/tego/0123456789abcdef-fmod_ret" {
		t.Errorf("pin dir %s", got)
	}
}

// TestAdoptPinnedPlane: a run adopts a pinned build's answer only for the mode its bpf.plane would select, so an
// adoption never picks a worse mode than a probe would.
func TestAdoptPinnedPlane(t *testing.T) {
	active := LSMState{Modules: []string{"bpf"}, BPFActive: true}
	inactive := LSMState{Modules: []string{"landlock"}}
	pinned := func(m bpfobj.PlaneMode) func(string) (PlaneChoice, bool) {
		return func(dir string) (PlaneChoice, bool) {
			if strings.HasSuffix(dir, "-"+string(m)) {
				return PlaneChoice{Mode: m, Build: bpfobj.ObjectPlaneRdonly}, true
			}
			return PlaneChoice{}, false
		}
	}
	cases := []struct {
		name   string
		pin    string
		lsm    LSMState
		pinned bpfobj.PlaneMode
		want   string
	}{
		{"auto, bpf active, LSM build pinned", config.PlaneAuto, active, bpfobj.PlaneLSM, "lsm"},
		{"auto, bpf active, only a fmod_ret build: probe", config.PlaneAuto, active, bpfobj.PlaneFmodRet, ""},
		{"auto, bpf inactive, fmod_ret build pinned", config.PlaneAuto, inactive, bpfobj.PlaneFmodRet, "fmod_ret"},
		{"pinned fmod_ret", config.PlaneFmodRet, active, bpfobj.PlaneFmodRet, "fmod_ret"},
		{"pinned lsm, only fmod_ret pinned: probe", config.PlaneLSM, active, bpfobj.PlaneFmodRet, ""},
	}
	for _, tc := range cases {
		st, err := adoptPlaneFrom(tc.pin, tc.lsm, "0123456789abcdef", pinned(tc.pinned))
		got := ""
		if err == nil {
			got = st.Selected
			if st.Source != planeSourcePin || st.Build != bpfobj.ObjectPlaneRdonly {
				t.Errorf("%s: adopted %+v", tc.name, st)
			}
		}
		if got != tc.want {
			t.Errorf("%s: adopted %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestAdoptingRunProbesNoPlane: at reach cgroup the plane comes from the run-probe cache, else from a pinned
// build's answer, and only else from a probe; doctor's own scope always probes; reach landlock never does.
func TestAdoptingRunProbesNoPlane(t *testing.T) {
	counting := func(n *int) func(bool, int, string, string, bool) (*PlaneState, []HookResult) {
		return func(_ bool, _ int, _, pin string, _ bool) (*PlaneState, []HookResult) {
			*n++
			return passingPlane(pin), passingPlaneRows()
		}
	}
	var n int
	c := passingChecks(&calls{})
	c.plane = counting(&n)
	scope{reach: backend.TierLandlock, root: true, checks: c}.run(context.Background())
	if n != 0 {
		t.Errorf("reach landlock probed the plane %d times", n)
	}
	st := scope{root: true, checks: c, planePin: config.PlaneAuto}.run(context.Background())
	if n != 1 || st.plane == nil || st.plane.Selected != "lsm" {
		t.Errorf("doctor's scope: %d probes, plane %+v", n, st.plane)
	}
	if rows := st.hooks; len(rows) != len(hooks)+len(passingPlaneRows())+len(captureHooks) ||
		rows[len(hooks)].Plane == "" || !rows[len(rows)-1].Capture {
		t.Errorf("D7's rows are not tier 2's, the plane's, then capture's: %d rows", len(rows))
	}
	if d := st.byID[CheckPrograms].Detail; !strings.Contains(d, "; decision plane: lsm (tiers 2 and 3 decide opens in the kernel); build 0123abcd, lsm mode ok, fmod_ret mode ok") {
		t.Errorf("D7's line: %s", d)
	}

	// Adopted from a pinned build: no probe.
	n = 0
	adopted := scope{reach: backend.TierCgroup, root: true, checks: c, planePin: config.PlaneAuto,
		adopt: func(pin string) (*PlaneState, bool) {
			st, err := adoptPlaneFrom(pin, LSMState{BPFActive: true}, "h", func(string) (PlaneChoice, bool) {
				return PlaneChoice{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneRdonly}, true
			})
			return st, err == nil
		}}.run(context.Background())
	if n != 0 || adopted.plane == nil || adopted.plane.Source != planeSourcePin {
		t.Errorf("a run over a pinned build probed %d times, plane %+v", n, adopted.plane)
	}

	// From the run-probe cache: no probe, and the selection follows today's bpf.plane.
	cache, _ := testCache(t)
	first := scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneAuto}.run(context.Background())
	if n != 1 || first.cached != nil {
		t.Fatalf("the first run probed %d times, cached %v", n, first.cached)
	}
	second := scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneFmodRet}.run(context.Background())
	if n != 1 || second.cached == nil || second.plane == nil || second.plane.Source != planeSourceRunCache ||
		second.plane.Selected != "fmod_ret" {
		t.Errorf("the second run probed %d times, plane %+v", n, second.plane)
	}
	if !reflect.DeepEqual(second.byID[CheckPrograms].Detail, strings.Replace(strings.Replace(first.byID[CheckPrograms].Detail,
		"decision plane: lsm (tiers 2 and 3 decide opens in the kernel)",
		"decision plane: fmod_ret (tier 2 decides opens in the kernel; bpf.plane pins fmod_ret)", 1),
		"fmod_ret mode ok", "fmod_ret mode ok [from the runcache]", 1)) {
		t.Errorf("D7's line from the cache %q, fresh %q", second.byID[CheckPrograms].Detail, first.byID[CheckPrograms].Detail)
	}
}

// TestACachedAnswerOfOneModeDoesNotAnswerAPinOfTheOther: an answer adopted from a pinned build knows the one mode
// that build was loaded in, and the run-probe cache keeps it; a later run whose bpf.plane pins the other mode probes
// rather than read "not passed" from it and run on the listener (TIER3-PLAN T6). Under auto, or the same pin, the
// cache answers.
func TestACachedAnswerOfOneModeDoesNotAnswerAPinOfTheOther(t *testing.T) {
	var n int
	c := passingChecks(&calls{})
	c.plane = func(_ bool, _ int, _, pin string, _ bool) (*PlaneState, []HookResult) {
		n++
		return passingPlane(pin), passingPlaneRows()
	}
	adopt := func(pin string) (*PlaneState, bool) {
		st, err := adoptPlaneFrom(pin, LSMState{BPFActive: true}, "h", func(string) (PlaneChoice, bool) {
			return PlaneChoice{Mode: bpfobj.PlaneLSM, Build: bpfobj.ObjectPlaneRdonly}, true
		})
		return st, err == nil
	}
	cache, _ := testCache(t)
	first := scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneLSM, adopt: adopt}.run(context.Background())
	if n != 0 || first.plane == nil || first.plane.Selected != "lsm" {
		t.Fatalf("the adopting run probed %d times, plane %+v", n, first.plane)
	}
	same := scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneAuto, adopt: adopt}.run(context.Background())
	if n != 0 || same.plane.Selected != "lsm" {
		t.Errorf("auto over the cached lsm answer probed %d times, selected %s", n, same.plane.Selected)
	}
	other := scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneFmodRet}.run(context.Background())
	if n != 1 || other.plane == nil || other.plane.Selected != "fmod_ret" {
		t.Errorf("a pin of the other mode over a one-mode cached answer: %d probes, plane %+v; want a probe and fmod_ret", n, other.plane)
	}
}

// TestACachedFmodRetPinAnswerDoesNotAnswerAuto: a run pinned to fmod_ret adopts that one mode even where bpf is an
// active LSM; a later auto run on the same boot probes rather than select fmod_ret from it and lose tier bpflsm.
func TestACachedFmodRetPinAnswerDoesNotAnswerAuto(t *testing.T) {
	var n int
	c := passingChecks(&calls{})
	c.plane = func(_ bool, _ int, _, pin string, _ bool) (*PlaneState, []HookResult) {
		n++
		return passingPlane(pin), passingPlaneRows()
	}
	adopt := func(pin string) (*PlaneState, bool) {
		st, err := adoptPlaneFrom(pin, LSMState{BPFActive: true}, "h", func(string) (PlaneChoice, bool) {
			return PlaneChoice{Mode: bpfobj.PlaneFmodRet, Build: bpfobj.ObjectPlaneRdonly}, true
		})
		return st, err == nil
	}
	cache, _ := testCache(t)
	first := scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneFmodRet, adopt: adopt}.run(context.Background())
	if n != 0 || first.plane == nil || first.plane.Selected != "fmod_ret" {
		t.Fatalf("the adopting run probed %d times, plane %+v", n, first.plane)
	}
	auto := scope{reach: backend.TierCgroup, root: true, checks: c, cache: cache, planePin: config.PlaneAuto}.run(context.Background())
	if n != 1 || auto.cached != nil || auto.plane == nil || auto.plane.Selected != "lsm" {
		t.Errorf("auto over a cached fmod_ret pin answer: %d probes, cached %v, plane %+v; want a probe and lsm", n, auto.cached, auto.plane)
	}
}

// goldenReport renders a described report's D1-D9 lines, its summary line and everything after the matrix (tier,
// missing, fix), and its plane and plane rows as JSON: the parts T8 changed, without the capability matrix.
func goldenReport(t *testing.T, st probeState) (string, string) {
	t.Helper()
	rep := st.report(nil, "")
	var b bytes.Buffer
	if err := rep.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	i, j := strings.Index(text, "\ncapability matrix"), strings.Index(text, "\ntier:")
	if i < 0 || j < i {
		t.Fatalf("unexpected text shape:\n%s", text)
	}
	text = text[:i] + "\n[capability matrix]\n" + text[j:]
	var full bytes.Buffer
	if err := writeJSONForTest(&full, rep); err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(full.Bytes(), &obj); err != nil {
		t.Fatal(err)
	}
	var rows []HookResult
	for _, r := range rep.Programs {
		if r.Plane != "" {
			rows = append(rows, r)
		}
	}
	part, err := json.MarshalIndent(struct {
		Plane json.RawMessage `json:"plane"`
		Rows  []HookResult    `json:"plane_rows"`
		Tiers json.RawMessage `json:"tiers"`
	}{obj["plane"], rows, obj["tiers"]}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return text, string(part) + "\n"
}

// checkGolden compares got with testdata/<name>, rewriting it when TEGO_UPDATE_GOLDEN=1.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("TEGO_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; got:\n%s", err, got)
	}
	if got != string(want) {
		t.Errorf("%s differs (TEGO_UPDATE_GOLDEN=1 rewrites it):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// TestPlaneDoctorGolden holds doctor's text and --json for the plane to golden files, for the guest's two boots:
// lsm= with bpf (LSM mode, tier bpflsm's plane, and tier cgroup deciding by lsm) and the default boot (no bpf
// LSM: LSM mode ruled out with the GRUB line, tier cgroup deciding by fmod_ret).
func TestPlaneDoctorGolden(t *testing.T) {
	boots := map[string]probeState{
		"lsm-boot": state(func(st *probeState) {
			st.plane = passingPlane("")
			st.hooks = append(tierRowsOf(st.hooks), passingPlaneRows()...)
			st.results[6].Detail += planeSummary(st.plane, st.lsm.BPFActive)
			st.byID[CheckPrograms] = st.results[6]
		}),
		"default-boot": state(func(st *probeState) {
			st.lsm = LSMState{Modules: []string{"lockdown", "capability", "landlock", "yama", "apparmor"},
				Source: LSMSourceSyscall}
			fail(st, CheckLSM, "lockdown,capability,landlock,yama,apparmor via lsm_list_modules(2); bpf is not active: "+
				"tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected", st.lsm.GRUBFixFor(bootDebian))
			st.plane = defaultBootPlane()
			rows := passingPlaneRows()
			for i := range rows {
				if rows[i].Plane == bpfobj.PlaneLSM {
					rows[i].Loaded, rows[i].Attached, rows[i].Ran, rows[i].Inside, rows[i].Outside = false, false, false, "", ""
					rows[i].Object = ""
				}
			}
			st.hooks = append(tierRowsOf(st.hooks), rows...)
			st.results[6].Detail += planeSummary(st.plane, st.lsm.BPFActive)
			st.byID[CheckPrograms] = st.results[6]
		}),
	}
	boots["fanotify-fallback-boot"] = noPlaneBoot(PlaneEnv{BPFLoop: true, RdonlyCast: true,
		Lockdown: "none", LTO: ltoClang, LTOSource: "/boot/config-6.17.0-test"}, false)
	boots["lockdown-no-rdonly-cast-boot"] = noPlaneBoot(PlaneEnv{BPFLoop: true, Lockdown: "confidentiality",
		LTO: ltoNone, LTOSource: "/boot/config-6.1.0-test"}, true)
	boots["no-bpf-loop-boot"] = noPlaneBoot(PlaneEnv{RdonlyCast: false, Lockdown: "none", LTO: ltoNone,
		LTOSource: "/boot/config-5.14.0-test"}, true)
	for name, st := range boots {
		text, js := goldenReport(t, st)
		checkGolden(t, "plane-"+name+".txt.golden", text)
		checkGolden(t, "plane-"+name+".json.golden", js)
	}
}

// tierRowsOf keeps the rows that are not the plane's.
func tierRowsOf(rows []HookResult) []HookResult {
	var out []HookResult
	for _, r := range rows {
		if r.Plane == "" {
			out = append(out, r)
		}
	}
	return out
}

// noPlaneBoot is a boot on which neither plane mode passes and tier cgroup falls back to fanotify: the precondition
// or build check rules both modes out before any load. bpfActive is whether bpf is in lsm=.
func noPlaneBoot(env PlaneEnv, bpfActive bool) probeState {
	return state(func(st *probeState) {
		mods := []string{"lockdown", "capability", "landlock", "yama", "apparmor"}
		if bpfActive {
			mods = append(mods, "bpf")
		}
		st.lsm = lsmState(mods, LSMSourceSyscall)
		if !bpfActive {
			fail(st, CheckLSM, "lockdown,capability,landlock,yama,apparmor via lsm_list_modules(2); bpf is not active: "+
				"tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected", st.lsm.GRUBFixFor(bootDebian))
		}
		build, why, buildFix := choosePlaneBuild(env, func(bpfobj.Object) bool { return true })
		pl := &PlaneState{Env: env, Build: build, BuildWhy: why, Pin: config.PlaneAuto, Source: planeSourceProbed}
		if build != "" {
			pl.BuildHash = "0123abcd4567ef890123abcd4567ef89"
		}
		for _, m := range bpfobj.PlaneModes {
			if d, f := modePrecondition(m, env, st.lsm); d != "" {
				pl.Modes = append(pl.Modes, PlaneModeResult{Mode: m, Detail: d, Fix: f})
				continue
			}
			pl.Modes = append(pl.Modes, PlaneModeResult{Mode: m, Detail: "no build of decide.bpf.c loads here: " + why,
				Fix: buildFix})
		}
		selectPlane(pl)
		st.plane = pl
		st.hooks = tierRowsOf(st.hooks)
		st.results[6].Detail += planeSummary(st.plane, st.lsm.BPFActive)
		st.byID[CheckPrograms] = st.results[6]
	})
}

// TestPlaneSummaryWording holds doctor's plane clause to the words the operator reads: the mode tier 2 decides by,
// what tier 3 needs, and the build as a short hash, never the object's internal name.
func TestPlaneSummaryWording(t *testing.T) {
	def := planeSummary(defaultBootPlane(), false)
	for _, want := range []string{"decision plane: fmod_ret (tier 2 decides opens in the kernel; tier 3 needs bpf in lsm=)",
		"build 0123abcd,"} {
		if !strings.Contains(def, want) {
			t.Errorf("default boot's clause %q lacks %q", def, want)
		}
	}
	if strings.Contains(def, "decide_rd") || strings.Contains(def, "decide_pr") {
		t.Errorf("the clause names an object, not a hash: %s", def)
	}
	if got := planeSummary(passingPlane(""), true); !strings.Contains(got, "decision plane: lsm (") {
		t.Errorf("lsm boot's clause: %s", got)
	}
	fb := noPlaneBoot(PlaneEnv{BPFLoop: true, RdonlyCast: true, LTO: ltoClang}, false)
	if got := planeSummary(fb.plane, fb.lsm.BPFActive); !strings.Contains(got, "decision plane: fanotify (") ||
		!strings.Contains(got, "tier 2 decides opens by fanotify") {
		t.Errorf("fanotify clause: %s", got)
	}
}

// TestPlaneForExecPins is ADR 0048 (7): a tier's plane choice says the kernel can hold execs to the decided facts only
// where the chosen mode's exec pin cell ran and passed; a cell that did not run (nil) or failed says not, so no run
// claims pins on it.
func TestPlaneForExecPins(t *testing.T) {
	for _, c := range []struct {
		name string
		cell *PlaneExecPinCell
		want bool
	}{
		{"not run", nil, false},
		{"failed", &PlaneExecPinCell{Detail: "a pin whose mac_cov differs was not killed"}, false},
		{"passed", &PlaneExecPinCell{OK: true}, true},
	} {
		rep := state(func(st *probeState) {
			st.plane = passingPlane("")
			for i := range st.plane.Modes {
				st.plane.Modes[i].ExecPin = c.cell
			}
		}).report(nil, "")
		for _, tier := range []backend.Tier{backend.TierBPFLSM, backend.TierCgroup} {
			if ch, err := rep.PlaneFor(tier); err != nil || ch.ExecPins != c.want {
				t.Errorf("%s at %s: %+v %v, want ExecPins %t", c.name, tier, ch, err, c.want)
			}
		}
	}
}
