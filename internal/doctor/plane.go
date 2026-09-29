// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/btf"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The decision plane's mode probe (ADR 0024 (2), (3), (9); docs/p0/enforce-plane.md R18, R19, R21; TIER3-PLAN T8).
// This file is its pure half: the preconditions read from the kernel's BTF, lockdown and build config, the choice
// of object build, the per-hook prototype check, the mode selection and the words doctor prints. planeprobe.go is
// the half that loads, attaches and runs the probe syscalls.

// PlaneFanotify is the decision plane's name for the fallback: no plane mode, tier cgroup's fanotify marks (ADR
// 0021). It is what PlaneState.Selected holds when neither mode passes.
const PlaneFanotify = "fanotify"

// LTO states of PlaneEnv.LTO.
const (
	ltoNone    = "none"
	ltoClang   = "clang"
	ltoUnknown = "unknown"
)

// Where PlaneState came from.
const (
	planeSourceProbed   = "probed"
	planeSourceRunCache = "runcache"
	planeSourcePin      = "pin"
)

// PlaneEnv is what the mode probe reads before it loads anything: the kfuncs and helpers the two builds need in the
// kernel's BTF, lockdown, and whether the kernel was built with Clang LTO.
type PlaneEnv struct {
	// BPFLoop is the bpf_loop helper in BTF (5.17+ or a backport, RHEL 9.8): the walk's form needs it, so a
	// kernel without it has no plane mode (ADR 0024 (1)).
	BPFLoop bool `json:"bpf_loop"`
	// RdonlyCast is the bpf_rdonly_cast kfunc in BTF (6.2+ or a backport): the rd build needs it, and it is the
	// only build lockdown=confidentiality admits (ADR 0024 (9)).
	RdonlyCast bool `json:"rdonly_cast"`
	// Lockdown is the active lockdown mode (none, integrity, confidentiality), "" when the kernel has no
	// lockdown file.
	Lockdown string `json:"lockdown"`
	// LTO is ltoClang when the kernel's config shows CONFIG_LTO_CLANG=y (or, with no config to read, kallsyms
	// shows Clang's .llvm. suffixes), ltoNone when it shows neither, ltoUnknown when nothing could be read.
	LTO string `json:"lto"`
	// LTOSource names what LTO was read from.
	LTOSource string `json:"lto_source,omitempty"`
	// MemfdNoexec is vm.memfd_noexec (0 when the kernel has none). At 2 the kernel refuses every executable
	// memfd, which the probe's child needs to exec a file no path names, so no mode can be probed.
	MemfdNoexec int `json:"memfd_noexec,omitempty"`
}

// PlaneModeResult is one mode's answer.
type PlaneModeResult struct {
	Mode bpfobj.PlaneMode `json:"mode"`
	// OK is every hook of the mode loaded, attached, ran, passed outside the scratch cgroup and, where its body
	// decides, refused inside it (R21). A mode is selected only when OK.
	OK bool `json:"ok"`
	// Tested is false when a precondition ruled the mode out before any load (bpf not an active LSM, Clang LTO,
	// no object build, a hook missing from BTF).
	Tested bool `json:"tested"`
	// Faulted is a probe that could not finish (a load error other than one the kernel repeats (loadFault), an
	// error from the fixtures, the scratch cgroup or the child, an attach errno that can pass on its own
	// (attachFault), a probe syscall's errno that can
	// (planeOutcomeFaulted), or for LSM mode an active LSM list that could
	// not be read), not a mode that ran and failed. Its cause may be transient or the host's, so the run-probe
	// cache never keeps an answer holding one.
	Faulted bool   `json:"faulted,omitempty"`
	Detail  string `json:"detail"`
	// Fix is the one change that would make the mode pass, "" when there is none to name.
	Fix string `json:"fix,omitempty"`
	// Scope is the probe row's scope evidence (planeScope), "" when the syscalls did not run.
	Scope string `json:"scope,omitempty"`
	// Known is each known-answer cell's verdict and counters (planeknown.go), in the table's order; none when the
	// probe row's syscalls failed first. OK needs every cell to match exactly.
	Known []PlaneKnownAnswer `json:"known,omitempty"`
	// ExecPin is the mode's exec pin cell, plane.exec_pin (ADR 0048 (7)): its eight known answers, run once the mode
	// passed. nil is a cell that did not run, which no run may read as a pass: a run's handle claims exec pins only
	// where it passed (PlaneChoice.ExecPins).
	ExecPin *PlaneExecPinCell `json:"exec_pin,omitempty"`
	// KnownTook is what the known answers added to the mode's probe, the fill build's load included for the first
	// mode that loads it; logged by the guest tests, not reported.
	KnownTook time.Duration `json:"-"`
	// KnownPhases splits KnownTook by phase, for the same log.
	KnownPhases []string `json:"-"`
}

// planeScope is the evidence that the mode's programs decided the probe row's run and no one else: file_open's walk
// meets the probe row's missing rows map (NOROWS) and counts it at the row's slot, which no host process can reach,
// because nothing but the scratch cgroup is armed in the probe's own run set. Inside is the count the child's
// syscalls added, Outside the count doctor's own syscalls added after them, which must stay 0 (R1).
type planeScope struct {
	Inside, Outside uint64
}

// PlaneState is the decision plane's answer on this machine: which build of decide.bpf.c loads, which modes pass
// the probe, and the mode tier cgroup would use under the machine's bpf.plane setting.
type PlaneState struct {
	// Skipped marks a probe that could not run (not root); nothing else is set then.
	Skipped bool     `json:"skipped,omitempty"`
	Env     PlaneEnv `json:"env"`
	// Build is the object build the probe chose (bpf.ObjectPlaneRdonly or bpf.ObjectPlaneProbe), "" when none
	// can load here; BuildWhy says why.
	Build    bpfobj.Object `json:"build"`
	BuildWhy string        `json:"build_why"`
	// BuildHash is this binary's object hash (bpf.Hash), the name of the build's pin directory, "" when the
	// binary carries none. Doctor prints its first planeHashLen characters as the build.
	BuildHash string `json:"build_hash,omitempty"`
	// Modes is LSM mode then fmod_ret mode.
	Modes []PlaneModeResult `json:"modes"`
	// Pin is the machine's bpf.plane setting (auto, lsm, fmod_ret).
	Pin string `json:"pin"`
	// Selected is the mode tier cgroup uses: lsm, fmod_ret or fanotify (R19). SelectedWhy says why when it is
	// not the best mode that passed.
	Selected    string `json:"selected"`
	SelectedWhy string `json:"selected_why,omitempty"`
	// Source is probed, runcache (this boot's run-probe cache) or pin (a pinned build's recorded answer).
	Source string `json:"source"`
}

// faulted reports whether any mode's probe faulted (PlaneModeResult.Faulted).
func (s *PlaneState) faulted() bool {
	if s == nil {
		return false
	}
	for _, r := range s.Modes {
		if r.Faulted {
			return true
		}
	}
	return false
}

// mode returns the result of mode m, and whether the state holds one.
func (s *PlaneState) mode(m bpfobj.PlaneMode) (PlaneModeResult, bool) {
	if s == nil {
		return PlaneModeResult{}, false
	}
	for _, r := range s.Modes {
		if r.Mode == m {
			return r, true
		}
	}
	return PlaneModeResult{}, false
}

// answers reports whether the state holds what selecting under pin reads: under auto or the fanotify pin, any
// probed answer (an adopted one only where it is LSM's or was adopted under auto); under a pinned mode, that mode's own result. An answer adopted from a pinned build holds its one mode only.
func (s *PlaneState) answers(pin string) bool {
	if s == nil {
		return false
	}
	switch pin {
	case config.PlaneLSM, config.PlaneFmodRet:
		_, ok := s.mode(bpfobj.PlaneMode(pin))
		return ok
	}
	if s.Source == planeSourcePin && s.Pin != config.PlaneAuto {
		// A build pinned to fmod_ret loaded that mode even where bpf is an active LSM, which auto would prefer:
		// only an LSM answer, or one adopted under auto, is what a fresh auto (or fanotify) selection would read.
		_, lsm := s.mode(bpfobj.PlaneLSM)
		return lsm
	}
	return true
}

// planeParams is each plane hook's parameters as decide.bpf.c's TEGO_PLANE_HOOK declares them: the struct each
// pointer argument points to, in order, a prefix of the hook's 6.1 prototype (bpf/README.md); "int" for a scalar the
// body reads, "__u64" for an unsigned long it reads, and "void" for the inode hooks' void * idmap (a struct user_namespace * below 6.3 and a struct mnt_idmap *
// from 6.3, which no body reads). The prototype check asks the kernel's own bpf_lsm_<hook> and security_<fn> for at
// least these, in this order: the struct ones by name, an int as a 4-byte int, a __u64 as an 8-byte one, a void as any argument
// (TestPlaneParamsMatchTheSource holds the table to the C).
var planeParams = map[string][]string{
	"file_open":           {"file"},
	"bprm_check":          {"linux_binprm"},
	"path_rename":         {"path", "dentry", "path", "dentry"},
	"path_link":           {"dentry", "path", "dentry"},
	"path_unlink":         {"path", "dentry"},
	"path_rmdir":          {"path", "dentry"},
	"path_mknod":          {"path", "dentry", "umode_t"},
	"path_mkdir":          {"path", "dentry"},
	"path_symlink":        {"path", "dentry"},
	"path_truncate":       {"path"},
	"file_truncate":       {"file"},
	"path_chmod":          {"path"},
	"path_chown":          {"path"},
	"inode_setxattr":      {"void", "dentry"},
	"inode_removexattr":   {"void", "dentry"},
	"inode_set_acl":       {"void", "dentry"},
	"inode_remove_acl":    {"void", "dentry"},
	"socket_create":       {"int", "int", "int", "int"},
	"socket_connect":      {"socket", "sockaddr", "int"},
	"socket_sendmsg":      {"socket", "msghdr"},
	"mmap_file":           {"file", "__u64", "__u64", "__u64"},
	"file_mprotect":       {"vm_area_struct", "__u64", "__u64"},
	"socket_bind":         {"socket", "sockaddr", "int"},
	"socket_listen":       {"socket", "int"},
	"ptrace_access_check": {"task_struct", "int"},
	"ptrace_traceme":      {"task_struct"},
	"bpf":                 {"int", "bpf_attr", "int"},
	"key_permission":      {"key_ref_t", "cred", "int"},
}

// planeParamsFmodRet is a hook's parameters in fmod_ret mode where its security_ function takes fewer than its LSM
// hook: security_mmap_file(file, prot, flags) against bpf_lsm_mmap_file(file, reqprot, prot, flags). The program's
// fourth parameter is then security_mmap_file's return slot, which the body never reads (enforce-plane §2.14).
var planeParamsFmodRet = map[string][]string{
	"mmap_file": {"file", "__u64", "__u64"},
}

// planeParamsFor is what the prototype check asks of hook h's target in mode m.
func planeParamsFor(h bpfobj.PlaneHook, m bpfobj.PlaneMode) []string {
	if p, ok := planeParamsFmodRet[h.Name]; ok && m == bpfobj.PlaneFmodRet {
		return p
	}
	return planeParams[h.Name]
}

// planeParamAny reports whether a planeParams entry asks only that the kernel's function has an argument there.
func planeParamAny(w string) bool { return w == "void" }

// planeTarget is the kernel function a hook's program attaches to in mode m: bpf_lsm_<hook> for LSM mode, the
// security_ function for fmod_ret mode.
func planeTarget(h bpfobj.PlaneHook, m bpfobj.PlaneMode) string {
	if m == bpfobj.PlaneLSM {
		return "bpf_lsm_" + h.LSM
	}
	return h.Security
}

// planeRowName is D7's row name for a hook in a mode: its ELF section, as the other rows are named.
func planeRowName(h bpfobj.PlaneHook, m bpfobj.PlaneMode) string { return h.Section(m) }

// checkPrototype is the prototype check (ADR 0024 (3)): the kernel's BTF declares fn as a function whose first
// parameters point to the structs want names, in order. It returns the kernel's parameter count.
func checkPrototype(spec *btf.Spec, fn string, want []string) (int, error) {
	var f *btf.Func
	if err := spec.TypeByName(fn, &f); err != nil {
		return 0, fmt.Errorf("%s is not in the kernel's BTF: %w", fn, err)
	}
	proto, ok := f.Type.(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("%s has no prototype in BTF", fn)
	}
	n := len(proto.Params)
	if n < len(want) {
		return n, fmt.Errorf("%s takes %d arguments in this kernel, the program reads %d", fn, n, len(want))
	}
	for i, w := range want {
		if planeParamAny(w) {
			continue
		}
		if w == "key_ref_t" {
			if got := pointee(proto.Params[i].Type); got != "__key_reference_with_attributes" {
				return n, fmt.Errorf("%s's argument %d is %s, the program reads key_ref_t", fn, i+1, got)
			}
			continue
		}
		if size, ok := map[string]uint32{"int": 4, "__u64": 8, "umode_t": 2}[w]; ok {
			var actual uint32
			switch it := btf.UnderlyingType(proto.Params[i].Type).(type) {
			case *btf.Int:
				actual = it.Size
			case *btf.Enum:
				actual = it.Size
			}
			if actual != size {
				return n, fmt.Errorf("%s's argument %d is %s in this kernel, the program reads a %d-byte integer", fn,
					i+1, pointee(proto.Params[i].Type), size)
			}
			continue
		}
		got := pointee(proto.Params[i].Type)
		if got != w {
			return n, fmt.Errorf("%s's argument %d is %s in this kernel, the program reads struct %s *", fn, i+1, got, w)
		}
	}
	return n, nil
}

// pointee names what a parameter type points to: "file" for struct file *, through const and typedefs, or a
// description of what it is instead.
func pointee(t btf.Type) string {
	p, ok := btf.UnderlyingType(t).(*btf.Pointer)
	if !ok {
		return fmt.Sprintf("a %T", btf.UnderlyingType(t))
	}
	if s, ok := btf.UnderlyingType(p.Target).(*btf.Struct); ok {
		return s.Name
	}
	if u, ok := btf.UnderlyingType(p.Target).(*btf.Union); ok {
		return u.Name
	}
	if f, ok := btf.UnderlyingType(p.Target).(*btf.Fwd); ok {
		return f.Name
	}
	return fmt.Sprintf("a pointer to %T", btf.UnderlyingType(p.Target))
}

// inBTF reports whether the kernel's BTF declares a function of that name.
func inBTF(spec *btf.Spec, name string) bool {
	var f *btf.Func
	return spec.TypeByName(name, &f) == nil
}

// memfdNoexecPath is the vm.memfd_noexec sysctl.
const memfdNoexecPath = "/proc/sys/vm/memfd_noexec"

// readPlaneEnv reads the probe's preconditions from the kernel's BTF, the lockdown file and the kernel config.
func readPlaneEnv(spec *btf.Spec, release string) PlaneEnv {
	env := PlaneEnv{BPFLoop: inBTF(spec, "bpf_loop"), RdonlyCast: inBTF(spec, "bpf_rdonly_cast")}
	if b, err := os.ReadFile(lockdownPath); err == nil {
		env.Lockdown = parseLockdown(string(b))
	}
	env.LTO, env.LTOSource = readLTO(release)
	if b, err := os.ReadFile(memfdNoexecPath); err == nil {
		env.MemfdNoexec, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	return env
}

// parseLockdown returns the bracketed mode of /sys/kernel/security/lockdown ("none [integrity] confidentiality").
func parseLockdown(s string) string {
	if i := strings.IndexByte(s, '['); i >= 0 {
		if j := strings.IndexByte(s[i:], ']'); j > 0 {
			return s[i+1 : i+j]
		}
	}
	return strings.TrimSpace(s)
}

// kernelConfigPaths are where a kernel's build config is read from, the running kernel's own first.
func kernelConfigPaths(release string) []string {
	return []string{"/proc/config.gz", "/boot/config-" + release, "/lib/modules/" + release + "/config"}
}

// readLTO decides whether this kernel was built with Clang LTO, where a security_ function can be inlined at a
// call site and fmod_ret mode would miss that site (ADR 0024 (2)). The kernel's config answers; with none readable,
// kallsyms' ".llvm." suffixes, which only Clang's LTO leaves on local symbols, answer instead (T0 read both).
func readLTO(release string) (string, string) {
	for _, p := range kernelConfigPaths(release) {
		if v, ok := configLTO(p); ok {
			return v, p
		}
	}
	if v, ok := kallsymsLTO("/proc/kallsyms"); ok {
		return v, "/proc/kallsyms"
	}
	return ltoUnknown, ""
}

// configLTO reads one kernel config file, gzip or plain.
func configLTO(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", false
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	return scanConfigLTO(r)
}

// scanConfigLTO answers from a config's text: CONFIG_LTO_CLANG=y is Clang LTO, any other config read to the end is
// not. A file with no CONFIG_ line at all (empty, a stub, a placeholder) is no answer, as an empty kallsyms is: the
// caller then tries the next config and kallsyms rather than reading "no Clang LTO" off a file that says nothing.
func scanConfigLTO(r io.Reader) (string, bool) {
	sc := bufio.NewScanner(r)
	configs := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "CONFIG_LTO_CLANG=y" {
			return ltoClang, true
		}
		if strings.HasPrefix(line, "CONFIG_") || strings.HasPrefix(line, "# CONFIG_") {
			configs++
		}
	}
	if sc.Err() != nil || configs == 0 {
		return "", false
	}
	return ltoNone, true
}

// kallsymsLTO answers from the kernel's symbol list, readable with real addresses or not.
func kallsymsLTO(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		if strings.Contains(sc.Text(), ".llvm.") {
			return ltoClang, true
		}
	}
	if sc.Err() != nil || n == 0 {
		return "", false
	}
	return ltoNone, true
}

// choosePlaneBuild picks the object build from the environment (ADR 0024 (9)): the rd build where BTF has
// bpf_rdonly_cast, else the probe-read build unless lockdown=confidentiality refuses its probe reads; none without
// bpf_loop, or without the binary's objects.
func choosePlaneBuild(env PlaneEnv, have func(bpfobj.Object) bool) (bpfobj.Object, string, string) {
	switch {
	case !env.BPFLoop:
		return "", "this kernel's BTF has no bpf_loop (5.17+ or a backport), which the plane's walk needs",
			"boot a kernel >= 5.17, or one that backports bpf_loop"
	case env.RdonlyCast:
		if !have(bpfobj.ObjectPlaneRdonly) {
			return "", "this binary carries no plane objects (built without -tags tegobpf)", ""
		}
		return bpfobj.ObjectPlaneRdonly, "bpf_rdonly_cast is in BTF", ""
	case env.Lockdown == "confidentiality":
		return "", "lockdown=confidentiality refuses the probe-read build and this kernel's BTF has no " +
				"bpf_rdonly_cast for the rd build",
			"boot without lockdown=confidentiality, or a kernel whose BTF has bpf_rdonly_cast (6.2+ or a backport)"
	default:
		if !have(bpfobj.ObjectPlaneProbe) {
			return "", "this binary carries no plane objects (built without -tags tegobpf)", ""
		}
		return bpfobj.ObjectPlaneProbe, "no bpf_rdonly_cast in BTF: CO-RE probe reads", ""
	}
}

// modePrecondition is what rules mode m out before any load: LSM mode needs bpf in the active LSM list (a BPF LSM
// program attaches and never runs otherwise), fmod_ret mode a kernel without Clang LTO. It returns "" when nothing
// does, else the detail and the fix.
func modePrecondition(m bpfobj.PlaneMode, env PlaneEnv, lsm LSMState) (string, string) {
	if env.MemfdNoexec == 2 {
		return "vm.memfd_noexec=2 forbids the executable memfd the probe's child execs, so this mode cannot be " +
			"exercised", "set vm.memfd_noexec to 0 or 1 (sysctl -w vm.memfd_noexec=0)"
	}
	switch m {
	case bpfobj.PlaneLSM:
		if why, fix := lsm.bpfInactive(); why != "" {
			return why, fix
		}
	case bpfobj.PlaneFmodRet:
		if env.LTO == ltoClang {
			return fmt.Sprintf("this kernel is built with Clang LTO (%s), which can inline a security_ function at "+
				"a call site the program then never sees", env.LTOSource), "boot a kernel built without CONFIG_LTO_CLANG"
		}
	}
	return "", ""
}

// planeModeVerdict is one mode's result over its hook rows, the probe row's scope evidence and the known answers,
// pure so the wording is held to what the rows and counters say.
func planeModeVerdict(m bpfobj.PlaneMode, rows []HookResult, sc planeScope, known []PlaneKnownAnswer) PlaneModeResult {
	var failed []string
	decided := 0
	var absent []string
	faulted := false
	for _, r := range rows {
		if r.Absent {
			absent = append(absent, r.Hook)
			continue
		}
		if !r.OK() {
			failed = append(failed, r.Hook)
		}
		if planeOutcomeFaulted(r.Inside) || planeOutcomeFaulted(r.Outside) {
			faulted = true
		}
		if r.Decides {
			decided++
		}
	}
	rows = slices.DeleteFunc(slices.Clone(rows), func(r HookResult) bool { return r.Absent })
	out := PlaneModeResult{Mode: m, Tested: true}
	out.Detail = fmt.Sprintf("%d of %d hooks load, attach and run", len(rows)-len(failed), len(rows))
	switch {
	case decided == len(rows):
		out.Detail += ", each refused in the scratch cgroup and passed outside it"
	case decided == 0:
		out.Detail += ", each passed in and outside the scratch cgroup (no hook decides yet)"
	default:
		out.Detail += fmt.Sprintf(", %d refused in the scratch cgroup, every one passed outside it (the other %d "+
			"decide nothing yet)", decided, len(rows)-decided)
	}
	fix := "report the failed rows' lines (tego doctor --json) as a tego bug, or pin bpf.plane to the " +
		"other mode in /etc/tego/config.yaml"
	if len(absent) > 0 {
		out.Detail += "; not in this kernel, decided by another hook here: " + strings.Join(absent, " ")
	}
	faultFix := "re-run once the host has space, processes and descriptors to spare; nothing is cached, so " +
		"the next run probes again"
	if len(failed) > 0 {
		out.Detail += "; failed: " + strings.Join(failed, " ")
		out.Fix = fix
		if faulted {
			// A probe syscall failed with an errno that may pass on its own: the probe could not finish.
			out.Faulted = true
			out.Fix = faultFix
		}
		return out
	}
	out.Scope = fmt.Sprintf("the probe row was met %d times in the scratch cgroup and %d times outside it",
		sc.Inside, sc.Outside)
	if sc.Inside == 0 || sc.Outside != 0 {
		out.Detail += "; not scoped: " + out.Scope
		out.Fix = fix
		return out
	}
	// The known answers (R21): every cell of the table, each an exact verdict and counter match.
	out.Known = known
	want := planeKnownCells()
	var wrong []string
	matched := 0
	for _, c := range want {
		i := slices.IndexFunc(known, func(a PlaneKnownAnswer) bool { return a.Cell == c.Cell })
		if i < 0 {
			continue
		}
		matched++
		// The answer is held to this table's expectation, not to the one it carries.
		a := known[i]
		a.Want, a.WantCounts = c.Want, c.WantCounts
		if !a.OK() {
			wrong = append(wrong, a.fault())
		}
		// A cell whose action failed with an errno that may pass on its own (fork's EAGAIN or ENOMEM, EMFILE,
		// ENOSPC on the fixtures) could not run; it says nothing of how the mode decides, as a row's would not.
		if planeOutcomeFaulted(a.Got) {
			faulted = true
		}
	}
	switch {
	case matched != len(want):
		// A cell with no answer is a stage that could not run: a fault, never cached.
		out.Detail += fmt.Sprintf("; known answers: %d of %d cells answered", matched, len(want))
		out.Faulted = true
		out.Fix = faultFix
		return out
	case len(wrong) > 0:
		out.Detail += "; " + strings.Join(wrong, "; ")
		if faulted {
			out.Faulted = true
			out.Fix = faultFix
			return out
		}
	default:
		out.Detail += fmt.Sprintf("; %d known answers matched", len(want))
		out.OK = true
		return out
	}
	out.Fix = "this kernel decides a case the plane has a known answer for wrongly; report the line (tego doctor " +
		"--json) as a tego bug, or pin bpf.plane to the other mode in /etc/tego/config.yaml"
	return out
}

// selectPlane is R18 and R19's choice for tier cgroup: under auto the best mode that passed, LSM before fmod_ret,
// else the fanotify fallback; under a pin, that mode when it passed, else the fallback, said so.
func selectPlane(st *PlaneState) {
	pin := st.Pin
	if pin == "" {
		pin = config.PlaneAuto
	}
	var passed []bpfobj.PlaneMode
	for _, m := range bpfobj.PlaneModes {
		if r, ok := st.mode(m); ok && r.OK {
			passed = append(passed, m)
		}
	}
	st.Selected, st.SelectedWhy = PlaneFanotify, ""
	if pin == PlaneFanotify {
		// No config names it: a test build's TEGO_TEST_PLANE does (internal/cli machine_testhook.go), to run tier
		// cgroup on the listener where a plane mode passes (ADR 0017's mode axis).
		st.SelectedWhy = "the plane is pinned to fanotify"
		return
	}
	if pin == config.PlaneAuto {
		if len(passed) > 0 {
			st.Selected = string(passed[0])
		} else {
			st.SelectedWhy = "no plane mode passed the probe"
		}
		return
	}
	for _, m := range passed {
		if string(m) == pin {
			st.Selected = pin
			return
		}
	}
	st.SelectedWhy = fmt.Sprintf("bpf.plane pins %s, which did not pass the probe", pin)
}

// planeHashLen is how much of the build hash doctor prints.
const planeHashLen = 8

// planeBuildName is the build as doctor names it: the short hash, which is what an operator finds under
// /sys/fs/bpf/tego/, not the object's internal name; "none" when no build loads here.
func planeBuildName(st *PlaneState) string {
	switch {
	case st.Build == "":
		return "none loads (" + st.BuildWhy + ")"
	case st.BuildHash == "":
		return "unhashed"
	case len(st.BuildHash) > planeHashLen:
		return st.BuildHash[:planeHashLen]
	}
	return st.BuildHash
}

// planeSummary is the plane's clause of D7's line: the mode tier 2 decides opens by, what that means for tier 3,
// and the build and each mode's answer behind it. bpfActive is whether bpf is an active LSM (D6): where it is, a
// tier 2 on fmod_ret is the pin's doing or LSM mode's failed probe, never a missing lsm= entry.
func planeSummary(st *PlaneState, bpfActive bool) string {
	if st == nil {
		return ""
	}
	if st.Skipped {
		return "; decision plane: requires root to test"
	}
	out := "; decision plane: " + st.Selected
	lsm, _ := st.mode(bpfobj.PlaneLSM)
	switch {
	case st.Selected == string(bpfobj.PlaneLSM):
		out += " (tiers 2 and 3 decide opens in the kernel)"
	case st.Selected == string(bpfobj.PlaneFmodRet) && (lsm.OK || bpfActive && st.Pin == config.PlaneFmodRet):
		out += " (tier 2 decides opens in the kernel; bpf.plane pins fmod_ret)"
	case st.Selected == string(bpfobj.PlaneFmodRet) && !bpfActive:
		out += " (tier 2 decides opens in the kernel; tier 3 needs bpf in lsm=)"
	case st.Selected == string(bpfobj.PlaneFmodRet):
		out += " (tier 2 decides opens in the kernel; tier 3 needs LSM mode to pass, see the lsm mode line)"
	case st.SelectedWhy != "":
		out += " (" + st.SelectedWhy + "; tier 2 decides opens by fanotify)"
	default:
		out += " (tier 2 decides opens by fanotify)"
	}
	out += "; build " + planeBuildName(st)
	for _, r := range st.Modes {
		out += fmt.Sprintf(", %s mode ", r.Mode)
		if r.OK {
			out += "ok"
			if r.ExecPin != nil && !r.ExecPin.OK {
				// ADR 0048 (7): the mode decides, but no run of it claims that the kernel holds its execs.
				out += " (exec pins off: " + r.ExecPin.Detail + ")"
			}
		} else {
			out += "no: " + r.Detail
		}
	}
	if st.Source != planeSourceProbed {
		out += " [from the " + st.Source + "]"
	}
	if st.Selected == PlaneFanotify {
		out += "; the fanotify fallback does not scale past a few concurrent runs: every open on a marked mount waits on a listener"
	}
	return out
}

// PlaneExecPinCell is a mode's exec pin cell (ADR 0048 (7), plane.exec_pin): OK only when each of its known answers
// held, Detail the first that did not, or why the cell could not run.
type PlaneExecPinCell struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// execPinsPass reports whether a mode's exec pin cell ran and passed.
func (r PlaneModeResult) execPinsPass() bool { return r.ExecPin != nil && r.ExecPin.OK }

// PlaneChoice is the mode and build a tier's backend loads the plane in, or the fanotify fallback (Mode "").
type PlaneChoice struct {
	Mode  bpfobj.PlaneMode
	Build bpfobj.Object
	// ExecPins is the mode's exec pin cell passed (PlaneModeResult.ExecPin): a run pinned in this mode may claim
	// that the kernel holds its execs to the decided facts (ADR 0048 (7)).
	ExecPins bool
}

// PlaneUnavailableError is PlaneFor's refusal: a tier that needs a plane mode this machine does not pass. A
// pinned --tier bpflsm is refused with it at Prepare, carrying doctor's fix, never run at tier cgroup instead
// (R19).
type PlaneUnavailableError struct {
	Tier backend.Tier
	Why  string
	Fix  string
}

// Error renders the refusal with its fix.
func (e *PlaneUnavailableError) Error() string {
	s := fmt.Sprintf("tier %s needs the decision plane in LSM mode: %s", e.Tier, e.Why)
	if e.Fix != "" {
		s += "; fix: " + e.Fix
	}
	return s
}

// ErrPlaneUnavailable is what every PlaneUnavailableError matches with errors.Is.
var ErrPlaneUnavailable = errors.New("doctor: plane mode unavailable")

// Unwrap makes errors.Is(err, ErrPlaneUnavailable) hold.
func (e *PlaneUnavailableError) Unwrap() error { return ErrPlaneUnavailable }

// PlaneFor is the seam a tier's backend reads its plane mode from (TIER3-PLAN T6, T7; R19): tier bpflsm gets LSM
// mode or a PlaneUnavailableError with the fix that makes LSM mode pass here (the GRUB line when bpf is not an
// active LSM), never another mode; tier cgroup gets the selected mode, or Mode "" for the fanotify fallback. Any
// other tier has no plane.
func (r *Report) PlaneFor(t backend.Tier) (PlaneChoice, error) {
	st := r.Plane
	switch t {
	case backend.TierBPFLSM:
		if st == nil || st.Skipped {
			return PlaneChoice{}, &PlaneUnavailableError{Tier: t, Why: "the plane's mode probe did not run",
				Fix: "re-run as root: " + sudoDoctor()}
		}
		if st.Pin == config.PlaneFmodRet {
			return PlaneChoice{}, &PlaneUnavailableError{Tier: t,
				Why: "bpf.plane pins fmod_ret, and tier bpflsm is the plane in LSM mode",
				Fix: "set bpf.plane: auto or lsm in /etc/tego/config.yaml"}
		}
		res, ok := st.mode(bpfobj.PlaneLSM)
		if !ok || !res.OK {
			why, fix := res.Detail, res.Fix
			if w, f := r.LSM.bpfInactive(); w != "" {
				why, fix = w, f
			}
			if why == "" {
				why = "LSM mode was not probed"
			}
			return PlaneChoice{}, &PlaneUnavailableError{Tier: t, Why: why, Fix: fix}
		}
		return PlaneChoice{Mode: bpfobj.PlaneLSM, Build: st.Build, ExecPins: res.execPinsPass()}, nil
	case backend.TierCgroup:
		if st == nil || st.Skipped || st.Selected == PlaneFanotify || st.Selected == "" {
			return PlaneChoice{}, nil
		}
		res, _ := st.mode(bpfobj.PlaneMode(st.Selected))
		return PlaneChoice{Mode: bpfobj.PlaneMode(st.Selected), Build: st.Build, ExecPins: res.execPinsPass()}, nil
	case backend.TierLandlock, backend.TierObserve, backend.TierAuto:
	}
	return PlaneChoice{}, nil
}

// planeMissing is what stands between this machine and LSM mode, for tier bpflsm's missing list (R19). A machine
// without bpf active says so on the lsm line already, so LSM mode's own detail is not repeated then.
func (st probeState) planeMissing() []string {
	if !st.root || !st.lsm.BPFActive {
		return nil
	}
	p := st.plane
	switch {
	case p == nil || p.Skipped:
		return []string{"plane: the decision plane's mode probe did not run"}
	case p.Pin == config.PlaneFmodRet:
		return []string{"plane: bpf.plane pins fmod_ret, and tier bpflsm is the plane in LSM mode"}
	}
	res, ok := p.mode(bpfobj.PlaneLSM)
	switch {
	case !ok:
		return []string{"plane: LSM mode was not probed"}
	case !res.OK:
		return []string{"plane: LSM mode: " + res.Detail}
	}
	return nil
}

// planeFix is LSM mode's own fix line, "" when it has none or passes.
func (st probeState) planeFix() string {
	if st.plane == nil {
		return ""
	}
	if st.plane.Pin == config.PlaneFmodRet {
		return "set bpf.plane: auto or lsm in /etc/tego/config.yaml"
	}
	if res, ok := st.plane.mode(bpfobj.PlaneLSM); ok && !res.OK {
		return res.Fix
	}
	return ""
}
