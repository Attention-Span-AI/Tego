// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// CheckID names one probe; the values are the fixed D1..D9 order of R27.
type CheckID string

// The nine probe ids of R27, in the order Probe and Run produce them. D9 gates no tier.
const (
	CheckKernel   CheckID = "kernel"
	CheckBTF      CheckID = "btf"
	CheckCgroupV2 CheckID = "cgroupv2"
	CheckLandlock CheckID = "landlock"
	CheckSeccomp  CheckID = "seccomp"
	CheckLSM      CheckID = "lsm"
	CheckPrograms CheckID = "programs"
	CheckFanotify CheckID = "fanotify"
	CheckSwap     CheckID = "swap"
)

// Result is one probe's answer. Fix is "" when OK.
type Result struct {
	ID     CheckID `json:"id"`
	OK     bool    `json:"ok"`
	Detail string  `json:"detail"`
	Fix    string  `json:"fix,omitempty"`
	// Skipped marks a probe that could not run rather than one that ran and failed: on this box, as
	// uid 1000, the program-load and fanotify probes need capabilities the process does not have, so
	// what they report is "unknown", not "your machine is broken" (§6 E18). OK stays false, because a
	// skipped probe has still not established the capability a tier needs, and every consumer that
	// keys on OK keeps behaving as it did; only what a person reads changes.
	Skipped bool `json:"skipped,omitempty"`
}

// btfPath is the kernel's own BTF (D2). A variable so the test can point D2 at a symlink; nothing in a
// product build reassigns it.
var btfPath = defaultBTFPath

const defaultBTFPath = "/sys/kernel/btf/vmlinux"

// loadKernelSpec is the parse of the kernel's own BTF that cilium/ebpf keeps for the process, so D2 and the
// program loads a run makes after it (their CO-RE relocation) parse the file once, not once each. A variable
// so a test can count the calls.
var loadKernelSpec = bpfobj.KernelBTF

// loadBTF parses the BTF at path: through the process's kept parse when it is the kernel's own file.
func loadBTF(path string) (*btf.Spec, error) {
	if path == defaultBTFPath {
		return loadKernelSpec()
	}
	return btf.LoadSpec(path)
}

// cgroupKillFile is cgroup v2's atomic kill (Linux 5.14, docs/p0/limits-check-doctor-cli.md R27 D1).
// It is write-only (mode 0200) and exists only below the cgroup root, so W_OK on a freshly created
// cgroup is the whole test; R_OK would fail on a kernel that has it.
const cgroupKillFile = "cgroup.kill"

// probeKernelVersion is D1 with the parsed release the later probes need.
func probeKernelVersion() (Result, string, Version) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Result{ID: CheckKernel, Detail: fmt.Sprintf("uname(2): %v", err), Fix: "run on Linux"}, "", Version{}
	}
	release := unix.ByteSliceToString(u.Release[:])
	v, err := ParseKernelRelease(release)
	if err != nil {
		return Result{ID: CheckKernel, Detail: fmt.Sprintf("release %q: %v", release, err),
			Fix: "run a kernel whose release starts with major.minor.patch"}, release, Version{}
	}
	if !v.AtLeast(MinKernel) {
		return Result{ID: CheckKernel, Detail: fmt.Sprintf("%s is below %s (cgroup.kill, SECCOMP_ADDFD_FLAG_SEND)", release, MinKernel),
			Fix: fmt.Sprintf("boot a kernel >= %s", MinKernel)}, release, v
	}
	detail := fmt.Sprintf("%s (>= %s)", release, MinKernel)
	if !v.AtLeast(TestedFloor) {
		detail += fmt.Sprintf("; below the tested floor %s", TestedFloor)
	}
	if missing := MissingMechanisms(v); len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for _, m := range missing {
			names = append(names, fmt.Sprintf("%s (%s, %s)", m.Name, m.Since, m.What))
		}
		detail += "; without: " + strings.Join(names, ", ")
	}
	return Result{ID: CheckKernel, OK: true, Detail: detail}, release, v
}

// probeBTF is D2: the kernel exposes its BTF, the precondition of every tier-2/3 program load, and that BTF
// carries every type, member and enum value the embedded objects read through CO-RE
// (enforce-cgroup-observe.md E31).
func probeBTF() Result { return probeBTFWith(objectCORENeeds) }

// probeBTFWith is probeBTF with the objects' needs supplied, so a test can check a fake BTF against
// needs of its own.
func probeBTFWith(needs func() ([]coreNeed, error)) Result {
	const btfFix = "boot a kernel built with CONFIG_DEBUG_INFO_BTF=y"
	f, err := os.Open(btfPath) // open(2) follows a symlink, matching what the kernel exposes (E24)
	if err != nil {
		return Result{ID: CheckBTF, Detail: fmt.Sprintf("%s: %v (no tier-2/3 program loads)", btfPath, err),
			Fix: btfFix}
	}
	st, serr := f.Stat()
	_ = f.Close()
	if serr != nil {
		return Result{ID: CheckBTF, Detail: fmt.Sprintf("%s: %v", btfPath, serr), Fix: btfFix}
	}
	detail := fmt.Sprintf("%s (%d bytes)", btfPath, st.Size())
	spec, err := loadBTF(btfPath)
	if err != nil {
		return Result{ID: CheckBTF, Detail: fmt.Sprintf("%s: parse: %v (no tier-2/3 program loads)", detail, err),
			Fix: btfFix}
	}
	list, err := needs()
	if err != nil {
		// The objects are this binary's own; one it cannot read is a broken build, not a machine to fix.
		return Result{ID: CheckBTF, Detail: fmt.Sprintf("%s: reading the objects' CO-RE relocations: %v", detail, err),
			Fix: "reinstall tego: its embedded BPF objects are unreadable"}
	}
	if len(list) == 0 {
		return Result{ID: CheckBTF, OK: true, Detail: detail + "; this build carries no BPF objects to check against it"}
	}
	if missing := missingCORE(spec, list); len(missing) > 0 {
		return Result{ID: CheckBTF,
			Detail: fmt.Sprintf("%s lacks what the BPF programs read (no tier-2/3 program loads): %s", detail,
				strings.Join(missing, "; ")),
			Fix: fmt.Sprintf("boot a kernel >= %s whose BTF carries these fields, or run at tier landlock", TestedFloor)}
	}
	return Result{ID: CheckBTF, OK: true, Detail: fmt.Sprintf("%s; all %d kernel types and fields the BPF programs read "+
		"are present", detail, len(list))}
}

// delegateFix is D3's answer when nothing more specific is known: the systemd user delegation
// every unprivileged launcher needs.
const delegateFix = "enable systemd user delegation: Delegate=cpu memory pids in /etc/systemd/system/user@.service.d/delegate.conf, then systemctl daemon-reload and re-login"

// probeCgroup is D3. It fails when any one of these does not hold, and each can be the sole reason:
// cgroup.Detect finds a cgroup2fs root this uid may use (for every uid that includes case 39's refusal
// of a mount that does not hold this process's own cgroup); this process can place a process in that
// root (FS.CanPlace, runtime-launch.md case 41: a login over ssh or a service runs outside its
// user@<uid>.service and cannot, although everything below can be shown there); that root's cgroup.procs
// and cgroup.subtree_control are writable; a scratch cgroup can be made one level below and removed
// again; that scratch cgroup has a writable cgroup.kill, asked between the mkdir and the rmdir since
// only a non-root cgroup has the file; and cpu, memory and pids are all enabled in the root's
// cgroup.subtree_control.
func probeCgroup(uid int) Result {
	return probeCgroupWith(uid, cgroup.Detect)
}

// probeCgroupWith is probeCgroup with the detection step supplied, so a Detect refusal this machine
// cannot produce (case 39 needs a cgroup namespace the test process is not in) can still be driven
// through the code that turns it into D3's Result.
func probeCgroupWith(uid int, detect func(uid int) (*cgroup.FS, error)) Result {
	fs, err := detect(uid)
	if err == nil {
		err = fs.CanPlace()
	}
	if err != nil {
		detail, fix := detectFailure(err)
		return Result{ID: CheckCgroupV2, Detail: detail, Fix: fix}
	}
	fix := delegateFix
	root := fs.Root()
	for _, name := range []string{"cgroup.procs", "cgroup.subtree_control"} {
		if err := unix.Access(filepath.Join(root, name), unix.W_OK); err != nil {
			return Result{ID: CheckCgroupV2, Detail: fmt.Sprintf("%s/%s not writable: %v", root, name, err), Fix: fix}
		}
	}
	scratch, err := makeScratchDir(root, ".tego-doctor-")
	if err != nil {
		return Result{ID: CheckCgroupV2, Detail: err.Error(), Fix: fix}
	}
	// Ask the cgroup the kernel just made whether it exposes cgroup.kill, rather than inferring it
	// from the release: D1's own table says a distribution that backports into an older release
	// (RHEL 9's "5.14") is reported as missing what it has. cgroup.kill (5.14) is the only way to
	// empty a cgroup atomically — runtime-launch.md §502: "there is no mechanism to force-empty a
	// cgroup other than cgroup.kill + wait" — and without it stop and every limit breach fall back
	// to the freeze/enumerate/SIGKILL loop that runc opencontainers/runc#3135 and crun
	// containers/crun#724 both abandoned for racing forks. It is the one exact, cheap check, and
	// only a non-root cgroup has the file, so the scratch cgroup is the only place to ask.
	// The answer is taken before the rmdir and reported after it, so the probe still leaves nothing
	// behind (§4 "it leaves nothing behind") on the failing path.
	killErr := unix.Access(filepath.Join(scratch, cgroupKillFile), unix.W_OK)
	if err := unix.Rmdir(scratch); err != nil {
		return Result{ID: CheckCgroupV2, Detail: fmt.Sprintf("rmdir(%s): %v", scratch, err), Fix: fix}
	}
	if killErr != nil {
		return Result{ID: CheckCgroupV2,
			Detail: fmt.Sprintf("%s delegated, but a fresh cgroup has no writable %s: %v (a run could not be "+
				"stopped atomically)", root, cgroupKillFile, killErr),
			Fix: fmt.Sprintf("boot a kernel >= %s (cgroup.kill)", Version{5, 14, 0})}
	}
	return controllersResult(root, fix)
}

// controllersResult is D3's last step: cpu, memory and pids enabled in root's cgroup.subtree_control.
// A read that fails is reported with its errno: an empty list from it would be misdiagnosed as the
// controllers being missing, with a Delegate= fix that changes nothing.
func controllersResult(root, fix string) Result {
	enabled, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
	if err != nil {
		return Result{ID: CheckCgroupV2, Detail: fmt.Sprintf("read %s/cgroup.subtree_control: %v", root, err), Fix: fix}
	}
	controllers := strings.Fields(string(enabled))
	var missing []string
	have := map[string]bool{}
	for _, c := range controllers {
		have[c] = true
	}
	for _, c := range []string{cgroup.ControllerCPU, cgroup.ControllerMemory, cgroup.ControllerPids} {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	detail := fmt.Sprintf("%s delegated, %s writable, controllers: %s", root, cgroupKillFile, strings.Join(controllers, " "))
	if len(missing) > 0 {
		return Result{ID: CheckCgroupV2, Detail: detail + "; missing " + strings.Join(missing, " "),
			Fix: fmt.Sprintf("add %s to Delegate= of user@.service (limits on them fail at run start otherwise)", strings.Join(missing, " "))}
	}
	return Result{ID: CheckCgroupV2, OK: true, Detail: detail}
}

// detectFailure splits a cgroup.Detect or FS.CanPlace refusal into D3's detail and fix. ErrNotDelegated is not one
// failure with one remedy: a uid with no delegation needs the Delegate= drop-in, but case 39 — a
// cgroup namespace looking at the host's /sys/fs/cgroup — needs that namespace's own cgroup2 mount,
// and a Delegate= drop-in would change nothing there. Detect is the code that knows which it found,
// and its refusal of a mount or a candidate is a *cgroup.DetectError carrying that remedy as a field,
// so D3 reports the remedy Detect chose rather than one keyed on the sentinel, and never parses its
// prose. That also keeps the D3 line from carrying two different fixes, Detect's inside the detail
// and a canned one after it. Anything else (an error Detect did not build) falls back to keying on
// ErrNotCgroup2, and then to the delegation fix.
func detectFailure(err error) (detail, fix string) {
	var de *cgroup.DetectError
	if errors.As(err, &de) && de.Remedy != "" {
		return de.Diagnosis, de.Remedy
	}
	if errors.Is(err, cgroup.ErrNotCgroup2) {
		return err.Error(), "boot with systemd.unified_cgroup_hierarchy=1 (cgroup v2)"
	}
	return err.Error(), delegateFix
}

// probeLandlockABI is D4 with the ABI number the tier derivation needs.
func probeLandlockABI() (Result, int) {
	abi, err := sys.LandlockABI()
	if err != nil {
		fix := "boot a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK=y"
		if errors.Is(err, unix.EOPNOTSUPP) {
			fix = "add landlock to the kernel's lsm= line (or CONFIG_LSM) and reboot"
		}
		return Result{ID: CheckLandlock, Detail: fmt.Sprintf("landlock_create_ruleset: %v (tier landlock unavailable)", err), Fix: fix}, 0
	}
	if abi < MinLandlockABI {
		return Result{ID: CheckLandlock,
			Detail: fmt.Sprintf("ABI %d is below the supported minimum %d (rename and link confined to one directory)", abi, MinLandlockABI),
			Fix:    "boot a kernel >= 5.19 (Landlock ABI 2, LANDLOCK_ACCESS_FS_REFER)"}, abi
	}
	return Result{ID: CheckLandlock, OK: true, Detail: fmt.Sprintf("ABI %d", abi)}, abi
}

// writeResults prints one line per result: "ok", "skip" or "FAIL", then "<id>: <detail>" and, when the
// probe did not pass, "; fix: <fix>". A skipped probe is printed as skip rather than FAIL so a person
// scanning the output can tell a machine that cannot do something from a probe that was not allowed to
// find out. A failed probe for which off reports true is printed "off" (Report.optionalOff).
func writeResults(w io.Writer, rs []Result, off func(Result) bool) error {
	for _, r := range rs {
		state := "FAIL"
		switch {
		case r.OK:
			state = "ok  "
		case r.Skipped:
			state = "skip"
		case off != nil && off(r):
			state = "off "
		}
		line := fmt.Sprintf("%s %s: %s", state, r.ID, r.Detail)
		if !r.OK && r.Fix != "" {
			line += "; fix: " + r.Fix
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return fmt.Errorf("doctor: write results: %w", err)
		}
	}
	return nil
}

// executable is os.Executable, a variable so a test can name the binary the fix lines print.
var executable = os.Executable

// sudoDoctor is the command that re-runs this doctor as root, for a fix line. It names this binary by its
// absolute path: sudo resets PATH to its secure_path, which on Ubuntu leaves out $HOME/.local/bin, where the
// install script puts tego, so `sudo tego doctor` answered "command not found" on the default install.
// A path the shell would split or expand is single-quoted; a binary whose path cannot be
// read is named tego, as before.
func sudoDoctor() string {
	path, err := executable()
	if err != nil || path == "" {
		return "sudo tego doctor"
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return "sudo " + shellQuote(path) + " doctor"
}

// shellQuote returns s as one shell word: unchanged when every byte is one no shell treats specially,
// single-quoted otherwise.
func shellQuote(s string) string {
	safe := s != ""
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/._-+@%:,=", c) >= 0) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
