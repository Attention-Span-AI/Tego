// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
)

// The machine a run happens on, and the predicate of a baseline entry that says which machines the entry holds
// on (ADR 0017, amended 2026-10-05). A disagreement between a cell and the build can follow from the kernel: the
// truncate floor below Landlock ABI 3, a hook an older kernel lacks, the fanotify listener where a plane cannot
// load. A single baseline holds one entry per such machine, and a run reads only the entries written for it.

// RowEnv carries the name of the kernel matrix row a run is on (the names test/vm/fetch-kernel.py gives its rows).
// It is unset on a dev box, where a where.row predicate then matches nothing.
const RowEnv = "TEGO_VM_ROW"

// Machine is what a Where is judged against.
type Machine struct {
	// Kernel is the major and minor of uname -r.
	Kernel [2]int
	// ABI is the Landlock ABI the kernel reports; 0 where it reports none, and then no abi bound matches.
	ABI int
	// Arch is runtime.GOARCH.
	Arch string
	// BPFLSM says bpf is among the kernel's active LSMs: the lsm=...,bpf boot of TIER3-PLAN §9.
	BPFLSM bool
	// Row is the matrix row's name ($TEGO_VM_ROW), "" outside the matrix.
	Row string
	// BPFPerfLink says the kernel makes BPF perf links (5.15, or a backport: RHEL 9.8's 5.14), the only way the
	// decision plane's exec outcome tracepoints attach and pin, so where it is true a plane run's terminal exec line is
	// the kernel's (bpfPerfLink, a probe, never the version). A baseline entry may name it (bpf_perf_link).
	BPFPerfLink bool
	// MemfdNoexecSeal says the kernel honours memfd_create's MFD_NOEXEC_SEAL (6.3, or a backport): a cell's
	// want_where may name it (CondWant); no baseline entry does.
	MemfdNoexecSeal bool
	// PlaneFirst says the axis' decision plane answers before Landlock's own hooks: a fmod_ret program runs before
	// the whole security_ function, an lsm program in the chain's order (/sys/kernel/security/lsm), which the
	// lsm=...,bpf boot ends with bpf. It is the kernel runner's, set per axis (false where no plane decides): a cell's
	// want_where may name it (plane_first), no baseline entry does.
	PlaneFirst bool
	// SupervisorRoot says the run's supervisor is root: the runner is (a root `tego run` drops only the agent to
	// the sudo caller), so it reads an image the agent may only execute (ADR 0048 (3)). A cell's want_where may name
	// it (supervisor_root), no baseline entry does.
	SupervisorRoot bool
	// UnixDiag says the kernel answers sock_diag for AF_UNIX (supervisor.UnixDiagAvailable, the probe the supervisor
	// itself asks): without it R11a cannot read which socket holds an abstract name or is bound to a file the run's own
	// bind is recorded at, and refuses those unix-origin-unread. A cell's want_where may name it (unix_diag).
	UnixDiag bool
	// ExecmodRefused says the machine itself refuses this process execmod, a dirtied private map of a file made
	// executable, with no run around it (execmodRefused, a probe): an LSM's policy, SELinux enforcing on AlmaLinux 9.8
	// (selinuxuser_execmod off). A cell's want_where may name it (execmod_refused).
	ExecmodRefused bool
	// FanotifyInChain says another party's fanotify permission refusal is part of security_file_open's return, which
	// tier cgroup's recorder reads at fexit (ADR 0016 (3)): upstream up to 6.12, not from 6.13, and not on Debian 13's
	// 6.12.107. It is the kernel runner's, measured as root by fanotifyInChain (a probe, never the version), false
	// elsewhere. A cell's want_where may name it (fanotify_in_chain), no baseline entry does.
	FanotifyInChain bool
}

func (m Machine) String() string {
	return fmt.Sprintf("kernel %d.%d, Landlock ABI %d, %s, bpf LSM %t, bpf perf link %t, row %q", m.Kernel[0], m.Kernel[1],
		m.ABI, m.Arch, m.BPFLSM, m.BPFPerfLink, m.Row)
}

// CurrentMachine describes the machine this process runs on. A kernel release that does not start with
// major.minor is an error: a machine that cannot be placed would read every entry bounded on the kernel as
// matching or not by accident.
func CurrentMachine() (Machine, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return Machine{}, fmt.Errorf("uname: %w", err)
	}
	major, minor, err := parseKernel(unix.ByteSliceToString(u.Release[:]))
	if err != nil {
		return Machine{}, err
	}
	// ENOSYS or EOPNOTSUPP: no Landlock here, so no abi bound matches (Machine.ABI).
	abi, err := sys.LandlockABI()
	if err != nil {
		abi = 0
	}
	return Machine{Kernel: [2]int{major, minor}, ABI: abi, Arch: runtime.GOARCH, BPFLSM: bpfActiveLSM(), Row: os.Getenv(RowEnv),
		BPFPerfLink: bpfPerfLink(), MemfdNoexecSeal: memfdNoexecSeal(), SupervisorRoot: os.Geteuid() == 0, UnixDiag: supervisor.UnixDiagAvailable(),
		ExecmodRefused: execmodRefused()}, nil
}

// execmodRefused maps a page of a temporary file private and writable, writes to it, and makes the map executable,
// as the actor's execmod op does with the fixture's file, from this process and outside any run: EACCES is the
// machine's own refusal. The file is made in the temporary directory the fixtures are, so a label policy sees the
// same kind of file. Anything else that fails says nothing, and the answer is false.
func execmodRefused() bool {
	f, err := os.CreateTemp("", "tego-execmod-probe")
	if err != nil {
		return false
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer func() { _ = f.Close() }()
	page := os.Getpagesize()
	if _, err := f.Write(make([]byte, page)); err != nil {
		return false
	}
	b, err := unix.Mmap(int(f.Fd()), 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Munmap(b) }()
	b[0] = 1 // a copy-on-write page: the mapping gains an anon_vma, which is what execmod is
	return errors.Is(unix.Mprotect(b, unix.PROT_READ|unix.PROT_EXEC), unix.EACCES)
}

// memfdNoexecSeal creates one memfd with MFD_NOEXEC_SEAL, as tier 1's MemfdNoexecSealSupported probe does: a kernel
// without the flag answers EINVAL.
func memfdNoexecSeal() bool {
	fd, err := unix.MemfdCreate("tego-conformance-probe", unix.MFD_CLOEXEC|unix.MFD_NOEXEC_SEAL)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

// Where names the machines a baseline entry was written for: it is the entry's optional "where" object. Every field
// that is set must match the machine; a field left out matches every machine, so an entry with no Where holds on
// all of them, as every v1 entry did. The bounds are inclusive. The kernel bounds are uname -r's major.minor
// compared as numbers, so kernel_min "6.1" with kernel_max "6.1" is every 6.1.x and "6.17" is above "6.9". An
// unknown Landlock ABI (Machine.ABI 0) satisfies no abi bound.
type Where struct {
	KernelMin string `json:"kernel_min,omitempty"`
	KernelMax string `json:"kernel_max,omitempty"`
	ABIMin    int    `json:"abi_min,omitempty"`
	ABIMax    int    `json:"abi_max,omitempty"`
	// Arch is a GOARCH value (amd64, arm64), not uname -m's spelling.
	Arch string `json:"arch,omitempty"`
	// BPFLSM is a pointer so that "bpf is not an active LSM" (false) is told from "does not matter" (absent).
	BPFLSM *bool  `json:"bpf_lsm,omitempty"`
	Row    string `json:"row,omitempty"`
	// BPFPerfLink is Machine.BPFPerfLink: a capability RHEL backports, so no kernel bound can say it.
	BPFPerfLink *bool `json:"bpf_perf_link,omitempty"`
}

var (
	kernelRelease = regexp.MustCompile(`^(\d+)\.(\d+)`)
	kernelBound   = regexp.MustCompile(`^(\d+)\.(\d+)$`)
	matrixRow     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	// knownArch are the architectures this repository builds for.
	knownArch = []string{"amd64", "arm64"}
)

// parseKernel reads the major and minor of a kernel release string: "6.17.0-41-generic",
// "5.14.0-503.el9.x86_64", "6.1.115-126.197.amzn2023.x86_64".
func parseKernel(release string) (major, minor int, err error) {
	m := kernelRelease.FindStringSubmatch(release)
	if m == nil {
		return 0, 0, fmt.Errorf("kernel release %q does not start with major.minor", release)
	}
	if major, err = strconv.Atoi(m[1]); err != nil {
		return 0, 0, fmt.Errorf("kernel release %q: %w", release, err)
	}
	if minor, err = strconv.Atoi(m[2]); err != nil {
		return 0, 0, fmt.Errorf("kernel release %q: %w", release, err)
	}
	return major, minor, nil
}

// parseBound reads a kernel bound of a Where: exactly major.minor, no patch level and no suffix, so a bound
// has one spelling.
func parseBound(s string) ([2]int, error) {
	if !kernelBound.MatchString(s) {
		return [2]int{}, fmt.Errorf("%q is not a major.minor kernel such as 6.1", s)
	}
	major, minor, err := parseKernel(s)
	return [2]int{major, minor}, err
}

func cmpKernel(a, b [2]int) int {
	if a[0] != b[0] {
		return a[0] - b[0]
	}
	return a[1] - b[1]
}

// Validate says whether the Where can be read: both kernel bounds are major.minor and in order, the abi bounds
// are ABI numbers in order, the architecture is one the repository builds for, and the row is a matrix row's
// shape. An entry that cannot be read must not be taken to hold everywhere, so the baseline's loader refuses it.
func (w Where) Validate() error {
	var lo, hi [2]int
	var err error
	if w.KernelMin != "" {
		if lo, err = parseBound(w.KernelMin); err != nil {
			return fmt.Errorf("kernel_min: %w", err)
		}
	}
	if w.KernelMax != "" {
		if hi, err = parseBound(w.KernelMax); err != nil {
			return fmt.Errorf("kernel_max: %w", err)
		}
	}
	if w.KernelMin != "" && w.KernelMax != "" && cmpKernel(lo, hi) > 0 {
		return fmt.Errorf("kernel_min %s is above kernel_max %s", w.KernelMin, w.KernelMax)
	}
	if w.ABIMin < 0 || w.ABIMax < 0 {
		return fmt.Errorf("abi_min %d, abi_max %d: Landlock ABI numbers start at 1; leave a bound out to leave it open", w.ABIMin, w.ABIMax)
	}
	if w.ABIMax != 0 && w.ABIMin > w.ABIMax {
		return fmt.Errorf("abi_min %d is above abi_max %d", w.ABIMin, w.ABIMax)
	}
	if w.Arch != "" && !slices.Contains(knownArch, w.Arch) {
		return fmt.Errorf("arch %q: want a GOARCH value (%s), not uname -m's spelling", w.Arch, strings.Join(knownArch, ", "))
	}
	if w.Row != "" && !matrixRow.MatchString(w.Row) {
		return fmt.Errorf("row %q: want a matrix row's name such as al2023 or ubuntu-24.04", w.Row)
	}
	return nil
}

// Matches reports whether the entry this Where belongs to holds on m. A Where that cannot be read matches
// nothing, so it can never excuse a disagreement by accident.
func (w Where) Matches(m Machine) bool {
	if w.KernelMin != "" {
		if lo, err := parseBound(w.KernelMin); err != nil || cmpKernel(m.Kernel, lo) < 0 {
			return false
		}
	}
	if w.KernelMax != "" {
		if hi, err := parseBound(w.KernelMax); err != nil || cmpKernel(m.Kernel, hi) > 0 {
			return false
		}
	}
	if w.ABIMin != 0 || w.ABIMax != 0 {
		if m.ABI == 0 || m.ABI < w.ABIMin || (w.ABIMax != 0 && m.ABI > w.ABIMax) {
			return false
		}
	}
	if w.Arch != "" && w.Arch != m.Arch {
		return false
	}
	if w.BPFLSM != nil && *w.BPFLSM != m.BPFLSM {
		return false
	}
	if w.BPFPerfLink != nil && *w.BPFPerfLink != m.BPFPerfLink {
		return false
	}
	return w.Row == "" || w.Row == m.Row
}

// Where is the predicate that pins an entry to exactly this machine: its kernel, Landlock ABI (when it has one),
// architecture, bpf LSM state and, inside the matrix, its row. It is what -conformance.update gives the entries it
// adds. It is deliberately as narrow as the machine allows: the run saw the disagreement here and nowhere else,
// and the reviewer widens the bounds to the machines it is known to hold on.
func (m Machine) Where() Where {
	kernel := fmt.Sprintf("%d.%d", m.Kernel[0], m.Kernel[1])
	w := Where{KernelMin: kernel, KernelMax: kernel, Arch: m.Arch, BPFLSM: &m.BPFLSM, Row: m.Row}
	if m.ABI != 0 {
		w.ABIMin, w.ABIMax = m.ABI, m.ABI
	}
	return w
}

// String spells the fields that are set, as they are named in the file.
func (w Where) String() string {
	var f []string
	add := func(name string, v any) { f = append(f, fmt.Sprintf("%s=%v", name, v)) }
	if w.KernelMin != "" {
		add("kernel_min", w.KernelMin)
	}
	if w.KernelMax != "" {
		add("kernel_max", w.KernelMax)
	}
	if w.ABIMin != 0 {
		add("abi_min", w.ABIMin)
	}
	if w.ABIMax != 0 {
		add("abi_max", w.ABIMax)
	}
	if w.Arch != "" {
		add("arch", w.Arch)
	}
	if w.BPFLSM != nil {
		add("bpf_lsm", *w.BPFLSM)
	}
	if w.Row != "" {
		add("row", w.Row)
	}
	if w.BPFPerfLink != nil {
		add("bpf_perf_link", *w.BPFPerfLink)
	}
	return strings.Join(f, " ")
}

// canonical is the Where's one spelling as JSON, the second sort key of the canonical file and the identity of an
// entry beside its Key: the same cell may be baselined on several machines.
func (w Where) canonical() string {
	b, _ := json.Marshal(w) // strings, ints and a bool: encoding cannot fail
	return string(b)
}

// bpfActiveLSM reports whether bpf is in the kernel's active LSM list.
func bpfActiveLSM() bool {
	return slices.Contains(activeLSMs(), "bpf")
}

// bpfBeforeLandlock says an lsm-mode plane answers before Landlock: bpf is active and ahead of landlock in the
// chain's order, or landlock is not active at all (Machine.PlaneFirst).
func bpfBeforeLandlock() bool {
	order := activeLSMs()
	landlock, bpf := slices.Index(order, "landlock"), slices.Index(order, "bpf")
	return bpf >= 0 && (landlock < 0 || bpf < landlock)
}

// activeLSMs are the kernel's active LSMs in the chain's order, /sys/kernel/security/lsm; none where it is unreadable.
func activeLSMs() []string {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), ",")
}
