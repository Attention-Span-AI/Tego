// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	// modeExec runs the target's exec checks under a contract whose exec.allow names one real binary,
	// helperExecPayload, which the target also copies into a memfd and tries to run by every spelling.
	modeExec = "exec"
	// modeExecWalk is modeExec's contract with no memfd arm in the filter: the target creates an executable
	// memfd, standing in for an anonymous image that reached the run by a route the arm does not govern,
	// and runs it by every spelling, which only the supervisor's walk can refuse.
	modeExecWalk = "exec-walk"
	// helperExecPayload is the granted binary's path.
	helperExecPayload = "TEGO_SUPERVISOR_EXEC_PAYLOAD"

	// mfdNoexecSeal is MFD_NOEXEC_SEAL (linux/memfd.h): a memfd created with it has its execute bits
	// cleared and sealed, so the kernel refuses to exec it. The tier's filter refuses a memfd_create that
	// omits it (SEMANTICS §4).
	mfdNoexecSeal = 0x0008
	// mfdExec is MFD_EXEC: the opposite, an explicitly executable memfd. The filter refuses it too.
	mfdExec = 0x0010
	// mfdHugetlb is MFD_HUGETLB: hugetlbfs does not enforce the F_SEAL_EXEC that MFD_NOEXEC_SEAL sets, so the
	// sealing arm refuses it with or without the seal flag.
	mfdHugetlb = 0x0004
)

// execRuleTable is modeExec's contract: exec.allow names the payload, and nothing else. Exec is restricted
// and anonymous exec is not opted in, so this is the shape whose Prepare installs the memfd arm.
func execRuleTable(fs []agent.FSRule, env []string) *agent.RuleTable {
	payload := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, helperExecPayload+"="); ok {
			payload = v
		}
	}
	return &agent.RuleTable{
		FS: fs, Record: agent.RecordSummary, Tier: backend.TierLandlock,
		Exec:     []agent.ExecRule{{Raw: payload, Path: payload, Basename: filepath.Base(payload), Source: agent.ExecSourceAllow}},
		Contract: &agent.Contract{Exec: &agent.ExecSection{Allow: []string{payload}}},
	}
}

// execveat is execveat(2), which x/sys does not wrap. It returns only on failure.
func execveat(dirfd int, path string, argv []string, flags int) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	av, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	env := []*byte{nil}
	_, _, e := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&av[0])), uintptr(unsafe.Pointer(&env[0])), uintptr(flags), 0)
	return e
}

// memfdWith copies the payload into a fresh memfd created with flags and returns the descriptor, or an
// error from either step. It is the target's setup for the exec attempts.
func memfdWith(flags int, payload string) (int, error) {
	fd, err := unix.MemfdCreate("/../usr/bin/true", flags)
	if err != nil {
		return -1, err
	}
	image, err := os.ReadFile(payload)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if _, err := unix.Write(fd, image); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// spellingExecs runs the target's execs of the memfd fd by every spelling of its descriptor a hostile
// agent could reach for (SEMANTICS §4). Each becomes one check; were one continued, the target would be replaced
// by the payload and never report, which fails the test on its own.
func spellingExecs(fd int, dir string) []checkResult {
	var out []checkResult
	add := func(name string, err error) { out = append(out, checkResult{Name: name, Err: errText(err)}) }
	n := strconv.Itoa(fd)
	argv := []string{"payload"}
	link := filepath.Join(dir, "run")
	if err := os.Symlink("/proc/self/fd/"+n, link); err != nil {
		add("exec_setup", err)
		return out
	}
	add("exec_memfd_proc_self", unix.Exec("/proc/self/fd/"+n, argv, nil))
	add("exec_memfd_dev_fd", unix.Exec("/dev/fd/"+n, argv, nil))
	add("exec_memfd_symlink", unix.Exec(link, argv, nil))
	add("exec_memfd_thread_self", unix.Exec("/proc/thread-self/fd/"+n, argv, nil))
	add("exec_memfd_task", unix.Exec("/proc/self/task/"+strconv.Itoa(unix.Gettid())+"/fd/"+n, argv, nil))
	add("exec_memfd_tgid", unix.Exec("/proc/"+strconv.Itoa(os.Getpid())+"/fd/"+n, argv, nil))
	if fdDir, err := unix.Open("/proc/self/fd", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		add("exec_memfd_dirfd", execveat(fdDir, n, argv, 0))
	}
	add("exec_memfd_empty_path", execveat(fd, "", argv, unix.AT_EMPTY_PATH))
	if granted, err := unix.Open(os.Getenv(helperExecPayload), unix.O_PATH|unix.O_CLOEXEC, 0); err == nil {
		add("exec_memfd_flag_with_path", execveat(granted, "/proc/self/fd/"+n, argv, unix.AT_EMPTY_PATH))
	}
	return out
}

// execChecks are the target's exec attempts against the tier's real filter (SEMANTICS §4), whose memfd arm is arm.
// Three paths, matching what production installs:
//
//   - sealed (a restricted-exec run, kernel >= 6.3): memfd_create of an executable image (flags=0, MFD_EXEC)
//     and of a hugetlb memfd, sealed or not, must be refused at creation, so no executable anonymous image
//     can exist; a data memfd (MFD_NOEXEC_SEAL) must be allowed, and one written with the payload cannot be
//     exec'd — the supervisor's walk refuses it (kept as the record) and the kernel would too, for want of
//     execute bits.
//   - refused (a restricted-exec run, kernel < 6.3): every memfd_create must be refused (ENOSYS), the seal
//     flag included, since no flag makes a memfd non-executable there.
//   - open (no arm, modeExecWalk): memfd_create succeeds, and every spelling of the descriptor is refused by
//     the supervisor's walk — the backstop for an anonymous image that arrived by another route.
func execChecks(arm landlock.MemfdArm) []checkResult {
	dir := os.Getenv(helperDir)
	payload := os.Getenv(helperExecPayload)
	var out []checkResult
	add := func(name string, err error) { out = append(out, checkResult{Name: name, Err: errText(err)}) }
	create := func(name string, flags int) {
		if fd, err := memfdWith(flags, payload); err == nil {
			_ = unix.Close(fd)
			add(name, nil)
		} else {
			add(name, err)
		}
	}

	switch arm {
	case landlock.MemfdSealed:
		// Every creation that would yield an executable image must be refused at memfd_create.
		create("memfd_create_bare", 0)
		create("memfd_create_exec", mfdExec)
		create("memfd_create_hugetlb_sealed", mfdHugetlb|mfdNoexecSeal|unix.MFD_CLOEXEC)
		// A sealed (non-executable) data memfd is allowed to be created — an ordinary workload's shared
		// memory is unaffected — but the image it holds is not runnable.
		fd, err := memfdWith(mfdNoexecSeal|unix.MFD_CLOEXEC, payload)
		add("memfd_create_sealed", err)
		if err == nil {
			add("exec_sealed_memfd", execveat(fd, "", []string{"payload"}, unix.AT_EMPTY_PATH))
			_ = unix.Close(fd)
		}
		return out
	case landlock.MemfdRefused:
		create("memfd_create_refused_bare", 0)
		create("memfd_create_refused_cloexec", unix.MFD_CLOEXEC)
		create("memfd_create_refused_sealed", mfdNoexecSeal|unix.MFD_CLOEXEC)
		return out
	}

	// No arm: create an executable memfd and run every spelling; each must be refused by the supervisor's
	// walk.
	fd, err := memfdWith(0, payload)
	if err != nil {
		add("exec_setup", err)
		return out
	}
	out = append(out, spellingExecs(fd, dir)...)
	return out
}

// TestIntegrationExecDecisions is the anonymous-image refusal on a real kernel with the filter the exec-restricted tier installs.
//
// The anonymous-image exec vector is closed at *creation*: where the kernel honours MFD_NOEXEC_SEAL the
// sealing arm refuses a memfd_create that would yield an executable image (flags=0, MFD_EXEC, or a hugetlb
// memfd, whose F_SEAL_EXEC hugetlbfs does not enforce), so the spellings the skeptic listed have nothing to
// run; a sealed data memfd is still allowed, so an ordinary workload's shared memory works, and the payload
// written into it is refused when exec'd — by the supervisor's walk (the record we keep) and by the kernel
// (no execute bits). On a kernel too old for the flag (< 6.3) the refusing arm answers every memfd_create
// ENOSYS, matching production. The target has no Landlock domain, so nothing but the filter and the loop
// stands between it and the payload: a creation or a spelling that got through would run it.
func TestIntegrationExecDecisions(t *testing.T) {
	payload := truePayload(t)
	h := startHarnessWith(t, harnessOpts{mode: modeExec, env: []string{helperExecPayload + "=" + payload}})
	byName := map[string]checkResult{}
	for _, c := range h.report.Checks {
		if c.Name == "exec_setup" {
			t.Fatalf("target setup: %s", c.Err)
		}
		byName[c.Name] = c
	}

	if _, refused := byName["memfd_create_refused_bare"]; refused {
		for _, c := range h.report.Checks {
			if !isErrno(c.Err, unix.ENOSYS) {
				t.Errorf("%s: err = %q, want ENOSYS: below 6.3 no memfd may be created in a restricted-exec run (SEMANTICS §4)", c.Name, c.Err)
			}
		}
		if n := countAnon(h); n != 0 {
			t.Errorf("%d memfd exec lines recorded, want none: no memfd existed to run", n)
		}
		return
	}
	if _, sealed := byName["memfd_create_bare"]; !sealed {
		t.Fatalf("the target ran neither closing arm's checks: %+v", h.report.Checks)
	}
	// The executable-image creations were refused at memfd_create; the data memfd was allowed and its image
	// could not run.
	for _, name := range []string{"memfd_create_bare", "memfd_create_exec", "memfd_create_hugetlb_sealed"} {
		if c := byName[name]; !isErrno(c.Err, unix.EACCES) {
			t.Errorf("%s: err = %q, want EACCES: an exec-capable memfd must be refused at creation (SEMANTICS §4)", name, c.Err)
		}
	}
	if c := byName["memfd_create_sealed"]; c.Err != "" {
		t.Errorf("memfd_create_sealed: err = %q, want success: a sealed data memfd is allowed (ordinary workloads unaffected)", c.Err)
	}
	if c, ok := byName["exec_sealed_memfd"]; !ok || c.Err == "" {
		t.Errorf("exec_sealed_memfd: err = %q, want a failure: a sealed memfd holds no executable image", c.Err)
	}
	// The supervisor recorded the sealed memfd's exec attempt as a refused, fileless anonymous image — the
	// walk kept as the record (SEMANTICS §4). The refused creations were refused by the filter with no
	// notification, so they leave no ledger line, like every other errno arm (TIOCSTI, MPTCP).
	assertAnonRefusal(t, h)
}

// TestIntegrationExecWalkBackstop is the supervisor's walk on its own (R16b): with no memfd arm, as for an
// anonymous image that reached the run by a route the arm does not govern (a descriptor received over
// SCM_RIGHTS or inherited at launch), an executable memfd exists, and every spelling of it is refused by
// the loop and recorded refused, fileless, under its raw name. On a kernel at or above 6.3 this path is
// otherwise never reached by TestIntegrationExecDecisions, whose arm leaves nothing to run.
func TestIntegrationExecWalkBackstop(t *testing.T) {
	payload := truePayload(t)
	h := startHarnessWith(t, harnessOpts{mode: modeExecWalk, env: []string{helperExecPayload + "=" + payload}})
	for _, c := range h.report.Checks {
		if c.Name == "exec_setup" {
			t.Fatalf("target setup: %s", c.Err)
		}
		if !isErrno(c.Err, unix.EACCES) {
			t.Errorf("%s: err = %q, want EACCES from the loop", c.Name, c.Err)
		}
	}
	assertAnonRefusal(t, h)
	if countAnon(h) == 0 || len(h.report.Checks) == 0 {
		t.Errorf("no memfd exec lines recorded; want one per spelling")
	}
}

// truePayload is a real true(1) for the target to copy into a memfd, or a skip when the box has none.
func truePayload(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/usr/bin/true", "/bin/true"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no true(1) binary to copy into a memfd")
	return ""
}

// assertAnonRefusal checks that every exec the supervisor recorded is a refused, fileless exec-anon line —
// no anonymous exec was ever recorded allowed, and none carries a cleaned disk path.
func assertAnonRefusal(t *testing.T, h *harness) {
	t.Helper()
	anon := 0
	for _, ev := range h.sink.all() {
		if ev.Kind != record.KindExec {
			continue
		}
		var p execPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Verdict != record.VerdictRefused {
			t.Errorf("exec %q recorded %s: no anonymous exec ran, so none may read allow", p.Path, ev.Verdict)
		}
		if strings.HasPrefix(p.Path, "/memfd:") {
			anon++
			if ev.Rule != ruleExecAnon || !p.Fileless || p.Path != "/memfd:/../usr/bin/true" {
				t.Errorf("memfd exec recorded rule=%s fileless=%v path=%q, want exec-anon, true and the raw name",
					ev.Rule, p.Fileless, p.Path)
			}
		}
	}
	if anon == 0 {
		t.Error("no /memfd: exec line was recorded; the supervisor's walk must keep the anonymous exec as the record")
	}
}

// countAnon counts the recorded /memfd: exec lines.
func countAnon(h *harness) int {
	n := 0
	for _, ev := range h.sink.all() {
		if ev.Kind != record.KindExec {
			continue
		}
		var p execPayload
		if ev.DecodePayload(&p) == nil && strings.HasPrefix(p.Path, "/memfd:") {
			n++
		}
	}
	return n
}
