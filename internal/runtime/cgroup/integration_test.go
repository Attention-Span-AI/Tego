// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// detectOrSkip returns the real manager for this uid or skips when nothing is delegated.
func detectOrSkip(t testing.TB) *FS {
	t.Helper()
	fs, err := Detect(os.Getuid())
	if errors.Is(err, ErrNotDelegated) {
		t.Skipf("no delegated subtree: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// placeOrSkip is detectOrSkip for a test that puts a process in a run cgroup: it skips as well when this
// process runs outside the subtree and cannot place one there (FS.CanPlace, case 41), which is what a
// login over ssh or a service finds. From there the clone3 such a test makes fails with EACCES, and the
// one test that expects a refused clone3, the zero pids cap, would pass for that reason and not its own.
// TestIntegrationCanPlaceIsTheKernelsAnswer covers that shape instead.
func placeOrSkip(t testing.TB) *FS {
	t.Helper()
	fs := detectOrSkip(t)
	if err := fs.CanPlace(); err != nil {
		t.Skipf("no run can be placed from this process: %v", err)
	}
	return fs
}

func newRunID(t testing.TB) string {
	t.Helper()
	id, err := identity.NewRunID(identity.HostID([]byte("cgroup-integration")), time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// TestIntegrationLifecycle: create under user@<uid>.service, spawn a child
// with clone3(CLONE_INTO_CGROUP), limits written, cgroup.kill, populated 0 observed, remove.
//
// Also pins runtime-launch.md I3: the child is placed by clone3(CLONE_INTO_CGROUP), with no cgroup.procs write.
func TestIntegrationLifecycle(t *testing.T) {
	fs := placeOrSkip(t)
	t.Logf("root %s privileged=%v", fs.Root(), fs.Privileged())
	if err := checkCgroup2(fs.Root()); err != nil {
		t.Fatal(err)
	}
	c, err := fs.Create("itest", newRunID(t))
	if err != nil {
		t.Fatal(err)
	}
	// The body removes the scope itself (that is the last step of the acceptance), so the safety
	// net must not be a second Remove of the same value: it closes the fd and then removes by path,
	// which is a no-op once the body has run and still reclaims the scope when it has not.
	t.Cleanup(func() {
		_ = c.Close()
		_ = fs.Remove(context.Background(), Cgroup{Path: c.Path})
	})
	t.Logf("scope %s id=%d controllers=%v", c.Path, c.ID, c.Controllers)

	// ID: name_to_handle_at's kernfs handle equals st_ino on cgroup2fs.
	var st unix.Stat_t
	if err := unix.Stat(c.Path, &st); err != nil {
		t.Fatal(err)
	}
	if c.ID != st.Ino {
		t.Fatalf("ID %d != st_ino %d", c.ID, st.Ino)
	}

	l := Limits{CPUMax: "max 100000", CPUWeight: 50, MemoryMax: 256 << 20, MemoryHigh: 200 << 20, PidsMax: 64}
	if missing := Missing(c, l); len(missing) != 0 {
		t.Fatalf("controllers %v not delegated on this box; cgroup.controllers=%v", missing, c.Controllers)
	}
	if err := fs.SetLimits(c, l); err != nil {
		t.Fatal(err)
	}
	for _, f := range limitFiles(l) {
		got, err := os.ReadFile(filepath.Join(c.Path, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(got)) != f.Value {
			t.Fatalf("%s = %q want %q", f.Name, got, f.Value)
		}
	}
	// EINVAL is distinct from ENOENT (case 31 vs a bad value).
	if err := fs.SetLimits(c, Limits{CPUMax: "banana"}); !errors.Is(err, ErrInvalidLimit) {
		t.Fatalf("bad cpu.max: %v", err)
	}

	if p, err := Populated(c); err != nil || p {
		t.Fatalf("fresh scope populated=%v err=%v", p, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	events, err := fs.Events(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if v := <-events; v {
		t.Fatal("first event must be the empty state")
	}

	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := sys.CloneIntoCgroup(c.Dir(), cmd.SysProcAttr, cmd.Start); err != nil {
		t.Fatalf("clone3(CLONE_INTO_CGROUP): %v", err)
	}
	procCgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	rel := strings.TrimPrefix(c.Path, Mount)
	if !strings.Contains(string(procCgroup), "0::"+rel) {
		t.Fatalf("child is in %q, want %q", procCgroup, rel)
	}
	if v := <-events; !v {
		t.Fatal("populated transition not observed")
	}
	if err := fs.WaitEmpty(ctxWith(t, 200*time.Millisecond), c); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitEmpty on a live child: %v", err)
	}

	if err := fs.Kill(c); err != nil {
		t.Fatal(err)
	}
	if err := fs.WaitEmpty(ctx, c); err != nil {
		t.Fatal(err)
	}
	if v := <-events; v {
		t.Fatal("empty transition not observed")
	}
	werr := cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(werr, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child did not die by SIGKILL: %v", werr)
	}
	if oom, err := fs.OOMKilled(c); err != nil || oom {
		t.Fatalf("oom=%v err=%v", oom, err)
	}
	if o, p, err := ReadLimitEvents(c); err != nil || o != 0 || p != 0 {
		t.Fatalf("counters %d %d %v", o, p, err)
	}
	if err := fs.Remove(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scope survived: %v", err)
	}
	cancel()
	for range events {
	}
}

func ctxWith(t testing.TB, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// TestIntegrationPidsCap proves pids.max is enforced on the scope and pids.events.max counts it (R11).
func TestIntegrationPidsCap(t *testing.T) {
	fs := placeOrSkip(t)
	c, err := fs.Create("itest", newRunID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Remove(context.Background(), c) })
	if missing := Missing(c, Limits{PidsMax: 1}); len(missing) != 0 {
		t.Skipf("pids not delegated: %v", missing)
	}
	if err := fs.SetLimits(c, Limits{PidsMax: 1}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "sleep 30 & wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := sys.CloneIntoCgroup(c.Dir(), cmd.SysProcAttr, cmd.Start); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, p, err := ReadLimitEvents(c)
		if err != nil {
			t.Fatal(err)
		}
		if p > 0 || time.Now().After(deadline) {
			if p == 0 {
				t.Fatal("pids.events max never incremented")
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := fs.Kill(c); err != nil {
		t.Fatal(err)
	}
	if err := fs.WaitEmpty(ctxWith(t, 10*time.Second), c); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
}

var (
	memhogOnce sync.Once
	memhogPath string
	memhogErr  error
)

// memhogBinary builds testdata/memhog once per test run (same pattern as internal/runtime's
// tegoBinary): a real subprocess is required because memory.max is enforced by the kernel against
// a real cgroup member, not something a fake Manager could exercise.
func memhogBinary(t *testing.T) string {
	t.Helper()
	memhogOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tego-memhog-")
		if err != nil {
			memhogErr = err
			return
		}
		memhogPath = filepath.Join(dir, "memhog")
		cmd := exec.Command("go", "build", "-o", memhogPath, "github.com/attention-span-ai/tego/internal/runtime/cgroup/testdata/memhog")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			memhogErr = fmt.Errorf("go build memhog: %v: %s", err, out)
		}
	})
	if memhogErr != nil {
		t.Skipf("cannot build the memhog helper: %v", memhogErr)
	}
	return memhogPath
}

// TestIntegrationOOM is §10's "OOM detection" integration case, still missing before this test:
// R10 assigns `reason=oom` to a `memory.events.oom_kill` increase read through
// `cgroup.ReadLimitEvents`/`FS.OOMKilled`, mirroring how TestIntegrationPidsCap already covers
// R11's pids side. A process that keeps growing its own resident memory inside a cgroup with a low
// memory.max must be killed by the kernel, and the oom_kill counter must show it.
//
// memory.swap.max is pinned to 0 before memory.max is set: left at the delegated default the
// kernel reclaims by swapping the growing process out instead of killing it, which on this box's
// already near-full swap would either make the test slow and flaky or add real pressure to a
// swap device shared with every other process on the machine — neither of which this test may do
// (no sleeping to synchronise, no dependence on host state outside what the test itself sets up).
// Disabling swap for just this one cgroup keeps the kill immediate and the test's footprint capped
// at memory.max regardless of what else is running on the box.
func TestIntegrationOOM(t *testing.T) {
	fs := placeOrSkip(t)
	bin := memhogBinary(t)
	c, err := fs.Create("itest-oom", newRunID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Remove(context.Background(), c) })
	if missing := Missing(c, Limits{MemoryMax: 1}); len(missing) != 0 {
		t.Skipf("memory controller not delegated: %v", missing)
	}
	if err := os.WriteFile(filepath.Join(c.Path, "memory.swap.max"), []byte("0"), 0o644); err != nil {
		t.Fatalf("disable swap for the scope: %v", err)
	}
	const ceiling = 16 << 20 // trivial next to host RAM; the kernel must refuse to grow past it
	if err := fs.SetLimits(c, Limits{MemoryMax: ceiling}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	werr := sys.CloneIntoCgroup(c.Dir(), cmd.SysProcAttr, cmd.Run)
	if ctx.Err() != nil {
		t.Fatalf("memory.max=%d never stopped the child; the test's own timeout fired instead of the kernel (werr=%v)", ceiling, werr)
	}
	var ee *exec.ExitError
	if !errors.As(werr, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child did not die by SIGKILL under memory.max: %v", werr)
	}
	// The authoritative signal is the counter this package hands the caller (R10), not the process
	// exit status alone: a future regression in the read/parse path must fail here even if the
	// kernel's own kill behaviour (asserted above) still works.
	if oom, err := fs.OOMKilled(c); err != nil || !oom {
		t.Fatalf("OOMKilled = %v, %v; want true after a real memory.max kill", oom, err)
	}
	if o, _, err := ReadLimitEvents(c); err != nil || o == 0 {
		t.Fatalf("ReadLimitEvents oom_kill = %d, %v; want at least 1", o, err)
	}
}

// TestIntegrationZeroLimitsStayAtKernelDefault is case 30's real-kernel half. limitFiles (unit-
// tested in TestLimitFiles) already proves a zero Limits field is skipped, never written as a
// literal "0"; what only a live cgroup2 mount can prove is the other half of case 30's claim — that
// skipping the write actually leaves the kernel's own default in place, and that default is
// permissive enough to admit the run's own first process. A regression that instead computed and
// wrote "0" for an omitted field (case 30's named failure: "the run's own first process would be
// refused") would fail the pids.max content check below and, independently, would refuse the
// probe child outright.
//
// Also pins runtime-launch.md E30: an omitted limit leaves the kernel's default.
func TestIntegrationZeroLimitsStayAtKernelDefault(t *testing.T) {
	fs := placeOrSkip(t)
	c, err := fs.Create("itest-zero", newRunID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Remove(context.Background(), c) })
	if missing := Missing(c, Limits{MemoryMax: 1, PidsMax: 1}); len(missing) != 0 {
		t.Skipf("controllers %v not delegated on this box", missing)
	}
	// MemoryMax is set so the write path is exercised for real; PidsMax is left at its Go zero
	// value, the exact "contract omits pids:" shape case 30 names.
	if err := fs.SetLimits(c, Limits{MemoryMax: 64 << 20}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(c.Path, "pids.max"))
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.TrimSpace(string(got)); s != "max" {
		t.Fatalf("pids.max = %q, want the untouched kernel default %q (case 30: never a literal 0)", s, "max")
	}
	// End-to-end: a cgroup whose pids.max really were "0" refuses every task, so the first process
	// of the run could never start (case 30's stated consequence, not just a file-content detail).
	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := sys.CloneIntoCgroup(c.Dir(), cmd.SysProcAttr, cmd.Run); err != nil {
		t.Fatalf("first process inside the scope was refused: %v", err)
	}
}

// TestIntegrationExplicitZeroCapIsWritten is case 30's other arm, on a real kernel: the same zero,
// asked for. The kernel has to accept the literal "0" for a ceiling of 0 to mean anything,
// and the cap has to actually bite — a pids.max of 0 refuses the run's own first process, which is
// exactly the consequence case 30 names and, when the operator wrote the 0 on purpose, exactly what
// they asked for (limits-check-doctor-cli.md E16).
func TestIntegrationExplicitZeroCapIsWritten(t *testing.T) {
	fs := placeOrSkip(t)
	c, err := fs.Create("itest-zerocap", newRunID(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Remove(context.Background(), c) })
	if missing := Missing(c, Limits{PidsMax: 1}); len(missing) != 0 {
		t.Skipf("controllers %v not delegated on this box", missing)
	}
	if err := fs.SetLimits(c, Limits{PidsMax: 0, PidsMaxSet: true}); err != nil {
		t.Fatalf("the kernel refused a pids.max of 0, so E16 cannot be honoured this way: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(c.Path, "pids.max"))
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.TrimSpace(string(got)); s != "0" {
		t.Fatalf("pids.max = %q, want the literal %q an operator asked for", s, "0")
	}
	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := sys.CloneIntoCgroup(c.Dir(), cmd.SysProcAttr, cmd.Run); err == nil {
		t.Fatal("a pids.max of 0 admitted a process; the cap the operator asked for is not in force")
	}
}

func TestIntegrationDetect(t *testing.T) {
	fs := detectOrSkip(t)
	if os.Geteuid() != 0 {
		want := canonicalSubtree(os.Getuid())
		if fs.Root() != want {
			t.Fatalf("root %s want %s", fs.Root(), want)
		}
	}
	if err := writable(fs.Root()); err != nil {
		t.Fatal(err)
	}
}

// TestIntegrationCanPlaceIsTheKernelsAnswer holds FS.CanPlace to the kernel's own answer on this machine
// (case 41): a scratch cgroup under the root Detect chose, and a child cloned into it with
// CLONE_INTO_CGROUP, must succeed exactly when CanPlace says yes. Inside the delegated subtree (a desktop
// session's terminal, or `systemd-run --user --scope`) both say yes; from a login over ssh or a service,
// which run beside it, CanPlace refuses and the clone3 fails with EACCES, where Detect alone found the
// subtree usable.
//
// Also pins runtime-launch.md E41: CanPlace agrees with the kernel's clone3 answer.
func TestIntegrationCanPlaceIsTheKernelsAnswer(t *testing.T) {
	fs := detectOrSkip(t)
	placeErr := fs.CanPlace()
	scratch := filepath.Join(fs.Root(), fmt.Sprintf(".tego-canplace-%d", os.Getpid()))
	if err := os.Mkdir(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(scratch) })
	fd, err := unix.Open(scratch, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	runErr := cmd.Run()
	own, _ := os.ReadFile(procSelfCgroup)
	t.Logf("root %s, this process %s: CanPlace %v; clone3 into the root %v",
		fs.Root(), strings.TrimSpace(string(own)), placeErr, runErr)
	switch {
	case placeErr == nil && runErr != nil:
		t.Fatalf("CanPlace said this process can place a run, and the kernel refused the child: %v", runErr)
	case placeErr != nil && runErr == nil:
		t.Fatalf("CanPlace refused (%v), and the kernel placed the child", placeErr)
	case placeErr != nil:
		if !errors.Is(runErr, unix.EACCES) {
			t.Errorf("the kernel refused the child with %v, not the EACCES of delegation containment", runErr)
		}
		var de *DetectError
		if !errors.As(placeErr, &de) || !errors.Is(placeErr, ErrOutsideSubtree) ||
			!strings.Contains(de.Remedy, "systemd-run --user --scope") {
			t.Errorf("the refusal %v is not an ErrOutsideSubtree naming systemd-run --user --scope", placeErr)
		}
	}
}

// BenchmarkCgroupCreateRemove is the budget benchmark of §9 for one run's scope lifecycle.
func BenchmarkCgroupCreateRemove(b *testing.B) {
	fs := detectOrSkip(b)
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		c, err := fs.Create("bench", newRunID(b))
		if err != nil {
			b.Fatal(err)
		}
		if err := fs.SetLimits(c, Limits{PidsMax: 64, MemoryMax: 64 << 20}); err != nil {
			b.Fatal(err)
		}
		if err := fs.Remove(ctx, c); err != nil {
			b.Fatal(err)
		}
	}
}

// TestIntegrationMountAgrees is the other side of the cgroup-namespace check (case 39): on a host
// whose /sys/fs/cgroup is the tree /proc/self/cgroup is written against — every ordinary systemd
// user session — the check must cost nothing, i.e. the delegated candidate must survive it. It
// guards against the agreement test being so strict that Detect refuses a healthy host: a mount the
// check cannot show to agree is refused outright (requireMountAgreement), never tried by another
// path.
func TestIntegrationMountAgrees(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the delegated candidate is only built for an unprivileged launcher")
	}
	data, err := os.ReadFile(procSelfCgroup)
	if err != nil {
		t.Skipf("no %s: %v", procSelfCgroup, err)
	}
	if delegatedSubtree(data, os.Getuid()) == "" {
		t.Skipf("this process is not inside a user@%d.service: %s", os.Getuid(), data)
	}
	if got := delegatedCandidate(Mount, data, os.Getuid(), os.Getpid()); got == "" {
		t.Fatalf("the agreement check rejected a self-consistent host mount (%s = %q)", procSelfCgroup, data)
	}
}

// TestIntegrationDetectRefusesTheHostTree is case 39's motivating shape on a real mount. A
// cgroupns-private container handed the host's /sys/fs/cgroup reads "0::/" for its own namespace
// root (cgroup_namespaces(7)); that line carries no user@<uid>.service segment, so no derived
// candidate is built and the per-candidate agreement check is never consulted. Detect must refuse
// anyway, because the canonical user@<uid>.service under that mount is the host's user manager,
// not this namespace's — the same "real, writable, different subtree" case 39 is about, reached by
// the other road. The same holds for the shapes that leave nothing to compare against the mount: a
// "../" path, which cgroup_namespaces(7) prints for a cgroup outside the reader's namespace root,
// and a /proc/self/cgroup that could not be read at all.
func TestIntegrationDetectRefusesTheHostTree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the delegated subtree is only chosen for an unprivileged launcher")
	}
	uid := os.Getuid()
	// The precondition that gives this test its teeth: the canonical subtree is cgroup2 and
	// writable here, so nothing but the mount-level refusal stops Detect from accepting it.
	if err := writable(canonicalSubtree(uid)); err != nil {
		t.Skipf("no canonical delegated subtree that could be wrongly accepted: %v", err)
	}
	for _, in := range []string{
		"0::/\n",
		"0::/../../system.slice/docker-abc.scope\n",
		"0::/..\n",
		"12:pids:/user.slice\n",
		"",
	} {
		fs, err := detectDelegated(Mount, []byte(in), uid, os.Getpid())
		if fs != nil {
			t.Fatalf("detectDelegated(%q) built a manager on a mount it never showed to be this "+
				"process's tree: %s", in, fs.Root())
		}
		if !errors.Is(err, ErrNotDelegated) {
			t.Fatalf("detectDelegated(%q) = %v, want ErrNotDelegated", in, err)
		}
		if !strings.Contains(err.Error(), "case 39") {
			t.Fatalf("detectDelegated(%q): the refusal must say why it refused, not send the operator "+
				"to Delegate=: %v", in, err)
		}
	}

	// The other direction, so the refusal cannot be a blanket one: this host's own
	// /proc/self/cgroup agrees with this host's mount, and detection still works.
	data, rerr := os.ReadFile(procSelfCgroup)
	if rerr != nil {
		t.Skipf("no %s: %v", procSelfCgroup, rerr)
	}
	if _, err := detectDelegated(Mount, data, uid, os.Getpid()); err != nil {
		t.Fatalf("the mount-level check refused a self-consistent host: %v", err)
	}
}
