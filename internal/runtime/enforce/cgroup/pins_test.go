// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// TestPinLayout pins the directory shape §3 specifies, and the hashes that must be refused because they would
// escape the build's own directory: IsBuildHash's rule, the one the helpers and the reaper apply.
func TestPinLayout(t *testing.T) {
	t.Parallel()
	p, err := newPinLayout("/sys/fs/bpf", "abc123")
	if err != nil {
		t.Fatalf("newPinLayout: %v", err)
	}
	want := map[string]string{
		"root":  "/sys/fs/bpf/tego/abc123",
		"maps":  "/sys/fs/bpf/tego/abc123/maps",
		"progs": "/sys/fs/bpf/tego/abc123/progs",
		"links": "/sys/fs/bpf/tego/abc123/links",
	}
	got := map[string]string{"root": p.Root, "maps": p.Maps, "progs": p.Progs, "links": p.Links}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if def, err := newPinLayout("", "abc123"); err != nil || def.Root != want["root"] {
		t.Errorf("empty mount = %q, %v; want the default %q", def.Root, err, want["root"])
	}
	for _, bad := range []string{"", ".", "..", "../escape", "a/b", "nul\x00"} {
		if _, err := newPinLayout("/sys/fs/bpf", bad); !errors.Is(err, ErrProgramLoad) {
			t.Errorf("hash %q accepted", bad)
		}
	}
}

// TestCheckBPFFS covers enforce-cgroup-observe.md §6 E30: a path that is not a bpf filesystem is its own error with its own fix, never
// folded into the verifier-rejection bucket.
func TestCheckBPFFS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := checkBPFFS(dir)
	if !errors.Is(err, ErrBpffsUnavailable) {
		t.Fatalf("a tmpfs directory = %v, want ErrBpffsUnavailable", err)
	}
	if !strings.Contains(err.Error(), "mount -t bpf") {
		t.Errorf("error does not name the fix: %v", err)
	}
	if err := checkBPFFS(filepath.Join(dir, "missing")); !errors.Is(err, ErrBpffsUnavailable) {
		t.Fatalf("a missing path = %v, want ErrBpffsUnavailable", err)
	}
	// The real mount, when this machine has one, must pass.
	if _, statErr := os.Stat(DefaultBPFFS); statErr == nil {
		if err := checkBPFFS(DefaultBPFFS); err != nil {
			t.Logf("%s is present but not a bpf filesystem here: %v", DefaultBPFFS, err)
		}
	}
}

// TestPinCreateAndRemove exercises the directory lifecycle on an ordinary filesystem, which is the part of
// the protocol that needs no bpffs: create is idempotent and remove tolerates a half-built layout.
func TestPinCreateAndRemove(t *testing.T) {
	t.Parallel()
	p, err := newPinLayout(t.TempDir(), "hash")
	if err != nil {
		t.Fatalf("newPinLayout: %v", err)
	}
	if err := p.create(); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := p.create(); err != nil {
		t.Fatalf("create twice: %v", err)
	}
	for _, dir := range []string{p.Base, p.Root, p.Maps, p.Progs, p.Links} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Fatalf("%s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(p.Maps, "tego_run_set"), nil, 0o600); err != nil {
		t.Fatalf("stand in for a pin: %v", err)
	}
	if err := p.remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(p.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pin root survived removal: %v", err)
	}
	if info, err := os.Stat(p.Base); err != nil || !info.IsDir() {
		t.Fatalf("the shared base directory must survive one build's teardown: %v", err)
	}
	if err := p.remove(); err != nil {
		t.Fatalf("remove twice: %v", err)
	}
}

// TestPinRemovalKeepsMapsUnderALinkItCannotUnpin is R14 as amended 2026-10-05 (v73 review, plane-2): a build's
// pins go links first, and a link pin that cannot be removed keeps the programs and maps it runs over. Maps first
// left a link over maps no launcher held, which the next launcher, re-creating the maps, adopted and recorded
// nothing through. A non-empty directory stands in for a pin whose unlink fails, as root too.
func TestPinRemovalKeepsMapsUnderALinkItCannotUnpin(t *testing.T) {
	t.Parallel()
	p, err := newPinLayout(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.create(); err != nil {
		t.Fatal(err)
	}
	mapPin, progPin := filepath.Join(p.Maps, "tego_run_set"), filepath.Join(p.Progs, "tego_exec_result")
	stuck := filepath.Join(p.Links, "tego_exec_result")
	for _, pin := range []string{mapPin, progPin, filepath.Join(p.Links, "tego_sched_exec"), filepath.Join(stuck, "held")} {
		if err := os.MkdirAll(filepath.Dir(pin), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pin, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.remove(); err == nil {
		t.Fatal("remove over a link pin it cannot unpin: nil error")
	}
	for _, pin := range []string{mapPin, progPin} {
		if _, err := os.Stat(pin); err != nil {
			t.Errorf("%s was removed under a link that stayed pinned: %v", pin, err)
		}
	}
	if _, err := os.Stat(filepath.Join(p.Links, "tego_sched_exec")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a link that could be unpinned stayed: %v", err)
	}
	if err := os.RemoveAll(stuck); err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err != nil {
		t.Fatalf("remove once the link is gone: %v", err)
	}
	if _, err := os.Stat(p.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pin root survived removal: %v", err)
	}
}

// TestTeardownWaitsUntilTheKernelFreesThePrograms is perf-cold C3's wait: a removal returns once the kernel holds
// none of the programs its links ran, asking again until it does, and a program something outside the removal keeps
// is waited for teardownWait and then left to the kernel, as before C3. Not parallel: it replaces the package's
// programHeld and teardownWait.
func TestTeardownWaitsUntilTheKernelFreesThePrograms(t *testing.T) {
	heldFor := map[ebpf.ProgramID]int{7: 3, 9: 1, 11: 0}
	asked := map[ebpf.ProgramID]int{}
	restoreHeld, restoreWait := programHeld, teardownWait
	t.Cleanup(func() { programHeld, teardownWait = restoreHeld, restoreWait })
	programHeld = func(id ebpf.ProgramID) bool {
		asked[id]++
		return asked[id] <= heldFor[id]
	}
	td := teardown{progs: []ebpf.ProgramID{7, 9, 11}}
	td.wait()
	if want := map[ebpf.ProgramID]int{7: 4, 9: 2, 11: 1}; !maps.Equal(asked, want) {
		t.Fatalf("asked %v, want each program asked until the kernel no longer holds it: %v", asked, want)
	}
	if len(td.progs) != 0 {
		t.Fatalf("wait kept %v for the next one", td.progs)
	}

	teardownWait = 30 * time.Millisecond
	programHeld = func(ebpf.ProgramID) bool { return true }
	td = teardown{progs: []ebpf.ProgramID{13}}
	start := time.Now()
	td.wait()
	if took := time.Since(start); took < teardownWait || took > teardownWait+time.Second {
		t.Fatalf("a program held throughout was waited for %v, want teardownWait (%v) and no more", took, teardownWait)
	}

	programHeld = func(ebpf.ProgramID) bool { t.Error("asked about a program with none recorded"); return false }
	(&teardown{}).wait()
}

// TestUnpinLinkFallsBackToTheUnlink is perf-cold C3's fallback: a pin unpinLink cannot open as a bpf link (here a
// plain file on an ordinary filesystem, as a pin that is not a link or one this process may not open is) is removed
// alone, as before C3, and one already gone is os.ErrNotExist, which every caller tolerates. The build's removal
// takes link pins that way from each of its link directories: the planes', the capture probes', the run's and the
// build's own.
func TestUnpinLinkFallsBackToTheUnlink(t *testing.T) {
	t.Parallel()
	plain := filepath.Join(t.TempDir(), "tego_sched_exec")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var td teardown
	if err := td.unpinLink(plain); err != nil {
		t.Fatalf("unpinLink of a pin that is no link: %v", err)
	}
	if _, err := os.Stat(plain); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the pin stayed: %v", err)
	}
	if err := td.unpinLink(plain); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unpinLink of a pin already gone: %v, want os.ErrNotExist", err)
	}
	if len(td.progs) != 0 {
		t.Fatalf("a pin that is no link recorded programs %v for the wait", td.progs)
	}

	p, err := newPinLayout(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.create(); err != nil {
		t.Fatal(err)
	}
	plane := newPlaneLayout(p, "hash", planeModes[0])
	if err := plane.create(); err != nil {
		t.Fatal(err)
	}
	pins := []string{
		filepath.Join(plane.Links, "tego_plane_file_open"),
		filepath.Join(plane.Fill, "tego_plane_fill"),
		filepath.Join(p.Root, uprobePins, "libssl", "uprobe_ssl_write"),
		filepath.Join(p.runLinks("r1"), "tego_sock_create"),
		filepath.Join(p.Links, "tego_sched_exec"),
		filepath.Join(p.Progs, "tego_sched_exec"),
		filepath.Join(p.Maps, "tego_run_set"),
	}
	for _, pin := range pins {
		if err := os.MkdirAll(filepath.Dir(pin), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pin, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for _, dir := range []string{plane.Root, p.Root} {
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the build's removal: %v", dir, err)
		}
	}
}

// TestBuildLockLastOut is the coexistence protocol of §5 R14: one holder is the last out, two are not, and
// the survivor becomes the last out once the other leaves.
func TestBuildLockLastOut(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// A sole holder is the last out, and keeps the lock exclusive from then on.
	sole, err := acquireBuildLock(dir, "hash")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	last, err := sole.lastOut()
	if err != nil {
		t.Fatalf("lastOut: %v", err)
	}
	if !last {
		t.Fatal("a sole holder must be the last out")
	}
	if err := sole.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := sole.Close(); err != nil {
		t.Fatalf("close twice: %v", err)
	}
	if last, err := sole.lastOut(); last || err != nil {
		t.Fatalf("lastOut after close = %v, %v", last, err)
	}

	// With a second launcher holding the lock, teardown must not claim the pins; once it leaves, it must.
	survivor, err := acquireBuildLock(dir, "hash")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer survivor.Close()
	stop := holdLockInChild(t, dir, "hash")
	last, err = survivor.lastOut()
	if err != nil {
		t.Fatalf("lastOut with another holder: %v", err)
	}
	if last {
		t.Fatal("claimed to be the last out while another launcher holds the lock")
	}
	stop()

	last, err = survivor.lastOut()
	if err != nil {
		t.Fatalf("lastOut after the other left: %v", err)
	}
	if !last {
		t.Fatal("the survivor must become the last out")
	}
}

// TestBuildLockIsPerBuild asserts two builds' locks never contend, which is what lets an upgrade run both
// builds at once (§6 E22).
func TestBuildLockIsPerBuild(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, err := acquireBuildLock(dir, "aaaa")
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	defer a.Close()
	stop := holdLockInChild(t, dir, "bbbb")
	defer stop()

	last, err := a.lastOut()
	if err != nil {
		t.Fatalf("lastOut: %v", err)
	}
	if !last {
		t.Fatal("another build's holder must not block this build's teardown")
	}
}

// holdLockInChild takes the shared lock in a separate process, because flock is per open file description and
// a second lock in this process would be granted to the same holder. It returns a function that releases it.
func holdLockInChild(t *testing.T, dir, hash string) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestBuildLockHelper", "-test.v=false")
	cmd.Env = append(os.Environ(), "TEGO_LOCK_DIR="+dir, "TEGO_LOCK_HASH="+hash,
		"TEGO_LOCK_READY="+filepath.Join(dir, "ready-"+hash))
	var diag strings.Builder
	cmd.Stdout = &diag
	cmd.Stderr = &diag
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	ready := filepath.Join(dir, "ready-"+hash)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			in.Close()
			_ = cmd.Process.Kill()
			t.Fatalf("lock helper never reported ready: %s", diag.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	var once bool
	return func() {
		if once {
			return
		}
		once = true
		in.Close()
		_ = cmd.Wait()
		_ = os.Remove(ready)
	}
}

// TestBuildLockHelper holds the shared lock until its stdin closes. It does nothing in a normal run.
func TestBuildLockHelper(t *testing.T) {
	dir := os.Getenv("TEGO_LOCK_DIR")
	if dir == "" {
		t.Skip("helper process only")
	}
	l, err := acquireBuildLock(dir, os.Getenv("TEGO_LOCK_HASH"))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer l.Close()
	if err := os.WriteFile(os.Getenv("TEGO_LOCK_READY"), []byte("x"), 0o600); err != nil {
		t.Fatalf("report ready: %v", err)
	}
	buf := make([]byte, 1)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			return
		}
	}
}
