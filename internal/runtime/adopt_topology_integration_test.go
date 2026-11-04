// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package runtime

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

const adoptTopologyEnv = "TEGO_TEST_ADOPT_TOPOLOGY"

func init() {
	if os.Getenv(adoptTopologyEnv) == "" {
		return
	}
	// A live root agent without Landlock or seccomp, in its own mount namespace.
	goruntime.LockOSThread()
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		panic(err)
	}
	fmt.Println("ready")
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		err := unix.Mount(os.Args[1], os.Args[2], "", unix.MS_BIND, "")
		var errno syscall.Errno
		if err != nil {
			errno = err.(syscall.Errno)
		}
		if err == nil && in.Text() == "control" {
			if err := unix.Unmount(os.Args[2], unix.MNT_DETACH); err != nil {
				panic(err)
			}
		}
		fmt.Printf("errno=%d\n", errno)
	}
	os.Exit(0)
}

// migrationMountFS attempts the agent's mount synchronously after the actual
// cgroup.procs write, before Move or any subsequent adoption setup can continue.
// It embeds the real filesystem; no enforcement is prepared by the test.
type migrationMountFS struct {
	adopt.Cgroups
	pid       int
	attempt   func() (string, error)
	attempted bool
	result    string
}

func (f *migrationMountFS) Add(dir string, pid int) error {
	if err := f.Cgroups.Add(dir, pid); err != nil {
		return err
	}
	if pid == f.pid && !f.attempted {
		f.attempted = true
		var err error
		f.result, err = f.attempt()
		return err
	}
	return nil
}

// TestIntegrationAdoptFreezesTopologyAtMigration exercises the actual runtime
// order used by both adoption callers. A bind succeeds before adoption; the same
// syscall immediately after migration must already fail, before run_start.
func TestIntegrationAdoptFreezesTopologyAtMigration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for cgroup migration and mount namespaces")
	}
	m, rt, root := startupFixture(t)
	work := filepath.Join(root, "work")
	outside := filepath.Join(root, "outside")
	mount := filepath.Join(work, "mount")
	for _, dir := range []string{outside, mount} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rt.Tier = backend.TierCgroup
	rt.FS = []agent.FSRule{{Path: work, Resolved: work, Kind: agent.FSWrite, Raw: work}}
	mode := bpfobj.PlaneFmodRet
	lsms, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",bpf,") {
		mode = bpfobj.PlaneLSM
	}
	build := bpfobj.ObjectPlaneProbe
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	var rdonly *btf.Func
	if err := spec.TypeByName("bpf_rdonly_cast", &rdonly); err == nil {
		build = bpfobj.ObjectPlaneRdonly
	}
	b, ds := enforce.Select(m, rt, backend.Probe{backend.TierCgroup: true},
		enforce.Only(backend.TierCgroup), enforce.Plane(enforce.PlaneSetup{Mode: mode, Build: build}))
	if b == nil {
		t.Fatalf("select cgroup plane: %v", ds)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], outside, mount)
	cmd.Env = append(os.Environ(), adoptTopologyEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	reader := bufio.NewReader(out)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("helper setup: %q %v", line, err)
	}
	attempt := func(command string) (string, error) {
		if _, err := fmt.Fprintln(in, command); err != nil {
			return "", err
		}
		return reader.ReadString('\n')
	}
	if line, err := attempt("control"); err != nil || line != "errno=0\n" {
		t.Fatalf("unconfined bind control: %q %v", line, err)
	}
	proc := adopt.NewFS("")
	p, err := adopt.Identify(proc, cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	fs := &migrationMountFS{pid: p.PID, attempt: func() (string, error) { return attempt("migrated") }}
	started := make(chan AdoptStarted, 1)
	done := make(chan error, 1)
	go func() {
		_, err := Adopt(ctx, rt, AdoptSpec{Root: p, Boundary: true, Recheck: admitAll,
			Env:     adopt.Env{Proc: proc, FS: fs, Live: adopt.Pidfds{}},
			Started: func(s AdoptStarted) { started <- s }},
			AdoptDeps{Config: m, Enforce: b, ReaperExe: NoAdoptReaper, StateDir: filepath.Join(root, "adopted")})
		done <- err
	}()
	select {
	case s := <-started:
		if !fs.attempted || fs.result != "errno=1\n" {
			t.Errorf("bind immediately after migration: %q (attempted=%v); want EPERM before setup continues", fs.result, fs.attempted)
		}
		if s.DecisionPlane == "" {
			t.Error("boundary has no plane")
		}
		t.Logf("%s: unconfined bind=0; immediately after migration %s", s.DecisionPlane, strings.TrimSpace(fs.result))
	case err := <-done:
		t.Fatalf("adoption did not start: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("release adoption: %v", err)
	}
}
