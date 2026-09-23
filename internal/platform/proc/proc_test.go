// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// fakeProc writes a directory tree shaped like /proc so the file-level reads can be tested without
// spawning processes. Symlinks (exe, cwd) are real symlinks so Readlink behaves as it does on /proc.
func fakeProc(t *testing.T, pid int, files map[string]string, links map[string]string) *FS {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return NewAt(root)
}

func TestProcessReadsEveryField(t *testing.T) {
	f := fakeProc(t, 4242, map[string]string{
		"stat":    statLine(4242, "python3", 7, 2, 900),
		"cmdline": "python3\x00-m\x00pytest\x00",
		"cgroup":  "0::/tego/run-abc\n",
	}, map[string]string{
		"exe": "/usr/bin/python3.12",
		"cwd": "/work",
	})
	p, err := f.Process(4242)
	if err != nil {
		t.Fatal(err)
	}
	if p.Err != nil {
		t.Errorf("partial failure: %v", p.Err)
	}
	want := Process{
		PID: 4242, PPID: 7, Comm: "python3", State: 'S',
		StartTicks: 900, StartBootNS: 900 * NanosPerTick,
		Exe: "/usr/bin/python3.12", Argv: []string{"python3", "-m", "pytest"},
		Cwd: "/work", Cgroup: "/tego/run-abc",
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("got %+v\nwant %+v", p, want)
	}
}

func TestProcessGone(t *testing.T) {
	f := fakeProc(t, 1, map[string]string{"stat": statLine(1, "init", 0, 1, 1)}, nil)
	if _, err := f.Process(2); !errors.Is(err, ErrGone) {
		t.Fatalf("Process(2) = %v, want ErrGone", err)
	}
	if _, err := f.Stat(2); !errors.Is(err, ErrGone) {
		t.Fatalf("Stat(2) = %v, want ErrGone", err)
	}
	if _, err := f.Argv(2); !errors.Is(err, ErrGone) {
		t.Fatalf("Argv(2) = %v, want ErrGone", err)
	}
}

func TestProcessPartial(t *testing.T) {
	// No exe, no cwd, no cgroup: a kernel thread, or a process whose links we may not follow.
	f := fakeProc(t, 5, map[string]string{
		"stat":    statLine(5, "kworker/0:1", 2, 1, 3),
		"cmdline": "",
		"cgroup":  "0::/\n",
	}, nil)
	p, err := f.Process(5)
	if err != nil {
		t.Fatal(err)
	}
	if p.Comm != "kworker/0:1" || p.PPID != 2 {
		t.Errorf("got %+v", p)
	}
	if p.Err != nil {
		t.Errorf("an absent exe/cwd on a live pid is not an error: %v", p.Err)
	}
	if p.Exe != "" || p.Cwd != "" {
		t.Errorf("want empty best-effort fields, got %+v", p)
	}
}

func TestProcessMalformedStat(t *testing.T) {
	f := fakeProc(t, 6, map[string]string{"stat": "6 no-parens here"}, nil)
	_, err := f.Process(6)
	if !errors.Is(err, ErrStat) {
		t.Fatalf("Process = %v, want ErrStat", err)
	}
	if errors.Is(err, ErrGone) {
		t.Error("a malformed stat line must not look like a vanished process")
	}
}

func TestExeStripsDeleted(t *testing.T) {
	f := fakeProc(t, 7, map[string]string{"stat": statLine(7, "x", 1, 1, 1)}, map[string]string{
		"exe": "/tmp/build/agent (deleted)",
	})
	got, err := f.Exe(7)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/tmp/build/agent" {
		t.Errorf("Exe = %q", got)
	}
}

func TestPIDsAndRoot(t *testing.T) {
	f := fakeProc(t, 3, map[string]string{"stat": statLine(3, "a", 1, 1, 1)}, nil)
	if err := os.MkdirAll(filepath.Join(f.Root(), "11"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.Root(), "meminfo"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pids, err := f.PIDs()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pids, []int{3, 11}) {
		t.Errorf("PIDs = %v, want [3 11]", pids)
	}
	if New().Root() != DefaultRoot {
		t.Errorf("New().Root() = %q", New().Root())
	}
	var nilFS *FS
	if nilFS.Root() != DefaultRoot {
		t.Errorf("nil FS Root = %q", nilFS.Root())
	}
}

// TestSelfAgainstRealProc reads this very process: the one place the parsers meet the real kernel
// format. It needs no privilege.
func TestSelfAgainstRealProc(t *testing.T) {
	f := New()
	pid := os.Getpid()
	p, err := f.Process(pid)
	if err != nil {
		t.Fatalf("Process(self): %v", err)
	}
	if p.PID != pid || p.PPID != os.Getppid() {
		t.Errorf("pid %d ppid %d, want %d %d", p.PID, p.PPID, pid, os.Getppid())
	}
	if p.StartBootNS == 0 {
		t.Error("start time is zero")
	}
	if len(p.Argv) == 0 {
		t.Error("empty argv")
	}
	exe, err := os.Executable()
	if err == nil && p.Exe != exe {
		t.Logf("exe %q, os.Executable %q (test binaries may differ)", p.Exe, exe)
	}
	if p.Cgroup == "" {
		t.Log("no unified cgroup line: cgroup v1 host")
	}
	libs, err := f.Libraries(pid)
	if err != nil {
		t.Fatalf("Libraries(self): %v", err)
	}
	t.Logf("%d mapped files, cgroup %q", len(libs), p.Cgroup)
	if _, err := f.PIDs(); err != nil {
		t.Fatalf("PIDs: %v", err)
	}
}
