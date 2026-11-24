// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/runstatus"
)

func statusTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cliStatus() runstatus.Status {
	return runstatus.Status{Schema: runstatus.Schema, Run: "r-00000000-000000000000a-aaaaaa", Scope: "/sys/fs/cgroup/tego.slice/run-a.scope", CgroupID: "123"}
}

func TestRunStatusWriterAtomicLifecycleAndLauncherLost(t *testing.T) {
	path := filepath.Join(statusTestDir(t), "run-status.json")
	w, err := openRunStatusWriter(path, &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pre-scope refusal would leave a status")
	}
	s := cliStatus()
	if err := w.Write(s); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := runstatus.Decode(b)
	if err != nil || got.Removed || got.Deferred {
		t.Fatalf("launcher-loss initial state %+v, %v", got, err)
	}
	s.Removed = true
	if err := w.Write(s); err != nil {
		t.Fatal(err)
	}
	oldInfo, _ := old.Stat()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldInfo, info) {
		t.Fatal("final write overwrote original inode")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("status mode %v", info.Mode())
	}
	b, _ = os.ReadFile(path)
	got, err = runstatus.Decode(b)
	if err != nil || !got.Removed {
		t.Fatalf("final state %+v, %v", got, err)
	}
}

func TestRunStatusWriterRefusesExistingAndLinks(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "parent link", "parent writable", "relative"} {
		t.Run(kind, func(t *testing.T) {
			dir := statusTestDir(t)
			path := filepath.Join(dir, "run-status.json")
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
					t.Fatal(err)
				}
			case "parent link":
				link := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "run-status.json")
			case "parent writable":
				if err := os.Chmod(dir, 0o770); err != nil {
					t.Fatal(err)
				}
			case "relative":
				path = "run-status.json"
			}
			if w, err := openRunStatusWriter(path, &agent.RuleTable{}); err == nil {
				w.Close()
				t.Fatal("accepted unsafe status path")
			}
		})
	}
}

func TestRunStatusWriterRefusesOverlappingWrites(t *testing.T) {
	dir := statusTestDir(t)
	for _, grant := range []string{dir, filepath.Dir(dir), filepath.Join(dir, "child")} {
		for _, kind := range []agent.FSKind{agent.FSWrite, agent.FSAsk} {
			rt := &agent.RuleTable{FS: []agent.FSRule{{Path: grant, Kind: kind}}}
			if w, err := openRunStatusWriter(filepath.Join(dir, "run-status.json"), rt); err == nil {
				w.Close()
				t.Fatalf("accepted grant %s %s", kind, grant)
			}
		}
	}
}

func TestRunStatusWriterRefusesSymlinkGrantAlias(t *testing.T) {
	dir := statusTestDir(t)
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []agent.FSRule{{Path: link, Kind: agent.FSWrite}, {Path: "/old-name", Resolved: dir, Kind: agent.FSWrite}} {
		if w, err := openRunStatusWriter(filepath.Join(dir, "run-status.json"), &agent.RuleTable{FS: []agent.FSRule{rule}}); err == nil {
			w.Close()
			t.Fatal("accepted status parent alias in write grant")
		}
	}
}

func TestRunStatusWriterKeepsOriginalOnInvalidFinal(t *testing.T) {
	path := filepath.Join(statusTestDir(t), "run-status.json")
	w, err := openRunStatusWriter(path, &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	s := cliStatus()
	if err := w.Write(s); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Removed, s.Deferred = true, true
	if err := w.Write(s); err == nil {
		t.Fatal("accepted conflicting status")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed final write changed initial: %s, %v", after, err)
	}
}

func TestRunStatusWriterRefusesDestinationReplacement(t *testing.T) {
	path := filepath.Join(statusTestDir(t), "run-status.json")
	w, err := openRunStatusWriter(path, &agent.RuleTable{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Write(cliStatus()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("victim", path); err != nil {
		t.Fatal(err)
	}
	s := cliStatus()
	s.Removed = true
	if err := w.Write(s); err == nil {
		t.Fatal("accepted replaced destination")
	}
}

func TestRunStatusFlagRequiresAbsolutePath(t *testing.T) {
	var stderr bytes.Buffer
	if code := checkRunFlags(runOptions{statusFile: "relative"}, &stderr); code != identity.ExitUsage {
		t.Fatalf("exit=%d output=%s", code, stderr.String())
	}
}

func TestRunStatusWriteFailureOverridesAgentAndServiceExit(t *testing.T) {
	res := tegoruntime.Result{RunID: cliStatus().Run, ExitCode: 3, Reason: "stopped", StatusErr: errors.New("disk full")}
	for _, service := range []bool{false, true} {
		var stderr bytes.Buffer
		if code := serviceExitCode(&stderr, "tego run", res, service); code != identity.ExitLauncher {
			t.Fatalf("service=%v exit=%d output=%s", service, code, stderr.String())
		}
	}
}

func TestRunStatusFlagRefusesObserve(t *testing.T) {
	for _, tc := range []struct {
		name    string
		observe bool
	}{
		{"enforcing", false},
		{"observe", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := checkRunFlags(runOptions{statusFile: "/protected/run-status.json", observe: tc.observe}, &stderr)
			if !tc.observe {
				if code != identity.ExitOK {
					t.Fatalf("enforcing run exit=%d output=%s", code, stderr.String())
				}
				return
			}
			if code != identity.ExitUsage || !strings.Contains(stderr.String(), "--status-file cannot be used with --observe") {
				t.Fatalf("observe run exit=%d output=%s", code, stderr.String())
			}
		})
	}
}

// The walk to the status file's directory needs search permission on its ancestors, never read: an ancestor the
// launcher may search but not list is passed, as a whole-path open would pass it.
func TestRunStatusWriterNeedsOnlySearchOnAncestors(t *testing.T) {
	searchOnly := filepath.Join(statusTestDir(t), "search-only")
	parent := filepath.Join(searchOnly, "private")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(searchOnly, 0o311); err != nil { // write and search, no read
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(searchOnly, 0o700) })
	w, err := openRunStatusWriter(filepath.Join(parent, "run-status.json"), &agent.RuleTable{})
	if err != nil {
		t.Fatalf("--status-file beneath a 0311 ancestor: %v; want it opened, a walk needs only search there", err)
	}
	defer w.Close()
	if err := w.Write(cliStatus()); err != nil {
		t.Fatal(err)
	}
}
