// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
)

const markerSecret = "CANARY_MARKER_SECRET_19"

func processFixture(t *testing.T, root string, pid, ppid int, start uint64, exe string, argv []byte, tty int64) {
	t.Helper()
	dir := filepath.Join(root, itoa(pid))
	writeProcFile(t, root, itoa(pid)+"/status", statusFixture(uint32(os.Getuid())))
	writeProcFile(t, root, itoa(pid)+"/stat", statFixture(pid, ppid, start, tty, "worker"))
	writeProcFile(t, root, itoa(pid)+"/cmdline", argv)
	writeProcFile(t, root, itoa(pid)+"/cgroup", []byte("0::/user.slice\n"))
	writeProcFile(t, root, itoa(pid)+"/environ", []byte("TOKEN="+markerSecret+"\x00TEGO_RUN_ID=r-0123abcd-0000000000000-abcdef\x00"))
	if e := os.Symlink(exe, filepath.Join(dir, "exe")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/home/project", filepath.Join(dir, "cwd")); e != nil {
		t.Fatal(e)
	}
}

// spyProc provides deterministic faults and fails immediately on a forbidden environment open.
type spyProc struct {
	procAccess
	t         *testing.T
	hook      func(int, string, int, []byte, error) ([]byte, error)
	opened    map[int]bool
	fileHook  func(int, sig.FileID, error) (sig.FileID, error)
	ownerHook func(int, uint32, error) (uint32, error)
	linkHook  func(int, string, string, error) (string, error)
	openHook  func(int) error
}

func (p *spyProc) open(pid int) (processFiles, error) {
	if p.openHook != nil {
		if e := p.openHook(pid); e != nil {
			return nil, e
		}
	}
	f, e := p.procAccess.open(pid)
	if e != nil {
		return nil, e
	}
	p.opened[pid] = true
	return &spyProcess{processFiles: f, parent: p, pid: pid, reads: map[string]int{}}, nil
}

type spyProcess struct {
	processFiles
	parent *spyProc
	pid    int
	reads  map[string]int
}

func (p *spyProcess) read(name string, n int) ([]byte, error) {
	if name == "environ" {
		p.parent.t.Fatal("scan opened a process environment")
	}
	p.reads[name]++
	b, e := p.processFiles.read(name, n)
	if p.parent.hook != nil {
		return p.parent.hook(p.pid, name, p.reads[name], b, e)
	}
	return b, e
}
func (p *spyProcess) link(name string) (string, error) {
	v, e := p.processFiles.link(name)
	if p.parent.linkHook != nil {
		return p.parent.linkHook(p.pid, name, v, e)
	}
	return v, e
}
func (p *spyProcess) owner() (uint32, error) {
	uid, err := p.processFiles.owner()
	if p.parent.ownerHook != nil {
		return p.parent.ownerHook(p.pid, uid, err)
	}
	return uid, err
}
func (p *spyProcess) fileID() (sig.FileID, error) {
	id, err := p.processFiles.fileID()
	if p.parent.fileHook != nil {
		return p.parent.fileHook(p.pid, id, err)
	}
	return id, err
}
func (p *spyProcess) thread(tid int) (processFiles, error) {
	f, e := p.processFiles.thread(tid)
	if e != nil {
		return nil, e
	}
	return &spyProcess{processFiles: f, parent: p.parent, pid: tid, reads: map[string]int{}}, nil
}

func scanFixture(t *testing.T, root string, hook func(int, string, int, []byte, error) ([]byte, error)) processSnapshot {
	t.Helper()
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	spy := &spyProc{procAccess: fs, t: t, hook: hook, opened: map[int]bool{}}
	return readProcesses(context.Background(), spy, root, uint32(os.Getuid()), catalog.Rows())
}

func TestProcessEvidenceAndNoEnvironment(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00--key="+markerSecret+"\x00"), 0)
	processFixture(t, root, 11, 1, 100, "/bin/node", []byte("node\x00"+markerSecret+"\x00/lib/@openai/codex/bin/codex.js\x00"), 0)
	processFixture(t, root, 12, 1, 100, "/bin/other", []byte("gemini\x00"+markerSecret+"\x00"), 0)
	processFixture(t, root, 13, 1, 100, "/bin/other", []byte("other\x00"+markerSecret+"\x00"), 0)
	writeProcFile(t, root, "13/stat", statFixture(13, 1, 100, 0, "opencode"))
	got := scanFixture(t, root, nil)
	if !got.Usable || got.Unknown || len(got.Processes) != 4 {
		t.Fatalf("snapshot: %+v", got)
	}
	want := []string{"exe-name", "argv-pattern", "argv0-name", "comm-name"}
	for i, v := range got.Processes {
		if string(v.Fact) != want[i] || v.Membership != "outside-run" {
			t.Fatalf("fact: %+v", v)
		}
	}
	b, e := json.Marshal(got)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), markerSecret) || strings.Contains(string(b), "TEGO_RUN_ID") {
		t.Fatal("match input leaked into retained snapshot")
	}
}

func TestProcessFaults(t *testing.T) {
	cases := []struct {
		name, file  string
		read        int
		replacement []byte
		fault       error
		rows        int
		unknown     bool
		reason      string
	}{
		{"pid reused", "stat", 2, statFixture(10, 1, 999, 0, "worker"), nil, 0, true, "changed"},
		{"uid changed", "status", 2, statusFixture(uint32(os.Getuid() + 1)), nil, 0, true, "changed"},
		{"gone while reading", "stat", 2, nil, os.ErrNotExist, 0, false, ""},
		{"unreadable identity", "stat", 1, nil, os.ErrPermission, 0, true, "permission"},
		{"bad identity", "stat", 1, []byte("secret syntax"), nil, 0, true, "syntax"},
		{"unreadable uid", "status", 1, nil, os.ErrPermission, 0, true, "permission"},
		{"truncated argv", "cmdline", 1, []byte("claude"), nil, 1, true, "syntax"},
		{"argv gone", "cmdline", 1, nil, os.ErrNotExist, 0, false, ""},
		{"cgroup denied", "cgroup", 1, nil, os.ErrPermission, 1, true, "permission"},
		{"cgroup malformed", "cgroup", 1, []byte("secret"), nil, 1, true, "syntax"},
		{"cwd optional", "not-matching", 1, nil, nil, 1, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
			got := scanFixture(t, root, func(pid int, name string, n int, b []byte, e error) ([]byte, error) {
				if name == tc.file && n == tc.read {
					return tc.replacement, tc.fault
				}
				return b, e
			})
			if len(got.Processes) != tc.rows || got.Unknown != tc.unknown {
				t.Fatalf("fault classification: %+v", got)
			}
			if tc.reason != "" {
				found := false
				for _, s := range got.Sources {
					if s.Reason == tc.reason {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing failure reason %s", tc.reason)
				}
			}
			if tc.file == "cgroup" && got.Processes[0].Membership != "unknown" {
				t.Fatal("failed cgroup became outside")
			}
		})
	}
}

func TestOtherUIDNeverReadsCommand(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	writeProcFile(t, root, "10/status", statusFixture(uint32(os.Getuid()+1)))
	got := scanFixture(t, root, func(pid int, name string, n int, b []byte, e error) ([]byte, error) {
		if name != "status" {
			t.Fatalf("read other uid's %s", name)
		}
		return b, e
	})
	if len(got.Processes) != 0 || got.OtherUID != 1 || got.Unknown {
		t.Fatalf("other uid: %+v", got)
	}
}

func TestProcessSessionsAndOtherInterpreters(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/node", []byte("node\x00/lib/@openai/codex/bin/codex.js\x00"), 0)
	processFixture(t, root, 11, 10, 101, "/bin/codex", []byte("codex\x00"), 0)
	processFixture(t, root, 12, 11, 102, "/bin/python3", []byte("python3\x00secret.py\x00"), 7)
	processFixture(t, root, 20, 1, 100, "/bin/python3.12", []byte("python3\x00"+markerSecret+"\x00"), 7)
	processFixture(t, root, 21, 1, 100, "/bin/node", []byte("node\x00"+markerSecret+"\x00"), 0)
	processFixture(t, root, 22, 1, 100, "/bin/java", []byte("java\x00"+markerSecret+"\x00"), 0)
	writeProcFile(t, root, "22/cgroup", []byte("0::/user.slice/user-"+itoa(os.Getuid())+".slice/user@"+itoa(os.Getuid())+".service/app.slice/task.service\n"))
	got := scanFixture(t, root, nil)
	if got.Unknown || len(got.Processes) != 3 {
		t.Fatalf("grouping/G: %+v", got)
	}
	for _, v := range got.Processes {
		if v.PID != 10 && v.PID != 20 && v.PID != 22 {
			t.Fatalf("unexpected row %+v", v)
		}
		if v.Other && (v.Name != "" || v.RuleID != "") {
			t.Fatal("G has a copied or matched name")
		}
	}
}

func TestRunCgroupIsOnlyMembership(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	run := "r-0123abcd-0000000000000-abcdef"
	writeProcFile(t, root, "10/cgroup", []byte("0::/tego.slice/tego-agent.slice/run-"+run+".scope\n"))
	got := scanFixture(t, root, nil)
	if len(got.Processes) != 1 || got.Processes[0].RunID != run || got.Processes[0].Membership != "in-run" {
		t.Fatalf("membership %+v", got)
	}
}

type deniedProc struct{}

func (deniedProc) pids(context.Context) ([]int, error) { return nil, os.ErrPermission }
func (deniedProc) open(int) (processFiles, error)      { return nil, errors.New("unexpected open") }
func TestProcEnumerationDenied(t *testing.T) {
	got := readProcesses(context.Background(), deniedProc{}, "/proc", uint32(os.Getuid()), catalog.Rows())
	if got.Usable || !got.Unknown || len(got.Sources) != 1 || got.Sources[0].Reason != "permission" {
		t.Fatalf("denied enumeration: %+v", got)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestExitedLeaderUsesLiveThread(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	if e := os.Remove(filepath.Join(root, "10", "exe")); e != nil {
		t.Fatal(e)
	}
	processFixture(t, filepath.Join(root, "10", "task"), 11, 1, 101, "/bin/claude", []byte("claude\x00--key="+markerSecret+"\x00"), 0)
	got := scanFixture(t, root, nil)
	if got.Unknown || len(got.Processes) != 1 || got.Processes[0].PID != 10 || got.Processes[0].Start != 100 {
		t.Fatalf("leader identity was not preserved: %+v", got)
	}
	found := false
	for _, source := range got.Sources {
		if strings.HasSuffix(source.Path, "/10/exe") && source.Reason == "gone" {
			found = true
		}
	}
	if !found {
		t.Fatal("recovered leader read failure was hidden")
	}
}

func TestReusedParentDoesNotGroup(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 200, "/bin/claude", []byte("claude\x00"), 0)
	processFixture(t, root, 11, 10, 100, "/bin/codex", []byte("codex\x00"), 0)
	got := scanFixture(t, root, nil)
	if got.Unknown || len(got.Processes) != 2 {
		t.Fatalf("reused parent grouped a different identity: %+v", got)
	}
}

func TestRenamedUnknownAndNoTerminal(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/renamed", []byte("renamed\x00"+markerSecret+"\x00"), 0)
	processFixture(t, root, 11, 1, 100, "/bin/python3", []byte("python3\x00"+markerSecret+"\x00"), 0)
	got := scanFixture(t, root, nil)
	if got.Unknown || len(got.Processes) != 0 || got.Read != 2 {
		t.Fatalf("unknown names became found rows: %+v", got)
	}
}

func TestCustomRuleFacts(t *testing.T) {
	cases := []struct {
		name string
		rule sig.Rule
		want sig.Fact
	}{
		{"argv", sig.Rule{Name: "user-1", Argv: []string{"node", ".../project/agent.js"}}, sig.FactArgvPattern},
		{"path", sig.Rule{Name: "user-1", Path: "/opt/renamed"}, sig.FactPath},
		{"file identity", sig.Rule{Name: "user-1"}, sig.FactFileID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			exe := "/opt/renamed"
			if tc.want == sig.FactFileID {
				exe = filepath.Join(root, "program")
				writeProcFile(t, root, "program", []byte(markerSecret))
				var st unix.Stat_t
				if e := unix.Stat(exe, &st); e != nil {
					t.Fatal(e)
				}
				tc.rule.File = sig.FileID{Dev: uint64(st.Dev), Ino: st.Ino}
			}
			processFixture(t, root, 10, 1, 100, exe, []byte("node\x00--key="+markerSecret+"\x00/lib/project/agent.js\x00"), 0)
			fs, e := openProc(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fs.close()
			got := readProcesses(context.Background(), fs, root, uint32(os.Getuid()), []catalog.Row{{ID: "user-1", Rule: tc.rule}})
			if got.Unknown || len(got.Processes) != 1 || got.Processes[0].Fact != tc.want {
				t.Fatalf("custom fact: %+v", got)
			}
		})
	}
}

// generatedProc makes cap proofs independent of host process count and disk size.
type generatedProc struct {
	count     int
	largeArgv bool
	realistic bool
	opens     int
}

func (p *generatedProc) pids(context.Context) ([]int, error) {
	ids := make([]int, p.count)
	for i := range ids {
		ids[i] = i + 1
	}
	return ids, nil
}
func (p *generatedProc) open(pid int) (processFiles, error) {
	p.opens++
	return &generatedProcess{pid: pid, largeArgv: p.largeArgv, realistic: p.realistic}, nil
}

type generatedProcess struct {
	pid       int
	largeArgv bool
	realistic bool
}

func (p *generatedProcess) owner() (uint32, error) { return uint32(os.Getuid()), nil }
func (p *generatedProcess) read(name string, limit int) ([]byte, error) {
	var b []byte
	switch name {
	case "status":
		b = statusFixture(uint32(os.Getuid()))
		if p.realistic {
			b = append(b, []byte("Ignored: "+strings.Repeat("x", 1536-len(b)-10)+"\n")...)
		}
	case "stat":
		b = statFixture(p.pid, 0, 100, 0, "unknown")
		if p.realistic {
			b = bytes.TrimSuffix(b, []byte("\n"))
			b = append(b, []byte(strings.Repeat(" 0", 75)+"\n")...)
		}
	case "cmdline":
		if p.largeArgv {
			b = bytes.Repeat(append(bytes.Repeat([]byte{'x'}, 255), 0), 256)
		} else {
			b = []byte("unknown\x00")
			if p.realistic {
				b = append(b, append(bytes.Repeat([]byte{'x'}, 503), 0)...)
			}
		}
	default:
		return nil, errType
	}
	if len(b) > limit {
		return nil, errSize
	}
	return b, nil
}
func (*generatedProcess) link(name string) (string, error)     { return "/bin/unknown", nil }
func (*generatedProcess) fileID() (sig.FileID, error)          { return sig.FileID{}, errType }
func (*generatedProcess) tasks(context.Context) ([]int, error) { return nil, errType }
func (*generatedProcess) thread(int) (processFiles, error)     { return nil, errType }
func (*generatedProcess) close()                               {}

func TestSnapshotBudgetsAndCancellation(t *testing.T) {
	cases := []struct {
		name     string
		large    bool
		cancel   bool
		maxOpens int
	}{
		{"source rows", false, false, 2000},
		{"total bytes", true, false, 260},
		{"cancellation", false, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &generatedProc{count: 3000, largeArgv: tc.large}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			got := readProcesses(ctx, fs, "/proc", uint32(os.Getuid()), catalog.Rows())
			if !got.Unknown || !got.Limited || fs.opens > tc.maxOpens || len(got.Sources) > 2048 {
				t.Fatalf("cap not visible/bounded: opens=%d sources=%d unknown=%v limited=%v", fs.opens, len(got.Sources), got.Unknown, got.Limited)
			}
		})
	}
}

func TestOptionalCwdFailureIsDisclosed(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	if e := os.Remove(filepath.Join(root, "10", "cwd")); e != nil {
		t.Fatal(e)
	}
	got := scanFixture(t, root, nil)
	if got.Unknown || len(got.Processes) != 1 || got.Processes[0].Cwd != "" {
		t.Fatalf("optional detail changed identity/coverage: %+v", got)
	}
	found := false
	for _, s := range got.Sources {
		if strings.HasSuffix(s.Path, "/cwd") && s.Reason == "gone" {
			found = true
		}
	}
	if !found {
		t.Fatal("optional not-read path was hidden")
	}
}

func TestProcessCannotRetainSignatureAlias(t *testing.T) {
	for index, id := range []string{"user-1", markerSecret} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/renamed", []byte("renamed\x00"+markerSecret+"\x00"), 0)
			fs, e := openProc(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fs.close()
			got := readProcesses(context.Background(), fs, root, uint32(os.Getuid()), []catalog.Row{{ID: id, Rule: sig.Rule{Name: markerSecret, Basename: "renamed"}}})
			b, e := json.Marshal(got)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(b), markerSecret) {
				t.Fatal("signature alias escaped into retained data")
			}
			if id == "user-1" && (len(got.Processes) != 1 || got.Processes[0].Name != "user-1") {
				t.Fatal("numbered rule was not retained")
			}
			if id == markerSecret && (!got.Unknown || len(got.Processes) != 0) {
				t.Fatal("unknown rule identifier was retained")
			}
		})
	}
}

func TestCyclicAncestryKeepsIndependentEvidence(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 11, 100, "/bin/claude", []byte("claude\x00"), 0)
	processFixture(t, root, 11, 10, 100, "/bin/codex", []byte("codex\x00"), 0)
	got := scanFixture(t, root, nil)
	if !got.Unknown || len(got.Processes) != 2 {
		t.Fatalf("hostile parent graph hid evidence or coverage: %+v", got)
	}
}

func TestReusedAncestorDoesNotGroup(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 950, "/bin/claude", []byte("claude\x00"), 0)
	processFixture(t, root, 11, 10, 900, "/bin/worker", []byte("worker\x00"), 0)
	processFixture(t, root, 12, 11, 1000, "/bin/node", []byte("node\x00"), 7)
	got := scanFixture(t, root, nil)
	if got.Unknown || len(got.Processes) != 2 || got.Processes[1].PID != 12 {
		t.Fatalf("reused ancestor grouped an unrelated interpreter: %+v", got)
	}
}

func TestThreadFallbackUsesThreadComm(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/other", []byte("other\x00"), 0)
	writeProcFile(t, root, "10/stat", statFixture(10, 1, 100, 0, "claude"))
	if err := os.Remove(filepath.Join(root, "10/exe")); err != nil {
		t.Fatal(err)
	}
	processFixture(t, filepath.Join(root, "10/task"), 11, 1, 101, "/bin/other", []byte("other\x00"), 0)
	got := scanFixture(t, root, nil)
	if len(got.Processes) != 0 {
		t.Fatal("dead leader comm classified a different live thread")
	}
	writeProcFile(t, root, "10/stat", statFixture(10, 1, 100, 0, "worker"))
	writeProcFile(t, root, "10/task/11/stat", statFixture(11, 1, 101, 0, "codex"))
	got = scanFixture(t, root, nil)
	if len(got.Processes) != 1 || got.Processes[0].Fact != sig.FactCommName || got.Processes[0].Name != "codex" {
		t.Fatal("live thread comm was not classified")
	}
}

func TestGroupingPreservesIndependentMembership(t *testing.T) {
	run := "r-0123abcd-0000000000000-abcdef"
	for _, tc := range []struct{ name, exe, cg string }{
		{"outside child", "claude", "0::/user.slice\n"},
		{"other run", "claude", "0::/tego.slice/tego-agent.slice/run-r-0123abcd-0000000000001-abcdef.scope\n"},
		{"unknown child", "claude", "malformed"},
		{"different agent", "codex", "0::/tego.slice/tego-agent.slice/run-" + run + ".scope\n"},
		{"outside interpreter", "node", "0::/user.slice\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
			writeProcFile(t, root, "10/cgroup", []byte("0::/tego.slice/tego-agent.slice/run-"+run+".scope\n"))
			processFixture(t, root, 11, 10, 101, "/bin/"+tc.exe, []byte(tc.exe+"\x00"), 7)
			writeProcFile(t, root, "11/cgroup", []byte(tc.cg))
			got := scanFixture(t, root, nil)
			if len(got.Processes) != 2 {
				t.Fatalf("grouping hid independent evidence: %+v", got)
			}
		})
	}
}

func TestFileIdentityRechecked(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/other", []byte("other\x00"), 0)
	fs, err := openProc(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.close()
	calls := 0
	want := sig.FileID{Dev: 1, Ino: 2}
	spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, fileHook: func(_ int, _ sig.FileID, _ error) (sig.FileID, error) {
		calls++
		if calls == 1 {
			return want, nil
		}
		return sig.FileID{Dev: 1, Ino: 3}, nil
	}}
	got := readProcesses(context.Background(), spy, root, uint32(os.Getuid()), []catalog.Row{{ID: "user-1", Rule: sig.Rule{Name: "user-1", File: want}}})
	if len(got.Processes) != 0 || !got.Unknown {
		t.Fatal("replaced executable inode retained a file-id match")
	}
}

// Read counters via JSON so the old-source overlay can run the regression tests.
func snapshotCounter(t *testing.T, got processSnapshot, name string) int {
	t.Helper()
	b, e := json.Marshal(got)
	if e != nil {
		t.Fatal(e)
	}
	var values map[string]json.RawMessage
	if e := json.Unmarshal(b, &values); e != nil {
		t.Fatal(e)
	}
	var n int
	if raw := values[name]; raw != nil {
		if e := json.Unmarshal(raw, &n); e != nil {
			t.Fatal(e)
		}
	}
	return n
}

func TestExitedAndKernelProcessesAreNotCoverageGaps(t *testing.T) {
	for _, kind := range []string{"zombie", "kernel-thread", "vanished-open", "vanished-status", "vanished-stat", "vanished-argv", "vanished-recheck"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
			uid := uint32(os.Getuid())
			if kind == "zombie" || kind == "kernel-thread" {
				b := statFixture(10, 1, 100, 0, "private-kernel-name")
				if kind == "zombie" {
					b = bytes.Replace(b, []byte(") S "), []byte(") Z "), 1)
				} else {
					fields := strings.Fields(string(b[bytes.LastIndex(b, []byte(") "))+2:]))
					fields[6] = "2097152" // PF_KTHREAD, field 9 of /proc/pid/stat.
					b = []byte("10 (private-kernel-name) " + strings.Join(fields, " ") + "\n")
					uid = 0
					writeProcFile(t, root, "10/status", statusFixture(0))
				}
				writeProcFile(t, root, "10/stat", b)
				if e := os.Remove(filepath.Join(root, "10/exe")); e != nil {
					t.Fatal(e)
				}
				if e := os.MkdirAll(filepath.Join(root, "10/task"), 0700); e != nil {
					t.Fatal(e)
				}
			}
			fs, e := openProc(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fs.close()
			spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}}
			if kind == "kernel-thread" {
				spy.ownerHook = func(int, uint32, error) (uint32, error) { return 0, nil }
			}
			spy.openHook = func(int) error {
				if kind == "vanished-open" {
					return unix.ESRCH
				}
				return nil
			}
			spy.hook = func(_ int, name string, n int, b []byte, e error) ([]byte, error) {
				if kind == "vanished-status" && name == "status" && n == 1 || kind == "vanished-stat" && name == "stat" && n == 1 || kind == "vanished-argv" && name == "cmdline" || kind == "vanished-recheck" && name == "stat" && n == 2 {
					return nil, os.ErrNotExist
				}
				return b, e
			}
			got := readProcesses(context.Background(), spy, root, uid, catalog.Rows())
			counter := "Exited"
			if kind == "kernel-thread" {
				counter = "KernelThreads"
			}
			if got.Unknown || !got.Usable || len(got.Processes) != 0 || snapshotCounter(t, got, counter) != 1 {
				t.Fatalf("ended/kernel process became coverage gap or evidence: %+v", got)
			}
			for _, source := range got.Sources {
				if source.NotRead != 0 {
					t.Fatalf("ended/kernel process retained failure detail: %+v", source)
				}
			}
		})
	}
}

func TestUnreadableOwnProgramIsCountedWithoutMatchInput(t *testing.T) {
	for _, rootOwned := range []bool{false, true} {
		t.Run(strconv.FormatBool(rootOwned), func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/claude", []byte(markerSecret+"\x00"), 0)
			fs, e := openProc(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fs.close()
			spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}}
			spy.ownerHook = func(_ int, uid uint32, e error) (uint32, error) {
				if rootOwned {
					return 0, nil
				}
				return uid, e
			}
			spy.linkHook = func(_ int, name, value string, e error) (string, error) {
				if name == "exe" {
					return "", os.ErrPermission
				}
				return value, e
			}
			spy.hook = func(_ int, name string, _ int, b []byte, e error) ([]byte, error) {
				if name == "cmdline" || name == "cgroup" {
					t.Fatalf("unreadable program read match input %s", name)
				}
				return b, e
			}
			got := readProcesses(context.Background(), spy, root, uint32(os.Getuid()), catalog.Rows())
			encoded, e := json.Marshal(got)
			if e != nil {
				t.Fatal(e)
			}
			var fields struct{ UnreadablePIDs []int }
			if e := json.Unmarshal(encoded, &fields); e != nil {
				t.Fatal(e)
			}
			if got.Unknown || len(got.Processes) != 0 || !reflect.DeepEqual(fields.UnreadablePIDs, []int{10}) {
				t.Fatalf("unreadable own program misclassified: %+v", got)
			}
			found := false
			for _, s := range got.Sources {
				if s.State == "unreadable-program" && s.Reason == "permission" && s.NotRead == 1 && !s.Critical {
					found = true
				}
			}
			if !found {
				t.Fatalf("unreadable exception omitted: %+v", got.Sources)
			}
			if bytes.Contains(encoded, []byte(markerSecret)) {
				t.Fatal("unreadable process match input leaked")
			}
		})
	}
}

func TestPerProcessBudgetKeepsLaterProcesses(t *testing.T) {
	fs := &generatedProc{count: 2}
	budget := &budgetProc{procAccess: fs, remaining: 16 << 20}
	p, e := budget.open(1)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	limited := false
	for i := 0; i < 6; i++ {
		_, e := p.read("cgroup", 64<<10) // rejected input still consumes the attempted read bound
		if errors.Is(e, errLimit) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("one process can spend more than its 256 KiB read budget")
	}
	later, e := budget.open(2)
	if e != nil {
		t.Fatal(e)
	}
	defer later.close()
	if _, e := later.read("status", maxProcText); e != nil {
		t.Fatalf("one process exhausted a later process's budget: %v", e)
	}
}

func TestProcessBudgetMeasurementAndHeadroom(t *testing.T) {
	fs := &generatedProc{count: 1000, realistic: true}
	const total = 8 << 20
	budget := &budgetProc{procAccess: fs, remaining: total}
	got := readProcesses(context.Background(), budget, "/proc", uint32(os.Getuid()), catalog.Rows())
	used := total - budget.remaining
	t.Logf("1000 processes: %d bytes read/charged; total %d bytes, headroom %.2fx", used, total, float64(total)/float64(used))
	if got.Unknown || got.Read != 1000 || used < 3<<20 || used > total/2 {
		t.Fatalf("measurement lacks twofold headroom: used=%d read=%d unknown=%v", used, got.Read, got.Unknown)
	}
}

func TestProcessStateTransitionsDoNotChangeIdentity(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	got := scanFixture(t, root, func(_ int, name string, n int, b []byte, e error) ([]byte, error) {
		if name == "stat" && n == 2 {
			b = bytes.Replace(b, []byte(") S "), []byte(") R "), 1)
		}
		return b, e
	})
	if got.Unknown || len(got.Processes) != 1 {
		t.Fatalf("normal scheduling state changed identity: %+v", got)
	}
}

func TestExitedThreadRecheckIsCountedWithoutDetails(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	if e := os.Remove(filepath.Join(root, "10/exe")); e != nil {
		t.Fatal(e)
	}
	processFixture(t, filepath.Join(root, "10/task"), 11, 1, 101, "/bin/claude", []byte("claude\x00"), 0)
	got := scanFixture(t, root, func(pid int, name string, n int, b []byte, e error) ([]byte, error) {
		if pid == 11 && name == "stat" && n == 2 {
			return nil, os.ErrNotExist
		}
		return b, e
	})
	if got.Unknown || len(got.Processes) != 0 || snapshotCounter(t, got, "Exited") != 1 {
		t.Fatalf("thread exit became gap or evidence: %+v", got)
	}
	for _, source := range got.Sources {
		if source.NotRead != 0 {
			t.Fatalf("exited thread retained source detail: %+v", source)
		}
	}
}

func TestUnreadableProgramPIDsFollowRetainedSources(t *testing.T) {
	fs := &unreadableGeneratedProc{generatedProc: generatedProc{count: 3000}}
	got := readProcesses(context.Background(), fs, "/"+strings.Repeat("x", 3900), uint32(os.Getuid()), catalog.Rows())
	b, e := json.Marshal(got)
	if e != nil {
		t.Fatal(e)
	}
	var fields struct{ UnreadablePIDs []int }
	if e := json.Unmarshal(b, &fields); e != nil {
		t.Fatal(e)
	}
	sources := 0
	for _, source := range got.Sources {
		if source.State == "unreadable-program" {
			sources++
		}
	}
	if !got.Limited || !got.Unknown || len(fields.UnreadablePIDs) != sources {
		t.Fatalf("unreadable pids outlived sources: pids=%d sources=%d limited=%v unknown=%v", len(fields.UnreadablePIDs), sources, got.Limited, got.Unknown)
	}
}

type unreadableGeneratedProc struct{ generatedProc }

func (p *unreadableGeneratedProc) open(pid int) (processFiles, error) {
	f, e := p.generatedProc.open(pid)
	if e != nil {
		return nil, e
	}
	if pid <= 100 {
		return f, nil
	}
	return &unreadableGeneratedProcess{processFiles: f}, nil
}

type unreadableGeneratedProcess struct{ processFiles }

func (p *unreadableGeneratedProcess) link(name string) (string, error) {
	if name == "exe" {
		return "", os.ErrPermission
	}
	return p.processFiles.link(name)
}

func TestUnclassifiedLiveThreadRemainsCoverageGap(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	writeProcFile(t, root, "10/stat", bytes.Replace(statFixture(10, 1, 100, 0, "worker"), []byte(") S "), []byte(") Z "), 1))
	if e := os.Remove(filepath.Join(root, "10/exe")); e != nil {
		t.Fatal(e)
	}
	processFixture(t, filepath.Join(root, "10/task"), 11, 1, 101, "/bin/claude", []byte("claude\x00"), 0)
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, linkHook: func(pid int, name, value string, e error) (string, error) {
		if pid == 11 && name == "exe" {
			return "", os.ErrPermission
		}
		return value, e
	}}
	got := readProcesses(context.Background(), spy, root, uint32(os.Getuid()), catalog.Rows())
	if !got.Unknown || len(got.Processes) != 0 || snapshotCounter(t, got, "Exited") != 0 {
		t.Fatalf("unclassified live thread was treated as exited: %+v", got)
	}
}

func TestExitedSelectedThreadCannotHideAnotherLiveThread(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	if e := os.Remove(filepath.Join(root, "10/exe")); e != nil {
		t.Fatal(e)
	}
	for _, tid := range []int{11, 12} {
		processFixture(t, filepath.Join(root, "10/task"), tid, 1, uint64(100+tid), "/bin/claude", []byte("claude\x00"), 0)
	}
	got := scanFixture(t, root, func(pid int, name string, n int, b []byte, e error) ([]byte, error) {
		if pid == 11 && name == "stat" && n == 2 {
			return nil, os.ErrNotExist
		}
		return b, e
	})
	if !got.Unknown || len(got.Processes) != 0 || snapshotCounter(t, got, "Exited") != 0 {
		t.Fatalf("live group hidden by task exit: %+v", got)
	}
}

func TestRootOwnedZombieHasNoLiveProgram(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(strconv.FormatBool(denied), func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
			writeProcFile(t, root, "10/status", statusFixture(123))
			writeProcFile(t, root, "10/stat", bytes.Replace(statFixture(10, 1, 100, 0, "private-name"), []byte(") S "), []byte(") Z "), 1))
			if e := os.Remove(filepath.Join(root, "10/exe")); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(filepath.Join(root, "10/task"), 0700); e != nil {
				t.Fatal(e)
			}
			fs, e := openProc(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fs.close()
			spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(int, uint32, error) (uint32, error) { return 0, nil }, linkHook: func(_ int, name, value string, e error) (string, error) {
				if denied && name == "exe" {
					return "", os.ErrPermission
				}
				return value, e
			}}
			got := readProcesses(context.Background(), spy, root, 123, catalog.Rows())
			if got.Unknown || len(got.Processes) != 0 || snapshotCounter(t, got, "Exited") != 1 {
				t.Fatalf("root-owned zombie became live gap: %+v", got)
			}
			for _, source := range got.Sources {
				if source.NotRead != 0 {
					t.Fatalf("zombie retained failure details: %+v", source)
				}
			}
		})
	}
}

func TestRootOwnedExitedLeaderUsesCallerOwnedLiveThread(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(strconv.FormatBool(denied), func(t *testing.T) {
			root := t.TempDir()
			processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
			writeProcFile(t, root, "10/status", statusFixture(123))
			writeProcFile(t, root, "10/stat", bytes.Replace(statFixture(10, 1, 100, 0, "private-name"), []byte(") S "), []byte(") Z "), 1))
			if e := os.Remove(filepath.Join(root, "10/exe")); e != nil {
				t.Fatal(e)
			}
			processFixture(t, filepath.Join(root, "10/task"), 11, 1, 101, "/bin/claude", []byte("claude\x00"), 0)
			writeProcFile(t, root, "10/task/11/status", statusFixture(123))
			fs, e := openProc(root)
			if e != nil {
				t.Fatal(e)
			}
			defer fs.close()
			spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(pid int, _ uint32, _ error) (uint32, error) {
				if pid == 10 {
					return 0, nil
				}
				return 123, nil
			}, linkHook: func(pid int, name, value string, e error) (string, error) {
				if denied && pid == 11 && name == "exe" {
					return "", os.ErrPermission
				}
				return value, e
			}}
			got := readProcesses(context.Background(), spy, root, 123, catalog.Rows())
			if snapshotCounter(t, got, "Exited") != 0 || got.Unknown != denied {
				t.Fatalf("live task identity lost: %+v", got)
			}
			if denied && len(got.Processes) != 0 || !denied && (len(got.Processes) != 1 || got.Processes[0].Name != "claude") {
				t.Fatalf("live task classification: %+v", got)
			}
		})
	}
}

func TestRootOwnedProcessCanExitDuringRead(t *testing.T) {
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	writeProcFile(t, root, "10/status", statusFixture(123))
	if e := os.Remove(filepath.Join(root, "10/exe")); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(root, "10/task"), 0700); e != nil {
		t.Fatal(e)
	}
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(int, uint32, error) (uint32, error) { return 0, nil }}
	got := readProcesses(context.Background(), spy, root, 123, catalog.Rows())
	if got.Unknown || len(got.Processes) != 0 || snapshotCounter(t, got, "Exited") != 1 {
		t.Fatalf("root-owned process exit became owner gap: %+v", got)
	}
}
