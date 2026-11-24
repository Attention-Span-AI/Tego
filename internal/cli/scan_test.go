// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/scan"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// Fit Linux's 15-byte comm name so the fixture uses a possible kernel name.
const scanCanary = "SCAN_SECRET_53"

func fixtureScanCommand(t *testing.T) (scan.Options, []string) {
	t.Helper()
	f := newFakeProcRoot(t)
	home := t.TempDir()
	// Permission-policy tests use explicit writable layouts elsewhere. Keep this
	// command/privacy fixture independent of the temporary directory's mode.
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	f.add(10, 1, "self", scanCanary, []string{"self", scanCanary}, "/user.slice", "TOKEN="+scanCanary+"\x00")
	// The program and cwd paths remain safe to display. Only argv[0] identifies
	// this process as Claude, so this also covers the argv0-name evidence path.
	f.add(20, 1, "worker", scanCanary, []string{"/opt/" + scanCanary + "/claude", "--token=" + scanCanary}, "/user.slice/"+scanCanary+".slice", "TOKEN="+scanCanary+"\x00")
	f.add(30, 1, "node", scanCanary, []string{"node", "/opt/@google/gemini-cli/dist/index.js", scanCanary}, "/user.slice", "TOKEN="+scanCanary+"\x00")
	f.add(40, 1, "python3", scanCanary, []string{"python3", "bot.py", scanCanary}, "/user.slice/user-"+fmt.Sprint(uid)+".slice/user@"+fmt.Sprint(uid)+".service/app.slice/"+scanCanary+".service", "TOKEN="+scanCanary+"\x00")
	watched := []string{}
	for _, pid := range []string{"10", "20", "30", "40"} {
		status := fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\nNSpid:\t10\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n", uid, uid, uid, uid)
		writeTestFile(t, filepath.Join(f.root, pid, "status"), status)
		if err := os.Symlink(home, filepath.Join(f.root, pid, "cwd")); err != nil {
			t.Fatal(err)
		}
		watched = append(watched, filepath.Join(f.root, pid, "environ"))
	}
	for rel, contents := range map[string]string{
		".claude/settings.json": fmt.Sprintf("{%q:%q}\n", scanCanary, scanCanary),
		".codex/config.toml":    fmt.Sprintf("%q = %q\n", scanCanary, scanCanary),
		".gemini/settings.json": fmt.Sprintf("{%q:%q}\n", scanCanary, scanCanary),
		".env":                  scanCanary + "=" + scanCanary + "\n",
		".claude/auth.json":     fmt.Sprintf("{%q:%q}\n", scanCanary, scanCanary),
	} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, p, contents)
		if rel != ".codex/config.toml" && rel != ".gemini/settings.json" {
			watched = append(watched, p)
		}
	}
	for rel, content := range map[string]string{
		"package.json":     fmt.Sprintf(`{"name":%q,"author":%q,"scripts":{"start":%q},"dependencies":{"@openai/codex":%q,"@langchain/langgraph":%q,%q:%q},"url":%q}`, scanCanary, scanCanary, scanCanary, "https://user:"+scanCanary+"@example.invalid/"+scanCanary, scanCanary, "unknown-"+scanCanary, scanCanary, "https://"+scanCanary),
		"requirements.txt": "# " + scanCanary + "\nlanggraph==" + scanCanary + " # " + scanCanary + "\ncrewai>=1; python_version != '" + scanCanary + "'\nunknown-" + scanCanary + "==1\n",
	} {
		writeTestFile(t, filepath.Join(home, rel), content)
	}
	for _, rel := range []string{"langgraph.json", "crew.jsonc", "config/agents.yaml", scanCanary + ".txt", scanCanary + "/package.json", "requirements-" + scanCanary + ".txt", "pyproject.toml"} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, p, scanCanary)
		watched = append(watched, p)
	}

	install := filepath.Join(home, ".local/bin/claude")
	if err := os.MkdirAll(filepath.Dir(install), 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, install, scanCanary)
	if err := os.Chmod(install, 0700); err != nil {
		t.Fatal(err)
	}
	watched = append(watched, install)
	passwd := filepath.Join(home, "passwd")
	writeTestFile(t, passwd, fmt.Sprintf("me:x:%d:42:%s:%s:/bin/sh\n", uid, scanCanary, home))
	boot := filepath.Join(home, "boot")
	writeTestFile(t, boot, "01234567-89ab-cdef-0123-456789abcdef\n")
	oldInputs, oldRoot := scanInputs, scanLedgerRoot
	o := scan.Options{ReadCallerPasswd: os.ReadFile, ProcRoot: f.root, Passwd: passwd, Boot: boot, Directory: home, Path: "", Version: "dev", Caller: scan.Caller{UID: uid, EUID: uid, PID: 10, CgroupNamespace: runscope.InitCgroupNS, PIDNamespace: scan.InitPIDNS, Membership: answertest.Outside()}, OnProcRead: func(p string) {
		if strings.HasSuffix(p, "/environ") {
			t.Fatal("command attempted environ open")
		}
	}}
	scanInputs = func() scan.Options { return o }
	scanLedgerRoot = func(string, uint32) (string, error) { return filepath.Join(home, "runs"), nil }
	t.Cleanup(func() { scanInputs, scanLedgerRoot = oldInputs, oldRoot })
	return o, watched
}

func openTripwire(t *testing.T, paths []string) func() {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	for _, p := range paths {
		if _, err = unix.InotifyAddWatch(fd, p, unix.IN_OPEN|unix.IN_ACCESS); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		t.Helper()
		buf := make([]byte, 64<<10)
		n, err := unix.Read(fd, buf)
		if n > 0 {
			t.Fatal("command data-opened environment, settings, auth, source or program contents")
		}
		if err != nil && err != unix.EAGAIN {
			t.Fatal(err)
		}
	}
}

// TestScanWholeCommandPrivacy exercises Main, not a renderer or collector substitute.
// Every command line, comm, environment, selected cgroup and unit component, and
// settings key contains the same secret. Exe and cwd paths contain no secret.
func TestScanWholeCommandPrivacy(t *testing.T) {
	t.Setenv("TEGO_HINTS", "off")
	o, watched := fixtureScanCommand(t)
	checkOpens := openTripwire(t, watched)
	cache := filepath.Join(o.Directory, ".tego/scan/last.json")
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"short", nil, 0}, {"full", []string{"--verbose"}, 0}, {"json", []string{"--json"}, 0}, {"check", []string{"--check"}, 1}, {"all mine", []string{"--all-mine", "-v"}, 0}, {"json check", []string{"--json", "--check"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _ := os.ReadFile(cache)
			code, out, errs := run(t, append([]string{"scan"}, tc.args...)...)
			if code != tc.code {
				t.Fatalf("exit %d: %s %s", code, out, errs)
			}
			saved, err := os.ReadFile(cache)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range []string{out, errs, string(saved)} {
				if strings.Contains(b, scanCanary) {
					t.Fatal("marker leaked")
				}
			}
			if strings.Contains(strings.Join(tc.args, " "), "--check") && !bytes.Equal(before, saved) {
				t.Fatal("check wrote cache")
			}
			if !strings.Contains(errs, "Not looked at:") || !strings.Contains(errs, "agents under a name no rule knows") {
				t.Fatal("footer suppressed")
			}
			if _, err := result.Decode(saved); err != nil {
				t.Fatal("saved JSON invalid", err)
			}
			if strings.Contains(strings.Join(tc.args, " "), "--json") {
				if !strings.Contains(strings.Join(tc.args, " "), "--check") && !bytes.Equal([]byte(out), saved) {
					t.Fatal("JSON stdout and saved object differ")
				}
				var wire any
				if err := json.Unmarshal([]byte(out), &wire); err != nil {
					t.Fatal(err)
				}
				if err := jsonschema.Check("../../spec/scan/v1/schema.json", wire); err != nil {
					t.Fatal(err)
				}
				s, err := result.Decode([]byte(out))
				if err != nil {
					t.Fatal(err)
				}
				if s.Counts.Running != 2 || s.Counts.Settings != 3 || s.Counts.Installed != 1 || s.Counts.Other != 1 || s.Counts.Project != 7 {
					t.Fatalf("missing kinds: %+v", s.Counts)
				}
				argv0Matched := false
				for _, item := range s.Items {
					if item.Kind == "process" && item.Process().PID == 20 {
						argv0Matched = len(item.Evidence) == 1 && item.Evidence[0].Fact == "argv0-name"
					}
				}
				if !argv0Matched {
					t.Fatal("marker-bearing argv[0] did not exercise argv0-name")
				}
			}
			checkOpens()
		})
	}
}

func TestScanUsageAndCheckNoSave(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	for _, args := range [][]string{{"extra"}, {"--signature", "bad=" + scanCanary + " /bad/["}, {"--signature", strings.Repeat("x", 4097)}} {
		code, out, errs := run(t, append([]string{"scan"}, args...)...)
		if code != 2 || out != "" || !strings.Contains(errs, "usage: tego scan") || strings.Contains(errs, scanCanary) || strings.Contains(errs, "Not looked at") {
			t.Fatalf("usage response %d %q %q", code, out, errs)
		}
	}
	code, _, _ := run(t, "scan", "--check")
	if code != 1 {
		t.Fatal(code)
	}
	if _, err := os.Stat(filepath.Join(o.Directory, ".tego")); !os.IsNotExist(err) {
		t.Fatal("check created state")
	}
}

func TestScanUsageShowsAdvancedScope(t *testing.T) {
	fixtureScanCommand(t)
	for _, flag := range []string{"-h", "--help"} {
		code, out, errs := run(t, "scan", flag)
		if code != 0 || !strings.Contains(out+errs, "-advanced") || !strings.Contains(errs, "allow-unreadable-programs") {
			t.Fatalf("help omitted advanced scope or check policy: %d %q %q", code, out, errs)
		}
	}
	code, out, errs := run(t, "scan", "--allow-unreadable-programs")
	if code != 2 || out != "" || !strings.Contains(errs, "usage: tego scan") {
		t.Fatalf("check allowance accepted without --check: %d %q %q", code, out, errs)
	}
}

func TestScanHelpExplainsUnreadableAgentUncertainty(t *testing.T) {
	fixtureScanCommand(t)
	for _, flag := range []string{"-h", "--help"} {
		code, out, errs := run(t, "scan", flag)
		for _, want := range []string{
			"Tego cannot tell whether these are agents; any program can make itself unreadable.",
			"exit 0 does NOT mean no agent runs outside Tego",
		} {
			if code != 0 || !strings.Contains(out+errs, want) {
				t.Fatalf("help omits %q: %d %q %q", want, code, out, errs)
			}
		}
	}
}

func TestScanRefusalAndPanic(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	for _, args := range [][]string{{"--advanced"}, {"--advanced", "--json"}, {"--advanced", "--check"}} {
		code, out, errs := run(t, append([]string{"scan"}, args...)...)
		if code != 125 || !strings.Contains(out+errs, "scan-not-performed") {
			t.Fatalf("refusal %d %s %s", code, out, errs)
		}
	}
	old := scanCollect
	scanCollect = func(_ context.Context, _ scan.Options) scan.Outcome { panic(scanCanary) }
	t.Cleanup(func() { scanCollect = old })
	code, out, errs := run(t, "scan", "--json")
	if code != 125 || strings.Contains(out+errs, scanCanary) {
		t.Fatal("panic leaked")
	}
	if _, err := os.Stat(filepath.Join(o.Directory, ".tego")); !os.IsNotExist(err) {
		t.Fatal("refusal saved")
	}
}

func TestScanOutputFailure(t *testing.T) {
	fixtureScanCommand(t)
	code := Main([]string{"tego", "scan", "--check"}, scanBrokenWriter{}, io.Discard)
	if code != 125 {
		t.Fatal(code)
	}
}

type scanBrokenWriter struct{}

func (scanBrokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestAgentsAdditiveScanDisclosure(t *testing.T) {
	// The frozen legacy cases have exact stdout and stderr. Removing only the
	// additive disclosure must reproduce every original byte, including JSONL.
	sandboxAgents(t, t.TempDir(), true)
	t.Setenv("TEGO_HINTS", "off")
	for _, asJSON := range []bool{false, true} {
		args := []string{}
		wantOut := "no agent process is running\n"
		if asJSON {
			args = []string{"--json"}
			wantOut = ""
		}
		code, out, errs := runAgentsCmd(t, args...)
		addition := "tego agents: rules " + ruleNames(sig.Default()) + "; for another name, use tego watch -- " + startPlaceholder + "\n"
		legacy := "tego agents: looking for " + ruleNames(sig.Default()) + " (add another with --signature); this only observes and never signals, moves, blocks or changes a process\n"
		if code != 0 || out != wantOut || strings.Count(errs, addition) != 1 || strings.Replace(errs, addition, "", 1) != legacy {
			t.Fatalf("legacy output changed: %d %q %q", code, out, errs)
		}
	}
	agentsPrivileged = func() bool { return false }
	code, out, errs := runAgentsCmd(t)
	addition := "to look for your own agents without root: tego scan\n"
	legacy := agentsPrivilegeMessage(sig.Default(), false) + " [privilege]\n" + "to record any agent without root, start it under tego watch -- " + startPlaceholder + "\n"
	if code != 125 || out != "" || strings.Replace(errs, addition, "", 1) != legacy {
		t.Fatalf("refusal changed %d %q %q", code, out, errs)
	}
}

func TestScanNeverOpensEnvironment(t *testing.T) {
	_, watched := fixtureScanCommand(t)
	check := openTripwire(t, watched)
	code, _, _ := run(t, "scan", "--check")
	if code != 1 {
		t.Fatal(code)
	}
	check()
}

func TestScanSaveFailureReportsReads(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	for _, pid := range []string{"20", "30", "40"} {
		if err := os.RemoveAll(filepath.Join(o.ProcRoot, pid)); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{".claude", ".codex", ".gemini", ".local"} {
		if err := os.RemoveAll(filepath.Join(o.Directory, rel)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(o.Directory, ".tego/scan"), 0755); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "scan")
	if code != 125 || !strings.Contains(errs, "chmod 700") || strings.Contains(out, "Read: none; scan not performed.") {
		t.Fatalf("incorrect save failure: %d %s %s", code, out, errs)
	}
	code, _, _ = run(t, "scan", "--check")
	if code != 0 {
		t.Fatal("save failure influenced check", code)
	}
}

func TestScanRecordWording(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	writeTestFile(t, filepath.Join(o.ProcRoot, "20/cgroup"), "0::"+agentsRunCG+"\n")
	code, out, errs := run(t, "scan")
	fallback := "in a cgroup named for run " + agentsRunID + "; could not be checked against the record"
	if code != 0 || !strings.Contains(out, fallback) || strings.Contains(out, "in Tego run ") || !strings.Contains(errs, "reason gone") {
		t.Fatalf("cgroup promoted %d %s %s", code, out, errs)
	}
	root := filepath.Join(o.Directory, "runs")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, agentsRunID), record.RunRef{ID: agentsRunID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = w.Close(record.RunEndPayload{Reason: "exit"})
		}
	}()
	if err = w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Capture: "forwarder", Command: []string{scanCanary}}); err != nil {
		t.Fatal(err)
	}
	code, out, errs = run(t, "scan")
	if code != 0 || !strings.Contains(out, "in Tego run "+agentsRunID) || strings.Contains(out+errs, scanCanary) {
		t.Fatalf("live record %d %s %s", code, out, errs)
	}
	if err = w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
		t.Fatal(err)
	}
	closed = true
	code, out, errs = run(t, "scan")
	if code != 0 || !strings.Contains(out, fallback) || !strings.Contains(errs, "reason not-live") {
		t.Fatalf("ended record promoted or reason omitted: %d %s %s", code, out, errs)
	}
}

func TestScanRecordProbeCountsAsSource(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	writeTestFile(t, filepath.Join(o.ProcRoot, "20/cgroup"), "0::"+agentsRunCG+"\n")
	code, out, errs := run(t, "scan", "--check", "--json")
	if code != 1 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	s, err := result.Decode([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range s.Sources {
		if source.Locator != nil && *source.Locator == filepath.Join(o.Directory, "runs", agentsRunID) {
			if source.State != "not-read" || source.Reason != "gone" || source.NotRead != 1 || source.Read != 0 {
				t.Fatalf("record attempt not counted: %+v", source)
			}
			return
		}
	}
	t.Fatal("record source not reported")
}

func TestScanCheckExitTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{{"none", 0}, {"unknown", 125}, {"child namespace", 125}, {"outside priority", 1}, {"sudo", 125}} {
		t.Run(tc.name, func(t *testing.T) {
			o, _ := fixtureScanCommand(t)
			if tc.name != "outside priority" {
				for _, pid := range []string{"20", "30"} {
					if err := os.RemoveAll(filepath.Join(o.ProcRoot, pid)); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch tc.name {
			case "unknown", "outside priority":
				if err := os.Mkdir(filepath.Join(o.ProcRoot, "99"), 0700); err != nil {
					t.Fatal(err)
				}
				// A missing status describes an exited process. Malformed live
				// metadata is an actual classification gap, even when run as root.
				writeTestFile(t, filepath.Join(o.ProcRoot, "99/status"), "Uid: unreadable\n")
			case "child namespace":
				p := filepath.Join(o.ProcRoot, "10/status")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, p, strings.Replace(string(b), "NSpid:\t10", "NSpid:\t10 1", 1))
			case "sudo":
				o.Caller.Sudo = true
				scanInputs = func() scan.Options { return o }
			}
			code, out, errs := run(t, "scan", "--check", "--json")
			if code != tc.code {
				t.Fatalf("exit %d %s %s", code, out, errs)
			}
			if _, err := result.Decode([]byte(out)); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(o.Directory, ".tego")); !os.IsNotExist(err) {
				t.Fatal("check saved")
			}
		})
	}
}

func TestScanExitedAndKernelProcessesDoNotMakeCheckUnknown(t *testing.T) {
	for _, name := range []string{"zombie", "kernel thread", "vanished before open", "vanished at first read", "vanished mid-read"} {
		t.Run(name, func(t *testing.T) {
			o, _ := fixtureScanCommand(t)
			for _, pid := range []string{"20", "30", "40"} {
				if err := os.RemoveAll(filepath.Join(o.ProcRoot, pid)); err != nil {
					t.Fatal(err)
				}
			}
			dir := filepath.Join(o.ProcRoot, "99")
			if err := os.MkdirAll(filepath.Join(dir, "task/99"), 0700); err != nil {
				t.Fatal(err)
			}
			if name != "vanished at first read" {
				status, err := os.ReadFile(filepath.Join(o.ProcRoot, "10/status"))
				if err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(dir, "status"), string(status))
				state, flags := "S", 0
				if name == "zombie" {
					state = "Z"
				}
				if name == "kernel thread" {
					flags = 0x00200000 // Linux PF_KTHREAD.
				}
				writeTestFile(t, filepath.Join(dir, "stat"), fmt.Sprintf("99 (claude) %s 1 1 1 0 0 %d 0 0 0 0 0 0 0 0 20 0 1 0 5099 0", state, flags))
				writeTestFile(t, filepath.Join(dir, "cmdline"), "claude\x00")
				writeTestFile(t, filepath.Join(dir, "cgroup"), "0::/user.slice\n")
				if name != "zombie" && name != "kernel thread" {
					exe, err := os.Readlink(filepath.Join(o.ProcRoot, "10/exe"))
					if err != nil {
						t.Fatal(err)
					}
					for link, target := range map[string]string{"exe": exe, "cwd": o.Directory} {
						if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			previousRead := o.OnProcRead
			o.OnProcRead = func(path string) {
				previousRead(path)
				if name == "vanished before open" && path == "10/cmdline" || name == "vanished mid-read" && path == "99/cmdline" {
					if err := os.RemoveAll(dir); err != nil {
						t.Fatal(err)
					}
				}
			}
			scanInputs = func() scan.Options { return o }
			code, out, errs := run(t, "scan", "--check", "--json")
			if code != 0 {
				t.Fatalf("ended or kernel process made check unknown: %d %s %s", code, out, errs)
			}
			s, err := result.Decode([]byte(out))
			if err != nil {
				t.Fatal(err)
			}
			if s.Status != "ok" || s.Counts.Running != 0 || strings.Contains(errs, " gone") {
				t.Fatalf("incorrect ended or kernel process classification: %s %s", out, errs)
			}
			exited, kernel := 1, 0
			if name == "kernel thread" {
				exited, kernel = 0, 1
			}
			if s.Counts.Exited != exited || s.Counts.KernelThreads != kernel || !strings.Contains(errs, fmt.Sprintf("Exited during the scan: %d. Kernel threads: %d.", exited, kernel)) {
				t.Fatalf("incorrect category counts or footer: %s %s", out, errs)
			}
			for _, item := range s.Items {
				if item.Kind == "process" && item.Process().PID == 99 {
					t.Fatal("ended or kernel process retained detail")
				}
			}
		})
	}
}

func TestScanCustomAliasPrivacy(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	const alias = "private_canary_53"
	for _, args := range [][]string{{}, {"--verbose"}, {"--json"}, {"--check"}} {
		args = append(args, "--no-default-signatures", "--signature", alias+"=claude")
		code, out, errs := run(t, append([]string{"scan"}, args...)...)
		if code != 0 && code != 1 {
			t.Fatalf("custom rule refused: %d %s", code, errs)
		}
		saved, err := os.ReadFile(filepath.Join(o.Directory, ".tego/scan/last.json"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out+errs+string(saved), alias) || strings.Contains(out+errs+string(saved), scanCanary) {
			t.Fatal("input alias or marker leaked")
		}
		if !strings.Contains(out, "user-1") {
			t.Fatal("custom evidence not labelled")
		}
	}
}

func TestAgentsPositiveOutputUnchanged(t *testing.T) {
	f := newFakeProcRoot(t)
	f.add(500, 1, "claude", "claude", []string{"claude", "--resume"}, "/t.scope", "")
	sandboxAgents(t, f.root, true)
	t.Setenv("TEGO_HINTS", "off")
	base := "tego agents: looking for claude, codex, opencode, gemini (add another with --signature); this only observes and never signals, moves, blocks or changes a process\n"
	code, out, errs := runAgentsCmd(t, "--json")
	var clock struct {
		Time string `json:"time"`
	}
	if err := json.Unmarshal([]byte(out), &clock); err != nil {
		t.Fatal(err)
	}
	// Only the clock and fixture path vary. All legacy wire bytes are frozen.
	want := fmt.Sprintf("{\"event\":\"agent_started\",\"time\":%q,\"session\":1,\"pid\":500,\"ppid\":1,\"exe\":%q,\"argv\":[\"claude\",\"--resume\"],\"comm\":\"claude\",\"rule\":\"claude\",\"seen\":\"scan\",\"outside_governed_run\":true,\"cgroup\":\"/t.scope\",\"start\":5500}\n", clock.Time, filepath.Join(f.bin, "claude"))
	if code != 0 || out != want || errs != base {
		t.Fatalf("legacy JSON bytes changed: %d %q %q", code, out, errs)
	}
	code, out, errs = runAgentsCmd(t)
	clockWord, _, ok := strings.Cut(out, " ")
	if !ok {
		t.Fatal("missing timestamp")
	}
	want = clockWord + " agent_started session=1 pid=500 ppid=1 rule=claude seen=scan OUTSIDE-GOVERNED-RUN exe=" + filepath.Join(f.bin, "claude") + " argv=[\"claude\" \"--resume\"]\n"
	if code != 0 || out != want || errs != base {
		t.Fatalf("legacy text bytes changed: %d %q %q", code, out, errs)
	}
}

func TestScanLateFailureDoesNotClaimNoReads(t *testing.T) {
	fixtureScanCommand(t)
	original := scanCollect
	t.Cleanup(func() { scanCollect = original })
	for _, tc := range []struct {
		name           string
		panicAfterRead bool
	}{{"encode", false}, {"panic", true}} {
		t.Run(tc.name, func(t *testing.T) {
			scanCollect = func(ctx context.Context, o scan.Options) scan.Outcome {
				got := scan.Collect(ctx, o)
				if tc.panicAfterRead {
					panic(scanCanary)
				}
				got.Snapshot.Counts.Running++
				return got
			}
			code, out, errs := run(t, "scan")
			if code != 125 || strings.Contains(out+errs, scanCanary) || strings.Contains(out, "Read: none") || strings.Contains(out+errs, "scan-not-performed") {
				t.Fatalf("late failure report %d %s %s", code, out, errs)
			}
		})
	}
}

// TestScanProjectRefusalPrivacy covers secrets on unsupported include/URL lines
// and JSON comments/error locations, through Main in every output mode.
func TestScanProjectRefusalPrivacy(t *testing.T) {
	for _, file := range []string{"package.json", "requirements.txt"} {
		t.Run(file, func(t *testing.T) {
			o, _ := fixtureScanCommand(t)
			body := `{"dependencies":{"@openai/codex":"` + scanCanary + `"},/*` + scanCanary + `*/}`
			if file == "requirements.txt" {
				body = "langgraph\n-r " + scanCanary + ".txt\n--index-url https://user:" + scanCanary + "@example.invalid/" + scanCanary + "\n"
			}
			writeTestFile(t, filepath.Join(o.Directory, file), body)
			for _, args := range [][]string{nil, {"--verbose"}, {"--json"}, {"--check"}, {"--all-mine", "-v"}, {"--json", "--check"}} {
				code, out, errs := run(t, append([]string{"scan"}, args...)...)
				want := 0
				if strings.Contains(strings.Join(args, " "), "--check") {
					want = 1
				}
				if code != want {
					t.Fatalf("exit %d: %s", code, errs)
				}
				saved, e := os.ReadFile(filepath.Join(o.Directory, ".tego/scan/last.json"))
				if e != nil {
					t.Fatal(e)
				}
				if strings.Contains(out+errs+string(saved), scanCanary) {
					t.Fatal("marker leaked")
				}
				s, e := result.Decode(saved)
				if e != nil {
					t.Fatal(e)
				}
				found := false
				for _, src := range s.Sources {
					if src.Locator != nil && *src.Locator == filepath.Join(o.Directory, file) {
						found = src.State == "not-read" && src.NotRead == 1
					}
				}
				if !found || !strings.Contains(errs, file) || !strings.Contains(errs, "not-read") {
					t.Fatal("parse refusal hidden")
				}
			}
		})
	}
}

func TestScanProjectSecretFolderOnlyInTypedPaths(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	dir := filepath.Join(o.Directory, scanCanary)
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	writeTestFile(t, filepath.Join(dir, "package.json"), `{"name":"`+scanCanary+`","author":"`+scanCanary+`","dependencies":{"@openai/codex":"`+scanCanary+`"}}`)
	writeTestFile(t, filepath.Join(dir, "requirements.txt"), "langgraph=="+scanCanary+" # "+scanCanary+"\n")
	o.Directory = dir
	scanInputs = func() scan.Options { return o }
	for _, args := range [][]string{nil, {"--verbose"}, {"--json"}, {"--check"}, {"--all-mine", "-v"}, {"--json", "--check"}} {
		code, out, errs := run(t, append([]string{"scan"}, args...)...)
		want := 0
		if strings.Contains(strings.Join(args, " "), "--check") {
			want = 1
		}
		if code != want {
			t.Fatalf("exit %d: %s", code, errs)
		}
		// The destination is the passwd home, not this project's folder.
		saved, e := os.ReadFile(filepath.Join(filepath.Dir(o.Passwd), ".tego/scan/last.json"))
		if e != nil {
			t.Fatal(e)
		}
		allowed := map[string]bool{}
		var visit func(string, any)
		visit = func(key string, v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, val := range x {
					if strings.Contains(k, scanCanary) {
						t.Fatal("marker in field name")
					}
					visit(k, val)
				}
			case []any:
				for _, val := range x {
					visit(key, val)
				}
			case string:
				if strings.Contains(x, scanCanary) {
					switch key {
					case "project", "path", "locator", "exe", "cwd", "target":
						if !filepath.IsAbs(x) {
							t.Fatal("nonpath marker")
						}
						allowed[x] = true
					default:
						t.Fatalf("marker outside typed path: %s", key)
					}
				}
			}
		}
		var v any
		if e = json.Unmarshal(saved, &v); e != nil {
			t.Fatal(e)
		}
		visit("", v)
		if strings.Contains(strings.Join(args, " "), "--json") {
			if e = json.Unmarshal([]byte(out), &v); e != nil {
				t.Fatal(e)
			}
			visit("", v)
		} else {
			for path := range allowed {
				out = strings.ReplaceAll(out, fmt.Sprintf("%q", path), "")
			}
			if strings.Contains(out, scanCanary) {
				t.Fatal("marker outside text paths")
			}
		}
		for path := range allowed {
			errs = strings.ReplaceAll(errs, fmt.Sprintf("%q", path), "")
		}
		if strings.Contains(errs, scanCanary) {
			t.Fatal("marker outside footer paths")
		}
	}
}

// TestNamedDashboardIsTheHolderOfTheDashboardLock: scan.Options.NamedProgram, as the command sets it, names a process
// when the dashboard lock under the caller's home is held by it and proved (runlock.DashboardPID), and no other: not a
// pid the file merely names, not any pid when nobody holds the lock.
func TestNamedDashboardIsTheHolderOfTheDashboardLock(t *testing.T) {
	// A binary built with -tags tegotesthooks reads the lock under the home its environment names, fixed at start
	// (ownlog_testhook.go), and holds none with it unset; this test is of the lock's holder under the home it passes,
	// so it puts the product's own mapping (the caller's home) back for its length.
	prev := dashboardLockHome
	dashboardLockHome = func(home string) string { return home }
	t.Cleanup(func() { dashboardLockHome = prev })
	home := t.TempDir()
	if named := namedDashboard(); named(home, os.Getpid()) || named(home, 1) {
		t.Fatal("with no dashboard lock a process was named")
	}
	lock, err := runlock.HoldDashboard(home)
	if err != nil {
		t.Fatal(err)
	}
	named := namedDashboard()
	if !named(home, os.Getpid()) || named(home, os.Getppid()) || named(home, 1) {
		t.Fatalf("the holder %d was not named, or another pid was (parent %d)", os.Getpid(), os.Getppid())
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if namedDashboard()(home, os.Getpid()) {
		t.Fatal("a released lock names a process")
	}
}
