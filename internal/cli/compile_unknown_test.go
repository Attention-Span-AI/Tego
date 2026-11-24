// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// unknownVerdict is what a root-tier column answers when this user cannot be told (ADR 0043, amendment 2026-11-18).
const unknownVerdict = "cannot tell without root"

// lockFolder makes dir a folder this process can stat and neither list nor search, which is every answer the kernel
// gives a normal user for another account's 0700 folder (the review's `locked`); the test needs no second account.
// It reports whether the lock holds: root reads through it, and then needs no root to be told.
func lockFolder(t *testing.T, dir string) bool {
	t.Helper()
	if err := os.Chmod(dir, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	_, err := os.ReadDir(dir)
	if err == nil {
		return false
	}
	if !os.IsPermission(err) {
		t.Fatal(err)
	}
	return true
}

// rootPredictionProject is a project folder to compile in and a folder beside it, outside every scan of the project.
func rootPredictionProject(t *testing.T) (project, outside string) {
	t.Helper()
	base := t.TempDir()
	project, outside = filepath.Join(base, "project"), filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(project, "data"), filepath.Join(project, "open"), outside} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "data", "value"), []byte("v\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	buildsTiers(t, backend.TierLandlock)
	return project, outside
}

func writeRootPredictionFiles(t *testing.T, denyRead []string, rows string) {
	t.Helper()
	contract := "version: 0\nname: hidden\ncommand: [true]\nfs:\n  reads: direct\n"
	if len(denyRead) > 0 {
		contract += "  deny_read: [" + strings.Join(denyRead, ", ") + "]\n"
	}
	for name, body := range map[string]string{"agent.yaml": contract, "tests.yaml": "version: 0\ntests:\n" + rows} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// A step of the deny_read and name-entry compile that a permission failure cuts short for this user is one root
// finishes: root's table then denies a file this user's table does not name, so every file-backed root column is
// unknown, exit 125, and never allowed (review finding 2). Each case is cut at one step.
func TestRootPredictionUnknownWhereTheCompileIsCutShort(t *testing.T) {
	const row = "  - name: the hidden target\n    action: fs.read\n    path: data/value\n    expect: allow\n"
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, project, outside string) (denyRead []string, locked string)
	}{
		{"a pattern in a folder this user may not list (the review's ./locked/secret*)", func(t *testing.T, project, _ string) ([]string, string) {
			locked := filepath.Join(project, "locked")
			mkdirLink(t, locked, "secret-link", filepath.Join(project, "data", "value"))
			return []string{"./locked/secret*"}, locked
		}},
		{"a pattern's folder outside the project, listed by the expansion alone", func(t *testing.T, project, outside string) ([]string, string) {
			locked := filepath.Join(outside, "locked")
			mkdirLink(t, locked, "secret-link", filepath.Join(project, "data", "value"))
			return []string{filepath.Join(locked, "secret*")}, locked
		}},
		{"a .env link in a folder the built-in scan may not list", func(t *testing.T, project, _ string) ([]string, string) {
			locked := filepath.Join(project, "locked")
			mkdirLink(t, locked, ".env", filepath.Join(project, "data", "value"))
			return nil, locked
		}},
		{"a matched link whose target lies behind a folder this user may not search", func(t *testing.T, project, outside string) ([]string, string) {
			locked := filepath.Join(outside, "locked")
			if err := os.Mkdir(locked, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(locked, "value"), []byte("v\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(locked, "value"), filepath.Join(project, "open", "secret-link")); err != nil {
				t.Fatal(err)
			}
			return []string{"./open/secret*"}, locked
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project, outside := rootPredictionProject(t)
			denyRead, locked := tc.build(t, project, outside)
			writeRootPredictionFiles(t, denyRead, row)
			holds := lockFolder(t, locked)
			for _, tier := range []string{"cgroup", "bpflsm"} {
				code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", tier)
				if !holds {
					if strings.Contains(out, unknownVerdict) {
						t.Errorf("%s: root was told it needs root\n%s\n%s", tier, out, errs)
					}
					continue
				}
				if code != identity.ExitError || !strings.Contains(out, "got "+unknownVerdict+" via root-required") {
					t.Errorf("%s: exit %d, want 125 and %q\n%s\n%s", tier, code, unknownVerdict, out, errs)
				}
				code, out, errs = run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", tier, "--json")
				var report TestReport
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatalf("%s: %v\n%s\n%s", tier, err, out, errs)
				}
				if code != identity.ExitError || len(report.Rows) != 1 || len(report.Rows[0].Columns) != 1 ||
					report.Rows[0].Columns[0].Verdict != unknownVerdict || report.Rows[0].Columns[0].Rule != "root-required" || report.Rows[0].Pass {
					t.Errorf("%s json: exit %d, want 125 and the unknown verdict: %+v\n%s", tier, code, report, errs)
				}
			}
			// The landlock column is this user's own run: its answer stays the concrete one.
			code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", "landlock")
			if !holds {
				// Root lists the folder, so root's own table answers: the row may legitimately be refused (the
				// pattern finds the link the deny_read names). Only the unknown answer and the exit that goes
				// with it would be wrong here.
				if code == identity.ExitError || strings.Contains(out, unknownVerdict) {
					t.Errorf("landlock as root: exit %d, want root's own concrete answer\n%s\n%s", code, out, errs)
				}
				return
			}
			if code != identity.ExitOK || !strings.Contains(out, "PASS the hidden target") {
				t.Errorf("landlock: exit %d, want the concrete answer\n%s\n%s", code, out, errs)
			}
		})
	}
}

func mkdirLink(t *testing.T, dir, name, target string) {
	t.Helper()
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

// A row whose own walk stops at a folder this user may not search is unknown at a root tier, by itself: root's walk
// goes on to a place this user cannot name. The table is whole, so every other row keeps its answer.
func TestRootPredictionUnknownForARowItCannotWalk(t *testing.T) {
	_, outside := rootPredictionProject(t)
	locked := filepath.Join(outside, "locked")
	if err := os.Mkdir(locked, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "value"), []byte("v\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeRootPredictionFiles(t, nil,
		"  - name: through the folder\n    action: fs.read\n    path: "+filepath.Join(locked, "value")+"\n    expect: allow\n"+
			"  - name: a name in the folder\n    action: fs.delete\n    path: "+filepath.Join(locked, "value")+"\n    expect: refused\n"+
			"  - name: beside it\n    action: fs.read\n    path: data/value\n    expect: allow\n"+
			"  - name: a socket name in the folder\n    action: net.connect\n    path: unix:"+filepath.Join(locked, "s.sock")+"\n    expect: refused\n")
	holds := lockFolder(t, locked)
	for _, tier := range []string{"cgroup", "bpflsm"} {
		code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", tier, "--json")
		var report TestReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("%s: %v\n%s\n%s", tier, err, out, errs)
		}
		if len(report.Rows) != 4 {
			t.Fatalf("%s: %d rows\n%s", tier, len(report.Rows), out)
		}
		got := func(i int) string { return report.Rows[i].Columns[0].Verdict }
		if !holds {
			if got(0) == unknownVerdict || got(1) == unknownVerdict || got(3) == unknownVerdict {
				t.Errorf("%s: root was told it needs root\n%s", tier, out)
			}
			continue
		}
		if code != identity.ExitError || got(0) != unknownVerdict || report.Rows[0].Pass || got(1) != unknownVerdict || report.Rows[1].Pass {
			t.Errorf("%s: exit %d, rows %q and %q; want 125 and both unknown\n%s\n%s", tier, code, got(0), got(1), out, errs)
		}
		// A unix name's walk is the run's own and answers a class, not an errno: the name is asked once more.
		if got(3) != unknownVerdict || report.Rows[3].Pass {
			t.Errorf("%s: a connect to a socket name behind the folder answered %q, want unknown\n%s", tier, got(3), out)
		}
		if got(2) != "allow" || !report.Rows[2].Pass {
			t.Errorf("%s: the row beside it answered %q, want its own concrete allow\n%s", tier, got(2), out)
		}
	}
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", "landlock")
	if strings.Contains(out, unknownVerdict) || code == identity.ExitError {
		t.Errorf("landlock: exit %d, want concrete answers\n%s\n%s", code, out, errs)
	}
}

// compile --exec answers from the same table and walks its command as a row is walked, so it carries the same
// uncertainty: the unknown answer in each root column and exit 125, by the decision compile --test uses (review
// finding 3). It has no --json form; a script reads the answer from --test --json.
func TestCompileExecRootPredictionNeedsRoot(t *testing.T) {
	t.Run("the table is cut short", func(t *testing.T) {
		project, _ := rootPredictionProject(t)
		// The review's case: private/nested is reached only through a folder this user may not search.
		if err := os.MkdirAll(filepath.Join(project, "private", "nested"), 0755); err != nil {
			t.Fatal(err)
		}
		writeRootPredictionFiles(t, []string{"./private/nested/secret*"}, "")
		holds := lockFolder(t, filepath.Join(project, "private"))
		tool := filepath.Join(project, "data", "value")
		for _, tier := range []string{"cgroup", "bpflsm"} {
			code, out, errs := run(t, "compile", "agent.yaml", "--exec", tool+" --version", "--tier", tier)
			if !holds {
				if strings.Contains(out, unknownVerdict) {
					t.Errorf("%s: root was told it needs root\n%s\n%s", tier, out, errs)
				}
				continue
			}
			if code != identity.ExitError || !strings.Contains(out, "  "+tier+": "+unknownVerdict+" root-required") {
				t.Errorf("%s: exit %d, want 125 and the unknown answer in its column\n%s\n%s", tier, code, out, errs)
			}
		}
		code, out, errs := run(t, "compile", "agent.yaml", "--exec", tool+" --version", "--tier", "landlock")
		if code != identity.ExitOK || strings.Contains(out, unknownVerdict) || !strings.Contains(out, "  landlock: ") {
			t.Errorf("landlock: exit %d, want its concrete answer and exit 0\n%s\n%s", code, out, errs)
		}
	})
	t.Run("the command's own walk is cut short", func(t *testing.T) {
		project, outside := rootPredictionProject(t)
		locked := filepath.Join(outside, "locked")
		if err := os.Mkdir(locked, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(locked, "tool"), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
		writeRootPredictionFiles(t, nil, "")
		holds := lockFolder(t, locked)
		code, out, errs := run(t, "compile", "agent.yaml", "--exec", filepath.Join(locked, "tool"), "--tier", "cgroup,landlock")
		if !holds {
			if strings.Contains(out, unknownVerdict) {
				t.Errorf("root was told it needs root\n%s\n%s", out, errs)
			}
			return
		}
		if code != identity.ExitError || !strings.Contains(out, "  cgroup: "+unknownVerdict+" root-required") {
			t.Errorf("exit %d, want 125 and the unknown answer at cgroup\n%s\n%s", code, out, errs)
		}
		if strings.Contains(out, "  landlock: "+unknownVerdict) {
			t.Errorf("the landlock column lost its concrete answer\n%s", out)
		}
		// A script this user can reach through a link and may not read: root reads its #! line and decides on the
		// interpreter, so the root column is unknown, under the path the walk landed on.
		tool := filepath.Join(project, "data", "tool")
		if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0111); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(tool, filepath.Join(project, "open", "link")); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(tool); os.IsPermission(err) {
			code, out, errs = run(t, "compile", "agent.yaml", "--exec", filepath.Join(project, "open", "link"), "--tier", "cgroup")
			if code != identity.ExitError || !strings.Contains(out, "#! line not read") || !strings.Contains(out, "  cgroup: "+unknownVerdict+" root-required") {
				t.Errorf("an unreadable script behind a link: exit %d, want 125 and the unknown answer\n%s\n%s", code, out, errs)
			}
		}
		// A command this user can walk keeps exit 0 and concrete answers in every column.
		code, out, errs = run(t, "compile", "agent.yaml", "--exec", filepath.Join(project, "data", "value"), "--tier", "cgroup,landlock")
		if code != identity.ExitOK || strings.Contains(out, unknownVerdict) {
			t.Errorf("a walkable command: exit %d\n%s\n%s", code, out, errs)
		}
	})
}

// The first confirm review's scenario: a folder beneath a write entry that this user may search and not list
// (another account's 0711 folder; here the test's own, at 0311) holds a repository one level down. Root's deny-write
// search lists the folder, finds the repository and refuses a write to its git config; this user's search cannot list
// the folder, so it never finds the repository, and a write row by the config's exact name (which this user can walk)
// answered allow at a root tier, exit 0. That column is now unknown, exit 125, in text and JSON; the landlock column
// is this user's own run and keeps its concrete answer.
func TestRootPredictionUnknownWhereTheDenyWriteSearchIsCutShort(t *testing.T) {
	_, outside := rootPredictionProject(t)
	// Outside the project: the built-in .env traversal lists the project's folders and reports one it may not list
	// already, so the deny-write search alone must see this one.
	sub := filepath.Join(outside, "w", "sub")
	if err := os.MkdirAll(filepath.Join(sub, "repo", ".git", "hooks"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "repo", ".git", "config"), []byte("[core]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	contract := "version: 0\nname: hidden\ncommand: [true]\nfs:\n  reads: direct\n  write: [" + filepath.Join(outside, "w") + "]\n"
	rows := "version: 0\ntests:\n  - name: the config by its exact name\n    action: fs.write\n    path: " +
		filepath.Join(sub, "repo", ".git", "config") + "\n    expect: allow\n"
	for name, body := range map[string]string{"agent.yaml": contract, "tests.yaml": rows} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(sub, 0311); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0755) })
	if _, err := os.ReadDir(sub); err == nil {
		t.Skip("this process lists every folder (root): it is told root's answer")
	}
	for _, tier := range []string{"cgroup", "bpflsm"} {
		code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", tier)
		if code != identity.ExitError || !strings.Contains(out, "got "+unknownVerdict+" via root-required") {
			t.Errorf("%s: exit %d, want 125 and %q\n%s\n%s", tier, code, unknownVerdict, out, errs)
		}
		code, out, errs = run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", tier, "--json")
		var report TestReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("%s: %v\n%s\n%s", tier, err, out, errs)
		}
		if code != identity.ExitError || len(report.Rows) != 1 || len(report.Rows[0].Columns) != 1 ||
			report.Rows[0].Columns[0].Verdict != unknownVerdict || report.Rows[0].Pass {
			t.Errorf("%s json: exit %d, want 125 and the unknown verdict: %+v\n%s", tier, code, report, errs)
		}
	}
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", "landlock")
	if code != identity.ExitOK || strings.Contains(out, unknownVerdict) {
		t.Errorf("landlock: exit %d, want the concrete answer\n%s\n%s", code, out, errs)
	}
}

// The release line's guest (a stock Ubuntu 25.10 cloud image, a normal user): the FIFO inventory of the host IPC
// folders met /run/user/1001/systemd/inaccessible/dir, a folder systemd makes at mode 0000, and every file-backed
// root column of every table answered "cannot tell without root", the rows about the test's own folder included, with no
// word about which folder. The same mode-0000 folder stands here in the test home's .screen (a host IPC folder), as a
// child of it: the inventory's budget (4096 entries) is spent on this machine by the developer's own /run/user/<uid>
// before it would reach a folder nested deeper, as it is not in a guest. Only the rows about a path at, beneath or
// above the folder are unknown, and the compile names it once and gives the command for root.
func TestRootPredictionBuiltinFolderCutKeepsOtherRows(t *testing.T) {
	project, _ := rootPredictionProject(t)
	root := filepath.Join(testHome, ".screen", "dir")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700); _ = os.RemoveAll(filepath.Join(testHome, ".screen")) })
	holds := lockFolder(t, root)
	oldSelf := namedSelf
	namedSelf = func() (string, string) { return "/opt/tego/bin/tego", "" }
	t.Cleanup(func() { namedSelf = oldSelf })
	writeRootPredictionFiles(t, nil,
		"  - name: the report\n    action: fs.read\n    path: "+filepath.Join(project, "data", "value")+"\n    expect: allow\n"+
			"  - name: a write outside every entry\n    action: fs.write\n    path: "+filepath.Join(project, "open", "x")+"\n    expect: refused\n"+
			"  - name: a name in the folder\n    action: fs.read\n    path: "+filepath.Join(root, "x")+"\n    expect: allow\n"+
			"  - name: a socket in the folder\n    action: net.connect\n    path: unix:"+filepath.Join(root, "s.sock")+"\n    expect: refused\n")
	for _, tier := range []string{"cgroup", "bpflsm"} {
		code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml", "--tier", tier, "--json")
		var report TestReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("%s: %v\n%s\n%s", tier, err, out, errs)
		}
		if len(report.Rows) != 4 {
			t.Fatalf("%s: %d rows\n%s", tier, len(report.Rows), out)
		}
		got := func(i int) string { return report.Rows[i].Columns[0].Verdict }
		if !holds {
			if strings.Contains(out, unknownVerdict) {
				t.Errorf("%s: root was told it needs root\n%s", tier, out)
			}
			continue
		}
		for i := range 2 {
			if got(i) == unknownVerdict || !report.Rows[i].Pass {
				t.Errorf("%s: row %d (about the project) answered %q, want its own concrete answer\n%s", tier, i, got(i), out)
			}
		}
		for i := 2; i < 4; i++ {
			if got(i) != unknownVerdict || report.Rows[i].Pass {
				t.Errorf("%s: row %d (beneath the folder root lists) answered %q, want %q\n%s", tier, i, got(i), unknownVerdict, out)
			}
		}
		if code != identity.ExitError {
			t.Errorf("%s: exit %d, want 125 for the rows that are unknown", tier, code)
		}
		if n := strings.Count(errs, "could not read "+root+" (permission denied)"); n != 1 {
			t.Errorf("%s: the folder is named %d times, want once\n%s", tier, n, errs)
		}
		want := "root's answer: sudo /opt/tego/bin/tego compile agent.yaml --test tests.yaml --tier " + tier + " --json"
		if !strings.Contains(errs, want) {
			t.Errorf("%s: no command for root's answer (%q)\n%s", tier, want, errs)
		}
	}
	// A table whose rows lie elsewhere finds nothing unknown and prints nothing about the folder.
	writeRootPredictionFiles(t, nil, "  - name: the report\n    action: fs.read\n    path: "+filepath.Join(project, "data", "value")+"\n    expect: allow\n")
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "tests.yaml")
	if code != identity.ExitOK || strings.Contains(out, unknownVerdict) || strings.Contains(errs, "could not read") {
		t.Errorf("a table with no row about the folder: exit %d\n%s\n%s", code, out, errs)
	}
}

// Which rows each reach leaves unknown, and which it leaves their own answer (rootPrediction.unknown): the built-in
// lists' place reaches the rows about paths at, beneath or above it, an exec list's place every exec row, and any other
// place every file-backed row; a landlock column and a network row with no path are never unknown. The folders are
// under a root-level name no host has: /run/podman is root-only on the runner image, so this user's lstat of a row
// beneath it is EACCES, which unknown reads as a walk the row leaves to root, whatever the cut says.
func TestRootPredictionReach(t *testing.T) {
	fs := func(kind agent.ActionKind, path string) agent.Action { return agent.Action{Kind: kind, Path: path} }
	rows := map[string]agent.Action{
		"read at the folder":        fs(agent.ActionFSRead, "/tego-reach-test/podman"),
		"read beneath":              fs(agent.ActionFSRead, "/tego-reach-test/podman/podman.sock"),
		"connect beneath":           fs(agent.ActionNetConnect, "unix:/tego-reach-test/podman/podman.sock"),
		"delete above":              fs(agent.ActionFSDelete, "/tego-reach-test"),
		"read beside":               fs(agent.ActionFSRead, "/tego-reach-test/podmanx/s"),
		"read elsewhere":            fs(agent.ActionFSRead, "/home/u/project/out"),
		"exec elsewhere":            fs(agent.ActionExec, "/usr/bin/git"),
		"connect to a port":         {Kind: agent.ActionNetConnect, Host: "127.0.0.1", Port: 80},
		"exec script beneath":       {Kind: agent.ActionExec, Path: "/usr/bin/sh", Script: "/tego-reach-test/podman/x"},
		"relative path is no place": fs(agent.ActionFSRead, "run/podman/x"),
	}
	for _, tc := range []struct {
		name  string
		reach agent.CutReach
		want  map[string]bool
	}{
		{"built-in", agent.CutHere, map[string]bool{"read at the folder": true, "read beneath": true, "connect beneath": true, "delete above": true, "exec script beneath": true}},
		{"exec", agent.CutExec, map[string]bool{"exec elsewhere": true, "exec script beneath": true}},
		{"wide", agent.CutWide, map[string]bool{"read at the folder": true, "read beneath": true, "delete above": true, "read beside": true,
			"read elsewhere": true, "exec elsewhere": true, "exec script beneath": true, "relative path is no place": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &rootPrediction{}
			p.cutTable(agent.NameCut{Path: "/tego-reach-test/podman", Reach: tc.reach})
			for name, a := range rows {
				for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
					if got := p.unknown(a, tier); got != tc.want[name] {
						t.Errorf("%s at %s: unknown %v, want %v", name, tier, got, tc.want[name])
					}
				}
				if p.unknown(a, backend.TierLandlock) {
					t.Errorf("%s: the landlock column is this user's own run, never unknown", name)
				}
			}
		})
	}
}
