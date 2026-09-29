// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCompileTestRowsAreNeverProbedAgainstThisMachine is limits-check-doctor-cli.md E19: a write row under
// a directory that does not exist yet passes on the table as declared, since compile computes no inode, and
// a connect to an address that only a host entry, which this offline compile cannot resolve, could admit
// fails as "could not resolve <host>", a different line from a verdict mismatch, and with the finding exit.
func TestCompileTestRowsAreNeverProbedAgainstThisMachine(t *testing.T) {
	dir := t.TempDir()
	contract := `version: 0
name: rows
command: ["true"]
fs:
  write: ["./not-yet-created/"]
net:
  allow: ["api.example.test:443"]
record: summary
`
	table := `version: 0
tests:
  - name: a write under a directory that does not exist yet
    action: fs.write
    path: not-yet-created/report.md
    expect: allow
    rule: fs.write[./not-yet-created/]
  - name: a literal address only the unresolved host could admit
    action: net.connect
    host_port: 203.0.113.9:443
    expect: allow
`
	for name, body := range map[string]string{"agent.yaml": contract, "verdicts.yaml": table} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "not-yet-created")); !os.IsNotExist(err) {
		t.Fatalf("the fixture's directory exists: %v", err)
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d want %d (one failing row)\nstdout %s\nstderr %s", code, identity.ExitFinding, out, errs)
	}
	for _, want := range []string{
		"PASS a write under a directory that does not exist yet",
		"FAIL a literal address only the unresolved host could admit",
		"could not resolve 203.0.113.9 (declared host api.example.test)",
		"2 rows: 1 passed, 1 failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "want allow") {
		t.Errorf("the unresolved row was reported as a verdict mismatch:\n%s", out)
	}
}

// bpflsmTable is the rows of TestCompileTestBPFLSMColumn*: the plane's answers where tiers 1 and 2 differ.
func bpflsmTable(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "compile-test-bpflsm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestCompileTestBPFLSMColumnGolden is TIER3-PLAN T10: the bpflsm column, answered from the plane's rows, in the
// text form. A row with no tier: must hold in every column, so the root tiers
// both fail the mutation rows that Landlock allows. The header names the
// bpflsm column's source and its decision plane. The rows that pass
// at bpflsm are the plane's answers for a rename, an exec (an unlisted script refused under the Landlock floor),
// the nested deny_read, a hard link out of it (path_link's REFER) and a chmod beneath it (the attribute hooks
// protect deny_write targets alone; plans/adr0017 C9).
func TestCompileTestBPFLSMColumnGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	want, err := os.ReadFile(filepath.Join("testdata", "compile-test-bpflsm.golden")) // before copyExampleTests moves away
	if err != nil {
		t.Fatal(err)
	}
	copyExampleTests(t, bpflsmTable(t))
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitFinding, out, errs)
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// TestCompileTestBPFLSMColumnNamesTheNameEntries is ADR 0043 C9's print: where the plane's rows carry the table's
// name entries (the example's built-in .env pair), the bpflsm column's note says they answer from the name rows and
// the climb, files created later included.
func TestCompileTestBPFLSMColumnNamesTheNameEntries(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	copyExampleTests(t, bpflsmTable(t))
	buildsTiers(t, backend.TierBPFLSM)
	_, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml", "--tier", "bpflsm")
	note := ""
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, "bpflsm: ") {
			note = strings.TrimPrefix(line, "bpflsm: ")
		}
	}
	if want := PlaneColumnNote + "; " + PlaneColumnNamesNote; note != want {
		t.Errorf("the column's note is %q, want %q\nstderr %s", note, want, errs)
	}
}

// TestCompileTestConformanceActionsGolden is plans/adr0017 C9 (ADR 0019: compile --test answers every action a run
// can take): fs.link, fs.attr, net.socket, net.send and exec.anonymous rows answered in each tier's column, in the
// text form. The link out of the nested deny_read is allowed by Landlock's union at tier 1 and refused at tier 2
// (the supervisor's R15d) and in the plane column (REFER); the row "an anonymous image is allowed" fails everywhere,
// since the contract restricts images.
func TestCompileTestConformanceActionsGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	want, err := os.ReadFile(filepath.Join("testdata", "compile-test-actions.golden"))
	if err != nil {
		t.Fatal(err)
	}
	table, err := os.ReadFile(filepath.Join("testdata", "compile-test-actions.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	copyExampleTests(t, string(table))
	// A git directory's config beneath the write entry: a built-in deny_write target (agent-contract R20).
	if err := os.MkdirAll(filepath.Join("out", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("out", ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitFinding, out, errs)
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
	// --json: the plane column's fs.link and fs.attr cells are the plane's rows; socket, send and the anonymous
	// image's are the policy model's.
	code, out, errs = run(t, "compile", "agent.yaml", "--test", "verdicts.yaml", "--tier", "bpflsm", "--json")
	if code != identity.ExitFinding {
		t.Fatalf("--json exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var report TestReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	for _, row := range report.Rows {
		cell := row.Columns[0]
		plane := strings.HasPrefix(row.Name, "a hard link") || strings.HasPrefix(row.Name, "a chmod") || strings.HasPrefix(row.Name, "a second name")
		if got := cell.Mechanism == "plane" && cell.DecisionPlane == "lsm"; got != plane {
			t.Errorf("%q: mechanism %q decision_plane %q, want plane provenance %v", row.Name, cell.Mechanism, cell.DecisionPlane, plane)
		}
	}
}

// TestCompileTestLandlockReferGolden: a hard link and a rename as the Landlock ruleset decides them (hook_path_link,
// current_check_refer_path), in every column, since tier 3 keeps the ruleset under its plane: MAKE_REG and REFER on
// the ends' directories, never on the file, so a file-level write entry is refused a second name anywhere (it grants
// no directory right), and REFER's no-gain rule over the rights the ruleset grants, so a move into an exec.allow
// directory, where the file would gain EXECUTE, is refused (security F1, F3 and F4). A rename is
// compared as hook_path_rename compares it: nothing within one directory, and the new name's directory, never a rule
// on the name it replaces, so the atomic replace of an exec.allow file entry is allowed. The run's
// line says the same at each tier (supervisor TestLinkLineIsWhatLandlockAnswers, observe
// TestRecorderNamesTheLandlockLinkRefusal, conformance fixture refer).
func TestCompileTestLandlockReferGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	want, err := os.ReadFile(filepath.Join("testdata", "compile-test-refer.golden"))
	if err != nil {
		t.Fatal(err)
	}
	table, err := os.ReadFile(filepath.Join("testdata", "compile-test-refer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	contract := `version: 0
name: refer
command: ["sh", "agent.sh"]
fs:
  write: ["./out/", "./a.txt"]
exec:
  allow: ["sh", "./out/bin/", "./out/tool"]
record: summary
`
	files := map[string]string{"agent.yaml": contract, "verdicts.yaml": string(table), "a.txt": "x", "out/x.txt": "x", "out/bin/tool": "x",
		"out/tool": "x", "out/tool.new": "x", "out/sub/t2": "x"}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitOK, out, errs)
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// TestCompileTestSymlinkEntryEndsGolden: rename(2), linkat(2) without AT_SYMLINK_FOLLOW and unlink(2) act on a name
// itself, so a row's end that is a symlinked write entry's own name is the symlink, in the directory it lies in, where
// the Landlock builder put no rule (it put the entry's on the target). The ends were canonicalized to the targets: the
// atomic swap of a symlink write entry (mv out/cur.new out/cur) read refused, and a link and a move of the symlink into
// the exec.allow directory read allow, while the kernel answered the opposite (EXDEV for the last two); renames onto
// and of a symlink entry outside every write directory read allow while the kernel refused them (EACCES). Every column
// now answers what the kernel did on 6.17 (F1 and F2; the run's line: supervisor TestLinkLineIsWhatLandlockAnswers).
func TestCompileTestSymlinkEntryEndsGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	golden, err := filepath.Abs(filepath.Join("testdata", "compile-test-symlink-ends.golden"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(golden)
	if err != nil && !*updateGolden {
		t.Fatal(err)
	}
	table, err := os.ReadFile(filepath.Join("testdata", "compile-test-symlink-ends.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	contract := `version: 0
name: symlink-ends
command: ["sh", "agent.sh"]
fs:
  write: ["./out/", "./out/cur", "./w/", "./cur"]
exec:
  allow: ["sh", "./out/bin/"]
record: summary
`
	files := map[string]string{"agent.yaml": contract, "verdicts.yaml": string(table), "out/cur.new": "x", "out/sub/t": "x",
		"out/bin/v1/f": "x", "w/v1/f": "x", "w/x": "x"}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"out/cur": "bin/v1", "cur": "w/v1"} {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitOK, out, errs)
	}
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// TestCompileTestSymlinkedNewNameDirectoryGolden: rename(2) and linkat(2) follow every component of a new name but the
// last, so a move or a link through a symlink to an exec.allow directory lands in it and gains EXECUTE (EXDEV on 6.17,
// and the run's line says refused). A row's new name almost never exists, and a name that did not exist was evaluated
// as written, beneath the undeclared symlink out/u, so rows 01 and 02 read allow in every column; with the entry
// declared through the symlink (./out/bl/), the new name's directory was refused the grant the symlink-name rule keeps
// from an end the syscall acts on, so rows 04 and 05 read allow too. The symlinks themselves stay
// ends (rows 06 and 07). Rows 08 to 11 move and link into a subdirectory the agent makes after compile ran: a
// directory that did not exist was kept as written, beneath the link, and every column read allow while the kernel
// refused EXDEV.
func TestCompileTestSymlinkedNewNameDirectoryGolden(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the contract names sh, not on PATH")
	}
	golden, err := filepath.Abs(filepath.Join("testdata", "compile-test-symlinked-new-name-dir.golden"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(golden)
	if err != nil && !*updateGolden {
		t.Fatal(err)
	}
	table, err := os.ReadFile(filepath.Join("testdata", "compile-test-symlinked-new-name-dir.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	contract := `version: 0
name: symlinked-new-name-dir
command: ["sh", "agent.sh"]
fs:
  write: ["./out/"]
exec:
  allow: ["sh", "./out/realbin/", "./out/bl/", "./out/tool"]
record: summary
`
	files := map[string]string{"agent.yaml": contract, "verdicts.yaml": string(table), "out/x": "x", "out/y": "x",
		"out/realbin/exists": "x", "out/realbin2/t": "x", "out/sub/t": "x"}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"out/u": "realbin", "out/bl": "realbin2", "out/tool": "sub/t"} {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "--offline", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm")
	if code != identity.ExitOK {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitOK, out, errs)
	}
	out = strings.ReplaceAll(out, real+"/", "<dir>/") // each resolved new name is printed whole
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

// TestCompileTestBPFLSMColumnJSON is the --json schema for the plane column: v 1, one cell per tier per row in
// the order --tier gave them, and `mechanism: plane` with `decision_plane: lsm` on the row-backed FS/exec bpflsm cells; the
// other tiers' cells carry neither key.
func TestCompileTestBPFLSMColumnJSON(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	copyExampleTests(t, bpflsmTable(t))
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml", "--tier", "landlock,cgroup,bpflsm", "--json")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var raw struct {
		V     int      `json:"v"`
		Tiers []string `json:"tiers"`
		Rows  []struct {
			Name    string           `json:"name"`
			Columns []map[string]any `json:"columns"`
		} `json:"rows"`
		Passed, Failed int
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, out)
	}
	if raw.V != 1 || strings.Join(raw.Tiers, ",") != "landlock,cgroup,bpflsm" || len(raw.Rows) != 12 {
		t.Fatalf("report v=%d tiers=%v rows=%d", raw.V, raw.Tiers, len(raw.Rows))
	}
	keys := func(c map[string]any) string {
		var ks []string
		for k := range c {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	for _, r := range raw.Rows {
		want := 3 // a row with no tier: answers in every column
		if strings.Contains(r.Name, "holds at bpflsm") || strings.Contains(r.Name, "rename inside") ||
			strings.Contains(r.Name, "rename out of") || strings.Contains(r.Name, "script") || strings.Contains(r.Name, "undeclared") ||
			strings.Contains(r.Name, "plane refuses that map") || strings.Contains(r.Name, "hard link") || strings.Contains(r.Name, "chmod") {
			want = 1 // its own tier: narrows it to bpflsm
		}
		if len(r.Columns) != want {
			t.Errorf("%q: %d columns, want %d", r.Name, len(r.Columns), want)
			continue
		}
		for _, c := range r.Columns {
			if c["tier"] == "bpflsm" {
				if keys(c) != "decision_plane,mechanism,pass,rule,tier,verdict" || c["mechanism"] != "plane" || c["decision_plane"] != "lsm" {
					t.Errorf("%q: bpflsm cell %v", r.Name, c)
				}
			} else if keys(c) != "pass,rule,tier,verdict" {
				t.Errorf("%q: %v cell %v carries plane keys", r.Name, c["tier"], c)
			}
		}
	}
}

// TestCompileTestColumnProvenance exercises real compiled network policy and
// row-backed FS/exec decisions through the public CLI JSON projection.
func TestCompileTestColumnProvenance(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	executable, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	contract := "version: 0\nname: provenance\ncommand: [true]\ncapture: forwarder\nmodels:\n  - {provider: anthropic, host: 127.0.0.1, port: 443}\nfs:\n  write: [\"" + work + "\"]\n  deny_read: []\nexec:\n  allow: [true]\nnet:\n  allow: [127.0.0.1:8443]\n  listen: ['tcp://127.0.0.1:8080']\n  http:\n    - {host: 127.0.0.1, allow: [/v1/messages], methods: [POST]}\n"
	table := "version: 0\ntests:\n" +
		"  - {name: fs, action: fs.write, path: '" + filepath.Join(work, "file") + "', expect: allow}\n" +
		"  - {name: exec, action: exec, path: '" + executable + "', expect: allow}\n" +
		"  - {name: map, action: exec.map, path: '" + filepath.Join(work, "not-listed-library.so") + "', expect: refused}\n" +
		"  - {name: connect, action: net.connect, host_port: '127.0.0.1:8443', expect: allow}\n" +
		"  - {name: bind, action: net.bind, host_port: 'tcp://127.0.0.1:8080', expect: allow}\n" +
		"  - {name: http, action: net.http, host_port: '127.0.0.1:443', method: POST, path: /v1/messages, expect: allow}\n" +
		"  - {name: http-denied, action: net.http, host_port: '127.0.0.1:443', method: GET, path: /v1/messages, expect: refused}\n"
	for name, body := range map[string]string{"agent.yaml": contract, "rows.yaml": table} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierBPFLSM)
	args := []string{"compile", filepath.Join(dir, "agent.yaml"), "--offline", "--test", filepath.Join(dir, "rows.yaml"), "--tier", "bpflsm"}
	code, out, errs := run(t, append(args, "--json")...)
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	var report TestReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Passed != 7 || report.Failed != 0 || len(report.Rows) != 7 {
		t.Fatalf("%+v", report)
	}
	for _, row := range report.Rows {
		if len(row.Columns) != 1 || !row.Pass {
			t.Fatalf("%+v", row)
		}
		cell := row.Columns[0]
		switch row.Name {
		case "fs", "exec", "map":
			if cell.Mechanism != "plane" || cell.DecisionPlane != "lsm" {
				t.Errorf("row-backed %s lost plane provenance: %+v", row.Name, cell)
			}
		default:
			if cell.Mechanism != "" || cell.DecisionPlane != "" {
				t.Errorf("model-derived %s falsely claims loaded plane rows: %+v", row.Name, cell)
			}
		}
	}
	code, out, errs = run(t, args...)
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "fs, exec and exec.map answered from the plane's rows") || !strings.Contains(out, "exec.anonymous and network answer from the policy model") {
		t.Fatalf("ambiguous column provenance: %s", out)
	}
}

// TestCompileTestResolverRowsFollowDNSMode: net.dns.mode off and broker take away R14's implicit resolver
// exception from the run (network-controls.md "Cooperating DNS broker"; runtime runResolvers), so a direct
// query to a machine resolver falls through to net.allow and is refused. compile --test answered it from the
// machine config alone, allow via net.resolver in every mode, so an `expect: refused` row proving direct DNS is
// blocked failed and an `expect: allow` row certified a connect the run refuses.
func TestCompileTestResolverRowsFollowDNSMode(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "tego.yaml")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+filepath.Join(base, "runs")+"\nresolver: [\"192.0.2.53\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	for _, tc := range []struct{ dns, expect string }{
		{"", "allow"}, {"\n  dns:\n    mode: system", "allow"}, {"\n  dns:\n    mode: off", "refused"}, {"\n  dns:\n    mode: broker", "refused"},
	} {
		dir := t.TempDir()
		contract := "version: 0\nname: dnsmode\ncommand: [\"true\"]\nnet:\n  allow: [\"192.0.2.80:443\"]" + tc.dns + "\n"
		table := "version: 0\ntests:\n" +
			"  - {name: udp, action: net.connect, host_port: 'udp://192.0.2.53:53', expect: " + tc.expect + "}\n" +
			"  - {name: tcp, action: net.connect, host_port: 'tcp://192.0.2.53:53', expect: " + tc.expect + "}\n"
		for name, body := range map[string]string{"agent.yaml": contract, "rows.yaml": table} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		code, out, errs := run(t, "compile", filepath.Join(dir, "agent.yaml"), "--offline", "--test", filepath.Join(dir, "rows.yaml"), "--tier", "landlock,cgroup,bpflsm")
		if code != identity.ExitOK {
			t.Errorf("dns %q, expect %s: exit %d\n%s\n%s", tc.dns, tc.expect, code, out, errs)
		}
	}
}
