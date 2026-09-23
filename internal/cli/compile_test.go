// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestCompileMinimal(t *testing.T) {
	code, out, errs := run(t, "compile", filepath.Join("testdata", "minimal.yaml"))
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	for _, want := range []string{"contract ", "hash ", "tier ", "limits ", "exec ", "/true"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	// Flags after the positional argument work too.
	code, out, errs = run(t, "compile", filepath.Join("testdata", "minimal.yaml"), "--json", "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	var tbl Table
	if err := json.Unmarshal([]byte(out), &tbl); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if tbl.Name != "minimal" || len(tbl.ContractHash) != 64 || tbl.Tier == "" || len(tbl.Exec) != 1 || tbl.Exec[0].Basename != "true" {
		t.Fatalf("%+v", tbl)
	}
	if tbl.FS == nil || tbl.Net == nil {
		t.Fatal("empty sections are [] not null")
	}
}

// TestCompileNamesSecretEnv (ADR 0067): `tego compile` gives Compile the environment's names, so a contract with no
// env.pass draws secret-env naming the secret-looking variable, never its value; the exit is still ok (a warning).
func TestCompileNamesSecretEnv(t *testing.T) {
	t.Setenv("CSD_PROBE_API_KEY", "value-never-printed-7731")
	code, out, errs := run(t, "compile", filepath.Join("testdata", "minimal.yaml"), "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	if !strings.Contains(errs, "CSD_PROBE_API_KEY") || !strings.Contains(errs, "[secret-env]") {
		t.Errorf("stderr lacks the secret-env warning naming CSD_PROBE_API_KEY:\n%s", errs)
	}
	if strings.Contains(out+errs, "value-never-printed-7731") {
		t.Errorf("the variable's value was printed:\n%s\n%s", out, errs)
	}
}

// TestCompilePrintsEffectiveValues: spec/config/v0 says compile prints every effective machine config value with the
// file and line it came from, and config.WriteEffective existed with no caller, so it printed none of them. Both the
// table and --json carry them now.
func TestCompilePrintsEffectiveValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("retention: 7d\nlimits:\n  pids: 512\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	contract := filepath.Join("testdata", "minimal.yaml")
	code, out, errs := run(t, "compile", contract, "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	for _, want := range []string{
		"setting retention=7d  (" + cfg + ":1)",
		"ceiling limits.pids=512  (" + cfg + ":3)",
		"ceiling tier=auto  (built-in)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compile does not print %q:\n%s", want, out)
		}
	}
	code, out, errs = run(t, "compile", contract, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	var tbl Table
	if err := json.Unmarshal([]byte(out), &tbl); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	found := false
	for _, v := range tbl.Machine {
		if v.Key == "retention" && v.Value == "7d" && v.Source == cfg+":1" && !v.Ceiling {
			found = true
		}
	}
	if !found {
		t.Errorf("--json machine lacks retention=7d from %s:1: %+v", cfg, tbl.Machine)
	}
}

// TestCompileSaysUnrestricted: a contract with no net: or no exec: section is unrestricted there (SEMANTICS §1), and
// compile printed its entry lists (the command, or none) exactly like a section refusing everything else. The table
// says so, --json carries it as two booleans, and a section present with no value, which parsed as absent, is a
// schema error naming the fix. With no net: section the IP side is unrestricted and the unix side is the run's own
// sockets only (ADR 0070), which the net line and --json's host_sockets_refused say; host_sockets: true opens both.
func TestCompileSaysUnrestricted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TEGO_CONFIG", "")
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("version: 0\nname: u\ncommand: [\"true\"]\n"+body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const unixOnly = "IP unrestricted, unix sockets the run's own only (no net: section)"
	const optOut = "net unrestricted (no net: section, host_sockets: true)"
	for _, tc := range []struct {
		name, body string
		open       bool
		netLine    string // the net line's reading, "" for a net: section
	}{
		{"absent.yaml", "", true, unixOnly},
		{"optout.yaml", "host_sockets: true\n", true, optOut},
		{"empty.yaml", "net: {}\nexec: {}\n", false, ""},
	} {
		contract := write(tc.name, tc.body)
		code, text, errs := run(t, "compile", contract, "--offline")
		if code != identity.ExitOK {
			t.Fatalf("%s: exit %d stderr %q", tc.name, code, errs)
		}
		if want := "exec unrestricted (no exec: section)"; strings.Contains(text, want) != tc.open {
			t.Errorf("%s: printed %q is %v, want %v:\n%s", tc.name, want, !tc.open, tc.open, text)
		}
		for _, line := range []string{unixOnly, optOut} {
			if strings.Contains(text, line) != (line == tc.netLine) {
				t.Errorf("%s: printed %q is %v, want %v:\n%s", tc.name, line, !(line == tc.netLine), line == tc.netLine, text)
			}
		}
		code, out, errs := run(t, "compile", contract, "--offline", "--json")
		if code != identity.ExitOK {
			t.Fatalf("%s: exit %d stderr %q", tc.name, code, errs)
		}
		var tbl Table
		if err := json.Unmarshal([]byte(out), &tbl); err != nil {
			t.Fatalf("json: %v\n%s", err, out)
		}
		if tbl.NetUnrestricted != tc.open || tbl.ExecUnrestricted != tc.open {
			t.Errorf("%s: net_unrestricted %v exec_unrestricted %v, want %v", tc.name, tbl.NetUnrestricted, tbl.ExecUnrestricted, tc.open)
		}
		if tbl.HostSocketsRefused != (tc.netLine == unixOnly) {
			t.Errorf("%s: host_sockets_refused %v, want %v", tc.name, tbl.HostSocketsRefused, tc.netLine == unixOnly)
		}
		if !strings.Contains(out, `"net_unrestricted":`) || !strings.Contains(out, `"exec_unrestricted":`) || !strings.Contains(out, `"host_sockets_refused":`) {
			t.Errorf("%s: --json lacks the keys:\n%s", tc.name, out)
		}
	}
	contract := write("null.yaml", "net:\n  # allow: [\"api.example.com:443\"]\n")
	code, _, errs := run(t, "compile", contract, "--offline")
	if code == identity.ExitOK || !strings.Contains(errs, "write `net: {}` to refuse all, or remove the key") {
		t.Errorf("a null net: compiled (exit %d):\n%s", code, errs)
	}
}

// TestCompileJSONCarriesThePrintedNotes: --json left out the built-in deny_write set and the NOTES column the printed
// table shows, so a script could not see that an entry is refused best effort below a decision plane (ADR 0041 D1
// (a)), and it printed cpu as "" where every other unbounded limit is null.
func TestCompileJSONCarriesThePrintedNotes(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	// A harness settings file beneath a write entry is in the built-in deny_write set (R20), and Landlock
	// cannot deny beneath the write entry, so below a decision plane only the supervisor refuses a write to it,
	// best effort (fs.assurance's default, ADR 0041 D1 (a)).
	if err := os.WriteFile(filepath.Join(work, ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(dir, "agent.yaml")
	body := "version: 0\nname: notes\ncommand: [\"true\"]\nfs:\n  write: [\"" + work + "\"]\n"
	if err := os.WriteFile(contract, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", "")
	code, text, errs := run(t, "compile", contract, "--offline")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	if !strings.Contains(text, "best-effort(supervisor; landlock: parent writable)") {
		t.Fatalf("the printed table has no best-effort entry to compare with:\n%s", text)
	}
	code, out, errs := run(t, "compile", contract, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	var tbl Table
	if err := json.Unmarshal([]byte(out), &tbl); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	found := false
	for _, e := range tbl.FS {
		if e.Kind == string(agent.FSDenyWrite) && e.Path == filepath.Join(work, ".mcp.json") {
			found = true
			if !e.BestEffort || e.KernelPlaneRequired || e.Unenforced {
				t.Errorf("deny_write entry %+v: want best_effort, neither kernel_plane_required nor unenforced", e)
			}
		}
	}
	if !found {
		t.Errorf("--json lacks the deny_write entry the table prints:\n%s", out)
	}
	if !strings.Contains(out, `"cpu":null`) {
		t.Errorf("an unbounded cpu is not null:\n%s", out)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"unknown field", []string{"compile", filepath.Join("testdata", "bad.yaml")}, identity.ExitFinding, "bad.yaml:"},
		{"missing file", []string{"compile", filepath.Join("testdata", "nope.yaml")}, identity.ExitFinding, "[path-missing]"},
		{"two files", []string{"compile", "a", "b"}, identity.ExitUsage, "[usage]"},
		{"unknown flag", []string{"compile", "--nope", "x"}, identity.ExitUsage, "flag provided but not defined"},
		{"malformed test table", []string{"compile", filepath.Join("testdata", "minimal.yaml"), "--test", filepath.Join("testdata", "bad-table.yaml")}, identity.ExitUsage, "[schema]"},
		{"missing test table", []string{"compile", filepath.Join("testdata", "minimal.yaml"), "--test", filepath.Join("testdata", "nope.yaml")}, identity.ExitUsage, "[path-missing]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errs := run(t, tc.args...)
			if code != tc.wantCode { // R25: 1 a finding, 2 usage
				t.Fatalf("exit %d want %d: %q", code, tc.wantCode, errs)
			}
			if !strings.Contains(errs, tc.wantErr) {
				t.Fatalf("stderr %q lacks %q", errs, tc.wantErr)
			}
		})
	}
}

// TestInitThenCompile: the starter compiles with exit 0.
func TestInitThenCompile(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("starter names python3, not on PATH")
	}
	dir := t.TempDir()
	if code, _, errs := run(t, "init", "--name", "starter", dir); code != identity.ExitOK {
		t.Fatalf("init: %d %q", code, errs)
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	t.Setenv("TEGO_CONFIG", "")
	code, out, errs := run(t, "compile", "--offline", "agent.yaml")
	if code != identity.ExitOK {
		t.Fatalf("compile: %d\nstdout %s\nstderr %s", code, out, errs)
	}
	// The starter compiles silently: under record: full a read is a line, so its stall_after counts reads
	// and compile has nothing to warn about, even on the first compile.
	if strings.TrimSpace(errs) != "" {
		t.Errorf("the starter's first compile printed:\n%s\nwant nothing", errs)
	}
	for _, want := range []string{"agent.yaml", "python3", "memory=4GiB", "pids=256", "pass=PATH,HOME"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table lacks %q:\n%s", want, out)
		}
	}
}

func TestDirProfiles(t *testing.T) {
	root := trustedDir(t)
	if err := os.MkdirAll(filepath.Join(root, "base"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "base", "py.yaml"), []byte("version: 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := dirProfiles{Root: root}
	if p, data, err := src.Resolve("base/py"); err != nil || string(data) != "version: 0\n" || !strings.HasSuffix(p, "py.yaml") {
		t.Fatalf("%q %q %v", p, data, err)
	}
	for _, name := range []string{"../etc/passwd", "/etc/passwd", "", "base/../../x", "a\x00b"} {
		if _, _, err := src.Resolve(name); err == nil || !os.IsNotExist(errUnwrap(err)) {
			t.Errorf("%q: %v", name, err)
		}
	}
	if _, _, err := (dirProfiles{}).Resolve("base/py"); err == nil {
		t.Fatal("empty root resolves nothing")
	}
}

// A profiles: directory spelled with ".." after a link (<dir>/lnk/../profiles, lnk -> <dir>/real/sub) is opened at
// <dir>/real/profiles, and the profile's path names the file read there, not <dir>/profiles/base/py.yaml, which
// filepath.Join's cleaning spelled.
func TestDirProfilesNamesTheFileReadThroughDotDotAfterALink(t *testing.T) {
	dir := trustedDir(t)
	for _, d := range []string{filepath.Join("real", "sub"), filepath.Join("real", "profiles", "base")} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	want := filepath.Join(dir, "real", "profiles", "base", "py.yaml")
	if err := os.WriteFile(want, []byte("version: 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real", "sub"), filepath.Join(dir, "lnk")); err != nil {
		t.Fatal(err)
	}
	if real, err := filepath.EvalSymlinks(want); err != nil {
		t.Fatal(err)
	} else {
		want = real
	}
	src := dirProfiles{Root: dir + "/lnk/../profiles"}
	if p, _, err := src.Resolve("base/py"); err != nil || p != want {
		t.Fatalf("Resolve = %q, %v, want %s", p, err, want)
	}
	if p := src.Location("base/py"); p != want {
		t.Fatalf("Location = %q, want %s", p, want)
	}
}

// TestDirProfilesSymlinkEscape is E7 at resolution level: a profile name that is lexically inside the
// profiles directory but reaches a file outside it through a symlink — the file itself, or a directory on
// its path — is never read, and Load reports extends-not-found for it. A relative link that stays inside
// the directory still resolves; one with an absolute target is refused even when that target is inside.
func TestDirProfilesSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "profiles")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "base"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "version: 0\nname: outside-secret\n"
	if err := os.WriteFile(filepath.Join(outside, "x.yaml"), []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "base", "py.yaml"), []byte("version: 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		filepath.Join(root, "evil.yaml"):  filepath.Join("..", "outside", "x.yaml"),
		filepath.Join(root, "sub"):        filepath.Join("..", "outside"),
		filepath.Join(root, "alias.yaml"): filepath.Join("base", "py.yaml"),
		// os.Root refuses a link with an absolute target even when it names a file inside the root, so a
		// profile linked by absolute path (ln -s "$PWD/base/py.yaml", a stow farm of per-file links) is not
		// found: links in the profiles directory must be relative (E7).
		filepath.Join(root, "abs.yaml"): filepath.Join(root, "base", "py.yaml"),
	}
	for link, target := range links {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	src := dirProfiles{Root: root}
	for _, name := range []string{"evil", "sub/x", "abs"} {
		if _, data, err := src.Resolve(name); err == nil || data != nil {
			t.Errorf("%q: read %q through a link out of the profiles directory, or an absolute one (err %v)", name, data, err)
		}
	}
	if _, data, err := src.Resolve("alias"); err != nil || string(data) != "version: 0\n" {
		t.Errorf("a link inside the profiles directory must still resolve: %q %v", data, err)
	}

	contract := filepath.Join(base, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: t\nextends: evil\ncommand: [true]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.Load(contract, src)
	if err == nil || c != nil {
		t.Fatalf("extends through an escaping link loaded: %v", err)
	}
	found := false
	for _, d := range ds {
		if d.Code == agent.CodeExtendsNotFound {
			found = true
		}
		if strings.Contains(d.Message+d.Fix, "outside-secret") {
			t.Errorf("a diagnostic echoes the outside file: %v", d)
		}
	}
	if !found {
		t.Fatalf("want extends-not-found, got %v", ds)
	}
}

// TestExtendsNotFoundNamesTheFile: through the real profile source, the fix line names the file `extends:` is read
// from, never `tego init --profile`, which init does not have.
func TestExtendsNotFoundNamesTheFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "profiles")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: t\nextends: base/py\ncommand: [\"true\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, ds, err := agent.Load(contract, dirProfiles{Root: root})
	if err == nil {
		t.Fatal("a missing profile loaded")
	}
	want := "create " + filepath.Join(root, "base", "py.yaml") + ", or remove extends:"
	for _, d := range ds {
		if d.Code == agent.CodeExtendsNotFound {
			if !strings.Contains(d.Fix, want) || strings.Contains(d.Fix, "--profile") {
				t.Errorf("fix %q, want it to contain %q", d.Fix, want)
			}
			return
		}
	}
	t.Fatalf("want extends-not-found, got %v", ds)
}

// errUnwrap reaches the innermost error for os.IsNotExist, which does not unwrap.
func errUnwrap(err error) error {
	for {
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
}

// TestCompileTestTable: the shipped table under
// examples/tests passes, row for row, with exit 0 (R25, R28).
// (limits-check-doctor-cli.md R28.)
func TestCompileTestTable(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	t.Chdir(filepath.Join("..", "..", "examples", "tests"))
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup) // the released build: make build
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "testdata", "compile-test.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Errorf("output drifted from the golden file:\ngot:\n%s\nwant:\n%s", out, want)
	}
	// The README quotes the summary line; it said 20 rows when the table had 21.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if summary := lines[len(lines)-1]; !strings.Contains(string(readme), "# "+summary+"\n") {
		t.Errorf("examples/tests/README.md does not quote the summary line %q", summary)
	}
}

// TestCompileTestFailingRow pins the FAIL line and the finding exit code: the
// same table evaluated with one row's expectation inverted (R25, R28).
// (limits-check-doctor-cli.md R25 and R28.)
func TestCompileTestFailingRow(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	dir := t.TempDir()
	for _, name := range []string{"agent.yaml"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "examples", "tests", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, sub := range []string{"out/keys", "secrets", "config"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(sub)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	table := `version: 0
tests:
  - name: this expectation is wrong
    action: fs.write
    path: out/report.md
    expect: refused
  - name: this one is right
    action: fs.write
    path: notes.md
    expect: refused
`
	if err := os.WriteFile(filepath.Join(dir, "verdicts.yaml"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	// One tier, so the row answers in one column whatever this test binary builds: a static tegobpf binary
	// also builds cgroup, and the two-column form is TestCompileTestAnswersInEveryTierARunCanGet's.
	buildsTiers(t, backend.TierLandlock)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d want %d\nstdout %s\nstderr %s", code, identity.ExitFinding, out, errs)
	}
	for _, want := range []string{
		"FAIL this expectation is wrong (verdicts.yaml:3): got allow via fs.write[out/], want refused",
		"PASS this one is right",
		"2 rows: 1 passed, 1 failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
}

// TestCompileUpgradeRefusesWithItsCondition is COMPILE-UPGRADE-FLAG: R29 lists --upgrade, and until a
// contract version after 0 exists there is nothing to rewrite to. The flag is accepted and refused as a
// usage error that names the condition, never "flag provided but not defined" and never a silent 0.
func TestCompileUpgradeRefusesWithItsCondition(t *testing.T) {
	code, out, errs := run(t, "compile", filepath.Join("testdata", "minimal.yaml"), "--upgrade")
	if code != identity.ExitUsage {
		t.Fatalf("exit %d, want 2\nstdout %s\nstderr %s", code, out, errs)
	}
	if strings.Contains(errs, "not defined") || !strings.Contains(errs, "contract version 1") || !strings.Contains(errs, "[usage]") {
		t.Fatalf("stderr does not name the condition: %s", errs)
	}
	if out != "" {
		t.Fatalf("a refused upgrade printed %q", out)
	}
}

// copyExampleTests lays examples/tests' contract and its directories out in a scratch directory, with table
// as its verdict table, and moves there.
func copyExampleTests(t *testing.T, table string) {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "tests", "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.yaml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"out/keys", "secrets", "config"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(sub)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "verdicts.yaml"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
}

// readsDirect sets fs.reads: direct in the copied example contract (copyExampleTests).
func readsDirect(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Replace(string(data), "fs:\n", "fs:\n  reads: direct\n", 1)
	if out == string(data) {
		t.Fatal("the example contract has no fs: section")
	}
	if err := os.WriteFile("agent.yaml", []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}

// rootTierOnlyRow asserts a refusal the root tiers make and Landlock does not under fs.reads: direct: a deny_read
// beneath the write entry.
const rootTierOnlyRow = `version: 0
tests:
  - name: a secret beneath the write entry
    action: fs.read
    path: out/keys/token
    expect: refused
`

// TestCompileTestAnswersInEveryTierARunCanGet: a row with no tier: asserting out/keys/token refused PASSED, because
// it answered in bpflsm, the tier auto compiled to and no build contains, while the real run at landlock read the
// file. It now answers in every tier a run of the contract can get and fails, naming landlock's answer; --tier
// narrows the answer to the machine it will run on.
// (limits-check-doctor-cli.md E29 and R33: the answer is per tier a run can get, computed from the build alone.)
func TestCompileTestAnswersInEveryTierARunCanGet(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	copyExampleTests(t, rootTierOnlyRow)
	// fs.reads: direct keeps the nested deny_read unenforced at tier landlock, the one answer the tiers differ on; the
	// default holds the run's reads there and refuses it (ADR 0069).
	readsDirect(t)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, identity.ExitFinding, out, errs)
	}
	for _, want := range []string{
		"tiers landlock, cgroup (tier auto: every tier this tego builds)",
		"FAIL a secret beneath the write entry (verdicts.yaml:3): at landlock got allow via fs.deny_read[out/keys/] (unenforced: parent writable), want refused",
		"1 rows: 0 passed, 1 failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(errs, "unenforced in the landlock tier") {
		t.Errorf("compile did not warn that landlock leaves the deny_read unenforced:\n%s", errs)
	}

	code, out, errs = run(t, "compile", "agent.yaml", "--test", "verdicts.yaml", "--tier", "cgroup")
	if code != identity.ExitOK || !strings.Contains(out, "tiers cgroup (--tier)") || !strings.Contains(out, "PASS a secret beneath the write entry") {
		t.Fatalf("--tier cgroup: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}

	// A tier-1 build answers in landlock alone, and the row fails in the one-column form.
	buildsTiers(t, backend.TierLandlock)
	code, out, _ = run(t, "compile", "agent.yaml", "--test", "verdicts.yaml")
	if code != identity.ExitFinding || !strings.Contains(out, "tiers landlock (") ||
		!strings.Contains(out, ": got allow via fs.deny_read[out/keys/] (unenforced: parent writable), want refused") {
		t.Fatalf("tier-1 build: exit %d\n%s", code, out)
	}
}

// TestCompileTestJSON is ADR 0019 (4): compile --test --json is one versioned object with each row's answer
// in every tier it was evaluated in.
func TestCompileTestJSON(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("the example contract names sh, not on PATH")
	}
	copyExampleTests(t, rootTierOnlyRow)
	readsDirect(t) // the tiers answer the row differently (TestCompileTestAnswersInEveryTierARunCanGet)
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml", "--json")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var rep TestReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, out)
	}
	if rep.V != 1 || len(rep.Tiers) != 2 || rep.Failed != 1 || rep.Passed != 0 || len(rep.Rows) != 1 {
		t.Fatalf("report %+v", rep)
	}
	row := rep.Rows[0]
	if row.Pass || row.Line != 3 || len(row.Columns) != 2 {
		t.Fatalf("row %+v", row)
	}
	if c := row.Columns[0]; c.Tier != "landlock" || c.Verdict != "allow" || c.Pass {
		t.Errorf("landlock column %+v", c)
	}
	if c := row.Columns[1]; c.Tier != "cgroup" || c.Verdict != "refused" || !c.Pass {
		t.Errorf("cgroup column %+v", c)
	}
}

// TestCompileTierFlagIsTestTablesAlone: --tier names the tiers a test table answers in, so it is a usage error
// without --test, and it takes enforcement tiers, each once.
func TestCompileTierFlagIsTestTablesAlone(t *testing.T) {
	contract := filepath.Join("testdata", "minimal.yaml")
	table := filepath.Join("testdata", "nope.yaml")
	for _, args := range [][]string{
		{"compile", contract, "--tier", "landlock"},
		{"compile", contract, "--test", table, "--tier", "observe"},
		{"compile", contract, "--test", table, "--tier", "auto"},
		{"compile", contract, "--test", table, "--tier", "landlock,landlock"},
		{"compile", contract, "--test", table, "--tier", "landlock,"},
	} {
		if code, _, errs := run(t, args...); code != identity.ExitUsage || !strings.Contains(errs, "--tier") {
			t.Errorf("%v: exit %d, want 2 naming --tier\n%s", args, code, errs)
		}
	}
}

// TestCompileTestHardLinkOfGrantedBinaryIsRefused is the compile --test half of the supervisor's hard-link refusal: a
// hard link of a granted binary (on Ubuntu 25.10, /usr/bin/ls beside a granted /usr/bin/sleep, both one uutils
// binary) is refused at tier landlock, the answer the supervisor gives the run (supervisor
// TestExecHardLinkOfGrantedBinaryIsRefused). Landlock's EXECUTE on the shared inode would allow it; the supervisor's
// refusal is what makes this row true.
func TestCompileTestHardLinkOfGrantedBinaryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	a := filepath.Join(dir, "bin", "sleep")
	b := filepath.Join(dir, "bin", "ls")
	if err := os.MkdirAll(filepath.Dir(a), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard link: %v", err)
	}
	contract := "version: 0\nname: hardlink\ncommand: [\"" + a + "\"]\nexec:\n  allow: [\"" + a + "\"]\n"
	table := "version: 0\ntests:\n" +
		"  - name: the granted binary runs\n    action: exec\n    path: " + a + "\n    tier: landlock\n    expect: allow\n" +
		"  - name: a hard link of it does not\n    action: exec\n    path: " + b + "\n    tier: landlock\n    expect: refused\n    rule: unmatched\n"
	for name, data := range map[string]string{"agent.yaml": contract, "verdicts.yaml": table} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	buildsTiers(t, backend.TierLandlock)
	code, out, errs := run(t, "compile", "agent.yaml", "--test", "verdicts.yaml")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	for _, want := range []string{"PASS the granted binary runs", "PASS a hard link of it does not", "2 rows: 2 passed, 0 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
}

// TestCompileJSONRequiredDenyWriteAuthority checks the public JSON from a real compiled contract, rather than a
// constructed RuleTable: under fs.assurance: kernel a deny_write entry is kernel_plane_required, never best_effort
// (ADR 0041 D1 (a)), and the printed table says so.
func TestCompileJSONRequiredDenyWriteAuthority(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(work, ".mcp.json")
	if err := os.WriteFile(target, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(dir, "agent.yaml")
	body := "version: 0\nname: authority\ncommand: [true]\nfs:\n  write: [\"" + work + "\"]\n  assurance: kernel\n"
	if err := os.WriteFile(contract, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", "")
	if code, text, errs := run(t, "compile", contract, "--offline"); code != identity.ExitOK ||
		!strings.Contains(text, "kernel-plane-required(landlock: parent writable)") || !strings.Contains(text, "assurance kernel") {
		t.Fatalf("exit %d stderr %s: the printed table does not say a plane is required:\n%s", code, errs, text)
	}
	code, out, errs := run(t, "compile", contract, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %s", code, errs)
	}
	var doc struct {
		FS []map[string]any `json:"fs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, row := range doc.FS {
		if row["path"] != target || row["kind"] != "deny_write" {
			continue
		}
		if row["kernel_plane_required"] != true || row["best_effort"] == true || row["unenforced"] == true {
			t.Fatalf("mandatory deny_write authority mislabeled: %+v", row)
		}
		return
	}
	t.Fatalf("missing deny_write row in %s", out)
}

// TestCompileBindRows verifies the public loader, CLI dispatch and bpflsm
// network fallback together, using a real compiled listener declaration.
func TestCompileBindRows(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(work, "server.sock")
	contract := filepath.Join(dir, "agent.yaml")
	body := "version: 0\nname: bind\ncommand: [true]\nfs:\n  write: [\"" + work + "\"]\n  deny_read: []\nnet:\n  listen: [\"tcp://127.0.0.1:8080\", \"udp://[::1]:8081\", \"unix:" + socket + "\"]\n"
	if err := os.WriteFile(contract, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(dir, "rows.yaml")
	rows := "version: 0\ntests:\n" +
		"  - {action: net.bind, host_port: '127.0.0.1:8080', expect: allow}\n" +
		"  - {action: net.bind, host_port: 'tcp://127.0.0.1:8081', expect: refused}\n" +
		"  - {action: net.bind, host_port: 'udp://[::1]:8081', expect: allow}\n" +
		"  - {action: net.bind, host_port: 'tcp://[::1]:8081', expect: refused}\n" +
		"  - {action: net.bind, path: 'unix:" + socket + "', expect: allow}\n" +
		"  - {action: net.bind, host_port: 'unix:@undeclared', expect: refused}\n"
	if err := os.WriteFile(table, []byte(rows), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierCgroup, backend.TierBPFLSM)
	for _, asJSON := range []bool{false, true} {
		args := []string{"compile", contract, "--offline", "--test", table, "--tier", "cgroup,bpflsm"}
		if asJSON {
			args = append(args, "--json")
		}
		code, out, errs := run(t, args...)
		if code != identity.ExitOK {
			t.Fatalf("json=%v exit %d\n%s\n%s", asJSON, code, out, errs)
		}
		if !asJSON {
			if !strings.Contains(out, "6 rows: 6 passed, 0 failed") {
				t.Fatal(out)
			}
			continue
		}
		var report TestReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatal(err)
		}
		if report.Passed != 6 || report.Failed != 0 || len(report.Rows) != 6 {
			t.Fatalf("%+v", report)
		}
		for _, row := range report.Rows {
			if !row.Pass || len(row.Columns) != 2 {
				t.Fatalf("%+v", row)
			}
			for _, cell := range row.Columns {
				if !cell.Pass || cell.Verdict != row.Expect {
					t.Fatalf("%+v", cell)
				}
			}
		}
	}
}

// An fs.ask_read entry prints by the key it was declared in, with the note that a person decides its reads at tier
// landlock, and --json keeps kind deny_read (what every other mechanism applies) with ask_read set.
func TestCompilePrintsAskReadEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(dir, "vault")
	if err := os.MkdirAll(vault, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+filepath.Join(dir, "runs")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	contract := filepath.Join(dir, "project", "agent.yaml")
	if err := os.MkdirAll(filepath.Dir(contract), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "version: 0\nname: askread\ncommand: [\"true\"]\ntier: landlock\nfs:\n  ask_read: [\"" + vault + "\"]\n"
	if err := os.WriteFile(contract, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	code, text, errs := run(t, "compile", contract, "--offline")
	if code != identity.ExitOK || !strings.Contains(text, "ask_read") || !strings.Contains(text, "held-for-a-person(tier landlock)") {
		t.Fatalf("exit %d stderr %q:\n%s", code, errs, text)
	}
	code, out, errs := run(t, "compile", contract, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	var tbl Table
	if err := json.Unmarshal([]byte(out), &tbl); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	found := false
	for _, e := range tbl.FS {
		if e.Path == vault {
			found = e.Kind == string(agent.FSDenyRead) && e.AskRead
		}
	}
	if !found {
		t.Fatalf("--json lacks the ask_read entry as a deny_read with ask_read set:\n%s", out)
	}
}

// TestCompileAndRunRefuseWritesOverTheTegoBinary: `tego compile` and `tego run` name the running binary to the compiler
// (R10), so an entry over the install directory stops before the agent starts, in words that say why.
func TestCompileAndRunRefuseWritesOverTheTegoBinary(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(dir, "install")
	exe := filepath.Join(install, "tego")
	if err := os.MkdirAll(install, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldExe, oldRun := executable, startRun
	t.Cleanup(func() { executable, startRun = oldExe, oldRun })
	executable = func() (string, error) { return exe, nil }
	// Refused before anything starts. A real start here re-enters this test binary as tego's child stage, without end.
	startRun = func(context.Context, *agent.RuleTable, []string, tegoruntime.Deps) (tegoruntime.Result, error) {
		t.Error("the run started")
		return tegoruntime.Result{}, nil
	}
	contract := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: a\ncommand: [/bin/true]\nfs:\n  write: ["+install+"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"compile", contract, "--offline"}, identity.ExitFinding},
		{[]string{"run", contract}, identity.ExitLauncher},
	} {
		code, _, errs := run(t, c.args...)
		if code != c.code || !strings.Contains(errs, "contains the tego binary "+exe) ||
			!strings.Contains(errs, "[contradiction]") || !strings.Contains(errs, "can replace tego") {
			t.Errorf("tego %s: exit %d, stderr:\n%s", c.args[0], code, errs)
		}
	}
}

// TestRunningBinary: the running file is what R10 protects, but for a package's test binary, and an error names none.
func TestRunningBinary(t *testing.T) {
	old := executable
	t.Cleanup(func() { executable = old })
	for _, c := range []struct {
		exe  string
		err  error
		want string
	}{
		{"/opt/tego/tego", nil, "/opt/tego/tego"},
		{"/tmp/go-build1/cli.test", nil, ""},
		{"/opt/tego/tego", errors.New("no /proc"), ""},
	} {
		executable = func() (string, error) { return c.exe, c.err }
		if got := runningBinary(); got != c.want {
			t.Errorf("runningBinary(%q, %v) = %q, want %q", c.exe, c.err, got, c.want)
		}
	}
}
