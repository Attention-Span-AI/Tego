// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// copyFixture is a project whose contract extends a profile and names a write entry below a
// directory that exists only in the project, so the table it compiles to depends on both the
// profile and the directory relative entries resolve against.
type copyFixture struct {
	project, profiles, contract string
}

const (
	copyProfile  = "net:\n  allow: [\"api.github.com:443\"]\n"
	copyContract = "version: 0\nname: tester\nextends: base\ncommand: [\"/bin/true\"]\nfs:\n  write: [\"./sub/out\"]\n"
)

// newCopyFixture writes the project, its profile directory and a machine config naming both the
// ledger root and the profiles, and returns the ledger root.
func newCopyFixture(t *testing.T) (copyFixture, string) {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	f := copyFixture{
		project:  filepath.Join(base, "project"),
		profiles: filepath.Join(base, "profiles"),
	}
	f.contract = filepath.Join(f.project, "agent.yaml")
	root := filepath.Join(base, "runs")
	for _, d := range []string{filepath.Join(f.project, "sub"), f.profiles, root} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(f.profiles, "base.yaml"), copyProfile)
	writeTestFile(t, f.contract, copyContract)
	cfg := filepath.Join(base, "tego.yaml")
	writeTestFile(t, cfg, "ledger_root: "+root+"\nprofiles: "+f.profiles+"\n")
	t.Setenv("TEGO_CONFIG", cfg)
	return f, root
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// compileLikeRun compiles the fixture's contract the way `tego run` does, from the project directory.
func compileLikeRun(t *testing.T, f copyFixture) *agent.RuleTable {
	t.Helper()
	t.Chdir(f.project)
	c, ds, err := agent.Load(f.contract, dirProfiles{Root: f.profiles})
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	rt, ds, err := agent.Compile(c, config.Builtin(), agent.WithPATH(os.Getenv("PATH")), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	return rt
}

// recordRun writes the run directory `tego run` leaves behind for rt: run_start with the contract
// hash and the project as cwd, one allowed write against the declared entry, run_end, and the
// contract copy runRun hands the ledger.
func recordRun(t *testing.T, root string, f copyFixture, rt *agent.RuleTable) string {
	t.Helper()
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copyBytes, err := contractCopy(rt)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, string(id))
	w, err := ledger.Open(dir, record.RunRef{ID: string(id), Agent: "tester"},
		ledger.WithContract(copyBytes), ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{
		Command: []string{"/bin/true"}, Cwd: f.project, Tier: "landlock",
		ContractHash: hex.EncodeToString(rt.Hash[:]), Parsers: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	e := &record.Event{
		Kind: record.KindFS, Source: record.SourceLandlock, PID: 1, TID: 1,
		Rule: "fs.write[./sub/out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
		Attr: &record.Attribution{Confidence: "unattributed", Method: "none"},
	}
	if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: filepath.Join(f.project, "sub", "out")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(e); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// nopAnchor keeps these runs out of any chain.log.
type nopAnchor struct{}

func (nopAnchor) Append(string, string) error       { return nil }
func (nopAnchor) Head(string) (string, bool, error) { return "", false, nil }

// TestContractCopyIsTheCompiledContract is agent-contract.md R13 / P0-DESIGN §3.3: the bytes a run
// keeps as contract.yaml hash to its contract_hash, and they need no profile to reload into the
// same contract.
func TestContractCopyIsTheCompiledContract(t *testing.T) {
	f, _ := newCopyFixture(t)
	rt := compileLikeRun(t, f)
	b, err := contractCopy(rt)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); sum != rt.Hash {
		t.Fatalf("sha256(contract.yaml) = %x, contract_hash %x", sum, rt.Hash)
	}
	if !strings.Contains(string(b), "api.github.com:443") {
		t.Fatalf("the copy lacks the profile's entry, so it is not self-contained:\n%s", b)
	}
	c, ds, err := loadContractCopy(writeCopy(t, b), hex.EncodeToString(rt.Hash[:]), dirProfiles{})
	if err != nil {
		t.Fatalf("the copy does not reload without its profile: %v %v", err, ds)
	}
	if h, err := c.Hash(); err != nil || h != rt.Hash {
		t.Fatalf("reloaded hash %x (%v), want %x", h, err, rt.Hash)
	}
}

func writeCopy(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ledger.ContractFile)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDriftRecompilesTheRunsContract is R16 with CONTRACT-COPY-CANONICAL: a profile edited after
// the run and drift invoked from another directory change nothing about "what this run actually
// used" — the hash is unchanged and the declared entry is still the author's. Recompiling a copy of
// the file as written, against today's profiles and the invoking shell's directory, reported the
// contract as changed and the write as undeclared.
func TestDriftRecompilesTheRunsContract(t *testing.T) {
	f, root := newCopyFixture(t)
	rt := compileLikeRun(t, f)
	dir := recordRun(t, root, f, rt)
	writeTestFile(t, filepath.Join(f.profiles, "base.yaml"), copyProfile+"  ask: [\"example.com:443\"]\n")
	t.Chdir(t.TempDir())
	code, out, errs := run(t, "drift", dir, "--json")
	var got driftJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("exit %d json: %v\nstdout %s\nstderr %s", code, err, out, errs)
	}
	if got.HashChanged || got.CurrentHash != got.ContractHash {
		t.Errorf("hash changed: current %s, recorded %s\nstderr %s", got.CurrentHash, got.ContractHash, errs)
	}
	declared := false
	for _, r := range got.Rules {
		if r.Rule == "fs.write[./sub/out]" {
			declared = r.Declared
		}
	}
	if !declared {
		t.Errorf("fs.write[./sub/out] is not declared: the copy compiled against the wrong directory\n%s\nstderr %s", out, errs)
	}
}

// TestDriftSaysUnobservableAndPrintsGaps is R34 through the CLI: a contract declaring an
// MCP server, on a run whose record names no MCP producer, prints the server as not observable and
// exits by the rest of the report; the gap line is printed either way.
// (limits-check-doctor-cli.md R34.)
func TestDriftSaysUnobservableAndPrintsGaps(t *testing.T) {
	root := gcRoot(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, string(id))
	w, err := ledger.Open(dir, record.RunRef{ID: string(id), Agent: "tester"},
		ledger.WithContract([]byte("version: 0\nname: tester\ncommand: [\"/bin/true\"]\nmcp:\n  - name: fs\n    command: [\"/bin/true\"]\n")),
		ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Cwd: "/", Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	g := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 1, TID: 1}
	if err := g.SetPayload(record.GapPayload{What: "record", Why: "channel-full", Count: 3}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(g); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "drift", dir)
	flat := columns(out)
	for _, want := range []string{
		"mcp servers not observable (no MCP producer recorded): mcp[fs]",
		"gaps: record/channel-full x1 (3 events lost)",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("output lacks %q:\n%s\nstderr %s", want, out, errs)
		}
	}
	if strings.Contains(out, "unused mcp servers") {
		t.Errorf("an unobservable server was reported unused:\n%s", out)
	}
	_ = code // the contract hash differs from the empty recorded one; the exit is not what this pins
	code, out, _ = run(t, "drift", dir, "--json")
	var got driftJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("exit %d json: %v\n%s", code, err, out)
	}
	if len(got.UnusedMCP) != 0 || len(got.UnobservableMCP) != 1 || got.UnobservableMCP[0] != "mcp[fs]" {
		t.Errorf("unused %v unobservable %v", got.UnusedMCP, got.UnobservableMCP)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].What != "record" || got.Gaps[0].Lost != 3 || got.Gaps[0].Binaries == nil {
		t.Errorf("gaps %+v", got.Gaps)
	}
}

// TestStatusJSONCarriesGaps is R34 for status --json: the gap line as data, [] when there is none.
// (limits-check-doctor-cli.md R34.)
func TestStatusJSONCarriesGaps(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	_, out, errs := run(t, "status", id, "--json")
	if !strings.Contains(out, `"gaps":[]`) {
		t.Fatalf("status --json lacks an empty gaps list:\n%s\nstderr %s", out, errs)
	}
}
