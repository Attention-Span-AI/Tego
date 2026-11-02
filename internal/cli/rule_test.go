// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const ruleContract = `version: 0
name: rule-test
# keep me
command:
  - sh
fs:
  write:
    - ./out/
exec:
  allow:
    - sh
    - cat
tier: landlock
`

// ruleRun writes a contract and a run record of it whose line #1 is a read of proj/secret.txt; it returns the run
// directory, the contract's path and the secret's.
func ruleRun(t *testing.T) (dir, contract, secret string) {
	t.Helper()
	root := resolvedTemp(t)
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(filepath.Join(proj, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	contract = filepath.Join(root, "agent.yaml")
	secret = filepath.Join(proj, "secret.txt")
	for p, b := range map[string]string{contract: ruleContract, secret: "s3cret"} {
		if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	start := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
		ContractSource: &record.ContractSource{Path: contract}})
	read := ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: secret}, func(e *record.Event) {
		e.Seq, e.Source, e.Rule, e.Verdict, e.Authority = 1, record.SourceSeccomp, "unmatched", record.VerdictAllow, record.AuthorityRule
		e.Prev = strings.Repeat("a", 64)
		e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
	})
	var buf bytes.Buffer
	for _, e := range []*record.Event{start, read} {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	// The run lives in a ledger root of its own: a contract inside the ledger root is refused (internal/rulefile).
	dir = filepath.Join(resolvedTemp(t), "r-fixture")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, contract, secret
}

// TestRuleBlockWritesAndBacksUp: tego rule --block from a read line adds the file to fs.deny_read with its dated
// comment, keeps the old file as .bak, says what the next run does and journals the change with its sentence and
// direction; --dry-run writes nothing.
func TestRuleBlockWritesAndBacksUp(t *testing.T) {
	dir, contract, _ := ruleRun(t)
	code, out, errs := run(t, "rule", dir, "1", "--block", "--dry-run")
	if code != identity.ExitOK {
		t.Fatalf("dry run: exit %d: %s", code, errs)
	}
	if b, _ := os.ReadFile(contract); string(b) != ruleContract {
		t.Fatalf("--dry-run wrote the contract:\n%s", b)
	}
	if !strings.Contains(out, "+  deny_read:") || !strings.Contains(out, "dry run: nothing written") {
		t.Errorf("dry run printed:\n%s", out)
	}
	code, out, errs = run(t, "rule", dir, "1", "--block")
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	b, err := os.ReadFile(contract)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "  deny_read:\n    - ./secret.txt # from run r-fixture line #1, ") || !strings.Contains(string(b), "# keep me") {
		t.Errorf("new contract:\n%s", b)
	}
	if old, _ := os.ReadFile(contract + ".bak"); string(old) != ruleContract {
		t.Errorf(".bak holds:\n%s", old)
	}
	if !strings.Contains(out, "will refuse reads of") {
		t.Errorf("stdout does not say what the next run does:\n%s", out)
	}
	// The change is journaled in the run's ledger root, as the dashboard's are (internal/rulefile).
	es, err := rulefile.ReadJournal(filepath.Dir(dir))
	if err != nil || len(es) != 1 || es[0].Via != "cli" || es[0].Run != "r-fixture" || es[0].Line != 1 ||
		es[0].OldSHA256 != rulefile.Sum([]byte(ruleContract)) || es[0].NewSHA256 != rulefile.Sum(b) {
		t.Errorf("journal: %+v, %v", es, err)
	}
	// The line says the change as the dashboard's line for the same change does: in words and narrowing, so the
	// dashboard's history shows the sentence and its Undo of the change widens (internal/control/rules revert.go).
	if want := []string{"May read ./secret.txt → Can never read ./secret.txt"}; len(es) == 1 &&
		(es[0].Direction != "narrows" || !slices.Equal(es[0].Sentences, want)) {
		t.Errorf("journal line: direction %q, sentences %q; want narrows, %q", es[0].Direction, es[0].Sentences, want)
	}
	// The same rule again changes nothing and says so.
	if code, _, errs = run(t, "rule", dir, "1", "--block"); code != identity.ExitFinding || !strings.Contains(errs, "already") {
		t.Errorf("second block: exit %d: %s", code, errs)
	}
}

// TestRuleUsage: tego rule takes a run, a line and exactly one action.
func TestRuleUsage(t *testing.T) {
	dir, _, _ := ruleRun(t)
	if code, _, _ := run(t, "rule", dir, "1"); code != identity.ExitUsage {
		t.Errorf("no action: exit %d", code)
	}
	if code, _, _ := run(t, "rule", dir, "1", "--block", "--allow"); code != identity.ExitUsage {
		t.Errorf("two actions: exit %d", code)
	}
}

// TestRuleScopes: --level N names that ancestor folder, never past the run's working directory; --command and
// --host are refused on a read; the scope flags exclude each other.
func TestRuleScopes(t *testing.T) {
	dir, contract, _ := ruleRun(t)
	code, out, errs := run(t, "rule", dir, "1", "--block", "--level", "1", "--dry-run")
	if code != identity.ExitOK || !strings.Contains(out, "+    - ./ # from run r-fixture line #1") {
		t.Fatalf("--level 1: exit %d\n%s%s", code, out, errs)
	}
	if code, _, errs = run(t, "rule", dir, "1", "--block", "--level", "2"); code != identity.ExitFinding || !strings.Contains(errs, "widest folder") {
		t.Errorf("--level 2 past the working directory: exit %d: %s", code, errs)
	}
	for _, f := range []string{"--command", "--host"} {
		if code, _, _ := run(t, "rule", dir, "1", "--block", f); code != identity.ExitFinding {
			t.Errorf("%s on a read: exit %d", f, code)
		}
	}
	if code, _, _ := run(t, "rule", dir, "1", "--block", "--folder", "--level", "2"); code != identity.ExitUsage {
		t.Errorf("two scopes: exit %d", code)
	}
	if b, _ := os.ReadFile(contract); string(b) != ruleContract {
		t.Errorf("a refused or dry rule wrote the contract:\n%s", b)
	}
}

const netRuleContract = `version: 0
name: rule-net-test
command:
  - sh
exec:
  allow:
    - sh
net:
  allow:
    - 192.0.2.1:443
tier: landlock
`

// netRuleRun writes netRuleContract and a run of it whose line #1 is a connection to dest the contract refused; it
// returns the run directory and the contract's path.
func netRuleRun(t *testing.T, dest string) (dir, contract string) {
	t.Helper()
	root := resolvedTemp(t)
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	contract = filepath.Join(root, "agent.yaml")
	if err := os.WriteFile(contract, []byte(netRuleContract), 0o600); err != nil {
		t.Fatal(err)
	}
	start := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
		ContractSource: &record.ContractSource{Path: contract}})
	refused := ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "connect", Target: dest}, func(e *record.Event) {
		e.Seq, e.Rule, e.Reason = 1, "unmatched", record.ReasonNetNotAllowed
		e.Prev = strings.Repeat("a", 64)
	})
	var buf bytes.Buffer
	for _, e := range []*record.Event{start, refused} {
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
	}
	dir = filepath.Join(resolvedTemp(t), "r-fixture")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, contract
}

// failingHosts is a resolver that fails the names it holds (no such host) and resolves every other one.
type failingHosts map[string]bool

func (f failingHosts) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if f[host] {
		return nil, &net.DNSError{Err: "no such host", Name: host, Server: "127.0.0.53:53", IsNotFound: true}
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

// TestRuleWarnsUnresolvedHost: tego rule --allow on a refused connection to a host that does not resolve here warns on
// stderr and still writes, exit 0: the check compiles with no DNS and the next run resolves the host when it starts,
// so the warning is where a typo shows before then. A host that resolves warns of nothing.
func TestRuleWarnsUnresolvedHost(t *testing.T) {
	outsideEveryRun(t)
	old := ruleResolver
	t.Cleanup(func() { ruleResolver = old })
	ruleResolver = failingHosts{"api.exmple.com": true}
	dir, contract := netRuleRun(t, "api.exmple.com:443")
	const warning = "warning: tego rule: host api.exmple.com does not resolve here (no such host): the next run resolves it"
	code, out, errs := run(t, "rule", dir, "1", "--allow", "--dry-run")
	if code != identity.ExitOK || !strings.Contains(errs, warning) || !strings.Contains(errs, "[host-unresolvable]") ||
		!strings.Contains(out, "+    - api.exmple.com:443") {
		t.Fatalf("dry run: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	if b, _ := os.ReadFile(contract); string(b) != netRuleContract {
		t.Fatalf("--dry-run wrote the contract:\n%s", b)
	}
	code, out, errs = run(t, "rule", dir, "1", "--allow")
	if code != identity.ExitOK || !strings.Contains(errs, warning) || !strings.Contains(out, "wrote ") {
		t.Fatalf("write: exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	if b, _ := os.ReadFile(contract); !strings.Contains(string(b), "    - api.exmple.com:443 # from run r-fixture line #1") {
		t.Errorf("a host that does not resolve kept the rule from being written:\n%s", b)
	}
	ruleResolver = failingHosts{}
	dir, _ = netRuleRun(t, "api.example.com:443")
	if code, _, errs = run(t, "rule", dir, "1", "--allow", "--dry-run"); code != identity.ExitOK || strings.Contains(errs, "warning:") {
		t.Errorf("a host that resolves: exit %d: %s", code, errs)
	}
}
