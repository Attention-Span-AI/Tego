// SPDX-License-Identifier: Apache-2.0

package container

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// helloVerdicts is what the hello contract must decide in every tier a run of it can get, and what smoke.sh and the
// hello agent rely on: its one write allowed, the write beside it refused, nothing reachable, no other program.
const helloVerdicts = `version: 0
tests:
  - name: the greeting is written
    action: fs.write
    path: @WORK@/out/hello.txt
    expect: allow
  - name: a write beside out/ is refused
    action: fs.write
    path: @WORK@/outside.txt
    expect: refused
    rule: unmatched
  - name: the agent's own script may run
    action: exec
    path: @SHARE@/hello-agent.sh
    expect: allow
  - name: a program the contract does not list may not
    action: exec
    path: /usr/bin/curl
    expect: refused
    rule: unmatched
  - name: nothing on the network
    action: net.connect
    host_port: 1.1.1.1:443
    expect: refused
  - name: the ledger, on its own volume, is not readable to the agent
    action: fs.read
    path: @LEDGER@/r-0/events.jsonl
    expect: refused
`

// TestHelloContractVerdicts compiles hello.yaml, with the image's /work and /usr/local/share/tego moved into a
// temporary directory, on a stand-in machine whose PATH holds the two programs it names, and holds its rule table to
// helloVerdicts through `tego compile --test`, offline. Errors fail the test; warnings are logged.
func TestHelloContractVerdicts(t *testing.T) {
	base := t.TempDir()
	// config.Load skips a layer whose directory others may write; t.TempDir is 0775 under umask 002.
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	work, share, bin := filepath.Join(base, "work"), filepath.Join(base, "share"), filepath.Join(base, "bin")
	// The ledger exists before compile, as `tego run` makes it first: a deny attaches to a path that exists.
	ledger := filepath.Join(base, "runs")
	for _, d := range []string{filepath.Join(work, "out"), share, bin, ledger} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stand, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("no /bin/true to stand in for sh and date: %v", err)
	}
	for _, p := range []string{filepath.Join(bin, "sh"), filepath.Join(bin, "date"), filepath.Join(share, "hello-agent.sh")} {
		if err := os.WriteFile(p, stand, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	src, err := os.ReadFile("hello.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := strings.NewReplacer("/usr/local/share/tego/", share+"/", `"/work/`, `"`+work+"/")
	contract := filepath.Join(base, "hello.yaml")
	if err := os.WriteFile(contract, []byte(r.Replace(string(src))), 0o644); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(base, "verdicts.yaml")
	if err := os.WriteFile(table, []byte(strings.NewReplacer("@WORK@", work, "@SHARE@", share, "@LEDGER@", ledger).Replace(helloVerdicts)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte("version: 0\nledger_root: "+ledger+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("TEGO_CONFIG", cfg)
	t.Setenv("HOME", filepath.Join(base, "home"))
	t.Chdir(base)
	var out, errb bytes.Buffer
	if code := cli.Main([]string{"tego", "compile", contract, "--offline", "--test", table}, &out, &errb); code != identity.ExitOK {
		t.Fatalf("tego compile --test: exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	t.Logf("compile --test:\n%s\n%s", out.String(), errb.String())
}
