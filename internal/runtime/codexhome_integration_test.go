// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// codexListener is a forwarder with an openai listener that binds nothing: what makes a run route Codex.
func codexListener() []source.Source {
	return []source.Source{&fakeLoopback{name: "forwarder", vars: map[string]string{envOpenAIBaseURL: "http://127.0.0.1:41001/v1"}}}
}

// codexGrant is run_start's fs.codex_home grant, or "".
func codexGrant(t *testing.T, start *record.Event) string {
	t.Helper()
	var p record.RunStartPayload
	if err := start.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	for _, g := range p.RuntimeGrants {
		if strings.HasPrefix(g, "fs.codex_home[") {
			return g
		}
	}
	return ""
}

// TestIntegrationARunRoutesCodexOrSaysItCannot is agent-contract.md R10a (2) and (3) through the real runner.run, at
// both euids, one real tier-1 run with an openai listener read back from its ledger. Unprivileged, the run grants its
// own CODEX_HOME (run_start.runtime_grants holds fs.codex_home) and writes no codex-unrouted gap. As root (the KVM
// root suites), the launcher writes no CODEX_HOME, so run_start holds no such grant and the gap what=capture
// why=codex-unrouted is written after run_start. The gap's unit test called emitCodexUnroutedGap
// directly, and deleting its call from run() passed every test.
func TestIntegrationARunRoutesCodexOrSaysItCannot(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t)) // a root launcher ignores it
	f := newFixture(t, contractFor("icodexroute", []string{"/bin/true"}, []string{"/bin/true"}))
	deps := f.deps(t, nil)
	deps.Capture = codexListener()
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result %+v, want exit 0", res)
	}
	evs := events(t, runDirs(t, f.root)[0])
	if evs[0].Kind != record.KindRunStart {
		t.Fatalf("first event %s, want run_start", evs[0].Kind)
	}
	var unrouted []int
	for i, e := range evs {
		var p record.GapPayload
		if e.Kind == record.KindGap && e.DecodePayload(&p) == nil && p.What == record.GapCapture && p.Why == GapCodexUnrouted {
			if p.Binary != "codex" {
				t.Errorf("the codex-unrouted gap names binary %q, want codex", p.Binary)
			}
			unrouted = append(unrouted, i)
		}
	}
	grant := codexGrant(t, evs[0])
	if os.Geteuid() == 0 {
		if len(unrouted) != 1 || grant != "" {
			t.Fatalf("a root run with an openai listener: codex-unrouted gaps at %v and grant %q, want one gap and no grant", unrouted, grant)
		}
		return
	}
	if len(unrouted) != 0 || grant == "" {
		t.Fatalf("an unprivileged run with an openai listener: codex-unrouted gaps at %v and grant %q, want none and a grant", unrouted, grant)
	}
}

// TestIntegrationADenyListRunRunsNothingFromItsCodexHome is agent-contract.md R10a's deny-list half on a real
// kernel: under exec.deny [id] and no fs.write entry, the agent copies /usr/bin/id into its own CODEX_HOME
// and runs the copy, directly and through the dynamic loader. Both are refused codex-home-exec, as the real id is
// refused exec.deny[id]; before, the copy ran and printed the uid. Each copy's own line carries the dropped
// flag, the run having written it under the CODEX_HOME write grant. A root launcher writes no CODEX_HOME.
func TestIntegrationADenyListRunRunsNothingFromItsCodexHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher writes no CODEX_HOME: its runtime directory is not the agent's")
	}
	const ld = "/lib64/ld-linux-x86-64.so.2"
	t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
	f := newFixture(t, `version: 0
name: icodexexec
command: ["/bin/sh"]
tier: landlock
exec:
  deny: ["id"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
`)
	deps := f.deps(t, nil)
	deps.Capture = codexListener()
	// 126 is the shell's answer to an exec refused EACCES; any other status is a copy that ran (on Ubuntu's uutils
	// it may run and fail, being a multicall binary under another name).
	//
	// A linked copy in a directory of the home that the agent then makes unsearchable, run
	// through its descriptor, directly and as the loader's operand. The supervisor cannot walk the kernel's spelling of
	// it back to the file, and the exec's own spelling, /proc/self/fd/7, is no path in the home: judged on that, both
	// were allowed unmatched and the copy ran. The directory is made searchable again before the run ends, so the
	// launcher can remove it.
	script := `/usr/bin/id -u; cp /usr/bin/id "$CODEX_HOME/notid" || exit 3; "$CODEX_HOME/notid" -u; [ $? -eq 126 ] || exit 4; ` +
		`if [ -e ` + ld + ` ]; then ` + ld + ` "$CODEX_HOME/notid" -u; [ $? -eq 126 ] || exit 5; fi; ` +
		`mkdir "$CODEX_HOME/sub" && cp /usr/bin/id "$CODEX_HOME/sub/notid" || exit 6; exec 7<"$CODEX_HOME/sub/notid"; ` +
		`chmod 0600 "$CODEX_HOME/sub" || exit 6; /proc/self/fd/7 -u; direct=$?; loader=126; ` +
		`if [ -e ` + ld + ` ]; then ` + ld + ` /proc/self/fd/7 -u; loader=$?; fi; chmod 0700 "$CODEX_HOME/sub"; ` +
		`[ $direct -eq 126 ] || exit 7; [ $loader -eq 126 ] || exit 8; exit 0`
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", script}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d: 3 and 6 are a copy the run could not write, 4 and 5 a copy that ran, 7 and 8 a copy in a "+
			"directory it made unsearchable that ran through its descriptor", res.ExitCode)
	}
	var rules []string
	for _, e := range runDirs(t, f.root) {
		for _, ev := range events(t, e) {
			if ev.Kind != record.KindExec || ev.Verdict != record.VerdictRefused {
				continue
			}
			var p struct {
				Path    string `json:"path"`
				Dropped bool   `json:"dropped"`
			}
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			rules = append(rules, ev.Rule+" "+p.Path)
			// The flag was judged only where the supervisor could walk the kernel's
			// spelling back to the image, so the copy in the directory the agent made unsearchable carried none.
			if ev.Rule == ruleCodexHomeExecName && (strings.HasSuffix(p.Path, "/codex/notid") || strings.HasSuffix(p.Path, "/fd/7")) && !p.Dropped {
				t.Errorf("the refused copy %s carries no dropped flag: the run wrote it under its CODEX_HOME grant", p.Path)
			}
		}
	}
	if !slices.ContainsFunc(rules, func(s string) bool { return strings.HasPrefix(s, "exec.deny[id] /usr/bin/id") }) {
		t.Errorf("refusals %q, want exec.deny[id] for /usr/bin/id", rules)
	}
	if !slices.ContainsFunc(rules, func(s string) bool {
		return strings.HasPrefix(s, ruleCodexHomeExecName+" ") && strings.HasSuffix(s, "/codex/notid")
	}) {
		t.Errorf("refusals %q, want %s for the copy in CODEX_HOME", rules, ruleCodexHomeExecName)
	}
	if !slices.ContainsFunc(rules, func(s string) bool {
		return strings.HasPrefix(s, ruleCodexHomeExecName+" ") && strings.HasSuffix(s, "/fd/7")
	}) {
		t.Errorf("refusals %q, want %s for the copy run through its descriptor", rules, ruleCodexHomeExecName)
	}
}

// ruleCodexHomeExecName is the supervisor's codex-home-exec rule as the ledger spells it.
const ruleCodexHomeExecName = "codex-home-exec"
