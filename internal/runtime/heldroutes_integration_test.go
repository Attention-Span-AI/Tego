// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// heldRoutesScript is the agent of TestIntegrationHeldCompletionClosesTheReviewedRoutes: each route its round-2 review
// took past a read gate, with its outcome written under out/.
//
//   - rw: a read-write open of the secret.
//   - unlinked: a write-only open of a second secret, its name removed, then a read of the descriptor through
//     /proc/self/fd.
//   - nested: setpriv makes a Landlock domain of its own that reads /usr, /etc and /lib only, then reads a worktree
//     file; setpriv is run only where it can make one.
const heldRoutesScript = `#!/bin/sh
(exec 3<>out/secret.env && cat <&3 > out/rw-leak); echo $? > out/rw-rc
(exec 4>>out/doomed.env && rm out/doomed.env && cat /proc/self/fd/4 > out/unlinked-leak); echo $? > out/unlinked-rc
if [ -n "$SETPRIV" ]; then
	"$SETPRIV" --landlock-access fs:read-file --landlock-rule path-beneath:read-file:/usr \
		--landlock-rule path-beneath:read-file:/etc --landlock-rule path-beneath:read-file:/lib \
		-- cat out/benign > out/nested 2> out/nested-err; echo $? > out/nested-rc
fi
echo done > out/done
`

// heldRoutesRun is one run of the routes' agent under completion, and returns what it wrote under out/ and the run's
// ledger.
func heldRoutesRun(t *testing.T, completion, setpriv string) (map[string]string, []*record.Event) {
	t.Helper()
	allow := []string{"/bin/sh", "/bin/cat", "/bin/rm"}
	if setpriv != "" {
		allow = append(allow, setpriv)
	}
	contract := contractFor("iheldroutes", []string{"/bin/sh", "./agent.sh"}, allow) +
		"gate:\n  completion: " + completion + "\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n"
	f := newFixture(t, contract)
	for name, body := range map[string]string{"benign": "benign-bytes", "secret.env": "TOKEN=1", "doomed.env": "TOKEN=2"} {
		if err := os.WriteFile(filepath.Join(f.out, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(f.dir, "agent.sh")
	// The agent's environment is the contract's (PATH and HOME): setpriv's path is written into the script.
	if err := os.WriteFile(script, []byte(strings.ReplaceAll(heldRoutesScript, "$SETPRIV", setpriv)), 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwnsTree(t, f.out)
	agentOwns(t, script)
	cfg := writeMachineConfig(t, f)
	run := exec.Command(tegoBinary(t), "run", filepath.Join(f.dir, "agent.yaml"))
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run (completion %s): %v\n%s", completion, err, out)
	}
	if strings.Contains(string(out), "open deputy did not start") {
		t.Fatalf("the deputy did not start:\n%s", out)
	}
	got := map[string]string{}
	for _, name := range []string{"rw-leak", "rw-rc", "unlinked-leak", "unlinked-rc", "nested", "nested-rc", "nested-err", "done"} {
		b, _ := os.ReadFile(filepath.Join(f.out, name))
		got[name] = strings.TrimSpace(string(b))
	}
	if got["done"] != "done" {
		t.Fatalf("the agent did not run to its end (completion %s): %v\n%s", completion, got, out)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", f.root, dirs)
	}
	return got, events(t, dirs[0])
}

// landlockSetpriv is a setpriv that can make a Landlock domain on this kernel, "" when there is none.
func landlockSetpriv() string {
	p, err := exec.LookPath("setpriv")
	if err != nil {
		return ""
	}
	help, _ := exec.Command(p, "--help").CombinedOutput()
	if !strings.Contains(string(help), "--landlock-access") {
		return ""
	}
	if exec.Command(p, "--landlock-access", "fs:read-file", "--landlock-rule", "path-beneath:read-file:/", "--", "/bin/true").Run() != nil {
		return ""
	}
	return p
}

// TestIntegrationHeldCompletionClosesTheReviewedRoutes is ADR 0041 Stage B's round-2 review findings through the real
// binary at tier landlock, unprivileged, under `fs.read matches "*.env"`: a read-write open of the secret, a
// read of a second secret through its descriptor after its name was removed, and a tool that sandboxes itself
// with Landlock reading a worktree file its own domain does not grant. Under completion: held none reaches what
// it reads: the read-write open and the reopen are refused by the gate, and the tool cannot make its domain, since a
// held run's processes are refused the Landlock syscalls (ENOSYS), so the deputy's domain is every process's. The
// reviewer's runs of the same routes before the fixes: the read-write open was not held and delivered the secret, the
// reopen read it (under copied too), and the tool read the file its own domain refused. Under the default completion
// the run is logged as well: the reopen is refused there too, and the tool's own domain refuses its read.
func TestIntegrationHeldCompletionClosesTheReviewedRoutes(t *testing.T) {
	setpriv := landlockSetpriv()
	if setpriv == "" {
		t.Log("no setpriv that makes a Landlock domain here: the nested route is not run")
	}
	copied, _ := heldRoutesRun(t, "copied", setpriv)
	t.Logf("completion copied: %v", copied)
	if copied["rw-leak"] != "" || copied["unlinked-leak"] != "" {
		t.Errorf("completion copied: the read gate's secret was read: %v", copied)
	}
	got, evs := heldRoutesRun(t, "held", setpriv)
	t.Logf("completion held: %v", got)
	if got["rw-leak"] != "" || got["rw-rc"] == "0" {
		t.Errorf("held: the read-write open of the secret succeeded (%q, status %s)", got["rw-leak"], got["rw-rc"])
	}
	if got["unlinked-leak"] != "" || got["unlinked-rc"] == "0" {
		t.Errorf("held: the reopen of the unlinked secret succeeded (%q, status %s)", got["unlinked-leak"], got["unlinked-rc"])
	}
	if setpriv != "" {
		if got["nested"] != "" || got["nested-rc"] == "0" || !strings.Contains(got["nested-err"], "not implemented") {
			t.Errorf("held: the tool that sandboxed itself read %q (status %s, %q): want its Landlock call refused ENOSYS", got["nested"], got["nested-rc"], got["nested-err"])
		}
		if copied["nested"] != "" || copied["nested-rc"] == "0" {
			t.Errorf("copied: the tool's own domain let it read %q (status %s)", copied["nested"], copied["nested-rc"])
		}
	}
	var unreadable, rwRefused bool
	for _, ev := range evs {
		if ev.Kind != record.KindFS || ev.Verdict != record.VerdictRefused {
			continue
		}
		var p struct {
			Path  string `json:"path"`
			Flags int    `json:"flags"`
		}
		_ = json.Unmarshal(ev.Payload, &p)
		switch {
		case ev.Rule == "gate.unreadable":
			unreadable = true
		case strings.HasSuffix(p.Path, "/out/secret.env") && ev.Reason == record.ReasonFSGate:
			rwRefused = true
		}
	}
	if !unreadable || !rwRefused {
		t.Errorf("held ledger: gate.unreadable refusal %t, gate refusal of the read-write open %t", unreadable, rwRefused)
	}
}
