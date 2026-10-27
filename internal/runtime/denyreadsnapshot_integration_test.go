// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationDenyReadSnapshotIsRecordedRefused at tier landlock through the real binary: Landlock is an
// allow-list, so a deny_read is built by granting every sibling of each of its ancestors as they stood at launch
// (enforce-landlock R3). A directory made beside an ancestor after the run started, and a file made there, are no
// sibling the ruleset grants: the kernel refuses a read of the file all run. Its line said allow (8 such lines in the
// 2026-10-25 always-on audit); it must say refused, read-denied, under the deny-read-snapshot rule, on both open paths:
// one this loop continues (record: full, reads direct) and one the open deputy completes (fs.reads: held), and under
// record: summary with reason.reads: on (ADR 0077), whose every-open arm brings the same opens to this loop, which keeps
// the snapshot rule for them and adds mechanism landlock only to the deny_read entry's own refusal. A new file inside a
// sibling that existed at launch, and a listing of the new directory (READ_DIR is the ancestor's), stay readable and
// are never refused.
func TestIntegrationDenyReadSnapshotIsRecordedRefused(t *testing.T) {
	for _, tc := range []struct {
		name, reads, record string
		reason              bool
	}{
		{"continued", "direct", "full", false},
		{"held", "held", "summary", false},
		{"reason", "direct", "summary", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, evs := denyReadSnapshotScene(t, tc.reads, tc.record, tc.reason)
			for _, n := range []string{"late", "top", "secret"} {
				if rc := strings.TrimSpace(s.out("res/" + n + ".rc")); rc == "0" || rc == "" {
					t.Errorf("%s: status %q, want a refusal (%q)", n, rc, s.out("res/"+n+".err"))
				}
				if e := s.out("res/" + n + ".err"); !strings.Contains(e, "Permission denied") {
					t.Errorf("%s: error %q, want EACCES", n, e)
				}
			}
			if got := s.out("res/early.out"); got != "early" {
				t.Errorf("a new file in a sibling that existed at launch read %q (%q), want early", got, s.out("res/early.err"))
			}
			if got := strings.TrimSpace(s.out("res/list.out")); got != "late/f.txt" {
				t.Errorf("listing the new directory gave %q, want late/f.txt", got)
			}
			project := s.f.dir
			refused := map[string]bool{}
			for _, e := range evs {
				var p record.FSPayload
				if e.Kind != record.KindFS || e.DecodePayload(&p) != nil || p.Op != record.FSOpen || !strings.HasPrefix(p.Path, project+"/") {
					continue
				}
				rel := strings.TrimPrefix(p.Path, project+"/")
				switch rel {
				case "late/f.txt", "late.txt":
					if e.Verdict != record.VerdictRefused || e.Reason != record.ReasonReadDenied || e.Rule != "deny-read-snapshot" || e.Authority != record.AuthorityRule {
						t.Errorf("%s: %s %s %s by %s, want refused read-denied deny-read-snapshot by rule", rel, e.Verdict, e.Reason, e.Rule, e.Authority)
					}
					refused[rel] = true
				case "old/late.txt", "late":
					if e.Verdict == record.VerdictRefused {
						t.Errorf("%s: refused %s %s, want it readable", rel, e.Reason, e.Rule)
					}
				case "secret/token":
					if tc.reason && (e.Verdict != record.VerdictRefused || p.Mechanism != record.MechanismLandlock) {
						t.Errorf("secret/token: %s mechanism %q, want refused by landlock", e.Verdict, p.Mechanism)
					}
					refused[rel] = true
				}
				if rel == "late/f.txt" || rel == "late.txt" {
					if p.Mechanism != "" {
						t.Errorf("%s: mechanism %q, want none: this loop refused it, not the ruleset", rel, p.Mechanism)
					}
				}
			}
			want := []string{"late/f.txt", "late.txt"}
			if tc.reason {
				want = append(want, "secret/token")
			}
			for _, rel := range want {
				if !refused[rel] {
					t.Errorf("no refused line for %s", rel)
				}
			}
		})
	}
}

// denyReadSnapshotScene runs an agent under fs.write ["./out/"] and deny_read ["./secret/"] at tier landlock, with
// old/g.txt made before the run. Once the agent waits, the test, a process outside the run, makes late/f.txt and
// late.txt beside the target's parent's children and old/late.txt inside a sibling that existed at launch; then the
// agent reads each, and secret/token, and lists late/. reason adds reason: {reads: on}.
func denyReadSnapshotScene(t *testing.T, reads, mode string, reason bool) (*askReadScene, []*record.Event) {
	t.Helper()
	bin := tegoBinary(t)
	var allow []string
	for _, name := range []string{"sh", "cat", "sleep"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("no %s: %v", name, err)
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{p, real} {
			if !slices.Contains(allow, fmt.Sprintf("%q", q)) {
				allow = append(allow, fmt.Sprintf("%q", q))
			}
		}
	}
	contract := fmt.Sprintf(`version: 0
name: isnapshot
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
  deny_read: ["./secret/"]
  reads: %s
exec:
  allow: [%s]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: %s
`, reads, strings.Join(allow, ", "), mode)
	if reason {
		contract += "reason:\n  reads: on\n"
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"secret/token": "s3cr3t", "old/g.txt": "old"} {
		p := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := &askReadScene{bin: bin}
	s.f = newFixtureIn(t, project, contract, nil)
	if err := os.Mkdir(filepath.Join(s.f.out, "res"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
r=out/res
t() { n=$1; shift; "$@" > $r/$n.out 2> $r/$n.err; echo $? > $r/$n.rc; }
echo ready > $r/ready
while [ ! -e out/go ]; do sleep 0.05; done
t late cat late/f.txt
t top cat late.txt
t early cat old/late.txt
t secret cat secret/token
echo late/* > $r/list.out
echo done > $r/done
`
	if err := os.WriteFile(filepath.Join(project, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwnsTree(t, s.f.out)
	agentOwns(t, filepath.Join(project, "agent.sh"))
	s.env = isolatedEnv(t, s.f)
	run, dir := s.start(t)
	for deadline := time.Now().Add(30 * time.Second); s.out("res/ready") == ""; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the agent never reached its wait\n%s", s.diagnose(t, dir))
		}
	}
	// Made after the ruleset's one listing of each ancestor, by a process outside the run.
	if err := os.Mkdir(filepath.Join(project, "late"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"late/f.txt": "late", "late.txt": "top", "old/late.txt": "early"} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.f.out, "go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	evs := s.finish(t, run, dir)
	if s.out("res/done") == "" {
		t.Fatalf("the agent did not run to its end\n%s", s.diagnose(t, dir))
	}
	return s, evs
}
