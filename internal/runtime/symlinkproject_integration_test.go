// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationSymlinkedProjectIsRecordedAsTheKernelDecided: at tier 1, a
// project reached through a symlink, the cwd a shell reports and a symlinked $HOME. compile keeps each entry's
// Path as declared and its Resolved canonical, and the supervisor joins a relative path to /proc/<pid>/cwd,
// which the kernel spells canonically. Matched against the declared spellings alone, the write Landlock allowed
// in the write entry was recorded refused write-outside-contract, and the read it refused in the deny_read
// entry allow. Each line must say what the agent saw.
func TestIntegrationSymlinkedProjectIsRecordedAsTheKernelDecided(t *testing.T) {
	requireLandlock(t)
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(real, "project")
	out, secrets := filepath.Join(project, "out"), filepath.Join(project, "secrets")
	for _, d := range []string{out, secrets} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(secrets, "key"), []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, out)
	agentReaches(t, link)
	agentOwns(t, out)
	contract := `version: 0
name: isymlink
command: ["/bin/sh", "./agent.sh"]
tier: landlock
fs:
  write: ["./out/"]
  deny_read: ["./secrets/"]
exec:
  allow: ["/bin/sh", "/bin/cat"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: full
`
	script := `#!/bin/sh
echo x > out/new.txt || exit 10
if cat secrets/key > out/sink 2>out/err; then echo READ=ok > out/read.txt; else echo READ=refused > out/read.txt; fi
exit 0
`
	path := filepath.Join(link, "agent.yaml")
	if err := os.WriteFile(path, []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(link, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(project, "agent.sh"))
	root := t.TempDir()
	m := config.Builtin()
	m.Home = link
	m.LedgerRoot = config.Setting[string]{Value: root}
	m.StopGrace = config.Setting[time.Duration]{Value: 2 * time.Second}
	c, ds, err := agent.Load(path, testProfiles{})
	if err != nil {
		t.Fatalf("load: %v (%v)", err, ds)
	}
	rt, ds, err := agent.Compile(c, m, agent.WithPATH(os.Getenv("PATH")), agent.WithHome(link), agent.WithCwd(link),
		agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v (%v)", err, ds)
	}
	b, sel := enforce.Select(m, rt, backend.Probe{backend.TierLandlock: true})
	if b == nil {
		t.Skipf("no backend for this machine: %v", sel)
	}
	yaml, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{dir: link, out: out, root: root, machine: m, rt: rt, yaml: yaml, backend: b}
	res, err := Run(context.Background(), rt, []string{"/bin/sh", "./agent.sh"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d (reason %s), want 0: the write in the write entry failed", res.ExitCode, res.Reason)
	}
	saw, err := os.ReadFile(filepath.Join(out, "read.txt"))
	if err != nil {
		t.Fatal(err)
	}
	readRefused := strings.TrimSpace(string(saw)) == "READ=refused"
	t.Logf("the agent's read of the deny_read entry: %s", strings.TrimSpace(string(saw)))
	var sawWrite, sawRead bool
	for _, e := range events(t, runDirs(t, root)[0]) {
		if e.Kind != record.KindFS {
			continue
		}
		var p record.FSPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		switch {
		case strings.HasSuffix(p.Path, "/out/new.txt"):
			sawWrite = true
			if e.Verdict != record.VerdictAllow || e.Rule != "fs.write[./out/]" {
				t.Errorf("the write Landlock allowed was recorded %s %s %s (path %s)", e.Rule, e.Verdict, e.Reason, p.Path)
			}
		case strings.HasSuffix(p.Path, "/secrets/key"):
			sawRead = true
			want := record.VerdictAllow
			if readRefused {
				want = record.VerdictRefused
			}
			if e.Verdict != want {
				t.Errorf("the read the agent saw %s was recorded %s %s %s (path %s)",
					strings.TrimSpace(string(saw)), e.Rule, e.Verdict, e.Reason, p.Path)
			}
		}
	}
	if !sawWrite || !sawRead {
		t.Errorf("no line for the write (%v) or the read (%v)", sawWrite, sawRead)
	}
}
