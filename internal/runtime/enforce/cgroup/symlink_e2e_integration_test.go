// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestE2ERecorderLinesSayWhatTheAgentSaw runs through a whole `tego run --tier
// cgroup`: a project reached through a symlink (the cwd a shell reports), a read of its deny_read entry, a write in
// its write entry, and a rename out of the write entry, which Landlock refuses at the destination. The recorder
// matched bpf_d_path's canonical paths against the declared ones and took a rename's verdict from its source
// alone, so its source=kernel lines said allow for the refused read and the refused rename, and observed for the
// allowed write. Each must say what the agent saw.
func TestE2ERecorderLinesSayWhatTheAgentSaw(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tier 2 loads BPF programs and a fanotify group")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("needs SUDO_UID: the agent runs as the invoking user")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("no objects: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	base, err := os.MkdirTemp("", "tego-r2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	bin := buildTaggedTego(t, base)
	_ = os.Chmod(base, 0o711)
	project := filepath.Join(base, "project")
	for _, d := range []string{"out", "secrets"} {
		if err := os.MkdirAll(filepath.Join(project, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(project, "secrets", "key"), "s3cret\n")
	mustWrite(filepath.Join(project, "out", "a.txt"), "a\n")
	link := filepath.Join(base, "link")
	if err := os.Symlink(project, link); err != nil {
		t.Fatal(err)
	}
	mustWrite(filepath.Join(project, "agent.py"), `import os
def result(n, o): print("RESULT", n, o, flush=True)
try:
    with open("secrets/key") as f: result("deny-read", "read:" + f.read().strip())
except OSError as e: result("deny-read", "refused errno=%d" % e.errno)
try:
    with open("out/new.txt", "w") as f: f.write("x")
    result("write-inside", "ok")
except OSError as e: result("write-inside", "refused errno=%d" % e.errno)
try:
    os.rename("out/a.txt", "a.txt"); result("rename-out", "ok")
except OSError as e: result("rename-out", "refused errno=%d" % e.errno)
`)
	mustWrite(filepath.Join(project, "agent.yaml"), `version: 0
name: r2
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  deny_read: ["./secrets/"]
exec:
  allow: ["python3"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`)
	_ = filepath.Walk(project, func(p string, _ os.FileInfo, err error) error { return os.Lchown(p, uid, gid) })
	ledgerRoot := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(base, "config.yaml")
	mustWrite(cfg, fmt.Sprintf("version: 0\nledger_root: %s\n", ledgerRoot))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--tier", "cgroup", filepath.Join(link, "agent.yaml"), "--", python, "./agent.py")
	cmd.Dir = link
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg, "PWD="+link)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	got := agentResults(t, stdout.String())
	t.Logf("the agent saw %v", got)
	if !strings.HasPrefix(got["deny-read"], "refused") || got["write-inside"] != "ok" ||
		!strings.HasPrefix(got["rename-out"], "refused") {
		t.Fatalf("the kernel's decisions were not the ones this test is about: %v", got)
	}
	var sawRead, sawWrite, sawRename bool
	for _, e := range runEvents(t, ledgerRoot) {
		if e["kind"] != "fs" || e["source"] != "kernel" {
			continue
		}
		path := fmt.Sprint(e["path"])
		line, _ := json.Marshal(e)
		switch {
		case e["op"] == "open" && strings.HasSuffix(path, "/secrets/key"):
			sawRead = true
			if e["verdict"] != "refused" {
				t.Errorf("the refused read was recorded %s", line)
			}
		case e["op"] == "open" && strings.HasSuffix(path, "/out/new.txt"):
			sawWrite = true
			if e["verdict"] != "allow" {
				t.Errorf("the allowed write was recorded %s", line)
			}
		case e["op"] == "rename" && strings.HasSuffix(path, "/out/a.txt"):
			sawRename = true
			if e["verdict"] == "allow" {
				t.Errorf("the refused rename was recorded %s", line)
			}
		}
	}
	if !sawRead || !sawWrite || !sawRename {
		t.Errorf("source=kernel lines: read %v write %v rename %v, want all three", sawRead, sawWrite, sawRename)
	}
}
