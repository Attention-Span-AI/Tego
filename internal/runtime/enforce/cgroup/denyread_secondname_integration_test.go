// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestTier2DenyReadSecondNameRefused, end to end in a full `tego run --tier cgroup`:
// a deny_read entry under a write entry, which only fanotify enforces at tier 2 (enforce-landlock R4), read
// through a second name the agent makes itself — a hard link, a rename of the file, a rename of its directory —
// and through a tmpfs mounted beneath it. All four were read, while the ledger said refused; the supervisor now
// refuses the link and the renames (supervisor R15d) and the listener marks the submount.
func TestTier2DenyReadSecondNameRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("SUDO_UID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("no objects: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	base, err := os.MkdirTemp("", "tego-secondname-")
	if err != nil {
		t.Fatal(err)
	}
	bin := buildTaggedTego(t, base)
	_ = os.Chmod(base, 0o711)
	project := filepath.Join(base, "project")
	secret := filepath.Join(project, "out", "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(secret, "key"), []byte("s3cret\n"), 0o644)
	_ = os.WriteFile(filepath.Join(secret, "key2"), []byte("s3cret2\n"), 0o644)
	sub := filepath.Join(secret, "sub")
	_ = os.MkdirAll(sub, 0o755)
	if err := syscall.Mount("tmpfs", sub, "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	defer syscall.Unmount(sub, syscall.MNT_DETACH)
	_ = os.WriteFile(filepath.Join(sub, "key3"), []byte("s3cret3\n"), 0o644)
	agent := `import os
def result(n, o): print("RESULT", n, o, flush=True)
def rd(p):
    try:
        with open(p) as f: return "read:" + f.read().strip()
    except OSError as e: return "refused errno=%d" % e.errno
result("direct", rd("out/secret/key"))
result("submount", rd("out/secret/sub/key3"))
try:
    os.link("out/secret/key", "out/hl"); result("link", rd("out/hl"))
except OSError as e: result("link", "link-refused errno=%d" % e.errno)
try:
    os.rename("out/secret/key2", "out/mv"); result("rename-file", rd("out/mv"))
except OSError as e: result("rename-file", "rename-refused errno=%d" % e.errno)
try:
    os.rename("out/secret", "out/notsecret"); result("rename-dir", rd("out/notsecret/key"))
except OSError as e: result("rename-dir", "rename-refused errno=%d" % e.errno)
`
	contract := `version: 0
name: secondname
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  deny_read: ["./out/secret/"]
exec:
  allow: ["python3"]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`
	_ = os.WriteFile(filepath.Join(project, "agent.py"), []byte(agent), 0o644)
	_ = os.WriteFile(filepath.Join(project, "agent.yaml"), []byte(contract), 0o644)
	_ = filepath.Walk(project, func(p string, _ os.FileInfo, err error) error { return os.Lchown(p, uid, gid) })
	ledgerRoot := filepath.Join(base, "ledger")
	_ = os.Mkdir(ledgerRoot, 0o700)
	cfg := filepath.Join(base, "config.yaml")
	_ = os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledgerRoot)), 0o644)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := tegoRunCommand(ctx, bin, "run", "--tier", "cgroup", filepath.Join(project, "agent.yaml"), "--", python, "./agent.py")
	cmd.Dir = project
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	t.Logf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	for _, e := range runEvents(t, ledgerRoot) {
		if e["kind"] == "fs" || e["kind"] == "gap" {
			t.Logf("ledger: %v", e)
		}
	}
	res := agentResults(t, stdout.String())
	for _, k := range []string{"direct", "submount", "link", "rename-file", "rename-dir"} {
		if res[k] == "" || (len(res[k]) > 5 && res[k][:5] == "read:") {
			t.Errorf("%s: the deny_read content was read, or the agent reported nothing: %q", k, res[k])
		}
	}
}
