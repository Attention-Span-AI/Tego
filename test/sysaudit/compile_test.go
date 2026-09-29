// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sysaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// auditContract exercises every part of Compile that touches the filesystem: fs entries resolved and
// stat'ed, deny_read, exec entries looked up on PATH with their ELF loaders read, a literal net entry (no DNS
// in a unit test, though a lookup would be allowed: DNS is I6's other read-only I/O).
const auditContract = `version: 0
name: audited
command: ["sh", "-c", "true"]
fs:
  write: ["WORK/out/"]
  deny_read: ["WORK/in/secret"]
  watch: ["WORK/in/watched/"]
exec:
  allow: ["sh", "env", "ls"]
net:
  allow: ["127.0.0.1:8080"]
limits:
  memory: 1GiB
  pids: 64
tier: landlock
capture: off
`

// Environment the traced child reads.
const envWork = "TEGO_AUDIT_WORK"

// forbidden are the syscalls agent-contract.md I6 names besides the file mutations: ptrace, bpf(2), mount,
// and the namespace calls that would put the process somewhere else.
var forbidden = map[uint64]string{101: "ptrace", 321: "bpf", 165: "mount", 166: "umount2", 272: "unshare", 308: "setns"}

// TestCompileMakesNoMutatingSyscall is agent-contract.md I6, syscall-audited: LoadBytes and Compile over a
// contract that uses every filesystem-touching part of the compiler make no write-flagged open, no unlink,
// rename, mkdir, chmod, chown, link or truncate, no write through a descriptor that is a file, and no ptrace,
// bpf or mount. Unprivileged: the test binary traces its own child.
func TestCompileMakesNoMutatingSyscall(t *testing.T) {
	if testutil.InSysTraceChild() {
		work := os.Getenv(envWork)
		body := []byte(strings.ReplaceAll(auditContract, "WORK", work))
		m := config.Builtin()
		testutil.MarkBegin()
		c, _, err := agent.LoadBytes(filepath.Join(work, "agent.yaml"), body, nil)
		var rt *agent.RuleTable
		if err == nil {
			rt, _, err = agent.Compile(c, m, agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(work),
				agent.WithHome(filepath.Join(work, "home")))
		}
		testutil.MarkEnd()
		if err != nil {
			t.Fatal(err)
		}
		if len(rt.FS) == 0 || len(rt.Exec) == 0 {
			t.Fatalf("the contract compiled to no fs or exec rules; the audit covered nothing: %+v", rt)
		}
		return
	}
	work := t.TempDir()
	for _, d := range []string{"in/watched", "out", "home"} {
		if err := os.MkdirAll(filepath.Join(work, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "in", "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := testutil.SysTrace(t, t.Name(), envWork+"="+work)
	opened := 0
	for _, c := range calls {
		if c.Written() {
			t.Errorf("Compile made a mutating syscall: %v", c)
		}
		if name, bad := forbidden[c.Nr]; bad {
			t.Errorf("Compile called %s", name)
		}
		if c.Nr == testutil.SysOpenat || c.Nr == testutil.SysOpen || c.Nr == testutil.SysOpenat2 {
			opened++
		}
	}
	if opened == 0 {
		t.Fatalf("the trace holds no open at all; it did not see Compile's reads: %v", calls)
	}
}

// TestSysTraceSeesAMutation is the audit's own control: the same tracer, over code that creates a file,
// renames it and removes it, must see each of those. An audit that saw nothing would pass the tests above.
func TestSysTraceSeesAMutation(t *testing.T) {
	if testutil.InSysTraceChild() {
		work := os.Getenv(envWork)
		testutil.MarkBegin()
		err := os.WriteFile(filepath.Join(work, "a"), []byte("x"), 0o600)
		if err == nil {
			err = os.Rename(filepath.Join(work, "a"), filepath.Join(work, "b"))
		}
		if err == nil {
			err = os.Remove(filepath.Join(work, "b"))
		}
		testutil.MarkEnd()
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	work := t.TempDir()
	seen := map[string]bool{}
	for _, c := range testutil.SysTrace(t, t.Name(), envWork+"="+work) {
		if c.Written() {
			seen[c.Name] = true
		}
	}
	for _, want := range [][]string{{"openat", "open"}, {"write", "pwrite64"}, {"renameat", "rename", "renameat2"}, {"unlinkat", "unlink"}} {
		found := false
		for _, n := range want {
			found = found || seen[n]
		}
		if !found {
			t.Errorf("the audit missed %v; it saw %v", want, seen)
		}
	}
}
