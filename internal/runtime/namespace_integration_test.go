// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unshareProbe tries to enter a new user and mount namespace, and writes "ok" or the errno's name. It calls unshare(2)
// through libc: os.unshare is Python 3.12's, and RHEL 9's python3 is 3.9 (AttributeError, so the probe wrote nothing).
const unshareProbe = `import ctypes, errno, sys
CLONE_NEWNS, CLONE_NEWUSER = 0x00020000, 0x10000000
libc = ctypes.CDLL(None, use_errno=True)
if libc.unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0:
    r = "ok"
else:
    e = ctypes.get_errno()
    r = errno.errorcode.get(e, str(e))
open(sys.argv[1], "w").write(r)
`

// TestTheAgentCannotEnterANewMountNamespace: on the real kernel at tier 1, a new user and mount namespace is a copy
// of the mount tree with none of tier 2's fanotify marks, where a deny_read fanotify alone enforced was read with no
// permission event. The unshare is refused with EPERM and recorded refused reason=landlock-topology op=unshare.
func TestTheAgentCannotEnterANewMountNamespace(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, contractFor("nsprobe", []string{python}, []string{python, resolved}))
	script := filepath.Join(f.dir, "probe.py")
	if err := os.WriteFile(script, []byte(unshareProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	out := filepath.Join(f.out, "result")
	if _, err := Run(context.Background(), f.rt, []string{python, script, out}, f.deps(t, nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the probe wrote nothing: %v", err)
	}
	if string(got) != "EPERM" {
		t.Fatalf("unshare(CLONE_NEWUSER|CLONE_NEWNS) = %s inside the run, want EPERM", got)
	}
	var found bool
	for _, e := range events(t, runDirs(t, f.root)[0]) {
		if e.Kind != record.KindRefused {
			continue
		}
		var p record.RefusedPayload
		if err := e.DecodePayload(&p); err == nil && p.Op == "unshare" && e.Reason == record.ReasonLandlockTopology &&
			strings.Contains(p.Target, "CLONE_NEWNS") {
			found = true
		}
	}
	if !found {
		t.Fatal("no refused line names the unshare")
	}
}
