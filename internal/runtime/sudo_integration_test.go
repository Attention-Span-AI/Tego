// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// agentUID is the uid and gid a root launcher drops the agent to (privilegedTarget) when these tests
// run as root under sudo — `sudo go test`, or test/vm/root-suites.sh in the KVM guest — and ok=false
// otherwise, when the agent simply runs as this process's own user.
func agentUID(t *testing.T) (uid, gid int, ok bool) {
	t.Helper()
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	invoking, viaSudo := config.InvokingUID()
	uid, gid, err := privilegedTarget(invoking, viaSudo, os.Getenv("SUDO_GID"), passwdGID)
	if err != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// agentOwns hands paths to the agent's uid when the launcher drops to one. A test running as root
// creates its fixtures as root with the test framework's 0700 and 0600 modes, and the dropped agent
// could then neither read its own script nor write its declared directory — which is not the run a real
// `sudo tego run` of the user's own project makes, where those files are the user's (KVM-11). It
// changes nothing for an unprivileged test.
func agentOwns(t *testing.T, paths ...string) {
	t.Helper()
	uid, gid, ok := agentUID(t)
	if !ok {
		return
	}
	for _, p := range paths {
		if err := os.Lchown(p, uid, gid); err != nil {
			t.Fatalf("chown %s to the agent's %d:%d: %v", p, uid, gid, err)
		}
	}
}

// agentReaches gives the agent's uid search permission on each directory between path and this
// package's temporary parent (TestMain's TMPDIR) that the root test process created without it:
// os.MkdirTemp and t.TempDir make 0700 directories, which the dropped agent cannot pass through to
// reach its project, its script or the model-agent binary (KVM-11). Only o+x is added, so no listing
// is granted, and nothing outside that parent is touched.
func agentReaches(t *testing.T, path string) {
	t.Helper()
	if _, _, ok := agentUID(t); !ok {
		return
	}
	top := filepath.Clean(os.TempDir())
	for dir := filepath.Dir(filepath.Clean(path)); strings.HasPrefix(dir+"/", top+"/"); dir = filepath.Dir(dir) {
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if st.Mode().Perm()&0o001 == 0 {
			if err := os.Chmod(dir, st.Mode().Perm()|0o001); err != nil {
				t.Fatalf("chmod o+x %s: %v", dir, err)
			}
		}
		if dir == top {
			return
		}
	}
}
