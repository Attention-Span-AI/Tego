// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestRunWarnsOfAStreamBeyondTheContract: a socket on stdin, or a file outside every write entry opened beyond its
// stream's direction, reaches the agent with access no rule gives, and run says so before it starts; output
// redirected into a file does not warn.
func TestRunWarnsOfAStreamBeyondTheContract(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sock, peer := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
	t.Cleanup(func() { _ = sock.Close(); _ = peer.Close() })
	path := filepath.Join(t.TempDir(), "notes")
	rw, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rw.Close() })
	out, err := os.OpenFile(path+".log", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = out.Close() })
	rt := &agent.RuleTable{Tier: backend.TierLandlock, Contract: &agent.Contract{Name: "a"}}

	var stderr bytes.Buffer
	warnStdio(&stderr, "tego run", rt, tegoruntime.Stdio{In: sock, Out: out})
	if got := stderr.String(); !strings.Contains(got, "stdin is a socket") || !strings.Contains(got, "["+codeStdio+"]") ||
		strings.Contains(got, "stdout") {
		t.Errorf("socket stdin, stdout into a file:\n%s", got)
	}
	stderr.Reset()
	warnStdio(&stderr, "tego run", rt, tegoruntime.Stdio{In: rw})
	if got := stderr.String(); !strings.Contains(got, "stdin is "+path+", open for reading and writing, outside every write entry") {
		t.Errorf("read-write stdin:\n%s", got)
	}
}
