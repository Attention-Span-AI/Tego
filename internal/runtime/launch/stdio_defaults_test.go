// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

func TestLauncherCommandDefaultsMissingStdioToNull(t *testing.T) {
	// A Go subprocess would reopen closed stdio during runtime initialization, concealing this
	// defect. Inspect the shell's descriptors from /proc instead, before it launches an agent.
	l := &Launcher{Exe: "/bin/sh", Args: []string{"-c", `
for fd in 0 1 2; do
    target=$(readlink "/proc/$$/fd/$fd") || exit 90
    [ "$target" = /dev/null ] || exit 91
done
`}}
	cmd := l.command(ChildSpec{}, &handshake{})
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	// This subprocess only inspects the command's stdio; it does not run the child stage or keep its
	// forking thread alive to own a parent-death signal.
	cmd.SysProcAttr.Pdeathsig = 0
	if _, err := proc.Start(cmd); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
	defer stop()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child's default streams were not /dev/null: %v", err)
	}
}
