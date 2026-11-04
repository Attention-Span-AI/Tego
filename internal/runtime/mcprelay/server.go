// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// ServerCommand is the child stage dispatched before CLI setup. It waits for the shim to register its pidfd with
// the relay before execing the declared command, so the server's exec cannot race ahead of its admission.
const ServerCommand = "__mcp_server"

// ServerMain runs the waiting server stage. args is the resolved path followed by the original argv. Descriptor 3
// is the shim's private control socket: a release byte permits exec, EOF refuses it; close-on-exec reports success
// to the shim, while an exec error is written back. It reads no machine config and never forks another process.
func ServerMain(args []string) int {
	fd, err := sys.Inherited(3, sys.KindSocket, "MCP server release")
	if err != nil {
		return identity.ExitError
	}
	defer func() { _ = fd.Close() }()
	if err := fd.Borrow(func(n int) error {
		_, err := unix.FcntlInt(uintptr(n), unix.F_SETFD, unix.FD_CLOEXEC)
		return err
	}); err != nil {
		return identity.ExitError
	}
	control, err := fd.Release("mcp-server-release")
	if err != nil {
		return identity.ExitError
	}
	defer func() { _ = control.Close() }()
	var release [1]byte
	if _, err := io.ReadFull(control, release[:]); err != nil || release[0] != 1 {
		return identity.ExitError
	}
	if len(args) < 2 {
		_, _ = fmt.Fprint(control, "missing server argv")
		return identity.ExitError
	}
	if err := syscall.Exec(args[0], args[1:], os.Environ()); err != nil {
		_, _ = fmt.Fprint(control, err)
	}
	return identity.ExitError
}
