// SPDX-License-Identifier: Apache-2.0

// Command tego-control is the control binary: the control service, its children and the nouns tego hands to
// it. tego reaches it only through its verified handoff (internal/handoff), which runs a sealed copy
// whose hash the tego build pinned. It links no part of the engine (TestControlLinksNoEngine), and refuses every
// command at euid 0 or with a capability.
package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/control/cli"
)

func main() {
	// A handoff runs this image through execveat(AT_EMPTY_PATH) or /proc/self/fd/N, and the kernel may then name the
	// process after the descriptor number ("3"); name it for ps, top and the logs. Best effort: the name is cosmetic.
	name := []byte("tego-control\x00")
	_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0)
	os.Exit(cli.Main(os.Args, os.Stdout, os.Stderr))
}
