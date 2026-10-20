// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package enforce

import (
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestFallbackIOUring set to 1 makes a binary built with -tags tegotesthooks admit io_uring on tier cgroup's
// fanotify fallback for a contract that declares io_uring: true (fallbackIOUringTestHook), which a product build never
// does (A-0018-5). It exists to prove cgroup/sock_create refuses an inet socket made through IORING_OP_SOCKET, inline,
// from an io-wq worker (IOSQE_ASYNC) and from an SQPOLL thread. A product build does not contain this file; a test build
// ignores it under AT_SECURE, like every TEGO_TEST_ variable.
const EnvTestFallbackIOUring = "TEGO_TEST_FALLBACK_IOURING"

func init() {
	// Never under AT_SECURE, where no environment variable may steer the capability-bearing binary
	// (identity-config.md R21).
	if secure, err := config.DetectSecureExec(); err != nil || secure || os.Getenv(EnvTestFallbackIOUring) != "1" {
		return
	}
	fallbackIOUringTestHook = func() bool { return true }
}
