// SPDX-License-Identifier: Apache-2.0

package enforce

// fallbackIOUringTestHook is the io_uring test seam (ADR 0018 PR 2, A-0018-5). A product build leaves it as it is
// here, false, so io_uring is admitted only where a plane mode decides the run (inheritedRun, ADR 0018 (5)): on the
// fanotify fallback cgroup/sock_create decides inet sockets alone, and nothing decides an IORING_OP_SOCKET of another
// family, a unix name below 6.7 or an fs operation only the supervisor decides. A build with -tags tegotesthooks
// sets it from TEGO_TEST_FALLBACK_IOURING (iouring_testhook.go), so a root test can admit io_uring there and show the
// backstop refusing an inet socket the seccomp filter never sees.
var fallbackIOUringTestHook = func() bool { return false }
