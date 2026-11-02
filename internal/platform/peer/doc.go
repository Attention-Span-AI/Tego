// SPDX-License-Identifier: Apache-2.0

// Package peer is the one peer check every local socket of Tego's that serves the person makes on a connection
// (ADR 0100 (3) and (7)): ask.sock and the dashboard's listener adopt it, each in its own package.
//
// Identify reads who connected: the SO_PEERCRED uid and pid, the unified cgroup of that pid (runscope.Unified: exactly
// one 0:: line), its cgroup namespace inode and its start time, all from /proc, and then proves the reads were of the
// process that connected. First, /proc must show the pidfd's process (its fdinfo's Pid: line) as the SO_PEERCRED
// pid: that pid is in this process's pid namespace, /proc's numbers in its mounter's, and a process that entered a
// pid namespace without remounting /proc would otherwise read another process under it. From Linux 6.5 it holds the
// peer's pidfd from SO_PEERPIDFD, which names the connecting process itself, and requires it alive after the reads:
// a live process keeps its pid, so a pid reused by another process can never have stood in. Below 6.5 (the rhel-9
// and al2023 rows) there is no SO_PEERPIDFD: it takes pidfd_open on the SO_PEERCRED pid and, as ADR 0042 (vii) does,
// re-checks the uid that holds the pid, the start time before and after the reads, that the connection is still open
// (the peer's socket not closed: a peer that shut down only its writing side is still there) and that the pidfd is
// alive. A pid reused between the connect and the pidfd_open is not detected there; the Peer says PidfdFallback, and
// a caller discloses it (WarnPidfdFallback). Anything Identify cannot read or prove is a Refusal [peer-unidentified]:
// it fails closed.
//
// Refuse judges an identified peer against the uid that owns the socket: another uid is [unmapped-uid], a cgroup
// that runscope.LooksGoverned is [run-member] (any run's or adoption's scope, and any look-alike of one), and a peer
// in another cgroup namespace, one whose namespace could not be read, or one whose cgroup lies above this process's
// cgroup namespace root is [peer-cgroupns]. So is every peer while this process itself is outside the initial cgroup
// namespace (runscope.InitCgroupNS), or cannot read its own: the peer's path is then read from that namespace's root,
// and a run's scope above the root would not show, the blind spot runscope.InRun refuses for the same reason. Nothing
// else is judged here: what a peer may do is its socket's own rule.
//
// TCPSocketCgroup (tcp.go) is the loopback TCP half, for the dashboard's listener, where no SO_PEERCRED exists: the id
// of the cgroup a client socket was made in, from the kernel's sock_diag answer (INET_DIAG_CGROUP_ID) for that exact
// tuple, which a caller compares with the run scopes' directory inodes. It judges nothing itself. A kernel with no TCP
// socket diagnostics loaded (the inet_diag and tcp_diag modules) is told apart from a closed socket (ErrNoTCPDiag).
//
// It is a Layer 1 platform package: no goroutines, no state, no clock. Every descriptor it holds is a sys.FD (ADR
// 0023), the pidfd closed before Identify returns.
//
// Imports: standard library, golang.org/x/sys/unix, internal/runscope, internal/platform/sys, internal/platform/proc
// (its stat parser), pkg/spec/identity (the message format) (depguard platform-peer-imports)
package peer
