// SPDX-License-Identifier: Apache-2.0

// Package peer is the one peer check every local socket of Tego's that serves the person makes on a connection
// (ADR 0100 (3) and (7)): ask.sock and the dashboard's listener adopt it, each in its own package.
//
// Identify reads who connected: the SO_PEERCRED uid and pid, the unified cgroup of that pid (runscope.Unified: exactly
// one 0:: line) and of every one of its threads, which must all name that one cgroup, with a first thread that has not
// exited (everyThread: a dead first thread keeps its old cgroup when the process is moved), its cgroup namespace inode
// (or, when /proc hides it, why: Undumpable) and its start time, all from /proc, and then proves the reads were of the process that connected. First, /proc must show the pidfd's process (its fdinfo's Pid: line) as the SO_PEERCRED
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
// in another cgroup namespace, one whose namespace could not be read (unless the files that stay readable show the
// reason to be the dumpable flag at 0 and nothing else, Peer.Undumpable: the peer's /proc/<pid>/environ belongs to another
// uid than its own, its status shows the connecting uid four times and its CapPrm is zero; a process that holds a secret,
// such as the dashboard, makes itself so, and it is then judged on everything else as any peer is, which an agent that makes
// itself undumpable gains nothing by: its cgroup path, read in this process's namespace, is its run's), or one whose cgroup lies above this process's
// cgroup namespace root is [peer-cgroupns]. So is every peer while this process cannot read its own cgroup namespace,
// and while it is outside the initial one (runscope.InitCgroupNS) unless its own answer is outside (Self): the peer's
// path is then read from that namespace's root, and only the rule's proof shows that no run's scope lies above the
// root where it would not show. Nothing else is judged here: what a peer may do is its socket's own rule.
//
// Self (self.go) is the rule for this process itself, runscope.Decide over the kernel's reads: whether it is outside
// every tego run made inside its own cgroup namespace, with three answers of which only Outside permits. In the
// initial cgroup namespace it reads this process's cgroup file and its namespace file (from a descriptor fstatfs
// shows to be a namespace file) and nothing else. In any other it reads the caller's ids, capabilities and seccomp
// mode, anchors /proc (a descriptor shown to be a procfs root; every later read is openat2 beneath it, crossing no
// mount and following no magic link), and makes one probe: NS_GET_USERNS on the namespace descriptor must give the
// first user namespace, pid 1 must be in /init.scope, and the listener on the user's service-manager socket
// (/run/user/<uid>/systemd/private; one non-blocking connect, nothing sent) must be a live process of this uid in
// exactly the manager's cgroup, taken by SO_PEERPIDFD with no fallback. Only that proof is remembered, in memory, for
// the namespace and uid; a failure is retried at most once a second; one probe runs at a time, and a caller waits at
// most ProbeLimit. On a WSL machine that shows two of WSL's marks the proof is used in an ordinary build, as anywhere
// (wslgate.go: the rule is on there since the guest rows that proved a run's refusal of WSL's own launcher, its
// home-folder alias, the Windows drive and the GUI and audio sockets passed); on one mark the answer stays unknown,
// cause wsl-launcher-unproven, in every build.
//
// TCPSocketCgroup (tcp.go) is the loopback TCP half, for the dashboard's listener, where no SO_PEERCRED exists: the id
// of the cgroup a client socket was made in, from the kernel's sock_diag answer (INET_DIAG_CGROUP_ID) for that exact
// tuple, which a caller compares with the run scopes' directory inodes. It judges nothing itself. A kernel with no TCP
// socket diagnostics loaded (the inet_diag and tcp_diag modules) is told apart from a closed socket (ErrNoTCPDiag).
//
// It is a Layer 1 platform package. Identify, Refuse and TCPSocketCgroup keep no state and start no goroutine; Self
// keeps this process's proofs and runs each probe on a goroutine of its own, bounded by a clock. Every descriptor it
// holds is a sys.FD (ADR 0023), the pidfd closed before Identify returns and every descriptor of a probe when it ends.
//
// Imports: standard library, golang.org/x/sys/unix, internal/runscope, internal/platform/sys, internal/platform/proc
// (its stat parser), pkg/spec/identity (the message format) (depguard platform-peer-imports)
package peer
