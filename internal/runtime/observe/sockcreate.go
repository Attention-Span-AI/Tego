// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// handleSockCreate records cgroup/sock_create's own refusal of an inet socket outside ADR 0018's allowlist
// (KindSockCreate; enforce-cgroup-observe §5 R4, R5): the one line of a socket that reached inet_create on a path the
// seccomp filter did not decide, io_uring's IORING_OP_SOCKET or any other. It is spelled as the supervisor's and the
// plane's socket refusals are (supervisor socket.go, handlePlaneSocket): a refused line naming the family, type and
// protocol, reason net-not-allowed and rule unmatched, since no entry of the contract can name a socket family, with
// mechanism cgroup and no decision_plane, since the program is not the plane and decides the same way whatever mode
// the run's plane is in. The kernel answered the caller EPERM.
//
// The program refuses with net-not-allowed alone and never a triple the allowlist admits without an ICMP entry, so
// a record that says otherwise is not its own and is a malformed-record gap; the line is still written, since the
// kernel refused that socket whatever the record says (a refusal is never silent, ADR 0015). A record of another
// generation of this run's slot never reaches here (mine).
func (r *Recorder) handleSockCreate(rec *Record) {
	s := rec.Sock
	if bpf.ReasonCode(rec.Reason) != bpf.ReasonNetNotAllowed || bpf.SocketAllowed(s.Family, s.Type, s.Protocol, false) {
		r.gap(GapMalformedRecord, 1)
	}
	reason := record.ReasonNetNotAllowed
	ev := r.event(rec, record.KindRefused, RuleUnmatched, record.VerdictRefused, reason)
	// A refused line is no action: it carries rule and reason, never a verdict or an authority (spec/record/v1).
	ev.Verdict, ev.Authority, ev.Attr = "", "", nil
	r.setPayload(ev, record.RefusedPayload{Op: "socket", Target: record.SocketTriple(s.Family, s.Type, s.Protocol),
		Reason: reason, Rule: RuleUnmatched, Mechanism: record.MechanismCgroup})
	r.emit(ev)
}

// handleSockopt records cgroup/setsockopt's own refusal of setsockopt(SOL_TCP, TCP_ULP) (KindSockopt; ADR 0018 (7)):
// the one line of an upper-layer protocol asked for on a path the seccomp filter does not see, io_uring's
// SOCKET_URING_OP_SETSOCKOPT. It is spelled as the supervisor's refusal of the same option is (supervisor socket.go,
// record.SocketOption): a refused setsockopt line naming the ULP, cut at the caller's optlen, the first NUL and the
// bytes the kernel reads, reason net-not-allowed and rule unmatched, with mechanism cgroup and no decision_plane. The
// kernel answered the caller EPERM.
//
// The program refuses TCP_ULP alone, with net-not-allowed, so a record of another option or reason is not its own and
// is a malformed-record gap; the line is still written, since the kernel refused that call whatever the record says
// (ADR 0015).
func (r *Recorder) handleSockopt(rec *Record) {
	o := rec.Sockopt
	if bpf.ReasonCode(rec.Reason) != bpf.ReasonNetNotAllowed || o.Level != unix.SOL_TCP || o.Optname != unix.TCP_ULP {
		r.gap(GapMalformedRecord, 1)
	}
	name := o.Name[:bpf.ULPNameMax]
	if o.Optlen >= 0 && int(o.Optlen) < len(name) {
		name = name[:o.Optlen]
	}
	reason := record.ReasonNetNotAllowed
	ev := r.event(rec, record.KindRefused, RuleUnmatched, record.VerdictRefused, reason)
	ev.Verdict, ev.Authority, ev.Attr = "", "", nil
	r.setPayload(ev, record.RefusedPayload{Op: "setsockopt", Target: record.SocketOption(o.Level, o.Optname, name, true),
		Reason: reason, Rule: RuleUnmatched, Mechanism: record.MechanismCgroup})
	r.emit(ev)
}
