// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// This file is the model tier 2's recorder (internal/runtime/observe) stamps a record-only sample with: the
// entry that names an action and the verdict the contract implies for it. The kernel already decided
// (enforce-cgroup-observe §5 R3, R9); these answers attribute a line, they enforce nothing (ADR 0016). Where the
// sample carries the LSM chain's own return, read by an fexit program, ChainFS makes that return the verdict and
// asks InferFS only which of Tego's refusals explains it; InferFS alone decides a sample that carries none.

// FSMatch is what the recorder knows about one filesystem action.
//
// Entry names the action: the nearest entry of any kind. Read and Write are the entries that decide a read and
// a modification of the path, from FSDecider, the chooser the root model decides by: a watch entry grants
// and withholds nothing and an implicit one grants no read, so neither may decide a verdict just by being
// nearer. When Entry decided, a read of the run's own ledger under the built-in deny_read on ~/.tego was
// recorded allow under fs.implicit, and a write under `watch: [/work/logs]` nested in `write: [/work]`
// refused (R9).
type FSMatch struct {
	Rule    string
	Entry   *agent.FSRule // nil when nothing matched
	Read    *agent.FSRule // the entry deciding a read; nil when none does (allowed)
	Write   *agent.FSRule // the entry deciding a modification; nil when none does (refused)
	Watched bool
	// DenyRead is whether a deny_read entry decides a read of the path (Read).
	DenyRead bool
	// Path is the path matched, which InferFS walks up from for an unlink or a rename (Landlock checks those
	// on the parent directory); "" when nothing matched.
	Path string
}

// InferFS is R9's userspace inference: the verdict an fs action implies given the entries that decide it
// (FSMatch.Read, FSMatch.Write). It decides a record-only sample that carries no chain return (a kernel without
// the fexit hook, ADR 0016's fallback), and explains the refusal of one that does (ChainFS); the kernel's own
// verdict wins whenever the producing program was an enforcing one. op is the record.FS* constant of the action. A path no entry
// covers at all is observed: the contract has nothing to attribute it to. rt is the run's table, nil when the
// recorder has none.
func InferFS(rt *agent.RuleTable, op string, write bool, m FSMatch) (record.Verdict, record.Reason) {
	return inferFS(rt, op, write, m, nil)
}

// inferFS is InferFS, asking ix when it is not nil and rt by scan otherwise.
func inferFS(rt *agent.RuleTable, op string, write bool, m FSMatch, ix *FSIndex) (record.Verdict, record.Reason) {
	if m.Entry == nil {
		return record.VerdictObserved, ""
	}
	if !write {
		if m.Read != nil && m.Read.Kind == agent.FSDenyRead {
			return record.VerdictRefused, record.ReasonReadDenied
		}
		return record.VerdictAllow, ""
	}
	d := m.Write
	if (op == record.FSUnlink || op == record.FSRename) && rt != nil && rt.Tier != backend.TierBPFLSM && m.Path != "" {
		// The inherited Landlock ruleset checks an unlink's REMOVE_* and a rename's REFER on the parent
		// directory, so an unlink of a write entry itself (write: [./out], then rm -rf out) is refused by
		// what grants the directory above it, which the entry does not, and the model must say so to explain the
		// chain's refusal (ChainFS). Evaluate answers the same (docs/p0/supervisor.md R15). Tier 3's hooks decide on the path.
		if ix != nil {
			d, _ = ix.FSDecider(filepath.Dir(m.Path), false)
		} else {
			d, _ = FSDecider(rt, filepath.Dir(m.Path), false)
		}
	}
	switch {
	case d == nil:
		return record.VerdictRefused, OpReason(op)
	case d.Kind == agent.FSWrite:
		return record.VerdictAllow, ""
	case d.Kind == agent.FSDenyRead && d.Unenforced:
		// A deny_read nested in a write entry: the inherited Landlock ruleset unions the write entry's
		// rights over it, so the write happened (a link or rename out of the entry the supervisor refuses
		// never reaches the kernel's hook). Refused was a line for an action that succeeded
		// (docs/p0/supervisor.md R15d, ADR 0016); the entry names the path, not a grant, so the line claims no
		// verdict.
		return record.VerdictObserved, ""
	default:
		return record.VerdictRefused, OpReason(op)
	}
}

// ChainFS is the verdict of an fs line whose sample carries the return of the kernel's LSM chain, read by the
// recorder's fexit program on the security_ function that ran it (ADR 0016 (1), (3)). ret is that return, 0 or
// -errno; model is the tier model's answer for the same action (InferFS), asked only when ret refuses.
//
// ret 0 is allow, whatever the model predicts: the chain let the action through. A refusal Landlock or Tego's
// fanotify listener answers with (-EACCES, -EPERM, or -EXDEV for a cross-directory move without refer) that the
// model also refuses is Tego's refusal, with the model's reason. Any other refusal is one no Tego mechanism
// explains — another LSM's, a third-party fanotify listener's, or one the model does not predict — and is
// observed with other true, never refused with a reason from REASON-CHANNEL's closed set, which names Tego's
// refusals only.
func ChainFS(ret int32, model func() (record.Verdict, record.Reason)) (v record.Verdict, reason record.Reason, other bool) {
	if ret == 0 {
		return record.VerdictAllow, "", false
	}
	switch -ret {
	case errnoEACCES, errnoEPERM, errnoEXDEV:
		if mv, mr := model(); mv == record.VerdictRefused {
			return record.VerdictRefused, mr, false
		}
	}
	return record.VerdictObserved, "", true
}

// The errno values ChainFS reads a refusal by. This package imports no syscall package (doc.go), and these are
// asm-generic's, which every architecture Tego ships (amd64, arm64) uses.
const (
	errnoEPERM  = 1
	errnoEACCES = 13
	errnoEXDEV  = 18
)

// OpReason is the refusal code of a modifying fs operation, by its record.FS* constant (the closed set of
// spec/reason/REASON-CHANNEL.md's four *-outside-contract codes): the recorder's and the supervisor's one
// mapping. Creating a symlink or a link is a write on its parent directory, so it carries the write code.
func OpReason(op string) record.Reason {
	switch op {
	case record.FSUnlink:
		return record.ReasonDeleteOutsideContract
	case record.FSRename:
		return record.ReasonRenameOutsideContract
	case record.FSMkdir:
		return record.ReasonMkdirOutsideContract
	default:
		return record.ReasonWriteOutsideContract
	}
}

// ProtoRaw is what the runtime calls a socket that is neither TCP nor UDP (a raw or ICMP socket).
const ProtoRaw = "raw"

// PortAdmits compares a rule's port with an observed one, as every enforcing side does (internal/platform/dns
// Set.Match, the supervisor's resolved-address check, the recorder): a declared port matches itself, and a
// port-0 rule, SEMANTICS §5's spelling of an ICMP or raw destination, covers a destination with port 0 and a
// raw socket whatever port its address carries, and nothing on a real TCP or UDP port — reading 0 as "any
// port" stamped a ping rule on every TCP connect to the host.
func PortAdmits(declared int, observed uint16, proto string) bool {
	if declared == 0 {
		return observed == 0 || proto == ProtoRaw
	}
	return declared == int(observed)
}

// MatchNetLPM finds the net entry of rules that tier 2's kernel rows name for an address and port. The rows
// are composed by the entries covering them (enforce/cgroup BuildRuleMaps, enforce-cgroup-observe §5 R3): a
// refusing covering entry decides whatever the declaration order, and otherwise the first declared one, so a
// /8 declared before a /16 names the /8 for an address inside both, as Evaluate's matcher (matchNet) does. It
// matches addresses only (a host entry by the addresses it resolved to), as the rows do, and returns the
// entry's position in rules, and false when none covers the address.
//
// Port and address are compared the way the enforcing sides compare them (PortAdmits; protoMatches, which
// Evaluate asks too): a rule's address is unmapped and stripped of its zone before it is compared.
func MatchNetLPM(rules []agent.NetRule, addr netip.Addr, port uint16, proto string) (int, bool) {
	if !addr.IsValid() {
		return -1, false
	}
	addr = Unmapped(addr)
	first := -1
	for i := range rules {
		r := &rules[i]
		if !protoMatches(r.Proto, proto) || !PortAdmits(r.Port, port, proto) {
			continue
		}
		covers := r.CIDR != nil && r.CIDR.Contains(addr)
		for _, ip := range r.IPs {
			if Unmapped(ip) == addr {
				covers = true
			}
		}
		if !covers {
			continue
		}
		if r.Verdict != agent.VerdictAllow { // the rows refuse an entry with no verdict too (verdictOf)
			return i, true
		}
		if first < 0 {
			first = i
		}
	}
	return first, first >= 0
}

// Unmapped is an address as every matcher compares it: a v4-mapped v6 address as the v4 one, with no zone.
func Unmapped(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }
