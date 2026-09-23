// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ActionKind is the kind of a hypothetical action `compile --test` evaluates.
type ActionKind string

// Action kinds.
const (
	ActionFSRead     ActionKind = "fs_read"
	ActionFSWrite    ActionKind = "fs_write"
	ActionFSDelete   ActionKind = "fs_delete"
	ActionFSRename   ActionKind = "fs_rename"
	ActionFSMkdir    ActionKind = "fs_mkdir"
	ActionExec       ActionKind = "exec"
	ActionNetConnect ActionKind = "net_connect"
	ActionNetHTTP    ActionKind = "net_http"
	ActionNetBind    ActionKind = "net_bind"
	// ActionMapExec is a PROT_EXEC map of the file at Path (ADR 0027): decided by a decision plane only, at
	// tier bpflsm and tier cgroup in a plane mode; tier landlock and the fanotify listener allow it (SEMANTICS §4).
	ActionMapExec ActionKind = "map_exec"
	// ActionFSLink is a hard link (link(2), linkat(2)): Path the existing file, DestPath the new name. Landlock decides
	// it at both ends' directories (MAKE_REG on the new name's, REFER on both across directories) and by REFER's no-gain
	// rule over the file rights its ruleset grants (hook_path_link), the root tiers' walk at the ends themselves first,
	// and a built-in deny_write target at either end refuses it (supervisor R15c, R17).
	ActionFSLink ActionKind = "fs_link"
	// ActionFSAttr is an attribute change of the file at Path: a mode (chmod), an owner (chown) or an extended
	// attribute, a POSIX ACL included. No Landlock ABI governs one, so it is allowed at every tier except beneath a
	// built-in deny_write target where a decision plane decides (path_chmod and the attribute hooks, enforce-plane
	// R12; CAPABILITIES fs.deny_chmod).
	ActionFSAttr ActionKind = "fs_attr"
	// ActionNetSocket is a socket(2), or with Socket.Pair a socketpair(2), of the triple in Socket: ADR 0018's
	// allowlist under a net: section, nothing refused without one, and IPPROTO_MPTCP refused everywhere (E30).
	ActionNetSocket ActionKind = "net_socket"
	// ActionNetSend is an unconnected datagram send (sendto(2), sendmsg(2) with an address): to Host:Port over UDP,
	// or to the unix socket Path names. It is decided as the connect to that destination (supervisor R13b).
	ActionNetSend ActionKind = "net_send"
	// ActionExecAnon is an exec of an anonymous image, a memfd or a file unlinked since it was opened (SEMANTICS §4):
	// refused, rule exec-anon, unless the run's images are unrestricted or the contract set exec.anonymous.
	ActionExecAnon ActionKind = "exec_anon"
)

// ExecAnonRule is the rule an anonymous image's refused exec carries (SEMANTICS §4: `rule: exec-anon`).
const ExecAnonRule = "exec-anon"

// The rules the run refuses a unix pathname with on what the walk of it met rather than on a socket an entry names
// (supervisor.md R11a): the supervisor's own names for them are these.
const (
	// PathUnreliableRule: the walk met what the run cannot place in its own view (a magic link, a symlink loop, procfs,
	// another mount tree), or failed where a datagram or a bind needs a place.
	PathUnreliableRule = "path-unreliable"
	// UnixAbsentRule: a datagram's name names nothing (ENOENT, ENOTDIR).
	UnixAbsentRule = "unix-absent"
	// UnixForeignRule: what the name reaches under a write entry is no socket a process of the run bound, a directory
	// or a file that is not a socket included, so the write entry's implicit admit does not hold (R11a).
	UnixForeignRule = "unix-foreign"
	// UnixAskScopeRule: what the name reaches is a net.ask unix: scope's place and no person was asked about it there
	// (supervisor.md R11c): a datagram, which is never asked, or a connect a declared entry's spelling admitted whose
	// walk reached the scope's place. Neither the write entry around it nor the run having bound the socket admits it.
	UnixAskScopeRule = "unix-ask-scope"
	// HostSocketsRule: a run with no net: section that did not set host_sockets: true reached for a unix socket no
	// process of the run bound, pathname or abstract, and not one of tego's own endpoints (ADR 0070,
	// HostSocketsRefused): the socket is foreign to the run, as unix-foreign's is under a write entry, and the rule
	// names the default that refuses it.
	HostSocketsRule = "host-sockets"
)

// UnixWalk is what the run's walk of a unix pathname met (the supervisor's unixWalk: one openat2(2) beneath the task's
// root with RESOLVE_NO_MAGICLINKS, then, where that lookup fails, a walk a component at a time that refuses every magic
// link), beyond the socket it reached (Action.Walk). The run decides a connect and a datagram on it (supervisor.md R11,
// R11a), and so does Evaluate.
type UnixWalk uint8

const (
	// UnixWalkLookup is the zero value: Landed, when set, is the socket the agent's own lookup reaches, and decides.
	UnixWalkLookup UnixWalk = iota
	// UnixWalkStepwise: only the walk a component at a time reached Landed (the lookup itself failed, as
	// fs.protected_symlinks fails it): a connect is refused path-unreliable, since the relay connects only where the
	// lookup lands; a datagram is decided on Landed.
	UnixWalkStepwise
	// UnixWalkAbsent: the name names nothing (ENOENT, ENOTDIR). A connect fails in the agent's own lookup and its line
	// keeps the name's verdict; a datagram is refused unix-absent.
	UnixWalkAbsent
	// UnixWalkFailed: the lookup failed otherwise as the agent's own fails (EACCES, ENAMETOOLONG). A connect's line keeps
	// the name's verdict; a datagram is refused path-unreliable.
	UnixWalkFailed
	// UnixWalkUnreliable: the walk met what the run cannot place in its own view (a magic link or a symlink loop,
	// ELOOP; a place on procfs; another mount tree), or a bind's walk failed: refused path-unreliable.
	UnixWalkUnreliable
)

// unixPathMax is sizeof(sockaddr_un.sun_path).
const unixPathMax = 108

// UnixCanonical reports whether an absolute unix pathname is spelled the way the run's kernel programs admit one:
// bpf/include/common.h's tego_unix_canonical, which connect_unix, sendmsg_unix and the plane's step-D hooks apply to
// the kernel's own copy of the name before they look it up (enforce-cgroup-observe §5 R7, enforce-plane §2.11). No
// component is empty, "." or "..", and the name does not end in "/" save the root itself. The name ends at its first
// NUL or after sun_path's 108 bytes, as the supervisor's parseSockaddr and the programs both read it. A name the
// programs refuse here is one the supervisor's name decision cleans and may admit (R11), so this says whether the
// kernel refuses it (the supervisor's kernelRefusal, and Evaluate's cgroup and bpflsm columns).
func UnixCanonical(p string) bool {
	// st is the current component so far: 0 none (just after a "/"), 1 ".", 2 "..", 3 anything else.
	st := 0
	for i := 1; i <= unixPathMax; i++ {
		var c byte
		if i < len(p) && i < unixPathMax {
			c = p[i]
		}
		if c == '/' || c == 0 {
			if st == 1 || st == 2 || (st == 0 && (c == '/' || i > 1)) {
				return false
			}
			if c == 0 {
				return true
			}
			st = 0
			continue
		}
		if c == '.' && st < 2 {
			st++
		} else {
			st = 3
		}
	}
	return true
}

// SocketTriple is a socket(2)'s family, type and protocol as the syscall passes them, the type with its flags
// (SOCK_NONBLOCK, SOCK_CLOEXEC) masked or not; Pair says it is a socketpair(2).
type SocketTriple struct {
	Family, Type, Protocol int32
	Pair                   bool
}

// Action is one hypothetical action for Evaluate.
type Action struct {
	Kind     ActionKind
	Path     string
	DestPath string // rename/link target, for the REFER check
	// Landed is, for a net.connect or net.send to a unix pathname, the socket the run's walk of that name reaches
	// (TestTable.RunResolved lands it with Landers.Unix, following a final symlink as connect(2) and sendto(2) do): the
	// run decides the name Path passes and then this socket (supervisor R11, R11a; SEMANTICS §5), and Evaluate does the
	// same. "" when the name was not landed; Walk then says why, and with Walk zero it is decided on its spelling alone.
	Landed string
	// NoSocket says Landed is no socket when the agent calls (ADR 0019's design note): a directory, one already there
	// or one the name has the agent make (it ends in "/", "." or "..",
	// or walks beneath the part it ends on), or a file already there that is not a socket. The run decides it as any
	// landing (decideResolved), and its write entry's implicit admit then refuses it unix-foreign, since no process of
	// the run bound it (R11a). False when Landed is the socket the name ends on: one already there, taken as the run's,
	// or the one the agent binds at a name that names nothing yet.
	NoSocket bool
	// Walk is what the run's walk of a unix pathname met (UnixWalk): for a connect or a datagram, beyond the socket
	// Landed names; for a pathname net.bind, UnixWalkUnreliable when the walk of its directory failed. Zero for every
	// other action.
	Walk UnixWalk
	// Uncanonical says a net.send's unix pathname is absolute as the agent passes it and not spelled canonically
	// (UnixCanonical): the run's own kernel programs refuse such a datagram where they decide unix names, at tiers
	// cgroup and bpflsm (supervisor.md R13b, enforce-cgroup-observe R7).
	Uncanonical bool
	// Dir says the filesystem action's object is a directory (a rename's source, an opendir, an rmdir); the zero
	// value is a file. ADR 0043's name entries never decide a directory, and a directory rename is asked D5's
	// coverage question. fs.mkdir's object is a directory whatever Dir says.
	Dir    bool
	Script string // exec only: the #! interpreter path, "" if none
	// ScriptArg is the #! line's optional argument (`#!/usr/bin/env node` has node), which binfmt_script passes the
	// interpreter before the script; exec only (ADR 0048 (4), compile --test's script_arg).
	ScriptArg string
	Host      string
	Port      int // Internet destinations: 0 through 65535; unused for Unix sockets
	Proto     string
	Method    string // HTTP request method; Path is the escaped path without query
	Argv      []string
	// Socket is a net.socket action's triple (ActionNetSocket only).
	Socket SocketTriple
}

// EvalResult is Evaluate's verdict for one Action.
type EvalResult struct {
	Score                 *int
	GateRule, GateOutcome string
	CompletionUnsupported bool
	Verdict               Verdict
	Rule                  string
	Reason                record.Reason
	// CommandRule, CommandList, CommandMatch and CommandVia are an exec's command-rule decision (ADR 0048 (4), (8)):
	// the entry that decided, its list (deny, ask, allow or unlisted), definite or ambiguous, and the
	// interpretation that read it. Empty when no command rule decided.
	CommandRule, CommandList, CommandMatch, CommandVia string
	// ArgvFacts is where the argv a command rule decided on came from: test_row in compile --test, copied_syscall
	// in a run.
	ArgvFacts string
}

// Sentinel rule names Evaluate reports when no declared entry decided.
const (
	// UnmatchedRule is the rule of an action no declared entry covers; every
	// view counts it as its own bucket (SEMANTICS §2, record/v1).
	UnmatchedRule = "unmatched"
	// InvalidActionRule is the rule of an Action malformed for its Kind: the
	// verdict is refused and no error is returned, so one bad row never
	// aborts a `compile --test` table (§4).
	InvalidActionRule = "invalid-action"
	// UnresolvedRule is the rule of a connect to a literal address that only
	// an unresolved host entry could have matched (E18, E19): the table was
	// compiled offline, so the row cannot be decided from it.
	UnresolvedRule = "unresolved"
	// ResolverRule is the rule of traffic the runtime allows on its own authority rather than the
	// contract's: a query to a configured resolver, permitted ungated by net.allow so that a contract
	// naming hosts does not also have to name the machine's nameservers (docs/p0/supervisor.md R14).
	ResolverRule = "net.resolver"
	// CaptureGrant is NetRule.Runtime for the loopback listener a capture source bound: the agent has
	// to reach it, and no contract can declare it because the port does not exist until the listener
	// binds. Its rule name is "net.capture[<addr>]".
	CaptureGrant = "capture"
	// DNSBrokerGrant admits only the run-owned cooperating DNS Unix socket.
	DNSBrokerGrant = "dns-broker"
	// CodexHomeGrant is FSRule.Runtime for the write grant on the run's own CODEX_HOME,
	// $XDG_RUNTIME_DIR/tego/<run id>/codex (capture-derive.md R19b, agent-contract.md R10a): Codex keeps its state
	// there, and no contract can name the directory because its path holds the run id. Its rule name is
	// "fs.codex_home[<path>]".
	CodexHomeGrant = "codex_home"
	// HarnessStateGrant is FSRule.Runtime for the write grant on the run's hook-state directory,
	// $XDG_RUNTIME_DIR/tego/<run id>/hook-state (agent-contract.md R10a, R27; ADR 0062): the harness hook keeps its
	// cursor there, and it is the one place in the run's runtime directory the agent may write. The launcher makes it
	// only when it provisions a harness. Its rule name is "fs.harness-state[<path>]".
	HarnessStateGrant = "harness-state"
	// HarnessHookGrant is ExecRule.Runtime, and the kind of the exact command rule beside it, of the harness hook's
	// exec grant (ADR 0064, agent-contract.md R27): under an allow-list contract the launcher admits the tego binary
	// with the hook's exact argv and no other. Its rule name is "exec.harness-hook[<tego binary>]".
	HarnessHookGrant = "harness-hook"
)

// IsRuntimeRule reports whether a rule name denotes a grant the runtime makes on its own authority, so a
// reader can tell it apart both from a contract entry and from an action nothing admitted.
//
// A view that treats such a rule as an undeclared entry reports drift on every run that resolves a
// hostname, which is nearly all of them, and a finding that fires every time carries no information.
func IsRuntimeRule(rule string) bool {
	return rule == ResolverRule || strings.HasPrefix(rule, "net."+CaptureGrant+"[") ||
		strings.HasPrefix(rule, "net."+DNSBrokerGrant+"[unix:/") && strings.HasSuffix(rule, "]") ||
		strings.HasPrefix(rule, "fs."+CodexHomeGrant+"[/") && strings.HasSuffix(rule, "]") ||
		strings.HasPrefix(rule, "fs."+HarnessStateGrant+"[/") && strings.HasSuffix(rule, "]") ||
		strings.HasPrefix(rule, "exec."+HarnessHookGrant+"[/") && strings.HasSuffix(rule, "]")
}

// MaxWalk bounds the root tiers' ancestor walk at the kernel's own bound
// (SEMANTICS §2, "bounded to 64 steps"); an exhausted walk is refused with
// path-unresolved, never guessed.
const MaxWalk = 64

// UnenforcedSuffix marks the rule of a read the Landlock tier allows under a deny_read entry it cannot
// enforce because a write entry sits at or above its parent (SEMANTICS §2, R15).
const UnenforcedSuffix = " (unenforced: parent writable)"

// OPathSuffix marks the rule of an O_PATH open allowed beneath a deny_read entry in a run that holds its reads (ADR
// 0069 D2): such an open reads nothing and no mechanism refuses it (the kernel runs no file_open hook for it), while
// every read through its descriptor is another open, held and refused.
const OPathSuffix = " (O_PATH: reads nothing)"

// ExecUnrestricted reports whether the run's images are unrestricted: the contract left exec: out entirely, the
// state SEMANTICS §1 spells "no exec: — deny nothing", or its exec: section is a deny-list (ADR 0048 (1): no allow
// key, a deny or ask key), where only the command rules apply. A hand-built table carries no Contract and fails
// closed, the same reading internal/runtime/enforce/landlock's builder takes. Every enforcer asks this method, never
// the Contract's fields (TestExecModeOneSpelling): one spelling, so no two of them read a deny-only section two ways.
func (rt *RuleTable) ExecUnrestricted() bool {
	return rt.Contract.ExecUnrestricted()
}

// ExecAnonymous reports whether the contract opted into anonymous-image exec (exec.anonymous: true); a table
// without its Contract does not.
func (rt *RuleTable) ExecAnonymous() bool {
	return rt.Contract.ExecAnonymous()
}

// NetUnrestricted reports whether the contract left net: out entirely, the state SEMANTICS §1 spells
// "no net: — deny nothing": a destination no entry names is admitted, a models[] endpoint under capture:
// forwarder excepted (GuardedModels). It is the one predicate Evaluate
// and internal/runtime/supervisor both ask, so compile --test and the ledger cannot answer one connect two
// ways, and the enforcement backends read the same bit: the Landlock builder handles no net right
// (netRestricted) and tier 2 attaches no network program (internal/runtime/enforce/cgroup, RuleMaps
// Unrestricted — before it did, its programs refused every TCP and UDP destination such a contract
// leaves them no row for). A hand-built table carries no Contract and fails closed, as the builder does.
func (rt *RuleTable) NetUnrestricted() bool {
	return rt.Contract != nil && rt.Contract.Net == nil
}

// HostSocketsRefused reports whether the run is in the unix-only state of ADR 0070: its contract has no net: section,
// so every IP destination stays admitted (NetUnrestricted), and did not set host_sockets: true, so a unix connect or
// an addressed unix datagram reaches only a socket a process of the run bound and tego's own endpoints (the runtime's
// unix: grants), and every other one, pathname or abstract, is refused rule host-sockets. It is kept apart from
// NetUnrestricted, which every IP decision asks: the restriction is on unix destinations alone. Evaluate, the
// supervisor and the Landlock builder (RESOLVE_UNIX, the bind notifications) all ask this one predicate. A hand-built
// table carries no Contract and answers false: NetUnrestricted is false for it too, so its net rules already refuse
// every unix destination they do not name.
func (rt *RuleTable) HostSocketsRefused() bool {
	return rt != nil && rt.NetUnrestricted() && !rt.Contract.HostSockets
}

// HostSocketsOpened reports whether the contract opted out of the unix-only state (host_sockets: true) where it
// would apply: no net: section. run_start records it (host_sockets) and compile warns with the sockets it opens.
func (rt *RuleTable) HostSocketsOpened() bool {
	return rt != nil && rt.NetUnrestricted() && rt.Contract.HostSockets
}

// DecidesDatagrams reports whether the run's supervisor decides where a datagram goes beyond best effort: under a
// net: section (decided datagrams, net.ask approvals), a models[] endpoint guarded under capture: forwarder
// (GuardedModels, whose datagrams are relayed) or a gate that scores net actions (whose admitted datagrams are relayed).
// It is the one predicate both layers of supervisor R13's pending frames read: the seccomp filter's arms that notify
// what could start a UDP frame (enforce/landlock) and the supervisor's refusal of it, so a run never has the one
// without the other. Without any of the three nothing names a datagram's destination but a best-effort line, and
// MSG_MORE and UDP_CORK are the agent's to use. A nil table decides nothing.
func (rt *RuleTable) DecidesDatagrams() bool {
	return rt != nil && (!rt.NetUnrestricted() || len(rt.GuardedModels()) > 0 || rt.Gate.Has(gate.Net))
}

// SocketPolicy is what a table asks of socket(2) and socketpair(2) (ADR 0018 (1), (5)): Restricted when the
// contract has a net: section, ICMP when that section names an ICMP destination (a non-unix entry with port
// 0, SEMANTICS §5's spelling). The zero value refuses nothing.
type SocketPolicy struct {
	Restricted, ICMP bool
}

// NetSocketPolicy is the table's socket policy. It is the one predicate both layers that decide socket
// creation read: the seccomp filter's socket arm (enforce/landlock SocketArmFor) and the decision plane's
// slot header net flags (enforce/cgroup netPolicyOf), so the two can never admit a ping socket one refuses.
// A nil table asks for nothing.
func (rt *RuleTable) NetSocketPolicy() SocketPolicy {
	if rt == nil || rt.NetUnrestricted() {
		return SocketPolicy{}
	}
	p := SocketPolicy{Restricted: true}
	for _, r := range rt.Net {
		if r.Proto != ProtoUnix && r.Port == 0 {
			p.ICMP = true
		}
	}
	return p
}

// Governed is the subtree a rule governs: FSRule.Resolved when Compile filled it in, else the declared path,
// which is all a table built by hand in a test carries. It is not cleaned (Canonical is).
func (r FSRule) Governed() string {
	if r.Resolved != "" {
		return r.Resolved
	}
	return r.Path
}

// CoverSteps reports whether entry is path or one of its ancestors, and how many components above path it
// sits: Covers with the distance the nearest-wins walk ranks entries by (internal/policy/decide). The
// comparison is on whole components, so /work/outside is never covered by /work/out. path must be clean.
func CoverSteps(entry, path string) (int, bool) {
	e := filepath.Clean(entry)
	if e == "" || e == "." {
		return 0, false
	}
	if e == path {
		return 0, true
	}
	// path lies beneath e when e is a prefix ending at a separator in path; checked in place, since
	// building e+"/" allocated on every step of every walk.
	if !strings.HasPrefix(path, e) {
		return 0, false
	}
	rest := path[len(e):]
	if !strings.HasSuffix(e, string(filepath.Separator)) {
		if rest == "" || rest[0] != filepath.Separator {
			return 0, false
		}
		rest = rest[1:]
	}
	if rest == "" {
		return 0, false
	}
	return strings.Count(rest, string(filepath.Separator)) + 1, true
}

// FSReason is the refusal reason of a filesystem action (the closed set of
// spec/reason/REASON-CHANNEL.md).
func FSReason(kind ActionKind) record.Reason {
	switch kind {
	case ActionFSRead:
		return record.ReasonReadDenied
	case ActionFSDelete:
		return record.ReasonDeleteOutsideContract
	case ActionFSRename:
		return record.ReasonRenameOutsideContract
	case ActionFSMkdir:
		return record.ReasonMkdirOutsideContract
	}
	// A write, a link (the supervisor's reasonFor(link), the plane's path_link) and an attribute change.
	return record.ReasonWriteOutsideContract
}

// The three RuleName methods below are the only place a `rule` field is
// spelled. An entry an Adjustable contract's live.fence added (Fence) is named
// after the fence entry, live.fence[<kind>:<value>] (ADR 0125 decision 9), so
// the record never says the contract allowed what only a lifted entry allows. spec/record/v1/README.md says the field holds "the declared entry
// or `unmatched`", so the name is the entry as its author wrote it — never a
// position in a list, which no reader of a contract thinks in and which
// changes the moment an entry is inserted above it. Every producer in every
// tier calls these, and internal/check/drift registers the declared side from
// them too: one scheme, so the two sides can be compared at all.
//
// Two entries may share a name (an exact duplicate, which Load warns about
// but admits). That is deliberate: the buckets a reader sees are declared
// entries, not positions, so a collision collapses into one bucket rather
// than splitting a reader's attention across indexes.

// RuleName is the rule field an event carries for this entry:
// "fs.<kind>[<declared entry>]", the shape of the frozen fixture ledger
// (spec/record/v1/fixtures/run-fixture.jsonl: fs.write[./out],
// fs.deny_read[~/.ssh]). An implicit or built-in entry has no declared text,
// so it carries its resolved path instead. A deny_read entry compiled from fs.ask_read is named after the key
// it was declared in, fs.ask_read[...], so a refusal, a held read and drift all name the entry the author wrote.
func (r FSRule) RuleName() string {
	if r.Fence {
		return LiveFenceRule(LiveKindRead, r.Path)
	}
	if r.Runtime != "" {
		return "fs." + r.Runtime + "[" + r.Path + "]"
	}
	kind := string(r.Kind)
	if r.AskRead && r.Kind == FSDenyRead {
		kind = fsAskReadKey
	}
	return "fs." + kind + "[" + rawOr(r.Raw, r.Path) + "]"
}

// fsAskReadKey is FSSection.AskRead's YAML key, the name its entries' rules carry.
const fsAskReadKey = "ask_read"

// AskReadRules is the table's fs.ask_read entries (FSRule.AskRead), in table order.
func (rt *RuleTable) AskReadRules() []FSRule {
	var out []FSRule
	for _, r := range rt.FS {
		if r.AskRead && r.Kind == FSDenyRead {
			out = append(out, r)
		}
	}
	return out
}

// HasAskRead reports whether the table holds reads for a person: it has an fs.ask_read entry.
func (rt *RuleTable) HasAskRead() bool {
	for i := range rt.FS {
		if rt.FS[i].AskRead && rt.FS[i].Kind == FSDenyRead {
			return true
		}
	}
	return false
}

// RuleName is the rule field a net event carries, "net[<declared entry>]",
// "net.<kind>[<address>]" for an entry the runtime added itself (Runtime), or
// "mcp[<name>]" for one an HTTP MCP server's URL declared (MCP).
func (r NetRule) RuleName() string {
	if r.Fence {
		return LiveFenceRule(LiveKindNet, strings.TrimPrefix(r.Raw, ProtoTCP+"://"))
	}
	if r.MCP != "" {
		return MCPRule(r.MCP)
	}
	raw := r.Raw
	if raw == "" {
		switch {
		case r.Host != "" && r.Port > 0:
			raw = r.Host + ":" + strconv.Itoa(r.Port)
		case r.Host != "":
			raw = r.Host
		default:
			raw = r.UnixPath
		}
	}
	if r.Runtime != "" {
		return "net." + r.Runtime + "[" + raw + "]"
	}
	return "net[" + raw + "]"
}

// RuleName is the rule field an exec event carries, "exec[<declared entry>]";
// an implicit grant (the agent's own command, an MCP server's binary) carries
// its basename.
//
// Source is deliberately not consulted. One binary that is both the agent's
// command and an exec.allow entry compiles to a single rule whose Source is
// the comma-joined "command,exec.allow" (compile_exec.go), which is a
// provenance note and not an entry anyone declared; naming the event after it
// put a string the schema does not admit into the ledger.
func (r ExecRule) RuleName() string {
	if r.Fence {
		if r.FenceEntry != "" {
			return LiveFenceRule(LiveKindExec, r.FenceEntry)
		}
		return LiveFenceRule(LiveKindExec, r.Path)
	}
	if r.Runtime != "" {
		return "exec." + r.Runtime + "[" + r.Path + "]"
	}
	return "exec[" + rawOr(rawOr(r.Raw, r.Basename), r.Path) + "]"
}

// rawOr returns raw when it is set, else the fallback.
func rawOr(raw, fallback string) string {
	if raw != "" {
		return raw
	}
	return fallback
}
