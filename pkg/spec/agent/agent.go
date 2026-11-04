// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// Contract is agent.yaml v0 after decoding and the extends merge.
//
// Pointer sections distinguish "key absent" (nil) from "key present but empty"
// (&FSSection{}); SEMANTICS §1 gives those two states different defaults (R6).
// Every Limits field is a pointer for the same reason: nil means "inherit the
// machine ceiling", not zero.
//
// The fields after IOUring are schema-only in P0: they are parsed so that
// KnownFields accepts the full v0 schema, and rejected as not-yet-supported
// when non-empty (R2).
type Contract struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"name"`
	// Revision is the contract author's name for this version of the file (agent-contract.md R28, ADR 0073):
	// ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$, "" for none. The top-level contract's own (a profile that sets it is a
	// [schema] error), part of the canonical bytes, and written as run_start.contract_revision.
	Revision string `yaml:"revision,omitempty"`
	// Extends names the profiles this file is laid over, one name or a list of 1 to MaxExtendsList, merged in
	// order (agent-contract R5, ADR 0066). The merged contract keeps the top file's own list.
	Extends ExtendsList `yaml:"extends,omitempty"`
	Command []string    `yaml:"command"`

	FS   *FSSection   `yaml:"fs,omitempty"`
	Net  *NetSection  `yaml:"net,omitempty"`
	Exec *ExecSection `yaml:"exec,omitempty"`
	Env  EnvSection   `yaml:"env,omitempty"`

	MCP     []MCPServer     `yaml:"mcp,omitempty"`
	Models  []ModelEndpoint `yaml:"models,omitempty"`
	Limits  Limits          `yaml:"limits,omitempty"`
	Record  RecordMode      `yaml:"record,omitempty"`  // "" = summary
	Tier    TierPin         `yaml:"tier,omitempty"`    // "" = auto
	Capture CaptureMode     `yaml:"capture,omitempty"` // "" = auto
	IOUring bool            `yaml:"io_uring,omitempty"`
	// Keyring lets the run use the kernel keyring (add_key, request_key, keyctl), which tiers 1 and 2
	// refuse by default because no fs, net or exec rule can see it (SEMANTICS §1).
	Keyring bool `yaml:"keyring,omitempty"`
	// IPC lets the run use System V IPC (shared memory, message queues, semaphores), which tiers 1 and 2
	// refuse by default: its namespace is the host's, its ids are guessable, and no fs, net or exec rule
	// can see it (SEMANTICS §1, R11).
	IPC bool `yaml:"ipc,omitempty"`
	// Setuid lets a setuid binary inside a root-tier run gain its ids and capabilities, by leaving
	// no_new_privs unset (ADR 0033). Refused at tier landlock, where no_new_privs is mandatory; warned at the
	// root tiers, where the agent can then become root.
	Setuid bool `yaml:"setuid,omitempty"`
	// Harness is the agent harness the launcher provisions for (agent-contract.md R27, ADR 0062): read-only files in
	// the run's runtime directory, an argv and TEGO_ environment additions, and a hook-state directory. "" reads as
	// auto, detected from the run's command.
	Harness harness.Name `yaml:"harness,omitempty"`
	// HostSockets lets a run with no net: section reach every unix socket on the host its uid can open, as before
	// ADR 0070: without it such a run reaches only the unix sockets it bound itself and tego's own endpoints
	// (SEMANTICS §1, §5). A net: section decides unix destinations by its own entries and ignores it. Across
	// extends the stricter value wins, so only the top-level contract can open them (agent-contract R19).
	HostSockets bool `yaml:"host_sockets,omitempty"`
	// KeepDescendants keeps a run going after the agent's main process exits for as long as any process the agent
	// started lives, as every run did before 2026-10-26 (runtime-launch.md case 24): for a main that is a launcher
	// daemonizing on purpose. Without it the run gives what is left stop_grace to exit, then kills it and ends
	// with the main process's status. Across extends false is the stricter value, so only the top-level
	// contract can keep descendants.
	KeepDescendants bool `yaml:"keep_descendants,omitempty"`
	// Reason is the reason channel's own keys (ADR 0077): reads says whether a read the Landlock ruleset refuses under
	// deny_read is recorded at tier landlock where the record mode keeps no read.
	Reason *ReasonSection `yaml:"reason,omitempty"`
	// Credentials is the credentials: section, which Compile refuses (agent-contract.md R30).
	Credentials []Credential `yaml:"credentials,omitempty"`
	// Live is live: (ADR 0125): Locked (absent, or mode: locked) or Adjustable with its fence. The top-level
	// contract's alone; compileLive turns an Adjustable fence into allow entries before the fs, net and exec tables.
	Live *LiveSection `yaml:"live,omitempty" json:",omitempty"`

	// Schema-only in P0 (R2).
	Gate       yaml.Node `yaml:"gate,omitempty"`
	Prompt     string    `yaml:"prompt,omitempty"`
	Skills     []string  `yaml:"skills,omitempty"`
	Visibility []string  `yaml:"visibility,omitempty"`
	Docker     yaml.Node `yaml:"docker,omitempty"`
	Containers string    `yaml:"containers,omitempty"`
	Ask        yaml.Node `yaml:"ask,omitempty"`

	// file is the path Load was given; origins maps every decoded field to
	// the file, line and column it came from, across the extends merge.
	file    string
	origins origins
	loaded  bool
	// profiles is every profile the extends walk merged, in merge order, each once (ADR 0066). It is not part of
	// Canonical: contract_hash covers the merged contract, whose entries already hold what each profile gave.
	profiles []ProfileUse
}

// Profiles returns the profiles Load merged into the contract, in merge order (deepest first, an extends list left
// to right), each profile once; nil for a contract that extends nothing. The caller must not modify the slice.
func (c *Contract) Profiles() []ProfileUse { return c.profiles }

// File returns the path the contract was loaded from ("" for a hand-built value).
func (c *Contract) File() string { return c.file }

// Pos returns where a field of the merged contract came from. The key is a
// dotted path such as "fs.write.2", "limits.memory", "env.set.HOME" or
// "mcp.0.command"; after an extends merge an entry may point into a profile.
// ok is false for a field that was never set.
func (c *Contract) Pos(key string) (p Pos, ok bool) {
	p, ok = c.origins[key]
	return p, ok
}

// FSSection is the fs: block.
//
// DenyRead's tri-state is read off the merged contract (R6), the value
// Compile and Canonical both see. After an extends merge the slice is the
// union of the chain (R5), so a file's `deny_read: []` disables the built-in
// list only when no file in the chain declares an entry.
type FSSection struct {
	Write    []string `yaml:"write,omitempty"`
	Ask      []string `yaml:"ask,omitempty"`       // approval scopes (agent-contract R22), never ordinary grants
	DenyRead []string `yaml:"deny_read,omitempty"` // nil = built-in list; []string{} = disabled (warns); populated = entries plus the built-in list
	// AskRead is fs.ask_read (POC 2026-10-06, SEMANTICS §6): literal files or directories whose reads are held
	// for a person, at tier landlock only. Each compiles as a deny_read entry marked FSRule.AskRead, so every
	// mechanism that does not hold a read refuses it as it refuses any deny_read.
	AskRead []string `yaml:"ask_read,omitempty"`
	Watch   []string `yaml:"watch,omitempty"`
	// DenyWrite is fs.deny_write (ADR 0071): literal files or directories beneath a write entry whose every
	// modification is refused, as the built-in deny_write set's targets are (R20), each compiled into
	// RuleTable.DenyWrite with BuiltIn false. A union across extends; nil and [] both add nothing, and neither
	// removes the built-in set.
	DenyWrite []string `yaml:"deny_write,omitempty"`
	// Assurance is fs.assurance (agent-contract R20, ADR 0041 D1 (a)): how the built-in deny_write set must be
	// enforced where no kernel decision plane decides the run. "" reads as best-effort.
	Assurance FSAssurance `yaml:"assurance,omitempty"`
	// Reads is fs.reads (ADR 0069): whether the open deputy completes the run's read opens so that a deny_read
	// inside a write entry, and a file a deny_read name rule covers that was made during the run, is refused at
	// tier landlock. "" reads as auto.
	Reads ReadsMode `yaml:"reads,omitempty"`
	// AppArmorAssumeRootNamespace is an administrator's assertion used only when
	// AppArmor's policy namespace depth is unreadable. It accepts the risk of
	// hidden ancestor restrictions; labels are still compared. Default false.
	AppArmorAssumeRootNamespace bool `yaml:"apparmor_assume_root_namespace,omitempty" json:",omitempty"`
}

// MarshalYAML keeps the explicit `deny_read: []` in Canonical. The omitempty
// tag drops an empty slice, which made `fs: {deny_read: []}` serialize, and
// hash, exactly like `fs: {}` while the two compile to different deny sets
// (R6): contract_hash could not tell the credential list had been switched
// off, and internal/ledger's contract.yaml recompiled with it back on (R13).
// Every other shape encodes as the tags say.
//
// The empty form is FSSection's own encoding with one sequence emptied, never
// a second list of its fields: a copy of the field list would have to be kept
// in step by hand, and a field added to FSSection but not to the copy would
// vanish from contract_hash exactly when deny_read is [] (R13 hashes every
// schema field).
//
// It is that encoding re-parsed: yaml.v3 encodes into a Node by emitting text
// and parsing it back, and a "<<" scalar comes back tagged !!merge, which
// would be written `!!merge <<` — a tag Load refuses, so the run's
// contract.yaml would not load back (R13). untagMerge turns every such scalar
// back into the string it was encoded from, which the encoder then quotes.
func (s FSSection) MarshalYAML() (any, error) {
	type plain FSSection // same fields and tags without this method, so encoding it cannot recurse
	if s.DenyRead == nil || len(s.DenyRead) > 0 {
		return plain(s), nil
	}
	// One placeholder entry is what keeps omitempty from dropping the key, at the place the
	// struct gives it; the sequence is then emptied, so the placeholder never reaches the output.
	p := plain(s)
	p.DenyRead = []string{""}
	var n yaml.Node
	if err := n.Encode(p); err != nil {
		return nil, err
	}
	untagMerge(&n)
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == fsDenyReadKey {
			n.Content[i+1].Content = nil
			n.Content[i+1].Style = yaml.FlowStyle
			return &n, nil
		}
	}
	return nil, fmt.Errorf("agent: fs.%s is missing from its own encoding", fsDenyReadKey)
}

// untagMerge resets every scalar the re-parse tagged !!merge to !!str. Every scalar in these sections
// was encoded from a Go string, so !!str is what it was; the encoder then quotes "<<" instead of writing
// the `!!merge` tag that Load refuses.
func untagMerge(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!merge" {
		n.Tag, n.Style = "!!str", 0
	}
	for _, c := range n.Content {
		untagMerge(c)
	}
}

// fsDenyReadKey is DenyRead's yaml key, read off the struct tag so the two
// cannot disagree.
var fsDenyReadKey = func() string {
	f, _ := reflect.TypeFor[FSSection]().FieldByName("DenyRead")
	key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	return key
}()

// NetSection is the net: block. Allow entries are kept as their raw scalar
// (bare destinations, tcp://, udp:// and unix:) and validated
// with ParseEndpoint at Load; Compile turns them into NetRules.
type NetSection struct {
	Assurance NetAssurance   `yaml:"assurance,omitempty"`
	Allow     []string       `yaml:"allow,omitempty"`
	Ask       []string       `yaml:"ask,omitempty"`  // approval candidates, never ordinary destination grants
	HTTP      []HTTPRule     `yaml:"http,omitempty"` // declared forwarder request policy
	Listen    []string       `yaml:"listen,omitempty"`
	Ingress   []IngressRule  `yaml:"ingress,omitempty"`
	Limits    *NetworkLimits `yaml:"limits,omitempty"`
	DNS       *DNSPolicy     `yaml:"dns,omitempty"`
	Proxy     *ProxyPolicy   `yaml:"proxy,omitempty"`
}

// HTTPRule is one allow-union entry for a declared model forwarder listener.
type HTTPRule struct {
	Host    string   `yaml:"host,omitempty"`
	Allow   []string `yaml:"allow,omitempty"`
	Methods []string `yaml:"methods,omitempty"`
}

// ExecSection is the exec: block.
//
// Its mode is decided by which keys are present, never by whether a list is empty (ADR 0048 (1)): an allow key,
// even `allow: []`, restricts images; no allow key with a deny or ask key, even empty, is deny-list mode, where
// images are unrestricted and only the command rules apply; neither key restricts images. Load keeps a present
// empty list non-nil, extends keeps it non-nil, and MarshalYAML keeps it in Canonical where dropping it would
// change the mode.
type ExecSection struct {
	// Allow entries are paths or PATH basenames (images), or command patterns: a command word and the words after
	// it, which constrain that tool's argv (`git status`).
	Allow []string `yaml:"allow,omitempty"`
	// Deny entries are command patterns that never run, at any specificity (`git push`, `rm -r`).
	Deny []string `yaml:"deny,omitempty"`
	// Ask entries are reserved: every match is refused at every tier until ADR 0044 gives a list floor a
	// completion (ADR 0048 (5)).
	Ask        []string `yaml:"ask,omitempty"`
	Privileged []string `yaml:"privileged,omitempty"` // schema-only in P0
	// Anonymous lets the run exec anonymous images (a memfd, another anon_inode). Tiers 1 and 2 otherwise
	// refuse the creation of an exec-capable memfd at the seccomp filter — where the kernel honours
	// MFD_NOEXEC_SEAL (upstream 6.3 and later, or a backport such as RHEL 9.8's 5.14; a probe decides) a
	// memfd_create without it or with MFD_HUGETLB, elsewhere every memfd_create — the only race-free
	// closure below tier 3 (SEMANTICS §4). Setting it true drops that refusal and gives up the
	// closure: it is on record in the run's contract copy and its contract_hash, compile warns about it, the
	// run's capability line reports exec.deny false at tier 1 (at tier 2 only once the cgroup
	// Handle.Capabilities narrows the row by the inherited tier-1 handle's, which it does not yet), and every
	// anonymous exec is still recorded fileless.
	Anonymous bool `yaml:"anonymous,omitempty"`
	// Assurance is exec.assurance (ADR 0048 (3) P2): kernel refuses the run before its child starts unless the kernel
	// holds every exec to the facts that were decided (ExecAssurance).
	Assurance ExecAssurance `yaml:"assurance,omitempty"`
}

// DenyList reports whether the section is in deny-list mode: no allow key, and a deny or ask key, even empty. Images
// are then unrestricted and only the command rules apply (ADR 0048 (1)). A nil section is not.
func (s *ExecSection) DenyList() bool {
	return s != nil && s.Allow == nil && (s.Deny != nil || s.Ask != nil)
}

// MarshalYAML keeps the mode of an exec: section in Canonical (ADR 0048 (1)). omitempty drops an empty list, so
// `exec: {allow: [], deny: [git push]}` (images restricted) would serialize like `exec: {deny: [git push]}`
// (deny-list), and `exec: {deny: []}` (deny-list) like `exec: {}` (restricted): the run's contract.yaml would
// recompile to the other mode (R13). It emits `allow: []` when the section restricts images, Allow is empty and
// deny or ask has entries, and `deny: []` when the section is a deny-list with no deny or ask entry. Every other
// section encodes as the tags say, so every contract written before ADR 0048 keeps its bytes and its contract_hash.
func (s ExecSection) MarshalYAML() (any, error) {
	type plain ExecSection // same fields and tags without this method, so encoding it cannot recurse
	var key string
	p := plain(s)
	switch {
	case s.Allow != nil && len(s.Allow) == 0 && len(s.Deny)+len(s.Ask) > 0:
		key, p.Allow = execAllowKey, []string{""}
	case s.DenyList() && len(s.Deny)+len(s.Ask) == 0:
		key, p.Deny, p.Ask = execDenyKey, []string{""}, nil
	default:
		return plain(s), nil
	}
	// One placeholder entry keeps omitempty from dropping the key at its place; the sequence is then emptied.
	var n yaml.Node
	if err := n.Encode(p); err != nil {
		return nil, err
	}
	untagMerge(&n)
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1].Content = nil
			n.Content[i+1].Style = yaml.FlowStyle
			return &n, nil
		}
	}
	return nil, fmt.Errorf("agent: exec.%s is missing from its own encoding", key)
}

// exec.allow's and exec.deny's YAML keys.
const (
	execAllowKey = "allow"
	execDenyKey  = "deny"
)

// ExecUnrestricted reports whether the contract restricts no image: it has no exec: section (SEMANTICS §1, "deny
// nothing"), or its section is a deny-list (ADR 0048 (1)). A nil contract does not: a hand-built table fails closed.
// It is the one spelling of the mode bit every enforcer reads (RuleTable.ExecUnrestricted).
func (c *Contract) ExecUnrestricted() bool {
	return c != nil && (c.Exec == nil || c.Exec.DenyList())
}

// ExecModeSource names the file whose key set the exec: section's mode (ADR 0048 (1)): the file that wrote the
// allow key of a restricted section, the deny or ask key of a deny-list, or the exec key itself; "" for no section or
// a hand-built contract. Compile prints it on the mode's line.
func (c *Contract) ExecModeSource() (file, key string) {
	if c == nil || c.Exec == nil {
		return "", ""
	}
	try := func(k string) (string, bool) {
		if p, ok := c.origins["exec."+k]; ok {
			return p.File, true
		}
		if p, ok := c.origins["exec."+k+".0"]; ok {
			return p.File, true
		}
		return "", false
	}
	switch {
	case c.Exec.Allow != nil:
		if f, ok := try(execAllowKey); ok {
			return f, execAllowKey
		}
	case c.Exec.DenyList():
		for _, k := range []string{execDenyKey, "ask"} {
			if f, ok := try(k); ok {
				return f, k
			}
		}
	}
	if p, ok := c.origins["exec"]; ok {
		return p.File, "exec"
	}
	return c.file, "exec"
}

// ExecAnonymous reports whether the contract set exec.anonymous: true (SEMANTICS §4).
func (c *Contract) ExecAnonymous() bool {
	return c != nil && c.Exec != nil && c.Exec.Anonymous
}

// EnvSection is the env: block.
type EnvSection struct {
	Pass []string          `yaml:"pass,omitempty"`
	Deny []string          `yaml:"deny,omitempty"`
	Mask []string          `yaml:"mask,omitempty"` // schema-only in P0 (R17)
	Set  map[string]string `yaml:"set,omitempty"`
}

// MarshalYAML keeps an explicit `pass: []` in Canonical, for the reason FSSection keeps `deny_read: []`:
// omitempty drops the empty slice, so `env: {pass: []}` (pass nothing) serialized and hashed like no env:
// section (inherit everything), and the run's contract.yaml recompiled to the opposite environment (R13).
func (s EnvSection) MarshalYAML() (any, error) {
	type plain EnvSection // same fields and tags without this method, so encoding it cannot recurse
	if s.Pass == nil || len(s.Pass) > 0 {
		return plain(s), nil
	}
	p := plain(s)
	p.Pass = []string{""} // keeps omitempty from dropping the key at its place; emptied below
	var n yaml.Node
	if err := n.Encode(p); err != nil {
		return nil, err
	}
	untagMerge(&n)
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == envPassKey {
			n.Content[i+1].Content = nil
			n.Content[i+1].Style = yaml.FlowStyle
			return &n, nil
		}
	}
	return nil, fmt.Errorf("agent: env.%s is missing from its own encoding", envPassKey)
}

// IsZero tells yaml.v3's omitempty that an env: section holding `pass: []` is not empty: Env is a value in
// Contract, and omitempty took a section whose only field was an empty slice for a missing section.
func (s EnvSection) IsZero() bool {
	return s.Pass == nil && len(s.Deny) == 0 && len(s.Mask) == 0 && len(s.Set) == 0
}

// envPassKey is env.pass's YAML key.
const envPassKey = "pass"

// MCPServer is one mcp: entry: a stdio server the agent launches, whose command gets exec rights implicitly (R8),
// or an HTTP server it connects to, whose URL's host and port get a net rule implicitly under a net: section (R16a).
// Exactly one of Command and URL is set.
type MCPServer struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command,omitempty"`
	URL     string   `yaml:"url,omitempty"`
	// Tools puts the server behind Tego's MCP relay with per-tool rules (agent-contract.md R16b, ADR 0126); nil is
	// today's behaviour, no relay.
	Tools *MCPTools `yaml:"tools,omitempty"`
}

// ModelEndpoint is one models: entry, the upstream a capture source may proxy.
type ModelEndpoint struct {
	Provider string `yaml:"provider"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	// Routes are the other backends a person may send this endpoint's requests to while a run lives (R32,
	// ADR 0127, model_routes.go); none keeps the forwarder exactly as it was.
	Routes []ModelRoute `yaml:"routes,omitempty"`
}

// Limits are the contract's budgets. Every field nil means "inherit the
// machine ceiling unchanged" (R11).
type Limits struct {
	CPU        *CPUCores `yaml:"cpu,omitempty"`         // cores, cgroup cpu.max numerator
	CPUWeight  *int      `yaml:"cpu_weight,omitempty"`  // 1..10000, cgroup cpu.weight
	Memory     *ByteSize `yaml:"memory,omitempty"`      // cgroup memory.max
	MemoryHigh *ByteSize `yaml:"memory_high,omitempty"` // cgroup memory.high
	Pids       *int      `yaml:"pids,omitempty"`
	Tokens     *int64    `yaml:"tokens,omitempty"`
	CostUSD    *float64  `yaml:"cost_usd,omitempty"`
	Wall       *Duration `yaml:"wall,omitempty"`
	StallAfter *Duration `yaml:"stall_after,omitempty"`
	Repeats    *int      `yaml:"repeats,omitempty"`
}

// RecordMode is what the ledger keeps; enforcement is unaffected.
type RecordMode string

// Record modes.
const (
	RecordFull    RecordMode = "full"
	RecordSummary RecordMode = "summary"
	RecordOff     RecordMode = "off"
)

// TierPin is the contract's tier request; "" and "auto" mean the highest
// tier at or below the machine ceiling. A resolved tier is a backend.Tier.
type TierPin string

// CaptureMode selects the model-traffic capture source.
type CaptureMode string

// Capture modes, ordered off < forwarder < uprobe for ceiling comparisons.
const (
	CaptureAuto      CaptureMode = "auto"
	CaptureUprobe    CaptureMode = "uprobe"
	CaptureForwarder CaptureMode = "forwarder"
	CaptureOff       CaptureMode = "off"
)

// Rank orders capture modes for ceiling comparisons; auto ranks highest.
func (m CaptureMode) Rank() int {
	switch m {
	case CaptureOff:
		return 0
	case CaptureForwarder:
		return 1
	case CaptureUprobe:
		return 2
	case CaptureAuto, "":
		return 3
	}
	return -1
}

// Pos is a position in a source file. Col is 0 when unknown.
type Pos struct {
	File string
	Line int
	Col  int
}

// RuleTable is the compiled, immutable, backend-neutral form of a contract.
// It is never mutated after Compile returns it (I4); a TTL refresh builds a
// new table.
type RuleTable struct {
	Builtins *BuiltinRefusals // immutable ADR 0113 boundary; nil only for synthetic tables

	NetAssurance NetAssurance // effective assurance; never empty after Compile
	FSAssurance  FSAssurance  // effective fs.assurance (FilesystemAssurance); never empty after Compile

	// ExecAssurance is the effective exec.assurance (ExecutionAssurance); never empty after Compile.
	ExecAssurance ExecAssurance

	Listen       []ListenRule
	Ingress      []IngressRuleCompiled
	NetLimits    NetworkLimits
	DNS          DNSPolicy
	DNSQueries   *dnspolicy.Policy
	Proxy        *CompiledProxyPolicy
	AskConfig    *AskConfig
	Gate         *gate.Policy // immutable supervisor escalation program
	Workdir      string       // captured, resolved compile worktree for gate facts
	FS           []FSRule
	FSAsk        []FSRule // approval scope, never an ordinary filesystem grant
	AskDenyWrite []FSRule // protected configuration under approval scope
	Net          []NetRule
	NetAsk       []NetRule          // approval candidates, never installed as ordinary allow grants
	HTTP         *httppolicy.Policy // immutable policy bound to declared model authorities
	Exec         []ExecRule
	// ExecCommands are the exec command rules (ADR 0048 (4)): exec.deny, exec.ask and the allow entries with words,
	// indexed by tool. nil when the contract names none.
	ExecCommands *ExecCommands
	Env          []string          // final pass-list, runtime-reserved names removed; nil = no env.pass (inherit all)
	Deny         []string          // env.deny as declared
	Set          map[string]string // final env.set after conflict checks
	Limits       ResolvedLimits    // clamped to the machine ceilings; ask Limits.Bounded, not the value
	Record       RecordMode        // never ""
	Tier         backend.Tier      // never ""; resolved, not a TierPin
	// Reach is every tier a run of this table can be given, lowest first (ADR 0019): the pinned tier alone
	// when the contract or the machine config pins one, since a pin is refused rather than lowered
	// (backend.Select); for a contract that leaves its tier to the machine, every tier at or below Tier the
	// binary builds (WithTiers). compile --test answers in each, and Compile reports a finding that holds in
	// one tier alone (Diagnostic.Tier) when that tier is here. Never empty.
	Reach   []backend.Tier
	Capture CaptureMode // never ""
	Hash    [32]byte    // contract_hash = sha256(Contract.Canonical())
	// Home is the directory "~" expanded to when this table was compiled, so a compile --test row
	// written with ~ is evaluated against the same path the contract's own entries were.
	Home string
	// Harness is the contract's harness: with auto resolved from the contract's own command (harness.Name.Resolve);
	// it stays auto for a contract with no command, and the launcher resolves it from the command it runs.
	Harness harness.Name

	// Contract is the merged contract the table was compiled from, kept for
	// consumers that need the declared form (the ledger's contract.yaml).
	Contract *Contract
	// Profiles are the profiles the contract merged through extends, in merge order, each once (Contract.Profiles,
	// ADR 0066): run_start records them. nil when the contract extends none.
	Profiles []ProfileUse
	// ContractPath is the absolute path of the contract file, one of the
	// implicit FS entries (R9).
	ContractPath string
	// PATH is the run's effective PATH the exec entries were resolved on.
	PATH string
	// RunCommandGrant is the absolute path of the exec rule the command given on tego run's command line
	// added (WithRunCommand), "" when none was given or it added no rule (a declared entry already covers it,
	// or it resolves nowhere). The contract hash does not include it, so run_start records it
	// (run_command_grant) for drift and every later reader (R8).
	RunCommandGrant string
	// HarnessHook is the exact argv of the harness hook the runtime granted on its own authority (WithHarnessHook,
	// ADR 0064), nil when it granted none. Compile never sets it; run_start records the grant (runtime_grants,
	// harness.hook).
	HarnessHook []string
	// DeniedResolved is the machine config's denied_resolved_addresses: ranges no host entry admits by
	// name, on top of the built-in classes (ResolvedDenied, R18).
	DeniedResolved []netip.Prefix
	// DenyWrite is the built-in deny_write set (R20): the self-modifying configuration beneath a write
	// entry that runs code outside the run (git hooks and config, harness config, shell startup files).
	// It is kept apart from FS because no ruleset can refuse a write beneath a write entry: Landlock unions
	// the entry's rights over the whole subtree. A kernel decision plane (cgroup with lsm/fmod_ret, or bpflsm)
	// refuses a write to one race-free; below one the supervisor refuses it best effort (R15c), or, under
	// fs.assurance: kernel (DenyWriteNeedsPlane), the run is refused before its child starts (ADR 0041 D1 (a)).
	// Evaluate, the supervisor and the kernel plane read the same targets from here.
	DenyWrite []FSRule
	// DenyWriteLinked is the regular files beneath an fs.deny_write directory entry (and outside every write entry
	// that reopens part of it) or a built-in directory target with another hard link when compile ran (ADR 0071 (6)):
	// the plane keys each at its inode, so a write through the other name, made before the run, meets
	// the entry's refusal, where its walk from that name's directory would reach only the write entry. It holds one
	// name per file, and none for a file whose every name lies beneath such a place or whose inode another row the
	// plane keys refuses modifying (the plane keys one fs row per inode). Below a plane no tier sees
	// the other name.
	DenyWriteLinked []string
	// NameDeny is the table's name entries (ADR 0043): the built-in .env list's and each whole deny_read glob's
	// whose final component is a literal or a literal prefix, beside the compile-time expansion in FS. Its order
	// decides and names between entries that cover one file: declared entries in declared order, then the
	// built-in exact entry, then the built-in prefix entry. Compile output, not contract input: contract_hash is
	// unaffected. Empty when no run of the table can land at a tier that applies them (tier landlock).
	NameDeny []NameDenyRule
	// NameExempt is ADR 0043 D3's exemptions: a top-level write entry at an existing file a name entry covers.
	NameExempt []NameExemptRule
	// NameLeftOut is every name-eligible entry the caps or a key collision left out of NameDeny (FitNameEntries; ADR
	// 0043 Terms), each with compile's unenforced warning: it keeps its compile-time expansion only, so a file created
	// later at a name it matches is not refused, and the run's fs.deny_read.created_later reads false (D7,
	// NameEntriesWhole). Compile output, not contract input.
	NameLeftOut []NameLeftOut
	// Reads is fs.reads as compiled (ADR 0069): the effective value, the deny_read targets that lie at or beneath
	// a write entry, and the name rules a held read is refused by (ReadsHeldAt). Compile output beside the
	// contract's key.
	Reads HeldReads
	// ReasonReads is reason.reads as compiled (ADR 0077): the effective value, never "" after Compile. ReasonReadsAt
	// says where it notifies every read open.
	ReasonReads ReasonReadsMode
	// OwnState is tego's own state as compile resolved it (POC 2026-10-06): the ledger root, the chain anchor and its
	// directory (the anchor itself added 2026-10-20, review RS7-1: a link leads out of the directory), ~/.tego, the
	// host state (/run/tego), tego's runtime parent ($XDG_RUNTIME_DIR/tego, WithRuntimeDir, added 2026-10-16), the
	// machine config's price table and profiles directory, and the contract file's directory, each as written and
	// where its walk lands (a final link leading nowhere yet followed), whether or not R6a could deny it. No
	// fs.ask_read entry may lie at or beneath one, a held read never completes on a file beneath one, and an
	// alternate a person names for a held open is refused there. Compile output, not contract input.
	OwnState []string
	// OwnReadable is tego's own state a run may read but never write (added 2026-10-20): the user
	// registry's agents/ and skills/ (agent-contract.md R26) and the machine config's layer files (config.Machine.Layers,
	// ADR 0059), as written and resolved. They are not read-denied, so an
	// fs.ask_read entry beneath them compiles and a held read there is asked like any other; R10 keeps every write
	// entry and fs.ask scope off them, and a person's alternate for a held write is refused there. Compile output,
	// not contract input.
	OwnReadable []string
	// DenyReadPatterns is what the alternate guard refuses beyond the fs rows (ADR 0057 D2): every whole declared
	// deny_read glob, and every path of the built-in deny_read list under the home directory, each as written and
	// by its resolved spelling, whether or not it matched a file when the table compiled and whatever deny_read
	// says (the rows cover only the files that existed). DenyReadPatternOf matches a path against them. Compile
	// output, not contract input: contract_hash is unaffected.
	DenyReadPatterns []DenyReadPattern
	// AbsentDenyRead is every row of the built-in deny_read list under the home directory that did not exist when the
	// table compiled, less one a write or exec.allow directory entry covers (ADR 0067 D3), each with the name the
	// Landlock ruleset leaves out for it (AbsentRow.At): the ruleset holds the directory that name lies in and
	// enumerates it with the name left out, so a file created at the row during the run (a login in another terminal)
	// gets no grant and its direct read is refused. Only the Landlock backend installs it, at tier landlock and in the
	// tier-1 ruleset tiers cgroup and bpflsm compose: no FS rule is made for a name that does not exist, since a plane
	// row keys an inode and a fanotify mark a mount. The tier models read it too (internal/policy/decide AbsentRead),
	// so Evaluate, the print and the ledger answer refused, named by the row, for the read the ruleset refuses. Compile
	// output, not contract input: contract_hash is unaffected.
	AbsentDenyRead []AbsentRow
	// AskReadRelaxes is every built-in deny_read entry an fs.ask_read entry of the top-level contract relaxes, a
	// refused read becoming one held for a person (ADR 0057 D4): the run_start line names each (ask_read_relaxes),
	// so the record says the built-in protection was relaxed and by which entry, and compile warns. Compile output,
	// not contract input.
	AskReadRelaxes []AskReadRelax
	// Live is the fence an Adjustable contract compiled (ADR 0125), which the launcher seeds its live refusals from;
	// nil for Locked, so a contract with no live: key compiles to the table it always did.
	Live *LiveTable `json:",omitempty"`
}

// NotifiesReads reports whether the table has the seccomp filter notify every read-open at tier landlock: a read gate
// scores each read and an fs.ask_read entry holds the ones it decides, at every tier and in an --observe run too, and
// reason reads (ReasonReadsAt, ADR 0077) record a read the Landlock ruleset refuses, at tier landlock alone (the
// landlock filter's gateRead arm). Each such open is then answered by the supervisor, which is activity under record:
// off (stall-reads-unseen).
func (rt *RuleTable) NotifiesReads() bool {
	return rt.notifiesReadsEverywhere() || rt.ReasonReadsAt(backend.TierLandlock)
}

// notifiesReadsEverywhere is the part of NotifiesReads that holds in an --observe run too.
func (rt *RuleTable) notifiesReadsEverywhere() bool {
	return rt.Gate.Has(gate.FSRead) || rt.HasAskRead()
}

// HoldsFSNotifications reports whether the table has an fs gate or an fs ask entry (fs.ask, fs.ask_read), which keeps
// every fs notification with the supervisor at every tier: a decision plane then decides none of them in the kernel
// (ADR 0024 (14); the landlock backend's planeSkips), so every write-open and path change is answered by the supervisor
// there too.
//
// An Adjustable table holds them too (ADR 0125 decision 6): its live layer refuses fence entries the kernel layers
// allow, so nothing a fence entry covers may be decided where Tego cannot see it.
func (rt *RuleTable) HoldsFSNotifications() bool {
	if rt.Adjustable() || rt.Gate.Has(gate.FSRead) || rt.Gate.Has(gate.FSWrite) || len(rt.FSAsk) != 0 || rt.HasAskRead() {
		return true
	}
	for i := range rt.FS {
		if rt.FS[i].Kind == FSAsk {
			return true
		}
	}
	return false
}

// AskReadRelax is one built-in deny_read entry an fs.ask_read entry relaxes (RuleTable.AskReadRelaxes).
type AskReadRelax struct {
	// Rule is the fs.ask_read entry's rule name, fs.ask_read[<entry>].
	Rule string
	// BuiltIn is the built-in deny_read entry's path.
	BuiltIn string
	// How is AskReadReplaces (the entry is at the built-in's path, which it replaces) or AskReadInside (it lies
	// beneath the built-in entry, which still refuses the rest of its tree).
	How string
}

// The two ways an fs.ask_read entry relaxes a built-in deny_read entry (AskReadRelax.How).
const (
	AskReadReplaces = "replaces"
	AskReadInside   = "inside"
)

// FSKind classifies an FSRule.
type FSKind string

// FS rule kinds.
const (
	FSWrite    FSKind = "write"
	FSAsk      FSKind = "ask" // an fs.ask scope, in RuleTable.FSAsk only (agent-contract R22)
	FSDenyRead FSKind = "deny_read"
	FSWatch    FSKind = "watch"
	FSImplicit FSKind = "implicit"
	// FSDenyWrite marks an entry of RuleTable.DenyWrite; it never appears in RuleTable.FS (R20).
	FSDenyWrite FSKind = "deny_write"
)

// FSRule is one filesystem entry, resolved to an absolute path.
type FSRule struct {
	BuiltinRule string `json:",omitempty"` // immutable ADR 0113 rule name, independent of contract spelling

	Path   string
	Kind   FSKind
	Access AccessSet // rights the entry grants; 0 for deny_read, watch and implicit entries
	Raw    string    // the declared entry, "" for implicit and built-in entries
	Pos    Pos       // where it was declared; zero for implicit and built-in entries

	// Resolved is Path with every symlink followed: the subtree the rule
	// actually governs. The run opens each entry O_PATH without O_NOFOLLOW,
	// which pins the link's target rather than the link (E8), so a symlinked
	// entry governs its target — and every containment question (does this
	// write entry swallow the run directory? does it shadow a deny_read?)
	// must be asked of Resolved, never of the name the author typed. Equal to
	// Path whenever no component is a symlink, which is the ordinary case;
	// for an entry that does not exist yet it is the resolved parent plus the
	// declared final component.
	Resolved string

	// Mount metadata for `compile`'s print (SEMANTICS §2 "Identity").
	Mount        string
	Filesystem   string
	Device       uint64
	IsMountPoint bool
	Overlay      bool
	Btrfs        bool
	// Missing is true for a write directory that does not exist yet; run creates it (R7).
	Missing bool
	// Unenforced is set on a deny_read entry that a write entry shadows in the
	// Landlock tier (SEMANTICS §2); the root tiers still enforce it. Every
	// deny_write entry carries it: each lies beneath a write entry, where
	// Landlock cannot deny, and only the supervisor's best-effort refusal
	// stands before tier 3 (R20).
	Unenforced bool
	// BuiltIn marks an entry of the built-in deny_read list or deny_write set.
	BuiltIn bool
	// AskRead marks a deny_read entry compiled from fs.ask_read (POC 2026-10-06, SEMANTICS §6). It is a deny_read
	// in every respect (the Landlock ruleset withholds its read rights, Evaluate refuses a read beneath it), and its
	// rule is named fs.ask_read[...]; only tier 1's supervisor reads the marker, to hold a read-open of a regular
	// file it decides for a person instead of letting the kernel refuse it.
	AskRead bool

	// What compile saw of the governed object, the facts ADR 0043 D6 lets the plane drop a covered file's row on
	// (decide.CompilePlane): Regular is a regular file by its Lstat, Nlink its link count, FileMountPoint a file
	// that is itself a mount point (a file bind-mounted over it; IsMountPoint keeps its directory-only meaning),
	// and DirCaseExact that compile read its directory's inode flags and found no FS_CASEFOLD_FL (gathered only
	// where the plane could compact, compactionFacts). Unknown reads as false, which keeps the row.
	Regular        bool
	Nlink          uint64
	FileMountPoint bool
	DirCaseExact   bool

	// Runtime names the kind of grant when the runtime added this entry on its own authority rather than reading it
	// from a contract: CodexHomeGrant for the run's own generated CODEX_HOME (capture-derive.md R19b), or
	// HarnessStateGrant for a provisioned harness's hook-state directory (agent-contract.md R10a (4)), which no
	// entry can name because its path holds the run id. It changes the rule name (RuleName) and is what
	// IsRuntimeRule recognises. "" is the ordinary case.
	Runtime string
	// RuntimeDev and RuntimeIno are, for a Runtime grant, the device and inode of the directory the runtime made
	// (agent-contract.md R10a): a backend that opens Path to grant it must reach exactly that directory or refuse,
	// so a link swapped in for it, or for a directory above it, between the grant and Prepare moves nothing. Both 0
	// for an entry with no such identity.
	RuntimeDev, RuntimeIno uint64
	// Fence marks an entry an Adjustable contract's live.fence added (ADR 0125): its rule name is the fence entry's,
	// live.fence[<kind>:<value>], so the record never says the contract allowed what only a lifted entry allows.
	Fence bool `json:",omitempty"`
}

// NetRule is one compiled net.allow entry.
type NetRule struct {
	Raw     string
	Host    string
	Port    int
	Proto   string // tcp | udp | unix
	Verdict Verdict
	IPs     []netip.Addr
	CIDR    *netip.Prefix
	// Unix socket entries.
	UnixPath string
	Abstract bool
	// UnixResolved is a pathname unix entry's place, UnixPath (the declared path made absolute and cleaned
	// lexically, as every contract path is) resolved at compile by ResolveUnixPlace, the resolution the run makes of
	// it too: walked one name at a time, every symlink followed, one whose target the run makes later included, the
	// names that do not exist yet kept, a ".." in a link's target applied after the symlink before it as the kernel's
	// lookup applies it (supervisor R11, R11c); UnixPath itself when it cannot be placed. It is the socket a landed
	// pathname is matched against (Action.Landed; the supervisor's decideResolved) and the place a net.ask unix:
	// scope is asked at. "" for an abstract name, an entry not resolved and in a hand-built table, where UnixPath
	// stands for it.
	UnixResolved string
	// Static is true for a literal IP, CIDR or unix entry: never re-resolved.
	Static bool
	// Denied are addresses the entry's name resolved to at compile that it may not admit (R18,
	// ResolvedDenied): dropped from IPs, kept here so a refusal can name the entry. In-memory only.
	Denied []netip.Addr
	// PublicAnswer is true for a host entry whose compile-time answer, once Denied was dropped, held at
	// least one address and only public ones (R18): a later answer's private address is then refused
	// (ResolvedDenied). In-memory only.
	PublicAnswer bool
	// Runtime names the kind of grant when the runtime added this entry on its own authority rather
	// than reading it from a contract: "capture" for the loopback listener a capture source bound.
	// It changes the rule name (RuleName) so the ledger says where the destination came from, and it
	// is what IsRuntimeRule recognises. "" is the ordinary case, a declared entry.
	Runtime string
	// MCP names the mcp[] HTTP server whose URL this entry was derived from (agent-contract.md R16a), "" for every
	// other entry. The rule then carries the server's name, mcp[<name>], the name the record gives that
	// declaration (RuleName).
	MCP string
	// ResolvedAt and TTL are in-memory only, never serialized (E23).
	ResolvedAt time.Time
	TTL        time.Duration
	// ExpiresAt is an optional runtime deadline for a refreshed hostname grant.
	// Static and runtime-authority grants do not expire through DNS policy.
	ExpiresAt time.Time
	Pos       Pos
	// Fence marks an entry an Adjustable contract's live.fence added (FSRule.Fence).
	Fence bool `json:",omitempty"`
}

// ExecRule is one binary the run may execute.
type ExecRule struct {
	Raw  string // the declared entry; "" for implicit grants
	Path string // resolved absolute path
	// Resolved is Path with every symlink followed, as FSRule.Resolved is: the file (or subtree) the grant
	// lands on. Path keeps the spelling the entry resolved to on PATH or as declared, which may pass through a
	// link (/bin/sh, a linked bin directory); tier 1's supervisor and tier 2's listener admit both, so
	// Evaluate matches both (R15). Equal to Path when nothing is a link; "" in a
	// hand-built table.
	Resolved string
	Basename string
	// ByName is true when some declared spelling of this entry was a bare
	// command name rather than a path, which is what earns tier 3's
	// name match (SEMANTICS §4: "a basename matches the final component of the
	// file's dentry after symlink resolution"; the Landlock tier "cannot match
	// by name" at all).
	//
	// Raw cannot answer this: two entries that resolve to the same file
	// collapse into one rule keeping the *first* spelling (compile_exec.go
	// add), so a command declared by path swallowed the `exec.allow: [python]`
	// beside it and silently withdrew the name match the author asked for.
	ByName  bool
	Interp  string // PT_INTERP target; "" for static or non-ELF
	Verdict Verdict
	// Source says why the rule exists: "exec.allow", "command", "mcp:<name>", "interpreter:<script>",
	// "helper:<tool>"; comma-joined when entries of several sources resolved to one path.
	Source string
	// IsDir marks an exec.allow entry naming a directory (EXECUTE beneath it).
	IsDir bool
	Pos   Pos
	// Runtime names the kind of grant when the runtime added this rule on its own authority rather than compiling it
	// from a contract: HarnessHookGrant for the harness hook's binary (WithHarnessHook, ADR 0064). It changes the
	// rule name (RuleName) and is what IsRuntimeRule recognises. "" is the ordinary case.
	Runtime string
	// Fence marks a rule an Adjustable contract's live.fence added, or one only a fence entry's taking out of an
	// exec.deny entry lets run (FSRule.Fence).
	Fence bool `json:",omitempty"`
	// FenceEntry is, on a Fence rule whose Path is not the fence entry's own (a helper image the entry's tool
	// re-executes, such as git's exec-path git, ADR 0048 (2)), that entry's value: the rule is named after it
	// (RuleName), and LiveEntry.Images lists the image. "" on every other rule.
	FenceEntry string `json:",omitempty"`
}

// Verdict is a compiled decision.
type Verdict string

// Verdicts.
const (
	VerdictAllow   Verdict = "allow"
	VerdictAsk     Verdict = "ask"
	VerdictRefused Verdict = "refused"
)

// BudgetSet names limit dimensions as bits, so ResolvedLimits can say which
// ones were actually asked for.
type BudgetSet uint16

// One bit per dimension of ResolvedLimits.
const (
	BudgetCPU BudgetSet = 1 << iota
	BudgetCPUWeight
	BudgetMemory
	BudgetMemoryHigh
	BudgetPids
	BudgetTokens
	BudgetCostUSD
	BudgetWall
	BudgetStallAfter
	BudgetRepeats
)

// ResolvedLimits has every field set after ceilings are applied (R11). Set
// records which dimensions a budget was actually asked for, by the contract or
// by a machine ceiling: without it a resolved 0 is indistinguishable from "no
// one asked", and every consumer reads the tightest possible budget as no
// budget at all (limits-check-doctor-cli.md E16). Ask Bounded, never the value.
type ResolvedLimits struct {
	CPU        string
	CPUWeight  int
	MemoryB    int64
	MemoryHigh int64
	Pids       int
	Tokens     int64
	CostUSD    float64
	Wall       time.Duration
	StallAfter time.Duration
	Repeats    int
	Set        BudgetSet
}

// Bounded reports whether dimension k carries a budget. k names one dimension.
//
// A positive value counts as a budget even with the bit clear, so a
// ResolvedLimits built by hand — a test, a caller that predates Set — enforces
// rather than silently waiving the ceiling. The bit is what decides a zero, and
// the only way to reach "unbounded" is to leave both the bit and the value
// alone (E16: unlimited is expressed by omitting the field).
func (l ResolvedLimits) Bounded(k BudgetSet) bool {
	if l.Set&k != 0 {
		return true
	}
	switch k {
	case BudgetCPU:
		return l.CPU != ""
	case BudgetCPUWeight:
		return l.CPUWeight > 0
	case BudgetMemory:
		return l.MemoryB > 0
	case BudgetMemoryHigh:
		return l.MemoryHigh > 0
	case BudgetPids:
		return l.Pids > 0
	case BudgetTokens:
		return l.Tokens > 0
	case BudgetCostUSD:
		return l.CostUSD > 0
	case BudgetWall:
		return l.Wall > 0
	case BudgetStallAfter:
		return l.StallAfter > 0
	case BudgetRepeats:
		return l.Repeats > 0
	}
	return false
}
