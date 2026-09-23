// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// PrintRuleTable writes the human-readable rule table `tego compile`
// shows: the contract, hash, resolved tier, capture and record mode, every
// limit after ceilings, then the fs, exec, net and env sections with each
// entry's resolution (mount, filesystem, device, loader, addresses, TTL).
// It writes to w only; this package never prints on its own.
func PrintRuleTable(w io.Writer, rt *RuleTable) error {
	if rt == nil {
		return fmt.Errorf("agent: PrintRuleTable: nil table")
	}
	p := &printer{w: w}
	p.header(rt)
	p.live(rt)
	p.harness(rt)
	p.limits(rt.Limits)
	p.ask(rt.AskConfig)
	// The built-in deny_write set (R20) is printed with the fs entries it would sit among in a tier that
	// enforces it, so the table shows what the write entries reach; it stays out of rt.FS itself.
	if rt.FilesystemAssurance() == FSAssuranceKernel {
		p.line("fs        assurance kernel (a deny_write target needs a decision plane, verified before launch)")
	}
	p.fs(append(append([]FSRule(nil), rt.FS...), rt.DenyWrite...), rt.FilesystemAssurance(), rt.heldAtLandlock())
	if s := heldReadsLine(rt); s != "" {
		p.line("reads     %s", s)
	}
	if s := reasonReadsLine(rt); s != "" {
		p.line("reason    %s", s)
	}
	p.names(rt)
	p.exec(rt.Exec, rt.ExecUnrestricted(), rt.Contract != nil && rt.Contract.Exec != nil)
	p.execCommands(rt)
	if rt.ExecutionAssurance() == ExecAssuranceKernel {
		p.line("exec      assurance kernel (the run needs a decision plane that pins its execs, verified before launch)")
	}
	p.net(rt)
	p.env(rt)
	p.gate(rt)
	return p.err
}

// live prints an Adjustable table's mode and fence (ADR 0125); a Locked table prints nothing here, as before.
func (p *printer) live(rt *RuleTable) {
	if !rt.Adjustable() {
		return
	}
	p.line("live      adjustable (live both ways): the kernel enforces the contract plus this fence; Tego's live layer, not the kernel, refuses each entry below until you lift or grant it")
	p.line("fence     %d entries, sha256 %s", len(rt.Live.Entries), rt.Live.SHA256)
	if len(rt.Live.Entries) == 0 {
		return
	}
	rows := make([][]string, 0, len(rt.Live.Entries))
	for _, e := range rt.Live.Entries {
		what := "new access (grant)"
		if e.Source == LiveSourceDeny {
			what = "takes out a contract refusal (lift)"
		}
		note := "refused at start"
		switch e.Kind {
		case LiveKindExec:
			note += "; best effort (decided on names: a copy under another name is not refused)"
			if e.Name != "" {
				note += "; refused by name " + e.Name + " at start: every program named " + e.Name + ", as exec.deny refused it"
			}
			if len(e.Images) > 0 {
				note += "; so are its helper images " + strings.Join(e.Images, ", ")
			}
		case LiveKindRead:
			note += "; checked on the object the open deputy pins"
		case LiveKindNet:
			note += "; TCP only, checked on Tego's relayed connect"
		}
		rows = append(rows, []string{e.Kind, e.Value, what, note})
	}
	p.table([]string{"KIND", "VALUE", "SOURCE", "AT START"}, rows)
}

type printer struct {
	w   io.Writer
	err error
}

// line writes one formatted line. String arguments are escaped for the terminal (record.Printable): paths
// come from the filesystem, where the .env scan finds names an earlier run could have planted.
func (p *printer) line(format string, args ...any) {
	if p.err != nil {
		return
	}
	for i, a := range args {
		if s, ok := a.(string); ok {
			args[i] = record.Printable(s)
		}
	}
	_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
}

// table renders rows with aligned columns under a header row.
func (p *printer) table(header []string, rows [][]string) {
	if p.err != nil {
		return
	}
	tw := tabwriter.NewWriter(p.w, 2, 4, 2, ' ', 0)
	write := func(cols []string) {
		if p.err == nil {
			safe := make([]string, len(cols))
			for i, c := range cols {
				safe[i] = record.Printable(c)
			}
			_, p.err = fmt.Fprintln(tw, "  "+strings.Join(safe, "\t"))
		}
	}
	write(header)
	for _, r := range rows {
		write(r)
	}
	if err := tw.Flush(); err != nil && p.err == nil {
		p.err = err
	}
}

func (p *printer) header(rt *RuleTable) {
	p.line("contract  %s", rt.ContractPath)
	p.line("hash      %s", hex.EncodeToString(rt.Hash[:]))
	if rt.Contract != nil && rt.Contract.Revision != "" {
		// The author's name for this version of the contract (R28), which run_start records as contract_revision.
		p.line("revision  %s", rt.Contract.Revision)
	}
	if len(rt.Reach) > 1 {
		// An auto table names every tier its run can get, not only the one it was compiled for (ADR 0019).
		names := make([]string, len(rt.Reach))
		for i, t := range rt.Reach {
			names[i] = string(t)
		}
		p.line("tier      %s (auto: a run gets one of %s)", rt.Tier, strings.Join(names, ", "))
	} else {
		p.line("tier      %s", rt.Tier)
	}
	p.line("capture   %s", rt.Capture)
	p.line("record    %s", rt.Record)
	if rt.NetworkAssurance() == NetAssuranceKernel {
		p.line("net       assurance kernel (client-only; verified before launch)")
	}
}

// limits prints one line of resolved budgets. "unbounded" comes from the presence bit, never from the
// number: a ceiling of exactly 0 is a budget, and printing it as unbounded is how an operator who asked
// for the tightest limit is told they got none (E16).
func (p *printer) limits(l ResolvedLimits) {
	unb := func(k BudgetSet, s string) string {
		if !l.Bounded(k) {
			return "unbounded"
		}
		return s
	}
	p.line("limits    cpu=%s cpu_weight=%s memory=%s memory_high=%s pids=%s tokens=%s cost_usd=%s wall=%s stall_after=%s repeats=%s",
		unb(BudgetCPU, l.CPU),
		unb(BudgetCPUWeight, strconv.Itoa(l.CPUWeight)),
		unb(BudgetMemory, ByteSize(l.MemoryB).String()),
		unb(BudgetMemoryHigh, ByteSize(l.MemoryHigh).String()),
		unb(BudgetPids, strconv.Itoa(l.Pids)),
		unb(BudgetTokens, strconv.FormatInt(l.Tokens, 10)),
		unb(BudgetCostUSD, strconv.FormatFloat(l.CostUSD, 'f', -1, 64)),
		unb(BudgetWall, Duration(l.Wall).String()),
		unb(BudgetStallAfter, Duration(l.StallAfter).String()),
		unb(BudgetRepeats, strconv.Itoa(l.Repeats)))
}

// ask prints the approval configuration of a table that asks (ask.*), with what a timed-out ask leaves behind:
// refuse_always is printed with what it does, since a retry it refuses is never held for a person again.
func (p *printer) ask(c *AskConfig) {
	if c == nil {
		return
	}
	onTimeout := string(c.OnTimeout)
	if c.OnTimeout == AskOnTimeoutRefuseAlways {
		onTimeout += " (a timed-out ask's operation, rule and target are refused at once for the rest of the run)"
	}
	p.line("ask       hold=%s timeout=%s max_pending=%d on_timeout=%s", string(c.Hold), Duration(c.Timeout).String(), c.MaxPending, onTimeout)
}

// fs prints the fs entries; held says a run at tier landlock holds its reads (ADR 0069), so a deny_read the ruleset
// leaves unenforced there is refused by the held read instead.
func (p *printer) fs(rules []FSRule, assurance FSAssurance, held bool) {
	p.line("fs        %d entries", len(rules))
	rows := make([][]string, 0, len(rules))
	for _, r := range rules {
		var notes []string
		if r.Missing {
			notes = append(notes, "missing")
		}
		if r.IsMountPoint {
			notes = append(notes, "mount-point")
		}
		if r.Overlay {
			notes = append(notes, "overlay")
		}
		if r.Btrfs {
			notes = append(notes, "btrfs")
		}
		switch {
		case r.Unenforced && r.Kind == FSDenyWrite && assurance == FSAssuranceKernel:
			// Landlock cannot deny beneath the enclosing write entry, and fs.assurance: kernel refuses a run no
			// decision plane decides (enforce-landlock R5a).
			notes = append(notes, "kernel-plane-required(landlock: parent writable)")
		case r.Unenforced && r.IsDeclaredDenyWrite():
			// An fs.deny_write entry (ADR 0071): the same refusal as a built-in target's, labelled as its users read it.
			notes = append(notes, "best effort at tier landlock")
		case r.Unenforced && r.Kind == FSDenyWrite:
			// Landlock cannot deny beneath the enclosing write entry; below a decision plane the seccomp
			// supervisor refuses a write to it, which a racing path can defeat (R20, ADR 0041 D1 (a)).
			notes = append(notes, "best-effort(supervisor; landlock: parent writable)")
		case r.Unenforced && held:
			notes = append(notes, "held(landlock: parent writable)")
		case r.Unenforced:
			notes = append(notes, "unenforced(landlock: parent writable)")
		}
		if r.BuiltIn {
			notes = append(notes, "built-in")
		}
		dev := "-"
		if r.Device != 0 {
			dev = fmt.Sprintf("%d:%d", r.Device>>8&0xfff, r.Device&0xff|r.Device>>12&^0xff)
		}
		kind := string(r.Kind)
		if r.AskRead && r.Kind == FSDenyRead {
			// A deny_read to every mechanism that does not hold a read; printed by the key it was declared in.
			kind = fsAskReadKey
			notes = append(notes, "held-for-a-person(tier landlock)")
		}
		rows = append(rows, []string{kind, r.Path, accessLabel(r.Access), dash(r.Mount), dash(r.Filesystem), dev, dash(strings.Join(notes, ","))})
	}
	p.table([]string{"KIND", "PATH", "ACCESS", "MOUNT", "FS", "DEV", "NOTES"}, rows)
}

// names prints the table's name entries (ADR 0043), nothing when it has none (a table that can only land at tier
// landlock): each entry's form, its scopes, the rule a refusal of a file created later carries, and the
// exemptions. The heading says where they apply (namesWhere), so the print never claims a refusal no run makes.
func (p *printer) names(rt *RuleTable) {
	if len(rt.NameDeny) == 0 {
		return
	}
	p.line("names     %d entries, %s", len(rt.NameDeny), namesWhere(rt))
	rows := make([][]string, 0, len(rt.NameDeny)+len(rt.NameExempt))
	for i := range rt.NameDeny {
		e := &rt.NameDeny[i]
		scopes := make([]string, len(e.Scopes))
		for j, s := range e.Scopes {
			scopes[j] = s.Spelling
		}
		var notes []string
		if len(e.Except) > 0 {
			notes = append(notes, "except "+strings.Join(e.Except, ","))
		}
		if e.BuiltIn {
			notes = append(notes, "built-in")
		}
		if e.BindExposed {
			notes = append(notes, "bind-exposed")
		}
		rows = append(rows, []string{e.Form(), strings.Join(scopes, ","), e.RuleName(0), dash(strings.Join(notes, ";"))})
	}
	for _, x := range rt.NameExempt {
		name := "-"
		if x.Write >= 0 && x.Write < len(rt.FS) {
			name = rt.FS[x.Write].RuleName()
		}
		rows = append(rows, []string{x.Name, x.Parent, name, "exempt"})
	}
	p.table([]string{"NAME", "SCOPES", "RULE", "NOTES"}, rows)
}

// namesWhere is the names heading's statement of where the entries apply: the plane's name check (or the fanotify
// fallback's listener and supervisor) at tiers cgroup and bpflsm, files created later included; at tier landlock the
// expansion decides, unless the table can land there and its runs there hold their reads (ADR 0069 D3 (c)), which refuse a file the
// built-in .env entries name and one a declared glob matches as written (RuleTable.Reads, narrower than a declared
// entry's scope), made during the run included.
func namesWhere(rt *RuleTable) string {
	const roots = "beneath their scopes at tiers cgroup and bpflsm, files created later included; "
	if !slices.Contains(rt.Reach, backend.TierLandlock) || !rt.ReadsHeldAt(backend.TierLandlock) {
		return roots + "tier landlock keeps the expansion"
	}
	what := "a file a declared glob matches as written"
	if len(rt.Reads.Names) > 0 {
		what = "a file the built-in .env entries name, and " + what
	}
	return roots + "at tier landlock held reads (fs.reads: " + string(rt.Reads.Mode) + ") refuse " + what +
		", made during the run included"
}

func (p *printer) exec(rules []ExecRule, unrestricted, hasSection bool) {
	// A deny-list section (present, no allow key) leaves images unrestricted, but it is not "no exec: section": that
	// parenthetical would misname it. execCommands prints the exact mode below.
	switch {
	case unrestricted && hasSection:
		p.line("%-9s exec unrestricted (deny-list); %d entries", "exec", len(rules))
	case unrestricted:
		p.line("%-9s exec unrestricted (no exec: section); %d entries", "exec", len(rules))
	default:
		p.line("%-9s %d entries", "exec", len(rules))
	}
	rows := make([][]string, 0, len(rules))
	for _, r := range rules {
		kind := "binary"
		switch {
		case r.IsDir:
			kind = "dir"
		case r.Interp == "":
			kind = "static/script"
		}
		rows = append(rows, []string{r.Source, dash(r.Raw), r.Path, kind, dash(r.Interp), string(r.Verdict)})
	}
	p.table([]string{"SOURCE", "ENTRY", "PATH", "KIND", "INTERP", "VERDICT"}, rows)
}

// execCommands prints one line per command pattern (ADR 0048 (9)): the list, the entry, the row with its version and
// source, and the exact reading; the entry's notes under it; then the mode with the file that set it.
func (p *printer) execCommands(rt *RuleTable) {
	ec := rt.ExecCommands
	if rt.Contract == nil || rt.Contract.Exec == nil {
		return
	}
	n := 0
	if ec != nil {
		for _, en := range ec.Entries {
			pat := en.Pattern
			row := "generic"
			if pat.Row != nil {
				row = "row " + pat.Row.Tool + " " + pat.Row.Version + " (" + pat.Row.Source.String() + ")"
			}
			p.line("exec %-5s %s  %s  %s", pat.List.String(), pat.Entry, row, pat.Reading())
			for _, note := range en.Notes {
				p.line("           %s", note)
			}
			n++
		}
	}
	file, key := rt.Contract.ExecModeSource()
	mode := "images restricted"
	if rt.ExecUnrestricted() {
		mode, key = "images unrestricted", "deny-list"
	}
	p.line("exec: %s (%s, set by %s), %d command rules", mode, key, filepath.Base(file), n)
}

func (p *printer) net(rt *RuleTable) {
	rules := rt.Net
	// The heading says what a section the contract left out leaves open (SEMANTICS §1), since its entries (an implicit
	// grant) or their absence print exactly like a section that refuses all else (R1): with no net: section the IP
	// side is unrestricted and, unless host_sockets: true opens them, the unix side is the run's own sockets only (ADR
	// 0070), so "net unrestricted" alone would say the host's daemon sockets are reachable.
	switch {
	case rt.HostSocketsRefused():
		p.line("%-9s IP unrestricted, unix sockets the run's own only (no net: section); %d entries", "net", len(rules))
	case rt.HostSocketsOpened():
		p.line("%-9s net unrestricted (no net: section, host_sockets: true); %d entries", "net", len(rules))
	default:
		p.line("%-9s %d entries", "net", len(rules))
	}
	rows := make([][]string, 0, len(rules))
	for _, r := range rules {
		target, addrs, ttl := "", "-", "-"
		switch {
		case r.Proto == ProtoUnix && r.Abstract:
			target = "@" + r.UnixPath
		case r.Proto == ProtoUnix:
			target = r.UnixPath
		case r.CIDR != nil:
			target = r.CIDR.String() + ":" + strconv.Itoa(r.Port)
			addrs = "static"
		default:
			target = r.Host + ":" + strconv.Itoa(r.Port)
			if r.Static {
				addrs = "static"
			} else {
				parts := make([]string, 0, len(r.IPs))
				for _, ip := range r.IPs {
					parts = append(parts, ip.String())
				}
				addrs = dash(strings.Join(parts, ","))
				if addrs == "-" {
					addrs = "unresolved(offline)"
				}
				ttl = Duration(r.TTL).String()
			}
		}
		rows = append(rows, []string{r.RuleName(), r.Proto, target, addrs, ttl, string(r.Verdict)})
	}
	p.table([]string{"RULE", "PROTO", "TARGET", "ADDRESSES", "TTL", "VERDICT"}, rows)
}

func (p *printer) env(rt *RuleTable) {
	pass := "inherit all"
	if rt.Env != nil {
		pass = strings.Join(rt.Env, ",")
		if pass == "" {
			pass = "none"
		}
	}
	keys := make([]string, 0, len(rt.Set))
	for k := range rt.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	set := make([]string, 0, len(keys))
	for _, k := range keys {
		set = append(set, k+"="+rt.Set[k])
	}
	p.line("env       pass=%s deny=%s set=%s", pass, dash(strings.Join(rt.Deny, ",")), dash(strings.Join(set, ",")))
	p.line("path      %s", dash(rt.PATH))
}

// accessLabel names the full write set in one word; anything else lists bits.
func accessLabel(a AccessSet) string {
	if a == AccessWriteSet {
		return "write-set"
	}
	return a.String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (p *printer) gate(rt *RuleTable) {
	if rt.Gate == nil {
		return
	}
	allow, ask := rt.Gate.Thresholds()
	facts := "copied syscall facts"
	if rt.GateOpensHeld() {
		// No process of the run makes a Landlock domain of its own beneath the deputy's (enforce-landlock R10's
		// held-completion arm, ADR 0041 D2): an agent that sandboxes its tools with Landlock finds it unavailable.
		facts = "fs opens held: the open deputy, a process of the run, completes them; other kinds copied syscall facts; " +
			"the run's processes make no Landlock domain of their own (landlock_* answer ENOSYS)"
		if !rt.ExecUnrestricted() {
			// The deputy's runtime exec grant (ADR 0041 D2, enforce-landlock): the domain, not the contract, lets the
			// child stage exec tego's own binary; no exec rule names it.
			facts += "; runtime exec grant: tego's own binary, for the deputy"
		}
	}
	p.line("gate      allow <%d, ask %d..%d, refused >%d (scores sum, saturating at 100; %s)", allow, allow, ask, ask, facts)
	p.line("worktree  %s", rt.Workdir)
	var rows [][]string
	for i, r := range rt.Gate.Rules() {
		rows = append(rows, []string{fmt.Sprintf("gate.rules[%d]", i), gatePredicateText(r), strconv.Itoa(r.Score)})
	}
	p.table([]string{"RULE", "PREDICATE", "SCORE"}, rows)
	// ADR 0048 (5): an exec rule now also matches what the shared matcher reads in its pattern, which broadens it.
	for i := range rt.Gate.Rules() {
		if reading := rt.Gate.CommandReading(i); reading != "" {
			p.line("gate.rules[%d] also matches as a command pattern: %s", i, reading)
		}
	}
	if rt.Gate.MayAsk(gate.Exec) {
		p.line("exec ask  unsupported completion: fail closed")
	}
}
