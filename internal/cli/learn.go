// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/internal/registry"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdLearn) }

// cmdLearn is `tego learn <run> [--save <name> | --out <file>] [--allow-host <host>[:<port>]]... [--reads on|off]
// [--workspace <dir>]` (C9, E65): read a
// finished run's ledger, an observe-only run of `tego watch` for instance, and print, or with --out write, a boundary
// contract PROPOSED from what the run did: the directories it wrote under the workspace, the programs it started, the
// addresses it connected to. With --save it is written as the agent <name> of the user registry, where `tego run
// <name>` finds it (saveProposal), recording each read it refuses unless --reads off. --allow-host names the service
// the run reached at some of its addresses (lookupAllowHosts): each address the name resolves to here now is written as
// the name. It proposes, a person reviews and the contract is theirs: a dangerous endpoint (a
// D-Bus bus, an agent socket, the container daemon) is only reported, never allowed, and fs.deny_read is never touched.
// Like events and measure it reads the record alone and never takes the run's lock, so a run still going can be
// learned from, and its proposal is the run so far.
func cmdLearn() Command {
	var (
		out       string
		save      string
		reads     string
		workspace string
		hosts     hostFlags
	)
	return Command{
		Name:    "learn",
		Summary: "propose a contract from what a finished run did",
		Usage:   "<run> [--save <name> | --out <file>] [--allow-host <host>[:<port>]]... [--reads on|off] [--workspace <dir>]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&out, "out", "", "write the proposal to this new file (mode 0600, never replacing one) instead of printing it")
			fs.StringVar(&save, "save", "", "save the proposal as this agent's contract in the user registry (~/.config/tego/agents/<name>.yaml, mode 0600, never replacing one), for tego run <name>")
			fs.StringVar(&reads, "reads", "", "on: the proposal records a read its contract refuses at tier landlock too (reason.reads: on; each read open is slower); "+
				"--save does unless off")
			fs.Var(&hosts, "allow-host", "a host name the run reached, or host:port: each address of the run that the name resolves to here now is "+
				"allowed by the name instead (repeatable, at most 8)")
			fs.StringVar(&workspace, "workspace", "", "the directory writes may be allowed under (default: the run's working directory)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego learn: exactly one run id or run directory", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			// --save records refused reads by default (the project lead's decision of 2026-11-10;
			// docs/OPERATIONS.md, `tego learn`'s amendment of that date):
			// a newcomer then sees the read the contract refused on every run. The printed proposal and --out keep the
			// contract's default unless --reads on.
			o := learnOptions{out: out, save: save, reads: reads, reasonReads: reads == "on" || (save != "" && reads == "")}
			switch {
			case reads != "" && reads != "on" && reads != "off":
				message(stderr, "", 0, 0, fmt.Sprintf("tego learn: --reads %q: on or off (left out, --save records refused reads and the "+
					"printed proposal keeps the contract's default)", reads), codeUsage)
				return identity.ExitUsage // R25: usage error
			case len(hosts) > agent.DefaultDNSParallel:
				message(stderr, "", 0, 0, fmt.Sprintf("tego learn: --allow-host: %d names; at most %d", len(hosts), agent.DefaultDNSParallel), codeUsage)
				return identity.ExitUsage // R25: usage error
			case save != "" && out != "":
				message(stderr, "", 0, 0, "tego learn: --save and --out: give one; --save writes to the user registry, --out to a file you name", codeUsage)
				return identity.ExitUsage // R25: usage error
			case flagGiven(fs, "save") && !registry.IsName(save):
				message(stderr, "", 0, 0, fmt.Sprintf("tego learn: --save %q is not an agent name: lower-case letters, digits and -, at most 40", save), codeUsage)
				return identity.ExitUsage // R25: usage error
			case flagGiven(fs, "save") && !saveableName(save):
				message(stderr, "", 0, 0, fmt.Sprintf("tego learn: --save %q starts with -, which tego run reads as a flag: give a name that "+
					"starts with a letter or a digit", save), codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			ws := workspace
			if ws != "" {
				abs, err := filepath.Abs(ws)
				if err != nil {
					message(stderr, "", 0, 0, "tego learn: --workspace: "+err.Error(), codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				// The ledger names paths the kernel's way, every link resolved, so the workspace is compared in that
				// form. One that does not resolve here (a run read on another machine) is kept as given.
				if real, err := filepath.EvalSymlinks(abs); err == nil {
					abs = real
				}
				if ws = abs; ws == "/" {
					message(stderr, "", 0, 0, "tego learn: --workspace / is every directory: name the directory the agent works in", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
			}
			o.workspace = ws
			for _, v := range hosts {
				h, err := allowHostArg(v)
				if err != nil {
					message(stderr, "", 0, 0, "tego learn: --allow-host "+strconv.Quote(v)+": "+err.Error(), codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				o.hosts = append(o.hosts, h)
				o.hostArgs = append(o.hostArgs, v)
			}
			// An agent held by Tego must not save its own contract: the registry is where tego run finds it by name.
			if o.save != "" && (refuseSaveGoverned(stderr) || refuseSaveForAnother(stderr)) {
				return identity.ExitLauncher
			}
			return runLearn(ctx, fs.Arg(0), o, stdout, stderr)
		},
	}
}

// learnEUID is the effective uid learn --save runs with; a variable so a test can stand in root.
var learnEUID = os.Geteuid

// learnOptions is what tego learn's flags resolved to.
type learnOptions struct {
	workspace, out, save string
	// reads is --reads as given: "on", "off" or "" (left out).
	reads string
	// reasonReads writes reason: {reads: on} into the proposal: --reads on, or --save without --reads off.
	reasonReads bool
	// hosts are the --allow-host names, without their answers, and hostArgs the values as given.
	hosts    []learn.HostAnswer
	hostArgs []string
}

// shapingFlags are the flags that shaped the proposal, as the hint's command repeats them so that its --save writes the
// proposal printed (with refused reads recorded unless --reads off, as the hint says, learnSaveHint): " --workspace
// <dir>" (the resolved full path, quoted for a shell), " --allow-host <value>" for each name given, and " --reads on"
// or " --reads off", each when given, else "".
func (o learnOptions) shapingFlags() string {
	var b strings.Builder
	if o.workspace != "" {
		b.WriteString(" --workspace " + shellword.Quote(o.workspace))
	}
	for _, h := range o.hostArgs {
		b.WriteString(" --allow-host " + shellword.Quote(h))
	}
	if o.reads != "" {
		b.WriteString(" --reads " + o.reads)
	}
	return b.String()
}

// hostFlags is --allow-host, given once per name.
type hostFlags []string

func (h *hostFlags) String() string { return strings.Join(*h, ",") }

func (h *hostFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// allowHostArg is one --allow-host value: a host name, or a host name and a port, as a net.allow entry spells them
// (agent.ParseEndpoint), never an address, a pattern or a URL.
func allowHostArg(v string) (learn.HostAnswer, error) {
	raw := v
	if !strings.Contains(v, ":") {
		raw += ":443" // any port: ParseEndpoint wants one, and none was given
	}
	e, err := agent.ParseEndpoint("tcp://" + raw)
	switch {
	case v == "" || strings.ContainsAny(v, "*?[/ ") || record.Printable(v) != v:
		return learn.HostAnswer{}, errors.New("give a host name, or host:port, such as api.example.com or api.example.com:443")
	case err != nil:
		return learn.HostAnswer{}, fmt.Errorf("give a host name, or host:port (%v)", err)
	case e.Kind != agent.EndpointHost || e.IP.IsValid():
		return learn.HostAnswer{}, errors.New("an address is allowed as it is; --allow-host takes the host name the agent uses")
	case e.Port <= 0:
		return learn.HostAnswer{}, errors.New("port 0 names no service")
	}
	h := learn.HostAnswer{Host: e.Host}
	if raw == v {
		h.Port = e.Port
	}
	return h, nil
}

// learnResolver is the DNS lookup --allow-host makes; nil is net.DefaultResolver, the one a run's start uses
// (nextrun.LookupHosts). Tests replace it.
var learnResolver agent.Resolver

// lookupAllowHosts looks each --allow-host name up here, now, all at once within nextrun.HostBudget, and returns them
// with their answers. A name that does not resolve fails the command, exit 1 with nothing written and nothing printed
// on stdout: its coverage cannot be checked. Where DNS said the name does not exist or has no addresses, a run under it
// would not start either (it resolves every name at start), and the message says so; a name that did not answer in
// time may still start one, which gives each name longer (agent.DefaultDNSTimeout). Exit 125 when ctx ends first.
func lookupAllowHosts(ctx context.Context, hosts []learn.HostAnswer, stderr io.Writer) ([]learn.HostAnswer, []int, int) {
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if !slices.Contains(names, h.Host) {
			names = append(names, h.Host)
		}
	}
	answers, err := nextrun.LookupHosts(ctx, learnResolver, names, nextrun.HostBudget)
	if err != nil {
		message(stderr, "", 0, 0, "tego learn: --allow-host: "+err.Error(), codeIO)
		return nil, nil, identity.ExitError
	}
	code := identity.ExitOK
	out := slices.Clone(hosts)
	var unresolved []int
	for _, a := range answers {
		if a.Why != "" {
			where := " (" + a.Why + ")"
			if strings.HasPrefix(a.Why, "no answer within ") {
				where = " " + strings.TrimPrefix(a.Why, "no answer ")
			}
			msg := "tego learn: " + a.Host + " did not resolve here" + where + "; nothing was written."
			if a.Why == "no such host" || a.Why == "no addresses" {
				msg += " A run under this name would not start either."
			}
			message(stderr, "", 0, 0, msg, codeAllowHost)
			code = identity.ExitFinding
			for i := range out {
				if out[i].Host == a.Host {
					unresolved = append(unresolved, i)
				}
			}
			continue
		}
		for i := range out {
			if out[i].Host == a.Host {
				out[i].Addrs = a.Addrs
			}
		}
	}
	slices.Sort(unresolved)
	return out, unresolved, code
}

// hostsRefusedHint is the next: line after learn refused --allow-host names (exit 1, nothing written): the same command
// without the names refused (refused, indexes into o.hosts), so the step that works is one line, never a guess
// (acceptance B, 2026-11-11). A name refused because the run's secrets may have gone to its addresses is not
// suggested again: the addresses learn kept stay allowed by address, and learn names --allow-host for them itself.
func hostsRefusedHint(stderr io.Writer, dir string, m *config.Machine, o learnOptions, refused []int) {
	if len(refused) == 0 {
		return
	}
	kept := o
	kept.hosts, kept.hostArgs = nil, nil
	for i, v := range o.hostArgs {
		if !slices.Contains(refused, i) {
			kept.hosts, kept.hostArgs = append(kept.hosts, o.hosts[i]), append(kept.hostArgs, v)
		}
	}
	command := "tego learn " + learnRunRef(dir, m)
	switch {
	case o.save != "":
		command += " --save " + shellword.Quote(o.save)
	case o.out != "":
		command += " --out " + shellword.Quote(o.out)
	}
	text := "make it without the names learn refused:"
	if len(kept.hostArgs) == 0 {
		text = "make it without --allow-host; learn allows the addresses it kept:"
	}
	writeHint(stderr, text, record.Printable(command+kept.shapingFlags()))
}

// codeAllowHost is the code of a refusal of an --allow-host name.
const codeAllowHost = "allow-host"

// pathArg is file written so that tego run reads it as a path: one with no '/' gets "./" before it. A bare word that is
// an agent name ([a-z0-9-]{1,40}) is one tego run looks up in the registries, and it refuses one that is also the name
// of a file in the working directory, as the file --out just wrote is, as agent-ambiguous.
func pathArg(file string) string {
	if strings.Contains(file, "/") {
		return file
	}
	return "./" + file
}

// refuseSaveGoverned is learn --save's refusal from inside a run (exit 125 [governed]): the user registry is where
// tego run finds a contract by name, and an agent held by Tego must not write the contract it, or another agent, will
// be held to. It reports true when it refused.
func refuseSaveGoverned(stderr io.Writer) bool {
	in, err := selfInRun()
	if !in {
		return false
	}
	why := "this process is inside a tego run's cgroup"
	if err != nil {
		why = "this process cannot be shown to be outside every tego run (" + err.Error() + ")"
	}
	message(stderr, "", 0, 0, "tego learn: --save: a governed agent cannot save a contract: "+why+"; nothing was written; "+
		"run it from a terminal outside any tego run", codeGoverned)
	return true
}

// refuseSaveForAnother is learn --save's refusal as root for another user, under sudo (exit 125 [privilege]): the
// registry is the invoking user's (the machine config's registry:, ~/.config/tego by default, under that user's
// home), and a folder and file root makes there, mode 0700 and 0600, are ones that user's own tego run <name> cannot
// read, and that refuse every later save. It reports true when it refused.
func refuseSaveForAnother(stderr io.Writer) bool {
	if learnEUID() != 0 {
		return false
	}
	if uid, _ := config.InvokingUID(); uid == 0 {
		return false
	}
	message(stderr, "", 0, 0, "tego learn: --save as root for another user: the file would be root's, in that user's registry, "+
		"where the user's own tego run cannot read it; nothing was written; run tego learn without sudo, or write the "+
		"proposal with --out <file>", codePrivilege)
	return true
}

// runLearn resolves the run, reads its record without the lock and renders one proposal.
func runLearn(ctx context.Context, ref string, o learnOptions, stdout, stderr io.Writer) int {
	mc := &machineOnce{stderr: stderr}
	dir, err := resolveRunDir("learn", ref, true, mc)
	if err != nil {
		return runRefFailed(stderr, "learn", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego learn: no run record at %s", dir), codeIO)
			return identity.ExitError
		}
		message(stderr, "", 0, 0, "tego learn: "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	// The warning that lines of a newer record version were skipped is said once: before the hint on the path that
	// reaches it (the hint is last), or as learn returns on any other.
	warned := false
	defer func() {
		if !warned {
			warnNewer(stderr, "learn", dir, r.SkippedNewer())
		}
	}()
	if err := needRunRecord(r, dir); err != nil {
		message(stderr, "", 0, 0, "tego learn: "+err.Error(), readCode(err))
		return identity.ExitError
	}

	var hosts []learn.HostAnswer
	var deniedResolved []netip.Prefix
	if len(o.hosts) > 0 {
		// The machine config's denied_resolved_addresses decide, with the built-in classes, which addresses a name may
		// stand for (compile drops the rest from its answer): without them learn could say a name allows what the next
		// run refuses.
		m, err := mc.load()
		if err != nil {
			message(stderr, "", 0, 0, "tego learn: --allow-host: machine config: "+err.Error()+"; its denied_resolved_addresses decide "+
				"which addresses a name may stand for; nothing was written", config.CodeUntrusted)
			return identity.ExitError
		}
		if m != nil {
			deniedResolved = m.DeniedResolved.Value
		}
		var code int
		var unresolved []int
		if hosts, unresolved, code = lookupAllowHosts(ctx, o.hosts, stderr); code != identity.ExitOK {
			if code == identity.ExitFinding {
				hostsRefusedHint(stderr, dir, m, o, unresolved)
			}
			return code
		}
	}
	l := learn.New(learn.Options{Workspace: o.workspace, StateDirs: learnStateDirs(r.Dir(), mc), Hosts: hosts,
		DeniedResolved: deniedResolved, Now: time.Now()})
	for e, err := range r.Iter() {
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = l.Add(e)
		}
		if err != nil {
			return readFailed(stderr, "learn", err) // a corrupt ledger is tego's own error, not a finding
		}
	}
	p, err := l.Proposal()
	var he *learn.HostError
	if errors.As(err, &he) {
		for _, why := range he.Problems {
			message(stderr, "", 0, 0, "tego learn: "+why+"; nothing was written", codeAllowHost)
		}
		m, _ := mc.load()
		hostsRefusedHint(stderr, dir, m, o, he.Refused)
		return identity.ExitFinding // a finding about the names given, as --out's existing file is
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego learn: "+err.Error(), codeUsage)
		return identity.ExitUsage // R25: usage error: the workspace the run or the flag names cannot be used
	}
	p.ReasonReads = o.reasonReads
	if o.save != "" {
		p.Name = o.save // the registry resolves a name only to a file whose name: is that name
	}
	text := p.Contract()
	var hint, command, file string
	m, merr := mc.load()
	if merr != nil {
		m = nil // the hint then proposes <name>; --save reports the config itself
	}
	switch {
	case o.save != "":
		code, path := saveProposal(ctx, o.save, text, p, mc, stderr)
		if code != identity.ExitOK {
			return code
		}
		file = path
		fmt.Fprintf(stderr, "tego learn: saved %s (mode 0600), made only from what run %s was recorded doing.\n", path, record.Printable(p.Run))
		if n := len(p.AddressEntries()); n > 0 {
			fmt.Fprintf(stderr, "  addresses: it allows %d %s the run reached, not host names; a site can move to another address.\n",
				n, pluralWord(n, "address", "addresses"))
		}
		if p.ReasonReads {
			fmt.Fprintf(stderr, "  reads: it records each read it refuses, at tier landlock too (reason.reads: on): %s, %s; --reads off leaves it out.\n",
				agent.ReasonReadCost, agent.ReasonReadWorkload)
		}
		hint, command = "run your agent under it:", "tego run "+o.save
		if folderHere(p.Cwd) {
			command = "cd " + shellword.Quote(p.Cwd) + " && " + command
		}
	case o.out != "":
		if code := writeProposal(o.out, text, p, stderr); code != identity.ExitOK {
			return code
		}
		file = o.out
		hint, command = "run your agent under it:", "tego run "+shellword.Quote(pathArg(o.out))
	default:
		if _, err := io.WriteString(stdout, text); err != nil {
			message(stderr, "", 0, 0, "tego learn: "+err.Error(), codeIO)
			return identity.ExitError
		}
		hint, command = learnSaveHint, "tego learn "+learnRunRef(dir, m)+" --save "+proposedName(m, p.Cwd)+o.shapingFlags()
		switch {
		case p.SuggestHosts():
			hint, command = learnNameHint, command+" --allow-host "+hostPlaceholder
		case o.reads == "off":
			hint = "save it as a contract:"
		}
	}
	for _, n := range p.Named {
		reached := n.Reached[:min(len(n.Reached), maxNamedListed)]
		more := ""
		if k := len(n.Reached) - len(reached); k > 0 {
			more = fmt.Sprintf(" and %d more", k)
		}
		fmt.Fprintf(stderr, "tego learn: %s resolves here now to %d %s; what the run reached at %d of them is now allowed by that name: %s%s.\n",
			n.Host, len(n.Answer), pluralWord(len(n.Answer), "address", "addresses"), reachedAddrs(n), strings.Join(reached, ", "), more)
	}
	for _, w := range p.Warnings() {
		fmt.Fprintf(stderr, "tego learn: warning: %s\n", w)
	}
	if left := p.AddressEntries(); len(left) > 0 {
		still := ""
		if len(o.hosts) > 0 {
			still = "still "
		}
		shown := make([]string, 0, min(len(left), maxNamedListed))
		for _, e := range left[:min(len(left), maxNamedListed)] {
			shown = append(shown, strings.Replace(e, "://", " ", 1))
		}
		more := ""
		if k := len(left) - len(shown); k > 0 {
			more = fmt.Sprintf(" and %d more", k)
		}
		// --allow-host is named only where learn takes a name the person gives (learn.Proposal.SuggestHosts): with a
		// withheld destination it refuses a name that also stands for one, so the warning never names a flag learn may
		// then refuse (acceptance 2B, 2026-11-11).
		fix := "Name each with --allow-host " + hostPlaceholder + ", or a later run can be refused."
		if len(p.Leaks) > 0 {
			fix = "A later run can be refused another address of the same service: write the host's name in their place " +
				"under net.allow yourself (--allow-host refuses a name that also stands for an address learn withheld)."
		}
		fmt.Fprintf(stderr, "tego learn: warning: %d %s the run reached %s %sallowed by address, not by name: %s%s. %s\n",
			len(left), pluralWord(len(left), "address", "addresses"), pluralWord(len(left), "is", "are"), still,
			strings.Join(shown, ", "), more, fix)
	}
	if w := withheldWords(p.Withheld(), file); w != "" {
		fmt.Fprintf(stderr, "tego learn: warning: %s\n", w)
	}
	if n := len(p.Left); n > 0 {
		fmt.Fprintf(stderr, "tego learn: %d kinds of action the run took are left out of the proposal; its header and its \"observed, not allowed\" comments say which and why\n", n)
	}
	warnNewer(stderr, "learn", dir, r.SkippedNewer())
	warned = true
	runHint(stderr, hint, record.Printable(command))
	return identity.ExitOK
}

// withheldWords is what learn says of the destinations its leak rule withheld (learn.Proposal.Withheld), "" for none:
// which, and why; that a run under the contract is refused them and --allow-host refuses a name that stands for one;
// and the two ways that work, both the person's own explicit act: write the host's name in the file (file, "" when
// the proposal was printed), or tego rule on the line of a later run that refused it. Nothing re-admits one by itself.
func withheldWords(dests []string, file string) string {
	if len(dests) == 0 {
		return ""
	}
	shown := make([]string, 0, min(len(dests), maxNamedListed))
	for _, d := range dests[:min(len(dests), maxNamedListed)] {
		shown = append(shown, record.Printable(d))
	}
	list := strings.Join(shown, ", ")
	if k := len(dests) - len(shown); k > 0 {
		list += fmt.Sprintf(" and %d more", k)
	}
	where := "the contract once you save it"
	if file != "" {
		where = record.Printable(file)
	}
	one := len(dests) == 1
	pick := func(single, plural string) string {
		if one {
			return single
		}
		return plural
	}
	return fmt.Sprintf("learn withheld %s, because the run opened a secret for reading next to a send %s, so a secret may "+
		"have gone there. A run under this contract is refused %s, and --allow-host refuses a name that stands for %s. "+
		"If %s the agent's own service and you mean to allow it, add it yourself once you have read the file: write the "+
		"host's name under net.allow in %s (for example tcp://api.example.com:443), or, after a run under it is refused "+
		"that connection, tego rule <run> <line> --allow, with the line tego events <run> --verdict refused shows.",
		list, pick("there", "to each"), pick("that connection", "those connections"), pick("it", "one of them"),
		pick("it is", "one is"), where)
}

// The sentences of learn's next: lines (hints.go's one format): to save a printed proposal, which --save writes with
// refused reads recorded (learnSaveHint), or, when it allows addresses, with the host name the person gives
// (learnNameHint); and a record-only watch's, when its run reached addresses (watchNameHint).
const (
	learnSaveHint = "save it as a contract, which also records each read it refuses:"
	learnNameHint = "save it as a contract, with the host name of the addresses it reached:"
	watchNameHint = "make a contract from what it did, with the host name of its addresses:"
)

// hostPlaceholder is what a hint writes for a host name only the person knows: the one the agent reaches at the
// addresses the run recorded, which the record does not hold.
const hostPlaceholder = "<host>"

// maxNamedListed is how many destinations one learn line names; the rest are counted.
const maxNamedListed = 4

// reachedAddrs is how many distinct addresses the destinations a name covered are at.
func reachedAddrs(n learn.NamedHost) int {
	seen := map[string]bool{}
	for _, d := range n.Reached {
		_, dst, _ := strings.Cut(d, " ")
		if ap, err := netip.ParseAddrPort(dst); err == nil {
			seen[ap.Addr().String()] = true
		}
	}
	return len(seen)
}

// runAddresses reports whether learn's proposal from the run res names, in sum's ledger root, should be made with
// --allow-host (guide.SuggestHosts, learn.Proposal.SuggestHosts: it allows addresses, and no secret may have gone to
// one): a watch's next: line then names --allow-host, as tego setup's does. It reads the record once more, within
// summaryBudget and even after a Ctrl-C ended the run, as the summary does; a record it cannot read reports false.
func runAddresses(ctx context.Context, sum *endSummary, res tegoruntime.Result) bool {
	if sum == nil || sum.root == "" || res.RunID == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), summaryBudget)
	defer cancel()
	return guide.SuggestHosts(ctx, filepath.Join(sum.root, res.RunID))
}

// learnRunRef is how learn's hint names the run in directory dir: its short id (shortRun) when dir lies in the ledger
// root of m, the only place a short id is looked for; else the directory's path, which tego learn takes as given.
func learnRunRef(dir string, m *config.Machine) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	if m != nil {
		if root, err := ledgerRootOf(m); err == nil && filepath.Clean(root) == filepath.Dir(abs) {
			return shortRun(root, filepath.Base(abs))
		}
	}
	return shellword.Quote(abs)
}

// saveProposal writes text, the proposal named name, as the agent name of the user registry
// (<registry>/agents/<name>.yaml, by default ~/.config/tego/agents/), where `tego run <name>` finds it, and returns the
// exit and the file's path. It writes through registry.Save, the registry's one writer, which the dashboard's "Make a
// contract from this run" writes through too. It refuses, writing nothing, a name that is not free from the working
// directory or from the run's folder, where learn's hint runs it next (refuseTakenName; --replace is later), a file that
// would lie inside one of the proposal's own fs.write entries (tego refuses to run a contract its agent could rewrite),
// and a proposal that does not compile here: each is exit 1, as --out's existing file is. The folder is made 0700 and
// the file 0600, never over one already there; a write that fails is 125.
func saveProposal(ctx context.Context, name, text string, p *learn.Proposal, mc *machineOnce, stderr io.Writer) (int, string) {
	m, err := mc.load()
	if err != nil {
		message(stderr, "", 0, 0, "tego learn: --save: machine config: "+err.Error(), config.CodeUntrusted)
		return identity.ExitError, ""
	}
	sv := registry.Save{Places: registry.Places{User: m.Registry.Value}, Name: name, Text: []byte(text), Writes: p.WriteDirs()}
	if places, perr := registryPlaces(m); perr == nil {
		sv.Places, sv.From = places, saveDirs(places.Dir, p.Cwd)
	}
	sv.Compile = func(path string, text []byte) error {
		c, ds, err := agent.LoadBytes(path, text, profileSources(m))
		if err == nil {
			_, ds, err = agent.Compile(c, m, append(learnCompileOptions(ctx, m), agent.Offline())...)
		}
		if err != nil {
			_ = agent.WriteDiagnostics(stderr, slices.DeleteFunc(ds, func(d agent.Diagnostic) bool { return d.Severity != agent.SeverityError }))
		}
		return err
	}
	path, err := sv.Write()
	var se *registry.SaveError
	if err == nil {
		return identity.ExitOK, path
	} else if !errors.As(err, &se) {
		message(stderr, path, 0, 0, "tego learn: --save: "+err.Error()+": nothing was written", codeIO)
		return identity.ExitError, ""
	}
	switch se.Step {
	case registry.SaveName:
		message(stderr, "", 0, 0, "tego learn: --save "+se.Err.Error(), codeUsage)
		return identity.ExitUsage, ""
	case registry.SaveNoRegistry:
		message(stderr, "", 0, 0, fmt.Sprintf("tego learn: --save: the machine config names no user registry directory (registry: %q); "+
			"nothing was written; use --out <file>", m.Registry.Value), codeIO)
		return identity.ExitError, ""
	case registry.SaveTaken:
		refuseTakenName(stderr, se, name, p.Cwd)
		return identity.ExitFinding, ""
	case registry.SaveInsideWrite:
		message(stderr, path, 0, 0, fmt.Sprintf("tego learn: --save: the file would lie inside its own fs.write entry %q, which "+
			"tego refuses to run; nothing was written; use --out <a file outside it>, or --workspace", se.Write), agent.CodeContradiction)
		return identity.ExitFinding, ""
	case registry.SaveNoCompile:
		message(stderr, path, 0, 0, "tego learn: --save: the proposal does not compile here ("+se.Err.Error()+"); nothing was written; "+
			"write it with --out, fix it and run tego compile on it", agent.CodeSchema)
		return identity.ExitFinding, ""
	case registry.SaveExists:
		message(stderr, path, 0, 0, "tego learn: --save: "+se.Err.Error()+": nothing was written; give another name", codeExists)
		return identity.ExitFinding, ""
	case registry.SaveUnusable:
		message(stderr, path, 0, 0, "tego learn: --save: tego run "+name+" in "+se.Dir+" would refuse the file: "+se.Err.Error()+
			"; nothing was written", codeExists)
		return identity.ExitFinding, ""
	case registry.SaveIO:
		if se.Op == "write" {
			message(stderr, path, 0, 0, "tego learn: --save: write: "+se.Err.Error(), codeIO)
			return identity.ExitError, ""
		}
		message(stderr, se.Path, 0, 0, "tego learn: --save: "+se.Err.Error()+": nothing was written", codeIO)
		return identity.ExitError, ""
	}
	message(stderr, path, 0, 0, "tego learn: --save: "+err.Error()+": nothing was written", codeIO)
	return identity.ExitError, ""
}

// learnCompileOptions are the options --save compiles a proposal with, as tego run <name> will: this PATH, the launch
// environment, the built tiers, the machine's home and chain anchor. --save adds agent.Offline: a host name is
// resolved when the run starts (E18).
func learnCompileOptions(ctx context.Context, m *config.Machine) []agent.CompileOption {
	opts := []agent.CompileOption{agent.WithContext(ctx), agent.WithPATH(os.Getenv("PATH")), agent.WithEnviron(launchEnviron()),
		agent.WithClock(time.Now), agent.WithTiers(builtTiers()...)}
	if m.Home != "" {
		opts = append(opts, agent.WithHome(m.Home))
	}
	return append(opts, anchorCompileOptions(m)...)
}

// saveDirs are the folders a saved name is looked up from: wd, where tego learn runs, and runDir, the run's own
// folder, where learn's hint runs tego run <name> next (cd <run folder> && tego run <name>); a name must name nothing
// else from either. runDir "" (a record that does not say), wd itself, or a folder not on this machine (a record
// copied from another, whose hint has no cd) adds none.
func saveDirs(wd, runDir string) []string {
	if runDir == wd || !folderHere(runDir) {
		return []string{wd}
	}
	return []string{wd, runDir}
}

// refuseTakenName is --save's refusal of name when registry.Save found it not free from the folder se.Dir (exit 1,
// nothing written): a name a registry resolves already, or one tego run would find ambiguous (a file of the name in
// that folder, the name in both registries), is taken; a registry that cannot be looked into is reported in its own
// words. runDir is the run's folder, which the message names when the lookup was made from it.
func refuseTakenName(stderr io.Writer, se *registry.SaveError, name, runDir string) {
	where := ""
	if se.Dir == runDir {
		where = fmt.Sprintf(" in %s, where tego run %s runs next", runDir, name)
	}
	var re *registry.Error
	switch {
	case se.Entry != nil:
		message(stderr, se.Entry.Path, 0, 0, fmt.Sprintf("tego learn: --save: the agent name %q is already this contract%s; nothing was "+
			"written; give another name", name, where), codeExists)
	case errors.As(se.Err, &re) && re.Code == registry.CodeAmbiguous:
		message(stderr, re.Path, 0, 0, fmt.Sprintf("tego learn: --save: the agent name %q is taken%s: %s; nothing was written; "+
			"give another name", name, where, se.Err.Error()), codeExists)
	case errors.As(se.Err, &re):
		message(stderr, re.Path, 0, 0, fmt.Sprintf("tego learn: --save: the registry cannot say whether %q is free%s: %s; nothing "+
			"was written", name, where, se.Err.Error()), re.Code)
	default:
		message(stderr, "", 0, 0, fmt.Sprintf("tego learn: --save: the registry cannot say whether %q is free%s: %s; nothing "+
			"was written", name, where, se.Err.Error()), codeIO)
	}
}

// learnStateDirs are tego's own directories for run dir: the run's record, the ledger root it lies in, the chain
// anchor's directory (~/.tego) and the host state directory, each as written and with its symlinks followed. A
// proposal never writes any of them, since tego refuses a contract that lets the agent.
func learnStateDirs(runDir string, mc *machineOnce) []string {
	dirs := []string{runDir, "/run/tego"}
	if m, err := mc.load(); err == nil && m != nil {
		if root, err := ledgerRootOf(m); err == nil {
			dirs = append(dirs, root)
		}
		if a, err := anchorPath(m); err == nil {
			dirs = append(dirs, filepath.Dir(a))
		}
	}
	for _, d := range slices.Clone(dirs) {
		if real, err := filepath.EvalSymlinks(d); err == nil && real != d {
			dirs = append(dirs, real)
		}
	}
	return dirs
}

// writeProposal creates the new file out with the proposal, mode 0600. An existing file, a link included, is
// refused and left as it is: the proposal is something to review beside the contract in use, never over it.
func writeProposal(out, text string, p *learn.Proposal, stderr io.Writer) int {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		code := codeIO
		exit := identity.ExitError
		if errors.Is(err, fs.ErrExist) {
			code, exit = codeExists, identity.ExitFinding // R25: a finding, as init's refusal of a foreign file is
		}
		message(stderr, out, 0, 0, "tego learn: "+err.Error()+": nothing was written; give --out a new file", code)
		return exit
	}
	_, err = io.WriteString(f, text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		message(stderr, out, 0, 0, "tego learn: write: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if abs, err := filepath.Abs(out); err == nil {
		warnWritable(stderr, abs, p)
	}
	fmt.Fprintf(stderr, "tego learn: wrote %s (mode 0600): a proposal for you to review; check it with tego compile %s\n", out, out)
	return identity.ExitOK
}

// warnWritable says so when the file just written lies inside one of its own fs.write entries: tego refuses to run
// a contract the agent could rewrite, so the proposal has to be kept elsewhere.
func warnWritable(stderr io.Writer, abs string, p *learn.Proposal) {
	dir := filepath.Dir(abs)
	for _, w := range p.WriteDirs() {
		if w = strings.TrimSuffix(w, "/"); w != "" && (dir == w || strings.HasPrefix(dir, w+"/")) {
			message(stderr, abs, 0, 0, fmt.Sprintf("tego learn: this file lies inside its own fs.write entry %q, which tego refuses to run: keep the contract outside the workspace", w), agent.CodeContradiction)
			return
		}
	}
}
