// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// field is one value read from a layer with the line it came from; set is false when absent.
type field[T any] struct {
	value     T
	line, col int
	set       bool
}

// layerData is the typed content of one layer file, before merging.
type layerData struct {
	version          field[int]
	tier             field[string]
	capture          field[string]
	ledgerRoot       field[string]
	prices           field[string]
	profiles         field[string]
	registry         field[string]
	privilegedBinary field[string]
	logLevel         field[string]
	landlockAudit    field[string]
	forwarderListen  field[string]
	retention        field[time.Duration]
	gcInterval       field[time.Duration]
	maxRunBytes      field[ByteSize]
	stopGrace        field[time.Duration]
	askTimeout       field[time.Duration]
	askNotify        field[[]string]
	ringbuf          field[ByteSize]
	bpfLinger        field[time.Duration]
	ringBudget       field[ByteSize]
	bpfPlane         field[string]
	resolver         field[ResolverMode]
	deniedResolved   field[[]netip.Prefix]
	users            field[map[string]UserPolicy]
	limits           limitsData
}

// limitsData is the limits: mapping of one layer.
type limitsData struct {
	cpu        field[float64]
	cpuWeight  field[int]
	memory     field[ByteSize]
	memoryHigh field[ByteSize]
	pids       field[int]
	tokens     field[int64]
	costUSD    field[float64]
	wall       field[time.Duration]
	stallAfter field[time.Duration]
	repeats    field[int]
}

// ErrInvalid is the sentinel wrapped when a layer does not parse or holds an invalid value.
var ErrInvalid = errors.New("config: invalid layer")

// yamlLine extracts the line yaml.v3 puts in its syntax error messages.
var yamlLine = regexp.MustCompile(`^yaml: line (\d+): `)

// parser walks one layer's node tree, collecting diagnostics instead of stopping at the first.
type parser struct {
	file  string
	diags []Diagnostic
}

func (p *parser) errorf(n *yaml.Node, format string, args ...any) {
	line, col := 0, 0
	if n != nil {
		line, col = n.Line, n.Column
	}
	p.diags = append(p.diags, Diagnostic{File: p.file, Line: line, Col: col,
		Message: fmt.Sprintf(format, args...), Code: CodeInvalid, Severity: SeverityError})
}

func (p *parser) warnf(n *yaml.Node, code, format string, args ...any) {
	p.diags = append(p.diags, Diagnostic{File: p.file, Line: n.Line, Col: n.Column,
		Message: fmt.Sprintf(format, args...), Code: code, Severity: SeverityWarning})
}

// parseLayer decodes one layer file. Every problem becomes an error diagnostic (CodeInvalid); the
// returned data is only meaningful when no diagnostic is an error.
func parseLayer(file string, data []byte) (*layerData, []Diagnostic) {
	p := &parser{file: file}
	d := &layerData{}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		line := 0
		msg := err.Error()
		col := 0
		if m := yamlLine.FindStringSubmatch(msg); m != nil {
			line, _ = strconv.Atoi(m[1])
			msg = "yaml: " + strings.TrimPrefix(msg, m[0])
		} else if strings.Contains(msg, "UTF-8") {
			// yaml.v3 gives a bad encoding no position; the first invalid byte is found here.
			line, col = invalidUTF8At(data)
		}
		p.diags = append(p.diags, Diagnostic{File: file, Line: line, Col: col, Message: msg, Code: CodeInvalid, Severity: SeverityError})
		return d, p.diags
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return d, nil // empty file: a present layer that sets nothing
	}
	// A layer is one document. yaml.Unmarshal read the first and dropped the rest, so ceilings appended
	// after a `---` silently did not apply.
	if n := YAMLDocuments(data); n > 1 {
		p.diags = append(p.diags, Diagnostic{File: file, Line: 1, Col: 1,
			Message: fmt.Sprintf("%s holds %d YAML documents; a layer is one: remove every '---' separator after the first document", file, n),
			Code:    CodeInvalid, Severity: SeverityError})
		return d, p.diags
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return d, nil
	}
	for _, kv := range p.mapping(root) {
		p.topLevel(d, kv.key, kv.value)
	}
	return d, p.diags
}

// invalidUTF8At is the 1-based line and byte column of the first byte of data that does not begin a valid
// UTF-8 sequence, 0, 0 when there is none.
func invalidUTF8At(data []byte) (line, col int) {
	line, start := 1, 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size <= 1 {
			return line, i - start + 1
		}
		if data[i] == '\n' {
			line, start = line+1, i+1
		}
		i += size
	}
	return 0, 0
}

// keyed is one mapping entry with its key node.
type keyed struct {
	name       string
	key, value *yaml.Node
}

// mapping returns the entries of a mapping node in order, reporting duplicate keys and non-mappings.
func (p *parser) mapping(n *yaml.Node) []keyed {
	if n.Kind != yaml.MappingNode {
		p.errorf(n, "expected a mapping")
		return nil
	}
	seen := map[string]bool{}
	out := make([]keyed, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if seen[k.Value] {
			p.errorf(k, "duplicate key %q", k.Value)
			continue
		}
		seen[k.Value] = true
		out = append(out, keyed{name: k.Value, key: k, value: v})
	}
	return out
}

func (p *parser) topLevel(d *layerData, key, v *yaml.Node) {
	switch key.Value {
	case "version":
		p.version(d, v)
	case "tier":
		d.tier = p.ranked(v, "tier", tierRank)
	case "capture":
		d.capture = p.ranked(v, "capture", captureRank)
	case "ledger_root":
		d.ledgerRoot = p.path(v, "ledger_root", false)
	case "retention":
		d.retention = p.duration(v, "retention")
	case "gc_interval":
		d.gcInterval = p.duration(v, "gc_interval")
	case "stop_grace":
		d.stopGrace = p.duration(v, "stop_grace")
		if d.stopGrace.set && d.stopGrace.value == 0 {
			p.warnf(v, CodeAdvisory, "stop_grace: 0s kills the run immediately on stop (fast-kill mode)")
		}
	case "limits":
		p.limits(&d.limits, v)
	case "ask":
		p.ask(d, v)
	case "record":
		p.record(d, v)
	case "bpf":
		p.bpf(d, v)
	case "resolver":
		d.resolver = p.resolver(v)
	case "denied_resolved_addresses":
		d.deniedResolved = p.prefixes(v, "denied_resolved_addresses")
	case "forwarder":
		p.forwarder(d, v)
	case "prices":
		d.prices = p.path(v, "prices", true)
	case "profiles":
		d.profiles = p.path(v, "profiles", true)
	case "registry":
		d.registry = p.path(v, "registry", true)
	case "log":
		p.log(d, v)
	case "landlock":
		p.landlock(d, v)
	case "privileged_binary":
		d.privilegedBinary = p.path(v, "privileged_binary", true)
	case "users":
		d.users = p.users(v)
	default:
		p.errorf(key, "unknown key %q", key.Value)
	}
}

// version applies E14 (absent = 0, handled by the zero field) and E15 (non-zero is an error).
func (p *parser) version(d *layerData, v *yaml.Node) {
	d.version = p.integer(v, "version", 0)
	if d.version.set && d.version.value != 0 {
		p.errorf(v, "unsupported machine config version %d (this binary supports version 0)", d.version.value)
	}
}

func (p *parser) limits(l *limitsData, v *yaml.Node) {
	for _, kv := range p.mapping(v) {
		switch kv.name {
		case "cpu":
			l.cpu = p.float(kv.value, "limits.cpu")
			if l.cpu.set && !CPUCoresInRange(l.cpu.value) {
				// A ceiling of 0 cores, or of more than cpu.max can hold, is EINVAL at every run's start
				// (CPUCoresInRange).
				p.errorf(kv.value, "limits.cpu: %q is outside %v..%v, the cores the kernel's cpu.max takes",
					kv.value.Value, MinCPUCores, MaxCPUCores)
				l.cpu.set = false
			}
		case "cpu_weight":
			// cpu.weight is 1..10000 in the kernel and in the contract (agent-contract.md §2). A ceiling
			// outside it has no enforceable reading: 0 would resolve as a budget that cgroup.limitFiles
			// then skips (the machine's 0 is a real value everywhere else), and above 10000 is
			// EINVAL at every run's startup. Refused here, where the operator wrote it.
			l.cpuWeight = p.integerIn(kv.value, "limits.cpu_weight", 1, 10000)
		case "memory":
			l.memory = p.limitBytes(kv.value, "limits.memory")
			// 0 is the tightest budget, not "unbounded" (E16), so it is kept; what it does is said
			// where it is written.
			if l.memory.set && l.memory.value == 0 {
				p.warnf(kv.value, CodeAdvisory, "limits.memory: 0 leaves no memory to any run: each is killed by the OOM killer as it starts")
			} else if l.memory.set && int64(l.memory.value) < MinStartMemory {
				p.warnf(kv.value, CodeAdvisory, "limits.memory: %s may not start a run: tego's own stage needs about %s in the run's cgroup before the agent exists",
					l.memory.value, ByteSize(MinStartMemory))
			}
		case "memory_high":
			l.memoryHigh = p.limitBytes(kv.value, "limits.memory_high")
			if l.memoryHigh.set && int64(l.memoryHigh.value) < MinStartMemory {
				p.warnf(kv.value, CodeAdvisory, "limits.memory_high: %s may not start a run: tego's own stage is throttled there before the agent exists",
					l.memoryHigh.value)
			}
		case "pids":
			l.pids = p.integerIn(kv.value, "limits.pids", 0, PidsMax)
			if l.pids.set && l.pids.value == 0 {
				p.warnf(kv.value, CodeAdvisory, "limits.pids: 0 lets no process into a run's cgroup: every run fails to start")
			} else if l.pids.set && l.pids.value < MinStartPids {
				p.warnf(kv.value, CodeAdvisory, "limits.pids: %d is below the %d tasks tego's own stage holds in a run's cgroup before the agent exists: every run fails to start",
					l.pids.value, MinStartPids)
			}
		case "tokens":
			l.tokens = p.integer64(kv.value, "limits.tokens")
		case "cost_usd":
			l.costUSD = p.float(kv.value, "limits.cost_usd")
		case "wall":
			l.wall = p.limitDuration(kv.value, "limits.wall")
		case "stall_after":
			l.stallAfter = p.limitDuration(kv.value, "limits.stall_after")
		case "repeats":
			l.repeats = p.integer(kv.value, "limits.repeats", 0)
		default:
			p.errorf(kv.key, "unknown key limits.%s", kv.name)
		}
	}
}

func (p *parser) ask(d *layerData, v *yaml.Node) {
	for _, kv := range p.mapping(v) {
		switch kv.name {
		case "timeout":
			d.askTimeout = p.duration(kv.value, "ask.timeout")
		case "notify":
			d.askNotify = p.stringList(kv.value, "ask.notify")
			for _, entry := range d.askNotify.value {
				if entry != "cli" && entry != "desktop" && !strings.HasPrefix(entry, "webhook:") {
					p.errorf(kv.value, "ask.notify: %q is not cli, desktop or webhook:<url>", entry)
				}
			}
			// cli (the run's answer line at its start) and desktop (a desktop notice per held request) are built
			// (ADR 0122); a webhook has no adapter yet, so naming one starts nothing and says so.
			if slices.ContainsFunc(d.askNotify.value, func(e string) bool { return strings.HasPrefix(e, "webhook:") }) {
				p.warnf(kv.value, CodeIgnored, "ask.notify: webhook is accepted but not built: no webhook is called; cli and desktop are")
			}
		default:
			p.errorf(kv.key, "unknown key ask.%s", kv.name)
		}
	}
}

// PidsMax is the largest pids.max the kernel accepts: PID_MAX_LIMIT on 64-bit. One more is EINVAL at every
// run's startup, so the machine parser and the contract schema both refuse it where it is written.
const PidsMax = 4194304

// MinStartPids and MinStartMemory are the least a run's own start takes in the run's cgroup, before the agent exists:
// the launcher's child stage is a Go process under the run's limits from its first instruction. Measured on
// 2026-11-01 at tier landlock: pids 5 fails every time and 6 passes, memory 4 MiB fails and 6 MiB passes. The machine
// parser warns of a ceiling below them where it is written, and the contract compile (agent-contract.md R11) of a
// limit below them, the contract's or the ceiling's.
const (
	MinStartPids   = 6
	MinStartMemory = 8 << 20
)

// RingbufMax is the largest record.ringbuf a run accepts: the ring map's max_entries is 32-bit. The parser and
// the cgroup launcher's validateRingbuf both read it, so a value the launcher refuses never passes the parser.
const RingbufMax = 1 << 31

// MinRunBytes is the smallest record.max_run_bytes the parser takes: a run_start line alone is a few KiB.
const MinRunBytes = ByteSize(64 << 10)

// record parses record.max_run_bytes, at least MinRunBytes, and record.ringbuf, and applies E16: a power of two and a page multiple, never rounded, and at most RingbufMax.
func (p *parser) record(d *layerData, v *yaml.Node) {
	for _, kv := range p.mapping(v) {
		switch kv.name {
		case "ringbuf":
			d.ringbuf = p.bytes(kv.value, "record.ringbuf")
			if d.ringbuf.set && int64(d.ringbuf.value) > RingbufMax {
				p.errorf(kv.value, "record.ringbuf: %s exceeds the %d-byte ring map limit", d.ringbuf.value, int64(RingbufMax))
			} else if d.ringbuf.set && (!d.ringbuf.value.IsPowerOfTwo() || int64(d.ringbuf.value)%int64(os.Getpagesize()) != 0) {
				p.errorf(kv.value, "record.ringbuf: %s is not a power-of-two page multiple", d.ringbuf.value)
			}
		case "max_run_bytes":
			d.maxRunBytes = p.bytes(kv.value, "record.max_run_bytes")
			if d.maxRunBytes.set && d.maxRunBytes.value < MinRunBytes {
				p.errorf(kv.value, "record.max_run_bytes: %s is under %s, which ends a run before it records anything",
					d.maxRunBytes.value, MinRunBytes)
				d.maxRunBytes.set = false
			}
		default:
			p.errorf(kv.key, "unknown key record.%s", kv.name)
		}
	}
}

// bpf parses bpf.linger, a duration of 0 or more, bpf.ring_budget, a size of 0 or more (0: no run gets a
// ring, so every tier-2 run is refused), and bpf.plane, one of auto, lsm and fmod_ret.
func (p *parser) bpf(d *layerData, v *yaml.Node) {
	for _, kv := range p.mapping(v) {
		switch kv.name {
		case "linger":
			d.bpfLinger = p.duration(kv.value, "bpf.linger")
		case "ring_budget":
			d.ringBudget = p.bytes(kv.value, "bpf.ring_budget")
		case "plane":
			d.bpfPlane = p.str(kv.value, "bpf.plane")
			switch d.bpfPlane.value {
			case PlaneAuto, PlaneLSM, PlaneFmodRet:
			default:
				if d.bpfPlane.set {
					p.errorf(kv.value, "bpf.plane: %q is not auto, lsm or fmod_ret", d.bpfPlane.value)
				}
			}
		default:
			p.errorf(kv.key, "unknown key bpf.%s", kv.name)
		}
	}
}

func (p *parser) forwarder(d *layerData, v *yaml.Node) {
	for _, kv := range p.mapping(v) {
		switch kv.name {
		case "listen":
			d.forwarderListen = p.str(kv.value, "forwarder.listen")
			if d.forwarderListen.set {
				if why := checkListen(d.forwarderListen.value); why != "" {
					p.errorf(kv.value, "forwarder.listen: %s", why)
				}
			}
		default:
			p.errorf(kv.key, "unknown key forwarder.%s", kv.name)
		}
	}
}

func (p *parser) log(d *layerData, v *yaml.Node) {
	for _, kv := range p.mapping(v) {
		switch kv.name {
		case "level":
			d.logLevel = p.str(kv.value, "log.level")
			switch d.logLevel.value {
			case "debug", "info", "warn":
			default:
				if d.logLevel.set {
					p.errorf(kv.value, "log.level: %q is not debug, info or warn", d.logLevel.value)
				}
			}
		default:
			p.errorf(kv.key, "unknown key log.%s", kv.name)
		}
	}
}

// landlock parses landlock.audit, refusing any value but the two a launcher knows how to apply: an unknown
// one silently read as off would be an audit the operator believes is on.
func (p *parser) landlock(d *layerData, v *yaml.Node) {
	for _, kv := range p.mapping(v) {
		switch kv.name {
		case "audit":
			d.landlockAudit = p.str(kv.value, "landlock.audit")
			switch d.landlockAudit.value {
			case LandlockAuditOff, LandlockAuditNewExec:
			default:
				if d.landlockAudit.set {
					p.errorf(kv.value, "landlock.audit: %q is not off or new-exec", d.landlockAudit.value)
				}
			}
		default:
			p.errorf(kv.key, "unknown key landlock.%s", kv.name)
		}
	}
}

// resolver parses "auto" or a list of ip[:port] servers (port 53 when omitted).
func (p *parser) resolver(v *yaml.Node) field[ResolverMode] {
	f := field[ResolverMode]{line: v.Line, col: v.Column, set: true}
	if v.Kind == yaml.ScalarNode {
		if v.Value == Auto {
			f.value = ResolverMode{Auto: true}
			return f
		}
		p.errorf(v, "resolver: %q is not auto or a list of servers", v.Value)
		return f
	}
	list := p.stringList(v, "resolver")
	for _, s := range list.value {
		ap, err := parseServer(s)
		if err != nil {
			p.errorf(v, "resolver: %q is not ip or ip:port", s)
			continue
		}
		f.value.Servers = append(f.value.Servers, ap)
	}
	return f
}

// prefixes parses a list of CIDRs; a bare address is its own /32 or /128. An IPv4-mapped IPv6 prefix is
// refused rather than guessed at, since the matcher compares unmapped addresses and would never meet it.
func (p *parser) prefixes(v *yaml.Node, key string) field[[]netip.Prefix] {
	list := p.stringList(v, key)
	f := field[[]netip.Prefix]{line: list.line, col: list.col, set: list.set, value: []netip.Prefix{}}
	for _, s := range list.value {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				p.errorf(v, "%s: %q is not a cidr or an address", key, s)
				continue
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		if pfx.Addr().Is4In6() || pfx.Addr().Zone() != "" {
			p.errorf(v, "%s: %q: write the IPv4 form, without a zone", key, s)
			continue
		}
		f.value = append(f.value, pfx.Masked())
	}
	return f
}

// parseServer accepts "1.1.1.1", "1.1.1.1:53", "[::1]:53" and "::1".
func parseServer(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, 53), nil
}

func (p *parser) users(v *yaml.Node) field[map[string]UserPolicy] {
	f := field[map[string]UserPolicy]{line: v.Line, col: v.Column, set: true, value: map[string]UserPolicy{}}
	for _, kv := range p.mapping(v) {
		// uid_t is 32 bits and 4294967295 is (uid_t)-1; one canonical spelling per uid, so "007" and
		// "7" cannot be two entries for the same user.
		if n, err := strconv.ParseUint(kv.name, 10, 32); err != nil || n == 0xffffffff || kv.name != strconv.FormatUint(n, 10) {
			p.errorf(kv.key, "users: %q is not a uid", kv.name)
			continue
		}
		var pol UserPolicy
		for _, sub := range p.mapping(kv.value) {
			switch sub.name {
			case "contracts":
				pol.Contracts = p.stringList(sub.value, "users."+kv.name+".contracts").value
			case "max_runs":
				pol.MaxRuns = p.integer(sub.value, "users."+kv.name+".max_runs", 0).value
			default:
				p.errorf(sub.key, "unknown key users.%s.%s", kv.name, sub.name)
			}
		}
		f.value[kv.name] = pol
	}
	return f
}

// scalar checks v is a scalar and returns its text.
func (p *parser) scalar(v *yaml.Node, key string) (string, bool) {
	if v.Kind != yaml.ScalarNode {
		p.errorf(v, "%s: expected a scalar", key)
		return "", false
	}
	return v.Value, true
}

func (p *parser) str(v *yaml.Node, key string) field[string] {
	s, ok := p.scalar(v, key)
	return field[string]{value: s, line: v.Line, col: v.Column, set: ok}
}

// path parses a filesystem path setting: absolute, or "~/..." for load to expand. A YAML null ("null",
// "~"), a relative path and "~user/x" were once taken as the text they spell, so compile resolved them
// against the cwd or home while every run refused them as not absolute. allowEmpty admits an explicit
// empty value, which means "none" for the keys that have a none.
func (p *parser) path(v *yaml.Node, key string, allowEmpty bool) field[string] {
	f := p.str(v, key)
	if !f.set {
		return f
	}
	empty := f.value == "" && (v.Tag == "!!null" || v.Tag == "!!str" || v.Tag == "")
	switch {
	case empty && allowEmpty:
		return f
	case empty:
		p.errorf(v, "%s: is empty", key)
	case v.Tag == "!!null":
		p.errorf(v, "%s: %q is a YAML null, not a path", key, f.value)
	case strings.HasPrefix(f.value, "/"):
		// A path whose walk reaches procfs (/proc/self/cwd/reg, /dev/fd/../cwd/reg) names a file relative to the process
		// that opens it, another one in every working directory, as a relative path does.
		via, proc := ThroughProc(f.value)
		if !proc {
			return f
		}
		p.errorf(v, "%s: %q reaches procfs (%q), which names a file relative to the process that opens it", key, f.value, via)
	case strings.HasPrefix(f.value, "~/"):
		return f
	default:
		p.errorf(v, "%s: %q is not an absolute path or a path starting with ~/", key, f.value)
	}
	f.set = false
	return f
}

// name parses a tier or capture name: a non-empty word.
func (p *parser) name(v *yaml.Node, key string) field[string] {
	f := p.str(v, key)
	if f.set && (f.value == "" || strings.ContainsAny(f.value, " \t/")) {
		p.errorf(v, "%s: %q is not a name", key, f.value)
	}
	return f
}

// ranked parses a named ceiling: auto or one of rank's names, refused at its own line otherwise. The
// names were once left for backend.ParseTier to refuse downstream (R24 as first written), which it did
// at the first run, as exit 125 naming no file, while compile printed `tier bogus`, doctor reported
// tier none, and a capture name nothing read ran with capture off. The rank maps are this package's own,
// so the check needs no import of backend.
func (p *parser) ranked(v *yaml.Node, key string, rank map[string]int) field[string] {
	f := p.name(v, key)
	if !f.set || f.value == "" || strings.ContainsAny(f.value, " \t/") {
		return f
	}
	if _, ok := rank[f.value]; ok || f.value == Auto {
		return f
	}
	names := slices.SortedFunc(maps.Keys(rank), func(a, b string) int { return rank[a] - rank[b] })
	p.errorf(v, "%s: %q is not %s or %s", key, f.value, Auto, strings.Join(names, ", "))
	f.set = false
	return f
}

// integer parses a non-negative int not below minimum (E20: negatives rejected).
func (p *parser) integer(v *yaml.Node, key string, minimum int) field[int] {
	f := field[int]{line: v.Line, col: v.Column}
	s, ok := p.scalar(v, key)
	if !ok {
		return f
	}
	n, err := strconv.ParseInt(s, 10, 0)
	if err != nil || int(n) < minimum {
		p.errorf(v, "%s: %q is not an integer >= %d", key, s, minimum)
		return f
	}
	f.value, f.set = int(n), true
	return f
}

// integerIn parses an int in [lo, hi], for a key the kernel itself bounds on both sides.
func (p *parser) integerIn(v *yaml.Node, key string, lo, hi int) field[int] {
	f := field[int]{line: v.Line, col: v.Column}
	s, ok := p.scalar(v, key)
	if !ok {
		return f
	}
	n, err := strconv.ParseInt(s, 10, 0)
	if err != nil || int(n) < lo || int(n) > hi {
		p.errorf(v, "%s: %q is not an integer in %d..%d", key, s, lo, hi)
		return f
	}
	f.value, f.set = int(n), true
	return f
}

func (p *parser) integer64(v *yaml.Node, key string) field[int64] {
	f := field[int64]{line: v.Line, col: v.Column}
	s, ok := p.scalar(v, key)
	if !ok {
		return f
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		p.errorf(v, "%s: %q is not a non-negative 64-bit integer", key, s)
		return f
	}
	f.value, f.set = n, true
	return f
}

func (p *parser) float(v *yaml.Node, key string) field[float64] {
	f := field[float64]{line: v.Line, col: v.Column}
	s, ok := p.scalar(v, key)
	if !ok {
		return f
	}
	// The contract's spelling (IsDecimal): ParseFloat alone also took hex floats and "1_0", and read a
	// nonzero 1e-400 as a 0 ceiling, a zero budget for every run.
	x, err := strconv.ParseFloat(s, 64)
	if !IsDecimal(s) || err != nil || x < 0 || x != x || x > 1e300 || strings.HasPrefix(s, "-") {
		p.errorf(v, "%s: %q is not a non-negative decimal number", key, s)
		return f
	}
	if Underflows(s, x) {
		p.errorf(v, "%s: %q is too small to represent and would read as 0; write 0 for none", key, s)
		return f
	}
	f.value, f.set = x, true
	return f
}

func (p *parser) duration(v *yaml.Node, key string) field[time.Duration] {
	f := field[time.Duration]{line: v.Line, col: v.Column}
	s, ok := p.scalar(v, key)
	if !ok {
		return f
	}
	d, err := ParseDuration(s)
	if err != nil {
		p.errorf(v, "%s: %s", key, unitDetail(err))
		return f
	}
	f.value, f.set = d, true
	return f
}

func (p *parser) bytes(v *yaml.Node, key string) field[ByteSize] {
	f := field[ByteSize]{line: v.Line, col: v.Column}
	s, ok := p.scalar(v, key)
	if !ok {
		return f
	}
	b, err := ParseByteSize(s)
	if err != nil {
		p.errorf(v, "%s: %s", key, unitDetail(err))
		return f
	}
	f.value, f.set = b, true
	return f
}

// unitDetail strips the ErrUnit prefix so the diagnostic reads "<key>: <detail>".
func unitDetail(err error) string {
	return strings.TrimPrefix(err.Error(), ErrUnit.Error()+": ")
}

func (p *parser) stringList(v *yaml.Node, key string) field[[]string] {
	f := field[[]string]{line: v.Line, col: v.Column, set: true}
	if v.Kind != yaml.SequenceNode {
		p.errorf(v, "%s: expected a list", key)
		f.set = false
		return f
	}
	f.value = make([]string, 0, len(v.Content))
	for _, item := range v.Content {
		if s, ok := p.scalar(item, key); ok {
			f.value = append(f.value, s)
		}
	}
	return f
}

// The contract's limits take one unit ("<n>(ms|s|m|h|d)", "<n>(B|KiB|MiB|GiB|TiB)"; pkg/spec/agent units.go),
// and the machine config's limits are ceilings "in the same units", so limits.wall, stall_after, memory and
// memory_high take those spellings only. "1h30m" or "1PiB" loaded here and were a schema error in a contract.
// retention, stop_grace and the other durations keep ParseDuration's wider grammar.
var limitDurationRE = regexp.MustCompile(`^[0-9]+(ms|s|m|h|d)$`)

func (p *parser) limitDuration(v *yaml.Node, key string) field[time.Duration] {
	if v.Kind == yaml.ScalarNode && !limitDurationRE.MatchString(strings.TrimSpace(v.Value)) {
		p.errorf(v, "%s: %q is not a duration in one unit, <n>(ms|s|m|h|d), such as 2h or 10m, the contract's spelling", key, v.Value)
		return field[time.Duration]{line: v.Line, col: v.Column}
	}
	return p.duration(v, key)
}

func (p *parser) limitBytes(v *yaml.Node, key string) field[ByteSize] {
	if v.Kind == yaml.ScalarNode && strings.HasSuffix(strings.TrimSpace(v.Value), "PiB") {
		p.errorf(v, "%s: %q is not an integer with an IEC suffix (B, KiB, MiB, GiB, TiB), the contract's spelling", key, v.Value)
		return field[ByteSize]{line: v.Line, col: v.Column}
	}
	return p.bytes(v, key)
}

// checkListen says why a forwarder.listen is not a loopback host:port, or "" when it is. The forwarder is
// loopback only (agent-contract R19, P0-DESIGN section 3.3): the host is "localhost" or a loopback IP
// literal, so 0.0.0.0, an empty host and a routable address are refused where written, and the port is a
// number in 0..65535 (net.Listen also takes a service name; here a port is a number, so a typo is not a
// runtime bind failure on the first run that has models[]).
func checkListen(v string) string {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Sprintf("%q is not host:port", v)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || port != strconv.FormatUint(n, 10) {
		return fmt.Sprintf("%q has a port that is not a number in 0..65535", v)
	}
	if host == "localhost" {
		return ""
	}
	if a, err := netip.ParseAddr(host); err != nil || !a.IsLoopback() {
		return fmt.Sprintf("%q is not a loopback address: the forwarder listens on 127.0.0.1, [::1] or localhost only", v)
	}
	return ""
}
