// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const etcLayer = `version: 0
tier: cgroup
capture: uprobe
stop_grace: 5s
limits:
  cpu: "8"
  memory: 32GiB
  pids: 4096
  wall: 24h
log:
  level: warn
`

const userLayer = `tier: bpflsm
capture: forwarder
ledger_root: ~/runs
limits:
  memory: 16GiB
  pids: 4096
  tokens: 1000000
ask:
  timeout: 2m
  notify: [cli, desktop]
`

const envLayer = `limits:
  memory: 64GiB
  cpu: "4"
retention: 7d
resolver: [1.1.1.1, "[::1]:5353"]
forwarder:
  listen: 127.0.0.1:8080
`

// layers writes the named layers into dir and returns Sources pointing at them.
func layers(t *testing.T, dir string, etc, user, env string) Sources {
	t.Helper()
	var src Sources
	if etc != "" {
		src.Etc = writeFile(t, dir, "etc.yaml", etc, 0o644)
	}
	if user != "" {
		src.User = writeFile(t, dir, "user.yaml", user, 0o600)
	}
	if env != "" {
		src.EnvFile = writeFile(t, dir, "env.yaml", env, 0o600)
	}
	return src
}

func mustLoad(t *testing.T, src Sources, home string) (*Machine, []Diagnostic) {
	t.Helper()
	m, diags, err := LoadSources(src, home, os.Getuid(), TrustAbort)
	if err != nil {
		t.Fatalf("LoadSources: %v (diags %v)", err, diags)
	}
	return m, diags
}

// Layer combinations with provenance per key (R14–R16).
// identity-config.md E11: an equal (not raised) ceiling in a later layer moves Provenance and warns nothing.
// identity-config.md R26: machine ask settings retain their values and provenance;
// an ask.notify webhook entry warns CodeIgnored because that adapter is not built (cli and desktop are, ADR 0122).
func TestLoadLayers(t *testing.T) {
	cases := []struct {
		name           string
		etc, user, env bool
		check          func(t *testing.T, m *Machine, diags []Diagnostic, src Sources)
	}{
		{name: "none: built-in everywhere", check: func(t *testing.T, m *Machine, diags []Diagnostic, _ Sources) {
			if len(diags) != 0 {
				t.Errorf("diags %v", diags)
			}
			if m.Tier.Bounded || !m.Tier.Value.Auto || m.Tier.Source.Layer != LayerBuiltin {
				t.Errorf("tier %+v", m.Tier)
			}
			if m.Limits.Memory.Bounded || m.Limits.Memory.Ptr() != nil {
				t.Error("built-in ceiling bounded")
			}
			if m.LedgerRoot.Value != "/home/test/.tego/runs" || m.Prices.Value != "/home/test/.tego/prices.yaml" {
				t.Errorf("home expansion: %q %q", m.LedgerRoot.Value, m.Prices.Value)
			}
			if m.StopGrace.Value != DefaultStopGrace || m.Retention.Value != DefaultRetention || m.Record.Ringbuf.Value != DefaultRingbuf {
				t.Error("defaults")
			}
			if m.Home != "/home/test" {
				t.Errorf("Home = %q", m.Home)
			}
		}},
		{name: "etc only", etc: true, check: func(t *testing.T, m *Machine, diags []Diagnostic, src Sources) {
			if m.Tier.Value.Tier != "cgroup" || !m.Tier.Bounded || m.Tier.Source != (Provenance{File: src.Etc, Line: 2, Layer: LayerEtc}) {
				t.Errorf("tier %+v", m.Tier)
			}
			if m.Capture.Value.Capture != "uprobe" || m.Capture.Source.Line != 3 {
				t.Errorf("capture %+v", m.Capture)
			}
			if m.StopGrace.Value != 5*time.Second || m.StopGrace.Source.Line != 4 {
				t.Errorf("stop_grace %+v", m.StopGrace)
			}
			if p := m.Limits.CPU.Ptr(); p == nil || *p != 8 || m.Limits.CPU.Source.Line != 6 {
				t.Errorf("cpu %+v", m.Limits.CPU)
			}
			if m.Limits.Memory.Value != 32<<30 || m.Limits.Pids.Value != 4096 || m.Limits.Wall.Value != 24*time.Hour {
				t.Errorf("limits %+v", m.Limits)
			}
			if m.Log.Level.Value != "warn" || m.Log.Level.Source.Line != 11 {
				t.Errorf("log %+v", m.Log)
			}
			if m.Limits.Tokens.Bounded {
				t.Error("tokens should stay unbounded")
			}
		}},
		{name: "user only", user: true, check: func(t *testing.T, m *Machine, diags []Diagnostic, src Sources) {
			if m.Tier.Value.Tier != "bpflsm" || m.Tier.Source.Layer != LayerUser {
				t.Errorf("tier %+v", m.Tier)
			}
			if m.LedgerRoot.Value != "/home/test/runs" || m.LedgerRoot.Source.Line != 3 {
				t.Errorf("ledger_root %+v", m.LedgerRoot)
			}
			if m.Ask.Timeout.Value != 2*time.Minute || strings.Join(m.Ask.Notify.Value, ",") != "cli,desktop" {
				t.Errorf("ask %+v", m.Ask)
			}
		}},
		{name: "etc+user: user lowers memory, cannot raise tier or capture (R15), equal pids moves provenance (E11)", etc: true, user: true,
			check: func(t *testing.T, m *Machine, diags []Diagnostic, src Sources) {
				if m.Tier.Value.Tier != "cgroup" || m.Tier.Source.File != src.Etc {
					t.Errorf("tier %+v", m.Tier)
				}
				if m.Capture.Value.Capture != "forwarder" || m.Capture.Source.File != src.User {
					t.Errorf("capture %+v", m.Capture)
				}
				if m.Limits.Memory.Value != 16<<30 || m.Limits.Memory.Source.File != src.User || m.Limits.Memory.Source.Line != 5 {
					t.Errorf("memory %+v", m.Limits.Memory)
				}
				if m.Limits.Pids.Value != 4096 || m.Limits.Pids.Source.File != src.User {
					t.Errorf("pids provenance %+v", m.Limits.Pids)
				}
				if m.Limits.CPU.Value != 8 || m.Limits.CPU.Source.File != src.Etc {
					t.Errorf("cpu %+v", m.Limits.CPU)
				}
				want := "ceiling tier=cgroup kept from " + src.Etc + ":2"
				if !hasDiag(diags, CodeCeilingKept, want) {
					t.Errorf("missing %q in %v", want, diags)
				}
				if kept := countCode(diags, CodeCeilingKept); kept != 1 {
					t.Errorf("%d ceiling-kept diagnostics, want 1: %v", kept, diags)
				}
			}},
		{name: "all three: settings last-wins, ceilings transitive (I4)", etc: true, user: true, env: true,
			check: func(t *testing.T, m *Machine, diags []Diagnostic, src Sources) {
				if m.Limits.Memory.Value != 16<<30 || m.Limits.Memory.Source.File != src.User {
					t.Errorf("memory %+v", m.Limits.Memory)
				}
				if m.Limits.CPU.Value != 4 || m.Limits.CPU.Source.File != src.EnvFile {
					t.Errorf("cpu %+v", m.Limits.CPU)
				}
				if m.Retention.Value != 7*day || m.Retention.Source.Layer != LayerEnvFile {
					t.Errorf("retention %+v", m.Retention)
				}
				if m.Resolver.Value.Auto || len(m.Resolver.Value.Servers) != 2 || m.Resolver.Value.String() != "1.1.1.1:53,[::1]:5353" {
					t.Errorf("resolver %+v", m.Resolver)
				}
				if m.Forwarder.Listen.Value != "127.0.0.1:8080" {
					t.Errorf("listen %+v", m.Forwarder.Listen)
				}
				if !hasDiag(diags, CodeCeilingKept, "ceiling limits.memory=16GiB kept from "+src.User+":5") {
					t.Errorf("diags %v", diags)
				}
				if countCode(diags, CodeCeilingKept) != 2 {
					t.Errorf("diags %v", diags)
				}
			}},
		{name: "env only", env: true, check: func(t *testing.T, m *Machine, diags []Diagnostic, src Sources) {
			if m.Limits.Memory.Value != 64<<30 || m.Limits.Memory.Source.Layer != LayerEnvFile {
				t.Errorf("memory %+v", m.Limits.Memory)
			}
			if len(diags) != 0 {
				t.Errorf("diags %v", diags)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pick := func(on bool, s string) string {
				if on {
					return s
				}
				return ""
			}
			src := layers(t, trustedDir(t), pick(tc.etc, etcLayer), pick(tc.user, userLayer), pick(tc.env, envLayer))
			m, diags := mustLoad(t, src, "/home/test")
			tc.check(t, m, diags, src)
		})
	}
}

func hasDiag(diags []Diagnostic, code, message string) bool {
	for _, d := range diags {
		if d.Code == code && d.Message == message {
			return true
		}
	}
	return false
}

func countCode(diags []Diagnostic, code string) int {
	n := 0
	for _, d := range diags {
		if d.Code == code {
			n++
		}
	}
	return n
}

// A raise across three layers is refused transitively, auto never raises.
// identity-config.md I4: every ceiling's effective value is <= every layer's attempted value, transitively across the chain.
func TestCeilingChain(t *testing.T) {
	src := layers(t, trustedDir(t),
		"limits:\n  tokens: 100\ntier: landlock\n",
		"limits:\n  tokens: 50\ntier: auto\n",
		"limits:\n  tokens: 75\ntier: cgroup\n")
	m, diags := mustLoad(t, src, "")
	if m.Limits.Tokens.Value != 50 || m.Limits.Tokens.Source.File != src.User {
		t.Errorf("tokens %+v", m.Limits.Tokens)
	}
	if m.Tier.Value.Tier != "landlock" || m.Tier.Source.File != src.Etc {
		t.Errorf("tier %+v", m.Tier)
	}
	for _, want := range []string{
		"ceiling limits.tokens=50 kept from " + src.User + ":2",
		"ceiling tier=landlock kept from " + src.Etc + ":3",
	} {
		if !hasDiag(diags, CodeCeilingKept, want) {
			t.Errorf("missing %q in %v", want, diags)
		}
	}
	if countCode(diags, CodeCeilingKept) != 3 {
		t.Errorf("want 3 kept diagnostics: %v", diags)
	}
	for _, d := range diags {
		if d.Code == CodeCeilingKept && (d.File == "" || d.Line == 0 || d.Severity != SeverityWarning) {
			t.Errorf("kept diagnostic lacks location: %+v", d)
		}
	}
}

// An illegal tier or capture name is an error at
// its own file and line. It used to load, and then compile printed `tier quantum`, doctor reported tier
// none naming no file, the run exited 125, and an illegal capture name ran with capture off.
// observe is a run mode, never a ceiling (identity-config R17), so it is illegal here too.
func TestCeilingBadName(t *testing.T) {
	src := layers(t, trustedDir(t), "tier: quantum\ncapture: tap\n", "", "")
	_, diags, err := LoadSources(src, "", os.Getuid(), TrustAbort)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	for _, want := range []struct {
		line int
		msg  string
	}{
		{1, `tier: "quantum" is not auto or landlock, cgroup, bpflsm`},
		{2, `capture: "tap" is not auto or off, forwarder, uprobe`},
	} {
		found := false
		for _, d := range diags {
			if d.Severity == SeverityError && d.File == src.Etc && d.Line == want.line && d.Message == want.msg {
				found = true
			}
		}
		if !found {
			t.Errorf("no error %q at %s:%d in %v", want.msg, src.Etc, want.line, diags)
		}
	}
	for _, good := range []string{"auto", "landlock", "cgroup", "bpflsm"} {
		src := layers(t, trustedDir(t), "tier: "+good+"\n", "", "")
		if _, diags := mustLoad(t, src, ""); HasErrors(diags) {
			t.Errorf("tier %s: %v", good, diags)
		}
	}
	for _, good := range []string{"auto", "off", "forwarder", "uprobe"} {
		src := layers(t, trustedDir(t), "capture: "+good+"\n", "", "")
		if _, diags := mustLoad(t, src, ""); HasErrors(diags) {
			t.Errorf("capture %s: %v", good, diags)
		}
	}
	src = layers(t, trustedDir(t), "tier: observe\n", "", "")
	if _, _, err := LoadSources(src, "", os.Getuid(), TrustAbort); !errors.Is(err, ErrInvalid) {
		t.Errorf("tier: observe loaded (err %v); it is a run mode, not a ceiling", err)
	}
}

// TestNonUTF8LayerNamesItsLine: yaml.v3 reports a bad encoding with no position, so the diagnostic named
// no line.
func TestNonUTF8LayerNamesItsLine(t *testing.T) {
	src := layers(t, trustedDir(t), "log:\n  level: info\nprices: \"/x\xff\"\n", "", "")
	_, diags, err := LoadSources(src, "", os.Getuid(), TrustAbort)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err %v", err)
	}
	if !slices.ContainsFunc(diags, func(d Diagnostic) bool {
		return d.Severity == SeverityError && d.Line == 3 && d.Col == 12 && strings.Contains(d.Message, "UTF-8")
	}) {
		t.Errorf("no UTF-8 error at 3:12: %v", diags)
	}
}

// TestLimitEdges: the bounds of cpu.max load, and a 0 memory or pids ceiling, the tightest budget E16 keeps,
// loads with a warning at its line saying what it does to a run.
// identity-config.md E12: limits.memory: 0 is valid and Load keeps the zero ceiling (Compile's refusal is agent's).
func TestLimitEdges(t *testing.T) {
	for _, cpu := range []string{"0.01", "175921860"} {
		src := layers(t, trustedDir(t), "limits:\n  cpu: \""+cpu+"\"\n", "", "")
		if m, diags := mustLoad(t, src, ""); HasErrors(diags) || !m.Limits.CPU.Bounded {
			t.Errorf("cpu %s: %v", cpu, diags)
		}
	}
	src := layers(t, trustedDir(t), "limits:\n  memory: 0\n  pids: 0\n", "", "")
	m, diags := mustLoad(t, src, "")
	if !m.Limits.Memory.Bounded || m.Limits.Memory.Value != 0 || !m.Limits.Pids.Bounded || m.Limits.Pids.Value != 0 {
		t.Fatalf("zero ceilings lost: memory %+v pids %+v", m.Limits.Memory, m.Limits.Pids)
	}
	for _, want := range []struct {
		line int
		msg  string
	}{{2, "limits.memory: 0 leaves no memory to any run"}, {3, "limits.pids: 0 lets no process into a run's cgroup"}} {
		if !slices.ContainsFunc(diags, func(d Diagnostic) bool {
			return d.Code == CodeAdvisory && d.Severity == SeverityWarning && d.File == src.Etc && d.Line == want.line &&
				strings.HasPrefix(d.Message, want.msg)
		}) {
			t.Errorf("no advisory %q at line %d: %v", want.msg, want.line, diags)
		}
	}
}

// TestCeilingsBelowARunsStartWarn: a pids ceiling of 1 to 5, or a memory or memory_high ceiling under 8 MiB, loads (it
// is enforced as written) with a warning at its line: below it tego's own stage cannot start any run. Only 0 warned.
func TestCeilingsBelowARunsStartWarn(t *testing.T) {
	for _, tc := range []struct {
		yaml, msg string
		warned    bool
	}{
		{"limits:\n  pids: 3\n", "limits.pids: 3 is below the 6 tasks", true},
		{"limits:\n  pids: 6\n", "limits.pids", false},
		{"limits:\n  memory: 4MiB\n", "limits.memory: 4MiB may not start a run", true},
		{"limits:\n  memory: 8MiB\n", "limits.memory", false},
		{"limits:\n  memory_high: 1MiB\n", "limits.memory_high: 1MiB may not start a run", true},
	} {
		src := layers(t, trustedDir(t), tc.yaml, "", "")
		m, diags := mustLoad(t, src, "")
		if HasErrors(diags) || (!m.Limits.Pids.Bounded && !m.Limits.Memory.Bounded && !m.Limits.MemoryHigh.Bounded) {
			t.Fatalf("%q: not loaded as a ceiling: %v", tc.yaml, diags)
		}
		got := slices.ContainsFunc(diags, func(d Diagnostic) bool {
			return d.Code == CodeAdvisory && d.Severity == SeverityWarning && d.File == src.Etc && d.Line == 2 &&
				strings.HasPrefix(d.Message, tc.msg)
		})
		if got != tc.warned {
			t.Errorf("%q: warned %v, want %v: %v", tc.yaml, got, tc.warned, diags)
		}
	}
}

// T-config-version-1 (E14, E15) and other parse-time rules.
// identity-config.md E20: a negative limits value is rejected at parse (E20 negative pids case).
func TestLoadInvalid(t *testing.T) {
	cases := []struct {
		name    string
		content string
		message string // substring of an error diagnostic
	}{
		{"E15 version 1", "version: 1\n", "unsupported machine config version 1"},
		{"unknown key", "tiers: x\n", `unknown key "tiers"`},
		{"unknown nested key", "limits:\n  gpus: 1\n", "unknown key limits.gpus"},
		{"E16 ringbuf not a power of two", "record:\n  ringbuf: 3MiB\n", "record.ringbuf: 3MiB is not a power-of-two page multiple"},
		{"E16 ringbuf above the ring map limit", "record:\n  ringbuf: 4GiB\n", "record.ringbuf: 4GiB exceeds the 2147483648-byte ring map limit"},
		{"E16 ringbuf below a page", "record:\n  ringbuf: 512\n", "not a power-of-two page multiple"},
		{"max_run_bytes under 64KiB", "record:\n  max_run_bytes: 1KiB\n", "record.max_run_bytes: 1KiB is under 64KiB"},
		{"E20 negative pids", "limits:\n  pids: -1\n", `limits.pids: "-1" is not an integer in 0..4194304`},
		{"decimal byte suffix", "limits:\n  memory: 8GB\n", `limits.memory: "8GB" is not an integer with an IEC suffix`},
		{"limit wall compound", "limits:\n  wall: 1h30m\n", `limits.wall: "1h30m" is not a duration in one unit`},
		{"limit stall fraction", "limits:\n  stall_after: 1.5h\n", `limits.stall_after: "1.5h" is not a duration in one unit`},
		{"limit memory PiB", "limits:\n  memory: 1PiB\n", `limits.memory: "1PiB" is not an integer with an IEC suffix`},
		{"bad duration", "retention: 1w\n", `retention: "1w" is not a duration`},
		{"negative duration", "stop_grace: -5s\n", `stop_grace: "-5s" is negative`},
		{"bad log level", "log:\n  level: loud\n", `log.level: "loud" is not debug, info or warn`},
		{"bad notify", "ask:\n  notify: [pager]\n", `ask.notify: "pager" is not cli, desktop or webhook:<url>`},
		{"bad listen", "forwarder:\n  listen: nope\n", `forwarder.listen: "nope" is not host:port`},
		{"listen bad port", "forwarder:\n  listen: \"127.0.0.1:abc\"\n", `has a port that is not a number in 0..65535`},
		{"listen port too big", "forwarder:\n  listen: \"127.0.0.1:99999\"\n", `has a port that is not a number in 0..65535`},
		{"listen empty host", "forwarder:\n  listen: \":0\"\n", `is not a loopback address`},
		{"listen all interfaces", "forwarder:\n  listen: \"0.0.0.0:8080\"\n", `is not a loopback address`},
		{"listen routable", "forwarder:\n  listen: \"10.1.2.3:8080\"\n", `is not a loopback address`},
		{"bad resolver", "resolver: manual\n", `resolver: "manual" is not auto or a list of servers`},
		{"bad resolver server", "resolver: [example.com]\n", `resolver: "example.com" is not ip or ip:port`},
		{"bad denied range", "denied_resolved_addresses: [example.com]\n", `denied_resolved_addresses: "example.com" is not a cidr or an address`},
		{"mapped denied range", "denied_resolved_addresses: [\"::ffff:10.0.0.0/104\"]\n", `write the IPv4 form`},
		{"bad user key", "users:\n  bob: {max_runs: 1}\n", `users: "bob" is not a uid`},
		{"uid leading zeros", "users:\n  \"007\": {max_runs: 1}\n", `users: "007" is not a uid`},
		{"uid is uid_t -1", "users:\n  4294967295: {}\n", `users: "4294967295" is not a uid`},
		{"uid above 32 bits", "users:\n  4294967296: {}\n", `users: "4294967296" is not a uid`},
		{"duplicate key", "tier: a\ntier: b\n", `duplicate key "tier"`},
		{"not a mapping", "- a\n- b\n", "expected a mapping"},
		{"scalar expected", "tier: [a]\n", "tier: expected a scalar"},
		{"list expected", "ask:\n  notify: cli\n", "ask.notify: expected a list"},
		{"malformed yaml", "tier: [\n", "yaml:"},
		{"empty tier name", "tier: \"\"\n", `tier: "" is not a name`},
		{"fraction cpu weight", "limits:\n  cpu_weight: 1.5\n", `limits.cpu_weight: "1.5" is not an integer`},
		// cpu.weight's kernel range is 1..10000: a 0 resolved as a budget the cgroup writer skipped,
		// and anything above failed every run at startup with EINVAL.
		{"zero cpu weight", "limits:\n  cpu_weight: 0\n", `limits.cpu_weight: "0" is not an integer in 1..10000`},
		{"pids above the kernel range", "limits:\n  pids: 4194305\n", `limits.pids: "4194305" is not an integer in 0..4194304`},
		{"cpu weight above the kernel range", "limits:\n  cpu_weight: 10001\n", `limits.cpu_weight: "10001" is not an integer in 1..10000`},
		// cpu.max's kernel range is a quota of 1 ms to 2^44-1 µs a 100 ms period: outside it every run
		// failed at startup with EINVAL, exit 125.
		{"zero cpu", "limits:\n  cpu: 0\n", `limits.cpu: "0" is outside 0.01..175921860, the cores the kernel's cpu.max takes`},
		{"cpu below a millisecond a period", "limits:\n  cpu: \"0.001\"\n", `limits.cpu: "0.001" is outside`},
		{"cpu above cpu.max", "limits:\n  cpu: 999999999\n", `limits.cpu: "999999999" is outside`},
		{"tokens overflow", "limits:\n  tokens: 99999999999999999999\n", "limits.tokens"},
		{"cost nan", "limits:\n  cost_usd: nan\n", "limits.cost_usd"},
		// The contract's decimal spelling (agent schema costRE): ParseFloat alone took hex floats and "1_0",
		// and read a nonzero 1e-400 as a 0 ceiling, a zero budget for every run.
		{"cost hex float", "limits:\n  cost_usd: 0x1p3\n", `limits.cost_usd: "0x1p3" is not a non-negative decimal number`},
		{"cost underscore", "limits:\n  cost_usd: 1_0\n", `limits.cost_usd: "1_0" is not a non-negative decimal number`},
		{"cost underflow", "limits:\n  cost_usd: 1e-400\n", `limits.cost_usd: "1e-400" is too small to represent`},
		{"cpu hex float", "limits:\n  cpu: 0x1p3\n", `limits.cpu: "0x1p3" is not a non-negative decimal number`},
		// A layer is one document: ceilings after a `---` were dropped without a word.
		{"second document", "tier: landlock\n---\nlimits:\n  cost_usd: 5\n", "holds 2 YAML documents; a layer is one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := layers(t, trustedDir(t), tc.content, "", "")
			m, diags, err := LoadSources(src, "", os.Getuid(), TrustAbort)
			if m != nil || !errors.Is(err, ErrInvalid) {
				t.Fatalf("m=%v err=%v diags=%v", m, err, diags)
			}
			found := false
			for _, d := range diags {
				if d.Severity == SeverityError && d.Code == CodeInvalid && strings.Contains(d.Message, tc.message) {
					found = true
					if d.File != src.Etc || d.Line == 0 {
						t.Errorf("diagnostic lacks location: %+v", d)
					}
				}
			}
			if !found {
				t.Errorf("no diagnostic containing %q: %v", tc.message, diags)
			}
		})
	}
}

// identity-config.md E17: stop_grace: 0s loads with one advisory and no error (E17 case).
func TestLoadValid(t *testing.T) {
	cases := []struct {
		name    string
		content string
		check   func(t *testing.T, m *Machine, diags []Diagnostic)
	}{
		{"E14 version absent is 0", "tier: landlock\n", func(t *testing.T, m *Machine, _ []Diagnostic) {
			if m.Version != 0 {
				t.Errorf("version %d", m.Version)
			}
		}},
		{"empty file", "", func(t *testing.T, m *Machine, diags []Diagnostic) {
			if len(diags) != 0 || m.Tier.Bounded {
				t.Errorf("empty layer changed something: %v", diags)
			}
		}},
		{"comment only", "# nothing\n", func(t *testing.T, m *Machine, diags []Diagnostic) {
			if len(diags) != 0 {
				t.Errorf("diags %v", diags)
			}
		}},
		{"E17 stop_grace 0s is advisory", "stop_grace: 0s\n", func(t *testing.T, m *Machine, diags []Diagnostic) {
			if m.StopGrace.Value != 0 || countCode(diags, CodeAdvisory) != 1 || HasErrors(diags) {
				t.Errorf("stop_grace %+v diags %v", m.StopGrace, diags)
			}
		}},
		// cli and desktop are built (ADR 0122); a webhook entry is accepted and still warned as not built.
		{"ask.notify webhook is accepted but not built", "ask:\n  notify: [cli, \"webhook:https://hooks.example/x\"]\n", func(t *testing.T, m *Machine, diags []Diagnostic) {
			if len(m.Ask.Notify.Value) != 2 || countCode(diags, CodeIgnored) != 1 || HasErrors(diags) {
				t.Errorf("notify %+v diags %v", m.Ask.Notify, diags)
			}
			for _, d := range diags {
				if d.Code == CodeIgnored && (!strings.Contains(d.Message, "webhook") || !strings.Contains(d.Message, "not built") || d.Line != 2) {
					t.Errorf("warning %+v does not say the webhook is not built at its line", d)
				}
			}
		}},
		{"ask.notify cli and desktop warn nothing", "ask:\n  notify: [cli, desktop]\n", func(t *testing.T, m *Machine, diags []Diagnostic) {
			if strings.Join(m.Ask.Notify.Value, ",") != "cli,desktop" || len(diags) != 0 {
				t.Errorf("notify %+v diags %v", m.Ask.Notify, diags)
			}
		}},
		{"ask.notify [] turns both off", "ask:\n  notify: []\n", func(t *testing.T, m *Machine, diags []Diagnostic) {
			if m.Ask.Notify.Value == nil || len(m.Ask.Notify.Value) != 0 || len(diags) != 0 {
				t.Errorf("notify %#v diags %v", m.Ask.Notify.Value, diags)
			}
		}},
		{"E12 memory 0 lowers to zero", "limits:\n  memory: 0\n", func(t *testing.T, m *Machine, _ []Diagnostic) {
			if p := m.Limits.Memory.Ptr(); p == nil || *p != 0 {
				t.Errorf("memory %+v", m.Limits.Memory)
			}
		}},
		{"ringbuf valid", "record:\n  ringbuf: 16MiB\n", func(t *testing.T, m *Machine, _ []Diagnostic) {
			if m.Record.Ringbuf.Value != 16<<20 || m.Record.Ringbuf.Source.Line != 2 {
				t.Errorf("ringbuf %+v", m.Record.Ringbuf)
			}
		}},
		{"high uid", "users:\n  3000000000: {max_runs: 1}\n", func(t *testing.T, m *Machine, _ []Diagnostic) {
			if _, ok := m.Users.Value["3000000000"]; !ok {
				t.Errorf("users %+v", m.Users.Value)
			}
		}},
		{"users", "users:\n  1000: {contracts: [a, b], max_runs: 2}\n  1001: {}\n", func(t *testing.T, m *Machine, _ []Diagnostic) {
			u := m.Users.Value
			if len(u) != 2 || u["1000"].MaxRuns != 2 || strings.Join(u["1000"].Contracts, ",") != "a,b" || u["1001"].MaxRuns != 0 {
				t.Errorf("users %+v", u)
			}
		}},
		{"webhook notify", "ask:\n  notify: [webhook:https://x/y]\n", func(t *testing.T, m *Machine, diags []Diagnostic) {
			if HasErrors(diags) {
				t.Errorf("diags %v", diags)
			}
		}},
		{"cpu as number", "limits:\n  cpu: 2.5\n", func(t *testing.T, m *Machine, _ []Diagnostic) {
			if m.Limits.CPU.Value != 2.5 {
				t.Errorf("cpu %+v", m.Limits.CPU)
			}
		}},
		{"all limits", "limits:\n  cpu_weight: 100\n  memory_high: 1GiB\n  cost_usd: 12.5\n  stall_after: 1h\n  repeats: 3\n", func(t *testing.T, m *Machine, _ []Diagnostic) {
			l := m.Limits
			if l.CPUWeight.Value != 100 || l.MemoryHigh.Value != 1<<30 || l.CostUSD.Value != 12.5 || l.StallAfter.Value != time.Hour || l.Repeats.Value != 3 {
				t.Errorf("limits %+v", l)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := layers(t, trustedDir(t), tc.content, "", "")
			m, diags := mustLoad(t, src, "")
			tc.check(t, m, diags)
		})
	}
}

// Privileged_binary is honoured from /etc only and its target is
// never opened by Load.
func TestPrivilegedBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	src := layers(t, trustedDir(t), "privileged_binary: "+missing+"\n", "privileged_binary: /usr/bin/other\n", "")
	m, diags := mustLoad(t, src, "")
	if m.PrivilegedBinary.Value != missing || m.PrivilegedBinary.Source.Layer != LayerEtc {
		t.Errorf("privileged_binary %+v", m.PrivilegedBinary)
	}
	// ADR 0042 (3)(d): the /etc value stays parsed and stored, and says once that nothing uses it in this release;
	// the user layer's is ignored as before.
	if countCode(diags, CodeIgnored) != 2 || !hasMessage(diags, "privileged_binary is honoured from /etc/tego/config.yaml only") ||
		!hasMessage(diags, "privileged_binary is not used in this release; ADR 0042 (3)(c)") {
		t.Errorf("diags %v", diags)
	}
	if _, diags := mustLoad(t, layers(t, trustedDir(t), "log:\n  level: info\n", "", ""), ""); hasMessage(diags, "privileged_binary") {
		t.Errorf("a config without privileged_binary warned about it: %v", diags)
	}
}

// TestUsersIsTheAdministrators is ADR 0042 (4): users: is authorization for tegod, so only
// /etc/tego/config.yaml may set it. The per-user layer and $TEGO_CONFIG are the invoking user's own files; read
// from there, an entry would be a user granting itself runs.
func TestUsersIsTheAdministrators(t *testing.T) {
	src := layers(t, trustedDir(t), "users:\n  1000: {max_runs: 1}\n", "users:\n  1001: {max_runs: 9}\n",
		"users:\n  1002: {max_runs: 9}\n")
	m, diags := mustLoad(t, src, "")
	if len(m.Users.Value) != 1 || m.Users.Value["1000"].MaxRuns != 1 || m.Users.Source.Layer != LayerEtc {
		t.Errorf("users %+v from %+v, want only /etc's entry", m.Users.Value, m.Users.Source)
	}
	if countCode(diags, CodeIgnored) != 2 || !hasMessage(diags, "users is honoured from /etc/tego/config.yaml only; ignored here") {
		t.Errorf("diags %v", diags)
	}
	if m, _ := mustLoad(t, layers(t, trustedDir(t), "", "users:\n  1001: {}\n", ""), ""); len(m.Users.Value) != 0 {
		t.Errorf("a per-user layer alone set users %+v", m.Users.Value)
	}
}

// hasMessage reports whether a diagnostic's message contains want.
func hasMessage(diags []Diagnostic, want string) bool {
	for _, d := range diags {
		if strings.Contains(d.Message, want) {
			return true
		}
	}
	return false
}

// TestBPFLingerIsTheAdministrators: bpf.linger decides how long a build stays attached host-wide after its last
// run (ADR 0022), so it is honoured from /etc/tego/config.yaml only, as privileged_binary is, and 0 is a value.
func TestBPFLingerIsTheAdministrators(t *testing.T) {
	src := layers(t, trustedDir(t), "bpf:\n  linger: 0s\n", "bpf:\n  linger: 1h\n", "")
	m, diags := mustLoad(t, src, "")
	if m.BPF.Linger.Value != 0 || m.BPF.Linger.Source.Layer != LayerEtc {
		t.Errorf("bpf.linger %+v, want 0 from /etc", m.BPF.Linger)
	}
	if countCode(diags, CodeIgnored) != 1 || !strings.Contains(diags[0].Message, "bpf.linger is honoured from /etc/tego/config.yaml only") {
		t.Errorf("diags %v", diags)
	}
	if m, _ := mustLoad(t, layers(t, trustedDir(t), "", "", ""), ""); m.BPF.Linger.Value != DefaultBPFLinger {
		t.Errorf("default bpf.linger %v, want %v", m.BPF.Linger.Value, DefaultBPFLinger)
	}
}

// TestLedgerCeilingAndGCInterval: record.max_run_bytes is a ceiling, which a later layer lowers and never raises (R15),
// unbounded by default; gc_interval is a setting, 0 (never) by default.
func TestLedgerCeilingAndGCInterval(t *testing.T) {
	src := layers(t, trustedDir(t), "record:\n  max_run_bytes: 1GiB\ngc_interval: 24h\n", "record:\n  max_run_bytes: 4GiB\n", "")
	m, diags := mustLoad(t, src, "")
	if c := m.Record.MaxRunBytes; !c.Bounded || c.Value != 1<<30 || c.Source.Layer != LayerEtc {
		t.Errorf("record.max_run_bytes %+v, want 1GiB from /etc", c)
	}
	if countCode(diags, CodeCeilingKept) != 1 {
		t.Errorf("diags %v, want the raise kept", diags)
	}
	if m.GCInterval.Value != 24*time.Hour {
		t.Errorf("gc_interval %v", m.GCInterval.Value)
	}
	if m, _ := mustLoad(t, layers(t, trustedDir(t), "", "", ""), ""); m.Record.MaxRunBytes.Bounded || m.GCInterval.Value != 0 {
		t.Errorf("defaults %+v %v, want unbounded and 0", m.Record.MaxRunBytes, m.GCInterval.Value)
	}
}

// TestRingSizesAreTheAdministrators: record.ringbuf sizes each run's rings and bpf.ring_budget caps them all,
// kernel memory the launcher allocates as root, so both are honoured from /etc/tego/config.yaml only and an
// invoking user's layer that sets either is ignored with a warning (ADR 0026 (2)).
func TestRingSizesAreTheAdministrators(t *testing.T) {
	src := layers(t, trustedDir(t), "record:\n  ringbuf: 4MiB\nbpf:\n  ring_budget: 64MiB\n",
		"record:\n  ringbuf: 64MiB\nbpf:\n  ring_budget: 8GiB\n", "")
	m, diags := mustLoad(t, src, "")
	if m.Record.Ringbuf.Value != 4<<20 || m.Record.Ringbuf.Source.Layer != LayerEtc {
		t.Errorf("record.ringbuf %+v, want 4MiB from /etc", m.Record.Ringbuf)
	}
	if m.BPF.RingBudget.Value != 64<<20 || m.BPF.RingBudget.Source.Layer != LayerEtc {
		t.Errorf("bpf.ring_budget %+v, want 64MiB from /etc", m.BPF.RingBudget)
	}
	if countCode(diags, CodeIgnored) != 2 {
		t.Errorf("diags %v, want two ignored settings", diags)
	}
	for _, key := range []string{"record.ringbuf", "bpf.ring_budget"} {
		found := false
		for _, d := range diags {
			found = found || strings.Contains(d.Message, key+" is honoured from /etc/tego/config.yaml only")
		}
		if !found {
			t.Errorf("no ignored diagnostic for %s: %v", key, diags)
		}
	}
	if m, _ := mustLoad(t, layers(t, trustedDir(t), "", "", ""), ""); m.Record.Ringbuf.Value != DefaultRingbuf ||
		m.BPF.RingBudget.Value != DefaultRingBudget {
		t.Errorf("defaults %v %v, want %v %v", m.Record.Ringbuf.Value, m.BPF.RingBudget.Value, DefaultRingbuf, DefaultRingBudget)
	}
}

// TestPlaneIsTheAdministrators: bpf.plane picks which programs decide every host process's opens (ADR 0024 (2),
// enforce-plane.md R18), so it is honoured from /etc/tego/config.yaml only, an invoking user's layer that sets it
// is ignored with a warning, the default is auto, and a value other than auto, lsm or fmod_ret is refused.
func TestPlaneIsTheAdministrators(t *testing.T) {
	m, diags := mustLoad(t, layers(t, trustedDir(t), "bpf:\n  plane: fmod_ret\n", "bpf:\n  plane: lsm\n", ""), "")
	if m.BPF.Plane.Value != PlaneFmodRet || m.BPF.Plane.Source.Layer != LayerEtc {
		t.Errorf("bpf.plane %+v, want fmod_ret from /etc", m.BPF.Plane)
	}
	if countCode(diags, CodeIgnored) != 1 || !strings.Contains(diags[0].Message, "bpf.plane is honoured from /etc/tego/config.yaml only") {
		t.Errorf("diags %v", diags)
	}
	if m, _ := mustLoad(t, layers(t, trustedDir(t), "", "", ""), ""); m.BPF.Plane.Value != PlaneAuto {
		t.Errorf("default bpf.plane %q, want auto", m.BPF.Plane.Value)
	}
	_, bad := parseLayer("/etc/tego/config.yaml", []byte("bpf:\n  plane: kprobe\n"))
	if len(bad) != 1 || !strings.Contains(bad[0].Message, `bpf.plane: "kprobe" is not auto, lsm or fmod_ret`) {
		t.Errorf("an unknown bpf.plane parsed: %v", bad)
	}
}

// TestLoadNeverAccessesPrivilegedBinaryTarget strengthens T-config-privbinary-trust-1 (I10, E31).
// The existing TestPrivilegedBinary above only points the field at a path that does not exist, so
// a hidden ENOENT-swallowing open of it would look identical to never opening it at all — the
// doc.go/README boundary is stronger: "config.Load never opens this file" (E31), part of what I10
// requires a syscall-audited integration test to verify in general ("opens exactly the files
// described in R14/R20 and nothing else"). No such integration test exists in this repo yet
// (grepped: no IT-config-syscalls anywhere), so this pins the one slice of I10 a plain unit test
// CAN prove without ptrace/strace: it points privileged_binary at a path whose PARENT directory
// has mode 000, so ANY attempt to open, stat or read anything under it — by any means, not just a
// blocking one a timeout could catch — fails with EACCES at the kernel's own name-resolution step,
// before Load's own logic ever runs. Load must still succeed with the path stored as inert data.
func TestLoadNeverAccessesPrivilegedBinaryTarget(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permission checks (DAC_OVERRIDE); this trap needs a real permission boundary")
	}
	trapDir := filepath.Join(t.TempDir(), "trap")
	if err := os.Mkdir(trapDir, 0o700); err != nil {
		t.Fatal(err)
	}
	trap := filepath.Join(trapDir, "priv-binary") // never created: the locked parent alone must be enough
	if err := os.Chmod(trapDir, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore before t.TempDir()'s own cleanup tries to RemoveAll the tree (cleanups run LIFO, so
	// registering this after TempDir's own internal cleanup call means it runs first).
	t.Cleanup(func() { _ = os.Chmod(trapDir, 0o700) })

	src := layers(t, trustedDir(t), "privileged_binary: "+trap+"\n", "", "")
	m, diags := mustLoad(t, src, "")
	if m.PrivilegedBinary.Value != trap {
		t.Errorf("privileged_binary = %q, want %q stored as plain, untouched data", m.PrivilegedBinary.Value, trap)
	}
	// The one diagnostic is ADR 0042 (3)(d)'s fixed warning that the setting is unused, which reads nothing of the
	// path; any other would mean something looked at the trap path.
	if len(diags) != 1 || diags[0].Code != CodeIgnored || diags[0].Message != "privileged_binary is not used in this release; ADR 0042 (3)(c)" {
		t.Errorf("diags %v, want only the fixed not-used warning: any other would mean something looked at the trap path", diags)
	}
}

// TestLoadRereadsDiskOnEachCall pins I3 ("a *Machine is immutable for its process's lifetime ...
// a disk edit never affects an in-flight run") and E18 ("each run keeps the *Machine from its own
// Load() call for its whole lifetime — no cache, no file-watch; concurrent runs may legitimately
// see different ceilings"). Neither number is cited by any test in this package, nor mapped to one
// in docs/p0/identity-config.md §10's own test table, even though every other rule/edge/invariant
// this component owns is: every existing LoadSources-based test here calls it exactly once per
// fixture, so a path-keyed cache accidentally added to readTrusted (a plausible "avoid re-reading
// the same file" optimization) would pass the whole suite today. This drives LoadSources twice
// over the identical Sources value, editing the file on disk in between, and checks the two things
// such a cache would break: the second call must see the edit, and the *Machine already returned
// by the first call must keep reporting what was on disk when it, specifically, ran.
func TestLoadRereadsDiskOnEachCall(t *testing.T) {
	dir := trustedDir(t)
	path := writeFile(t, dir, "etc.yaml", "tier: landlock\n", 0o644)
	src := Sources{Etc: path}

	m1, diags1 := mustLoad(t, src, "")
	if m1.Tier.Value.Tier != "landlock" || HasErrors(diags1) {
		t.Fatalf("first load: tier=%+v diags=%v", m1.Tier, diags1)
	}

	if err := os.WriteFile(path, []byte("tier: cgroup\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m2, diags2 := mustLoad(t, src, "")
	if m2.Tier.Value.Tier != "cgroup" {
		t.Errorf("second Load on the same Sources after an on-disk edit still reports %+v (E18: Load must re-read, never cache, a layer's bytes)", m2.Tier)
	}
	if HasErrors(diags2) {
		t.Fatalf("second load diags: %v", diags2)
	}

	if m1.Tier.Value.Tier != "landlock" {
		t.Errorf("the first Machine changed after the fact to %+v (I3: a *Machine must not be retroactively mutated by a later disk edit or Load call)", m1.Tier)
	}
}

// AT_SECURE x SUDO_UID (R21, E19) through Resolve.
func TestResolveSecure(t *testing.T) {
	envFile := writeFile(t, t.TempDir(), "env.yaml", "", 0o600)
	t.Setenv(EnvConfigVar, envFile)
	t.Setenv("HOME", "/nonexistent-home-must-not-be-used")
	uid := os.Getuid()
	cases := []struct {
		name    string
		uid     int
		secure  bool
		wantEnv string
		wantPw  bool
	}{
		{"plain", uid, false, envFile, true},
		{"secure drops TEGO_CONFIG", uid, true, "", true},
		{"no passwd entry warns, env kept", 65534 + 1000, false, envFile, false},
		{"secure and no passwd entry", 65534 + 1000, true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, home, diags := Resolve(tc.uid, tc.secure)
			if src.Etc != EtcPath || src.EnvFile != tc.wantEnv {
				t.Errorf("sources %+v", src)
			}
			if tc.wantPw {
				if home == "" || !strings.HasSuffix(src.User, "/"+UserRelPath) || strings.Contains(src.User, "nonexistent-home") {
					t.Errorf("user layer %q home %q", src.User, home)
				}
				if len(diags) != 0 {
					t.Errorf("diags %v", diags)
				}
			} else if src.User != "" || home != "" || countCode(diags, CodeIgnored) != 1 {
				t.Errorf("user layer %q home %q diags %v", src.User, home, diags)
			}
		})
	}
}

// Load and LoadMode on this box: the real layers are absent or trusted, so both succeed.
func TestLoadRealPaths(t *testing.T) {
	t.Setenv(EnvConfigVar, "")
	uid, _ := InvokingUID()
	m, _, err := Load(uid, false)
	if err != nil {
		if errors.Is(err, ErrUntrusted) || errors.Is(err, ErrInvalid) {
			t.Skipf("this box has a real machine config Load refuses: %v", err)
		}
		t.Fatal(err)
	}
	if m.LedgerRoot.Value == "" || strings.HasPrefix(m.LedgerRoot.Value, "~") {
		t.Errorf("ledger_root %q", m.LedgerRoot.Value)
	}
	if _, _, err := LoadMode(uid, true, TrustWarn); err != nil {
		t.Fatal(err)
	}
}

func TestEffective(t *testing.T) {
	src := layers(t, trustedDir(t), etcLayer, "", "")
	m, _ := mustLoad(t, src, "/home/test")
	values := m.Effective()
	byKey := map[string]Value{}
	for _, v := range values {
		byKey[v.Key] = v
	}
	if len(values) != 33 {
		t.Errorf("%d values", len(values))
	}
	cases := []struct {
		key, value, source string
		ceiling, unbounded bool
	}{
		{"tier", "cgroup", src.Etc + ":2", true, false},
		{"capture", "uprobe", src.Etc + ":3", true, false},
		{"limits.memory", "32GiB", src.Etc + ":7", true, false},
		{"limits.tokens", "unbounded", "built-in", true, true},
		{"limits.cpu", "8", src.Etc + ":6", true, false},
		{"limits.wall", "1d", src.Etc + ":9", true, false},
		{"stop_grace", "5s", src.Etc + ":4", false, false},
		{"retention", "30d", "built-in", false, false},
		{"ledger_root", "/home/test/.tego/runs", "built-in", false, false},
		{"registry", "/home/test/.config/tego", "built-in", false, false},
		{"ask.notify", "cli,desktop", "built-in", false, false},
		{"record.ringbuf", "2MiB", "built-in", false, false},
		{"record.max_run_bytes", "unbounded", "built-in", true, true},
		{"gc_interval", "0s", "built-in", false, false},
		{"bpf.ring_budget", "256MiB", "built-in", false, false},
		{"bpf.linger", "5m", "built-in", false, false},
		{"bpf.plane", "auto", "built-in", false, false},
		{"resolver", "auto", "built-in", false, false},
		{"denied_resolved_addresses", "[]", "built-in", false, false},
		{"log.level", "warn", src.Etc + ":11", false, false},
		{"landlock.audit", "off", "built-in", false, false},
		{"users", "{}", "built-in", false, false},
	}
	for _, tc := range cases {
		v, ok := byKey[tc.key]
		if !ok {
			t.Errorf("missing key %s", tc.key)
			continue
		}
		if v.Value != tc.value || v.Source.String() != tc.source || v.Ceiling != tc.ceiling || v.Unbounded != tc.unbounded {
			t.Errorf("%s = %+v, want value=%q source=%q ceiling=%v unbounded=%v", tc.key, v, tc.value, tc.source, tc.ceiling, tc.unbounded)
		}
	}
	var b strings.Builder
	if err := m.WriteEffective(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "ceiling limits.memory=32GiB  ("+src.Etc+":7)\n") || !strings.Contains(b.String(), "setting stop_grace=5s  ("+src.Etc+":4)\n") {
		t.Errorf("effective output:\n%s", b.String())
	}
	if formatUsers(map[string]UserPolicy{"1001": {MaxRuns: 1}, "1000": {MaxRuns: 3}}) != "1000:3,1001:1" {
		t.Error("formatUsers order")
	}
	// No layer sets tier or capture: each is auto, as the config file spells it, not "unbounded".
	for _, v := range Builtin().Effective() {
		if (v.Key == "tier" || v.Key == "capture") && (v.Value != Auto || !v.Unbounded) {
			t.Errorf("built-in %s = %+v, want auto", v.Key, v)
		}
	}
}

func TestDiagnosticString(t *testing.T) {
	d := Diagnostic{File: "/etc/tego/config.yaml", Line: 7, Col: 3, Message: "unknown key \"gpus\"", Code: CodeInvalid, Fix: "Remove it."}
	if got := d.String(); got != `/etc/tego/config.yaml:7:3: unknown key "gpus" [config-invalid] Remove it.` {
		t.Errorf("String = %q", got)
	}
	if got := (Diagnostic{Message: "m", Code: "c"}).String(); got != "m [c]" {
		t.Errorf("String = %q", got)
	}
	if (Provenance{File: "f", Layer: LayerEtc}).String() != "f" || (Provenance{File: "f", Line: 2, Layer: LayerUser}).String() != "f:2" {
		t.Error("Provenance.String")
	}
	for l, want := range map[Layer]string{LayerBuiltin: "built-in", LayerEtc: "etc", LayerUser: "user", LayerEnvFile: "env", LayerContract: "contract", Layer(9): "layer(9)"} {
		if l.String() != want {
			t.Errorf("%d.String() = %q", l, l.String())
		}
	}
}

// BenchmarkLoad: three small layer files, budget < 1 ms.
func BenchmarkLoad(b *testing.B) {
	dir := trustedDir(b)
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			b.Fatal(err)
		}
		return path
	}
	src := Sources{Etc: write("etc.yaml", etcLayer), User: write("user.yaml", userLayer), EnvFile: write("env.yaml", envLayer)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := LoadSources(src, "/home/test", os.Getuid(), TrustAbort); err != nil {
			b.Fatal(err)
		}
	}
}

// TestDeniedResolvedUnion pins denied_resolved_addresses as the one setting no later layer narrows: each
// layer adds its ranges, an empty list in the invoking user's layer lifts nothing /etc set, a bare address
// is its own host prefix, and the source is the last layer that added a range.
func TestDeniedResolvedUnion(t *testing.T) {
	src := layers(t, trustedDir(t), "denied_resolved_addresses: [10.0.0.0/8, 192.0.2.7]\n",
		"denied_resolved_addresses: []\n", "denied_resolved_addresses: [\"fc00::/7\", 10.0.0.0/8]\n")
	m, _ := mustLoad(t, src, "/home/test")
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("fc00::/7")}
	if !slices.Equal(m.DeniedResolved.Value, want) {
		t.Fatalf("denied_resolved_addresses = %v, want %v", m.DeniedResolved.Value, want)
	}
	if got := m.DeniedResolved.Source.String(); got != src.EnvFile+":1" {
		t.Errorf("source %s, want the last layer that added a range (%s:1)", got, src.EnvFile)
	}
	if b := Builtin(); len(b.DeniedResolved.Value) != 0 {
		t.Errorf("the built-in layer adds no range: %v", b.DeniedResolved.Value)
	}
}

// TestLayerPathIsAnOpaqueByteString is identity-config.md E21: a $TEGO_CONFIG path with non-ASCII and
// right-to-left override bytes is neither normalized nor rejected, so the layer is the file the kernel
// resolves those exact bytes to, and Provenance names it byte for byte.
func TestLayerPathIsAnOpaqueByteString(t *testing.T) {
	dir := trustedDir(t)
	odd := filepath.Join(dir, "café-\u202egnp")
	if err := os.Mkdir(odd, 0o700); err != nil {
		t.Skipf("this filesystem refuses the path: %v", err)
	}
	if err := os.Chmod(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	path := writeFile(t, odd, "ćonfig.yaml", "version: 0\nstop_grace: 7s\n", 0o600)
	t.Setenv(EnvConfigVar, path)
	src, _, _ := Resolve(os.Getuid(), false)
	if src.EnvFile != path {
		t.Fatalf("Resolve rewrote the path: %q, want %q", src.EnvFile, path)
	}
	m, _ := mustLoad(t, Sources{EnvFile: src.EnvFile}, "")
	if m.StopGrace.Value != 7*time.Second || m.StopGrace.Source.File != path {
		t.Errorf("stop_grace = %v from %q, want 7s from %q", m.StopGrace.Value, m.StopGrace.Source.File, path)
	}
}
