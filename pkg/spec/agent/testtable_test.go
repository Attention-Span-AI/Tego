// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestBindTablePolicy(t *testing.T) {
	f := newFixture(t)
	homeSockets := filepath.Join(f.home, "sockets")
	if err := os.Mkdir(homeSockets, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(f.project, "alias")
	if err := os.Symlink(filepath.Join(f.project, "out"), alias); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(f.project, "out", "allowed.sock")
	homeAllowed := filepath.Join(homeSockets, "allowed.sock")
	c := f.load(fmt.Sprintf(`version: 0
name: bind-table
command: [static-tool]
fs:
  write: [out/, "~/sockets/"]
  deny_read: []
net:
  listen: ["tcp://0.0.0.0:0", "udp://127.0.0.1:8080", "tcp://[::]:8080", "unix:%s", "unix:%s", "unix:@service"]
`, allowed, homeAllowed))
	rt, _ := f.compile(c)
	for _, tc := range []struct {
		name, fields, expect string
	}{
		{"bare ephemeral IPv4", `host_port: "127.0.0.1:0"`, "allow"},
		{"TCP selector ephemeral", `host_port: "tcp://127.0.0.1:0"`, "allow"},
		{"fixed port is not ephemeral", `host_port: "127.0.0.1:80"`, "refused"},
		{"bare UDP", "host_port: \"127.0.0.1:8080\"\n    proto: udp", "allow"},
		{"UDP selector", `host_port: "udp://127.0.0.1:8080"`, "allow"},
		{"wrong transport", `host_port: "tcp://127.0.0.1:8080"`, "refused"},
		{"IPv6 wildcard narrows", `host_port: "[::1]:8080"`, "allow"},
		{"mapped IPv4 remains IPv4", `host_port: "tcp://[::ffff:127.0.0.1]:0"`, "allow"},
		{"Unix pathname", fmt.Sprintf("path: %q", "unix:"+allowed), "allow"},
		{"Unix plain absolute path", fmt.Sprintf("path: %q\n    proto: unix", allowed), "allow"},
		{"Unix parent symlink", fmt.Sprintf("path: %q", "unix:"+filepath.Join(alias, "allowed.sock")), "allow"},
		{"Unix home", `path: "unix:~/sockets/allowed.sock"`, "allow"},
		{"Unix abstract host_port", `host_port: "unix:@service"`, "allow"},
		{"Unix abstract path", `path: "unix:@service"`, "allow"},
		{"undeclared Unix", `path: "unix:@other"`, "refused"},
		{"undeclared pathname", fmt.Sprintf("path: %q", "unix:"+filepath.Join(f.project, "out", "other.sock")), "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Put action after the endpoint to check that mapping order does not select its parser.
			src := fmt.Sprintf("tests:\n  - %s\n    action: net.bind\n    expect: %s\n", tc.fields, tc.expect)
			table, ds, err := LoadTestTableBytes("bind.yaml", []byte(src))
			if err != nil {
				t.Fatalf("load: %v %s", err, render(ds))
			}
			for _, result := range table.RunResolved((*RuleTable).Evaluate, rt, f.project, evalLanders, backend.TierCgroup, backend.TierBPFLSM) {
				if !result.Pass {
					t.Fatalf("compiled listener policy: %+v", result)
				}
				if tc.name == "Unix parent symlink" && result.Resolved.Path != allowed {
					t.Fatalf("bind parent did not resolve: %+v", result.Resolved)
				}
			}
		})
	}
	for _, tc := range []struct{ name, net, expect string }{
		{"legacy absent", "", "allow"},
		{"explicit empty", "net: {listen: []}\n", "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table, ds, err := LoadTestTableBytes("bind.yaml", []byte("tests:\n  - {action: net.bind, host_port: '127.0.0.1:0', expect: "+tc.expect+"}\n"))
			if err != nil {
				t.Fatalf("load: %v %s", err, render(ds))
			}
			compiled, _ := f.compile(f.load("version: 0\nname: bind-table\ncommand: [static-tool]\n" + tc.net))
			if results := table.Run(compiled, f.project, backend.TierCgroup); len(results) != 1 || !results[0].Pass {
				t.Fatalf("listener presence: %+v", results)
			}
		})
	}
}

func TestBindTestTableRejectsUnsupportedOrContradictoryEndpoints(t *testing.T) {
	for _, fields := range []string{
		`host_port: "tcp://localhost:8080"`,
		`host_port: "localhost:8080"`,
		`host_port: "tcp://127.0.0.0/8:8080"`,
		`host_port: "tcp://[fe80::1%eth0]:8080"`,
		`host_port: "tcp://127.0.0.1:-1"`,
		`host_port: "127.0.0.1:65536"`,
		`host_port: "::1:8080"`,
		`path: "unix:./relative.sock"`,
		`path: "unix:@"`,
		"host_port: \"udp://127.0.0.1:8080\"\n    proto: tcp",
		"path: \"unix:/run/a.sock\"\n    proto: tcp",
		"host_port: \"127.0.0.1:8080\"\n    proto: unix",
		"host_port: \"127.0.0.1:8080\"\n    path: unix:/run/a.sock",
		"host_port: \"127.0.0.1:8080\"\n    method: GET",
		"host_port: \"127.0.0.1:8080\"\n    argv: [tool]",
		"proto: udp",
	} {
		t.Run(fields, func(t *testing.T) {
			src := "tests:\n  - " + fields + "\n    action: net.bind\n    expect: refused\n"
			if table, ds, err := LoadTestTableBytes("bind.yaml", []byte(src)); err == nil || table != nil || !errors.Is(err, ErrInvalidTestTable) || len(ds) == 0 {
				t.Fatalf("invalid bind endpoint reached evaluator: table=%+v err=%v ds=%+v", table, err, ds)
			}
		})
	}
	if table, _, err := LoadTestTableBytes("connect.yaml", []byte("tests:\n  - {action: net.connect, path: unix:/run/a.sock, proto: unix, expect: refused}\n")); err == nil || table != nil {
		t.Fatal("net.bind's new proto spelling widened unrelated row parsing")
	}
}

func TestLoadTestTableRows(t *testing.T) {
	const src = `version: 0
tests:
  - name: writes land in out
    action: fs.write
    path: out/report.md
    expect: allow
    rule: fs.write[out/]
  - action: fs.rename
    path: out/a
    dest: out/b
    expect: allow
  - action: exec
    argv: [rg, -n, needle]
    tier: cgroup
    expect: refused
  - action: net.connect
    host_port: "[2001:db8::1]:443"
    proto: udp
    expect: refused
  - action: net.connect
    path: unix:/run/pg.sock
    expect: allow
`
	table, ds, err := LoadTestTableBytes("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if len(table.Rows) != 5 {
		t.Fatalf("%d rows", len(table.Rows))
	}
	first := table.Rows[0]
	if first.Name != "writes land in out" || first.Kind != ActionFSWrite || first.Path != "out/report.md" ||
		first.Expect != VerdictAllow || first.Rule != "fs.write[out/]" || first.Line != 3 {
		t.Errorf("row 0: %+v", first)
	}
	if table.Rows[1].Dest != "out/b" || table.Rows[1].Kind != ActionFSRename {
		t.Errorf("row 1: %+v", table.Rows[1])
	}
	if got := table.Rows[2]; got.Tier != backend.TierCgroup || len(got.Argv) != 3 || got.Label() != "exec rg -n needle" {
		t.Errorf("row 2: %+v", got)
	}
	if got := table.Rows[3]; got.Host != "2001:db8::1" || got.Port != 443 || got.Proto != "udp" {
		t.Errorf("row 3: %+v", got)
	}
	if got := table.Rows[4]; got.Path != "unix:/run/pg.sock" {
		t.Errorf("row 4: %+v", got)
	}
}

// agent-contract.md E35: a fs.chmod action is an unknown kind, never answered with a refusal.
func TestLoadTestTableErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
		line int
	}{
		{"unknown table field", "version: 0\nrows: []\n", `unknown field "rows"`, 2},
		{"no tests", "version: 0\n", "no tests: list", 1},
		{"bad version", "version: 1\ntests: []\n", "version 1 is not supported", 1},
		{"not a mapping", "- a\n", "test table must be a mapping", 1},
		{"tests not a list", "tests: {}\n", "tests must be a list", 1},
		{"row not a mapping", "tests:\n  - hello\n", "each test must be a mapping", 2},
		{"unknown row field", "tests:\n  - action: exec\n    path: /bin/sh\n    expect: allow\n    why: because\n", `unknown field "why"`, 5},
		{"unknown action", "tests:\n  - action: fs.chmod\n    path: /x\n    expect: allow\n", `unknown action "fs.chmod"`, 2},
		{"unknown expect", "tests:\n  - action: fs.read\n    path: /x\n    expect: maybe\n", `unknown expect "maybe"`, 4},
		{"unknown tier", "tests:\n  - action: fs.read\n    path: /x\n    tier: seccomp\n    expect: allow\n", `unknown tier "seccomp"`, 4},
		{"no action", "tests:\n  - path: /x\n    expect: allow\n", "test has no action", 2},
		{"no expect", "tests:\n  - action: fs.read\n    path: /x\n", "has no expect", 2},
		{"fs row without a path", "tests:\n  - action: fs.read\n    expect: allow\n", "fs.read test needs a path", 2},
		{"exec row without a target", "tests:\n  - action: exec\n    expect: allow\n", "exec test needs path or argv", 2},
		{"net row without a target", "tests:\n  - action: net.connect\n    expect: allow\n", "net.connect test needs host_port", 2},
		{"rename without a destination", "tests:\n  - action: fs.rename\n    path: /x\n    expect: allow\n", "fs.rename test needs path and dest", 2},
		{"argv not a list", "tests:\n  - action: exec\n    argv: rg\n    expect: allow\n", "argv must be a list", 3},
		// A value's Kind was never checked, a repeated top-level key kept its last value, and proto took any word; and an
		// unquoted ~ read as home where the contract refuses it.
		{"path a list", "tests:\n  - action: fs.read\n    path: [a, b]\n    expect: allow\n", "path must be a single value", 3},
		{"expect a mapping", "tests:\n  - action: fs.read\n    path: /x\n    expect: {a: 1}\n", "expect must be a single value", 4},
		{"argv entry a list", "tests:\n  - action: exec\n    argv: [[rg]]\n    expect: allow\n", "argv entry must be a single value", 3},
		{"version a list", "version: [0]\ntests: []\n", "version must be the number 0", 1},
		{"tests twice", "tests: []\ntests:\n  - action: fs.read\n    path: /x\n    expect: allow\n", "key tests appears twice", 2},
		{"bad proto", "tests:\n  - action: net.connect\n    host_port: example.com:443\n    proto: sctp\n    expect: allow\n", `unknown proto "sctp"`, 4},
		{"unquoted tilde path", "tests:\n  - action: fs.read\n    path: ~\n    expect: allow\n", "path: empty value", 3},
		{"empty rule", "tests:\n  - action: fs.read\n    path: /x\n    expect: allow\n    rule:\n", "rule: empty value", 5},
		{"bad host_port", "tests:\n  - action: net.connect\n    host_port: example.com\n    expect: allow\n", "host_port", 3},
		{"bad port", "tests:\n  - action: net.connect\n    host_port: example.com:99999\n    expect: allow\n", "host_port", 3},
		{"empty file", "", "empty test table", 1},
		{"not yaml", "tests:\n  - action: [\n", "did not find expected node content", 2},
		// Only the first document was read, so `compile --test` passed on it alone, and an empty tests: list passed having
		// checked nothing.
		{"two documents", "version: 0\ntests:\n  - {action: fs.read, path: /etc/passwd, expect: allow}\n---\ntests:\n  - {action: fs.read, path: /x, expect: refused}\n", "holds 2 YAML documents", 1},
		{"no rows", "version: 0\ntests: []\n", "no rows to check", 2},
		// A row was looser than the contract it checks.
		{"binary path", "tests:\n  - {action: fs.read, path: !!binary L2V0Yy9zaGFkb3c=, expect: allow}\n", "explicit YAML tag !!binary", 2},
		{"tagged host_port", "tests:\n  - {action: net.connect, host_port: !!str example.com:443, expect: allow}\n", "explicit YAML tag !!str", 2},
		{"tagged argv entry", "tests:\n  - {action: exec, argv: [!!binary cmc=], expect: allow}\n", "explicit YAML tag !!binary", 2},
		{"NUL in path", "tests:\n  - {action: fs.read, path: \"/a\\u0000b\", expect: allow}\n", "contains NUL", 2},
		{"NUL in argv", "tests:\n  - {action: exec, argv: [\"rg\\u0000\"], expect: allow}\n", "contains NUL", 2},
		{"newline in dest", "tests:\n  - {action: fs.rename, path: /a, dest: \"/b\\nc\", expect: allow}\n", "path contains a newline", 2},
		{"quoted version", "version: \"0\"\ntests:\n  - {action: fs.read, path: /x, expect: allow}\n", "version must be the number 0", 1},
		{"version 00", "version: 00\ntests:\n  - {action: fs.read, path: /x, expect: allow}\n", `version is written "00"`, 1},
		{"version -0", "version: -0\ntests:\n  - {action: fs.read, path: /x, expect: allow}\n", `version is written "-0"`, 1},
		{"zoned host_port", "tests:\n  - {action: net.connect, host_port: \"[fe80::1%eth0]:443\", expect: allow}\n", "IPv6 zone", 2},
		{"tagged version", "version: !!int 0\ntests:\n  - {action: fs.read, path: /x, expect: allow}\n", "version must be the number 0", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table, ds, err := LoadTestTableBytes("t.yaml", []byte(tc.src))
			if err == nil || table != nil {
				t.Fatalf("accepted: %+v", table)
			}
			if !errors.Is(err, ErrInvalidTestTable) {
				t.Errorf("error %v is not ErrInvalidTestTable", err)
			}
			if !HasErrors(ds) {
				t.Fatalf("no error diagnostic: %s", render(ds))
			}
			found := false
			for _, d := range ds {
				if !strings.Contains(d.Message, tc.want) {
					continue
				}
				found = true
				if d.Code != CodeSchema {
					t.Errorf("code %q", d.Code)
				}
				if tc.line != 0 && d.Line != tc.line {
					t.Errorf("line %d want %d", d.Line, tc.line)
				}
			}
			if !found {
				t.Errorf("no diagnostic carries %q:\n%s", tc.want, render(ds))
			}
		})
	}
}

func TestLoadTestTableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdicts.yaml")
	if err := os.WriteFile(path, []byte("tests:\n  - action: fs.read\n    path: /x\n    expect: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadTestTable(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, _, err := LoadTestTable(filepath.Join(dir, "missing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if _, _, err := LoadTestTable(""); err == nil {
		t.Error("empty path accepted")
	}
	big := strings.Repeat("#", MaxContractSize+1)
	if _, _, err := LoadTestTableBytes("t.yaml", []byte(big)); !errors.Is(err, ErrInvalidTestTable) {
		t.Errorf("oversized table: %v", err)
	}
}

// TestTestTableRun covers the row-to-Action translation: relative paths
// resolve against the caller's directory (E28), a bare exec name stays a
// basename, and a row's own tier overrides the table's compiled one (R33).
func TestTestTableRun(t *testing.T) {
	f, rt := evalFixture(t)
	const src = `tests:
  - action: fs.write
    path: out/report.md
    expect: allow
  - name: root tiers refuse this read
    action: fs.read
    path: out/keys/id_ed25519
    tier: cgroup
    expect: refused
    rule: fs.deny_read[out/keys/]
  - name: tier 1 holds the run's reads, which refuses it (ADR 0069)
    action: fs.read
    path: out/keys/id_ed25519
    tier: landlock
    expect: refused
    rule: fs.deny_read[out/keys/]
  - action: exec
    argv: [python, agent.py]
    expect: allow
  - name: wrong on purpose
    action: fs.write
    path: elsewhere.md
    expect: allow
`
	table, _, err := LoadTestTableBytes("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	results := table.Run(rt, f.project)
	if len(results) != 5 {
		t.Fatalf("%d results", len(results))
	}
	for i, r := range results[:4] {
		if !r.Pass {
			t.Errorf("row %d failed: %+v", i, r.Got)
		}
	}
	if results[4].Pass {
		t.Errorf("row 4 passed: %+v", results[4].Got)
	}
	if results[1].Tier != backend.TierCgroup || results[2].Tier != backend.TierLandlock {
		t.Errorf("tiers: %q %q", results[1].Tier, results[2].Tier)
	}
	if results[0].Tier != rt.Tier {
		t.Errorf("row without a tier ran in %q, want the compiled %q", results[0].Tier, rt.Tier)
	}
	// A nil table decides nothing and never panics.
	if got := (*TestTable)(nil).Run(rt, ""); got != nil {
		t.Errorf("nil table: %+v", got)
	}
}

// A nil rule table is answered like Evaluate answers it (refused, never
// allowed), not dereferenced: every row still gets a result.
func TestTestTableRunNilRuleTable(t *testing.T) {
	src := "tests:\n  - action: fs.read\n    path: ~/notes.md\n    tier: landlock\n    expect: allow\n"
	table, _, err := LoadTestTableBytes("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for name, run := range map[string]func() []TestResult{
		"Run":         func() []TestResult { return table.Run(nil, "/work") },
		"RunBy":       func() []TestResult { return table.RunBy((*RuleTable).Evaluate, nil, "/work") },
		"RunResolved": func() []TestResult { return table.RunResolved((*RuleTable).Evaluate, nil, "/work", evalLanders) },
	} {
		results := run()
		if len(results) != 1 || len(results[0].Columns) != 1 {
			t.Fatalf("%s: %+v", name, results)
		}
		if results[0].Pass || results[0].Got.Verdict == VerdictAllow {
			t.Errorf("%s: nil table allowed a row: %+v", name, results[0])
		}
	}

	// Rows with no tier: a nil table has no Reach to take columns from, and a row with no column must not
	// pass vacuously. Each is evaluated once, and the answer is the evaluator's invalid action.
	src = "tests:\n  - action: fs.read\n    path: /etc/hosts\n    expect: allow\n  - action: fs.write\n    path: /etc/hosts\n    expect: refused\n"
	table, _, err = LoadTestTableBytes("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	results := table.Run(nil, "/work")
	if len(results) != 2 {
		t.Fatalf("results %+v", results)
	}
	for i, r := range results {
		if len(r.Columns) != 1 || r.Got.Rule != InvalidActionRule {
			t.Errorf("row %d: want one column answered %s, got %+v", i, InvalidActionRule, r)
		}
	}
	if results[0].Pass {
		t.Errorf("an expect: allow row passed against a nil table: %+v", results[0])
	}
}
