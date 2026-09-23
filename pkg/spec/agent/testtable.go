// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTable A test table is `compile --test`'s input (R28): a YAML file of rows, each a
// hypothetical action and the verdict the compiled table must give it.
//
//	version: 0
//	tests:
//	  - name: writes land in the output directory
//	    action: fs.write
//	    path: ./out/report.md
//	    expect: allow
//	  - action: net.connect
//	    host_port: mcp.internal:8080
//	    expect: refused
//	    rule: unmatched          # optional: the entry that must decide
//	  - action: exec
//	    argv: [rg, -n, needle]
//	    tier: cgroup             # optional: this tier alone, not every tier the run can get
//	    expect: allow
//
// Every key is optional except `action` and `expect`; an unknown key, an
// unknown action or a row with nothing to evaluate is a schema diagnostic and
// the whole command fails before any row runs (§7).
type TestTable struct {
	// Version is the table's schema version; 0 in P0.
	Version int
	// Rows are the table's rows in file order.
	Rows []TestRow
	// File is the path the table was read from, for diagnostics.
	File string
}

// TestRow is one row of a test table.
type TestRow struct {
	// Name is the row's own label; empty rows are labelled by their action.
	Name string
	// Action is the row's action name as written ("fs.write", "net.connect").
	Action string
	// Kind is Action parsed into the evaluator's ActionKind.
	Kind ActionKind
	// Path, Dest and Script describe a filesystem or exec action; Path also
	// carries a unix: socket for net.connect, net.send or net.bind.
	Path, Dest, Script string
	// ScriptArg is an exec row's #! argument (script_arg:), passed to Script before the script (ADR 0048 (4)).
	ScriptArg string
	// Argv is an exec row's command line; Argv[0] stands in for Path.
	Argv []string
	// Dir is a filesystem row's `dir: true`: its object is a directory (Action.Dir), as a directory rename's is.
	// RunResolved also sets it when the row's path exists as a directory.
	Dir bool
	// Host and Port come from `host_port`, Proto from `proto` (tcp by default).
	Host   string
	Port   int
	Proto  string
	Method string
	// Socket is a net.socket row's family, type, protocol and socketpair keys.
	Socket SocketTriple
	// Tier evaluates this row in that tier alone; empty means every tier
	// Run was given, by default every tier the table's run can be given
	// (RuleTable.Reach, ADR 0019).
	Tier backend.Tier
	// Expect is the verdict the row asserts, and Rule the entry it asserts
	// decided ("" means any).
	Expect Verdict
	Rule   string
	// Line is the row's first line in the file, for diagnostics and output.
	Line int
}

// TestResult is one evaluated row.
type TestResult struct {
	// Row is the row as loaded.
	Row TestRow
	// Tier and Got are the first column that failed, else the last column: the tier and the evaluator's
	// answer a one-line report names.
	Tier backend.Tier
	Got  EvalResult
	// Columns are the row's answers, one per tier it was evaluated in, in the order Run was given them
	// (ADR 0019).
	Columns []TestColumn
	// Pass is true when every column matches the row's Expect (and Rule, when set).
	Pass bool
	// Resolved names the paths RunResolved evaluated in place of the row's own, each only when it differs
	// from the row's path made absolute; the zero value when nothing resolved elsewhere.
	Resolved ResolvedPaths
}

// ResolvedPaths are the filesystem paths a row was evaluated on after RunResolved followed its symlinks; an
// empty field is a path evaluated as written.
type ResolvedPaths struct {
	Path, Dest, Script string
}

// TestColumn is one row's answer in one tier.
type TestColumn struct {
	Tier backend.Tier
	Got  EvalResult
	Pass bool
	// BestEffort are the ids of the (D) cells Got rests on at Tier (RuleTable.BestEffortCellsFor, ADR 0041 D7): an
	// answer a run decides on copied syscall facts, never counted as enforced.
	BestEffort []string
}

// ErrInvalidTestTable wraps the first error diagnostic of LoadTestTable.
var ErrInvalidTestTable = errors.New("invalid test table")

// actionKinds maps a table's action names onto the evaluator's kinds (R28's
// four names plus the rest of ActionKind's closed set).
var actionKinds = map[string]ActionKind{
	"fs.read":     ActionFSRead,
	"fs.write":    ActionFSWrite,
	"fs.delete":   ActionFSDelete,
	"fs.rename":   ActionFSRename,
	"fs.mkdir":    ActionFSMkdir,
	"exec":        ActionExec,
	"net.connect": ActionNetConnect,
	"net.bind":    ActionNetBind,
	"net.http":    ActionNetHTTP,
	"exec.map":    ActionMapExec,
	// ADR 0017 (b)'s actions (plans/adr0017 C9): every action a conformance cell takes has a row (ADR 0019).
	"fs.link":        ActionFSLink,
	"fs.attr":        ActionFSAttr,
	"net.socket":     ActionNetSocket,
	"net.send":       ActionNetSend,
	"exec.anonymous": ActionExecAnon,
}

// actionNames lists the action names in a stable order for diagnostics.
var actionNames = []string{"exec", "exec.anonymous", "exec.map", "fs.attr", "fs.delete", "fs.link", "fs.mkdir", "fs.read",
	"fs.rename", "fs.write", "net.bind", "net.connect", "net.http", "net.send", "net.socket"}

// socketRowKeys are a net.socket row's own keys; no other action takes one.
var socketRowKeys = map[string]bool{"family": true, "type": true, "protocol": true, "socketpair": true}

// ipProtocols are the protocol names a net.socket row's protocol: may use (linux/in.h), besides a number.
var ipProtocols = map[string]int32{
	"IPPROTO_IP": 0, "IPPROTO_ICMP": 1, "IPPROTO_TCP": 6, "IPPROTO_UDP": 17, "IPPROTO_ICMPV6": 58,
	"IPPROTO_SCTP": 132, "IPPROTO_UDPLITE": 136, "IPPROTO_RAW": 255, "IPPROTO_MPTCP": 262,
}

// socketNumber reads a net.socket row's family, type or protocol: a non-negative 32-bit number, or the name named
// reads (case-insensitive).
func socketNumber(v string, named func(string) (int32, bool)) (int32, bool) {
	if n, err := strconv.ParseInt(v, 10, 32); err == nil {
		return int32(n), n >= 0
	}
	return named(v)
}

// protocolNumber is ipProtocols' reading of a name, any case.
func protocolNumber(name string) (int32, bool) {
	n, ok := ipProtocols[strings.ToUpper(name)]
	return n, ok
}

// LoadTestTable reads a `compile --test` table. err is nil iff every
// diagnostic is a warning; on any error diagnostic the table is nil, so a
// malformed table never reaches the evaluator (§7: the whole command fails
// before any row runs).
func LoadTestTable(path string) (*TestTable, []Diagnostic, error) {
	if path == "" {
		return nil, nil, errors.New("agent: LoadTestTable: empty path")
	}
	data, err := readCapped(path)
	if err != nil {
		return nil, nil, err
	}
	return LoadTestTableBytes(path, data)
}

// LoadTestTableBytes is LoadTestTable for bytes already in memory (stdin,
// tests, fuzzing); path labels the diagnostics.
func LoadTestTableBytes(path string, data []byte) (*TestTable, []Diagnostic, error) {
	var ds diags
	t := &TestTable{File: path}
	if len(data) > MaxContractSize {
		ds.errorf(Pos{File: path, Line: 1}, CodeSchema, "%v", ErrTooLarge)
		return nil, ds.list, fmt.Errorf("%w: %w", ErrInvalidTestTable, ds.list[0])
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		yamlDiagnostics(&ds, path, err, data)
		return nil, ds.list, fmt.Errorf("%w: %w", ErrInvalidTestTable, ds.list[0])
	}
	// A table is one document, as a contract is. yaml.Unmarshal reads the first and ignores the rest, so the
	// rows of a second document after `---` never ran, and `compile --test` passed on the first alone.
	if n := config.YAMLDocuments(data); n > 1 {
		ds.errorf(Pos{File: path, Line: 1}, CodeSchema, "%s holds %d YAML documents; a test table is one", path, n).
			fix("remove every '---' separator after the first document and move its rows into the first tests: list")
		return nil, ds.list, fmt.Errorf("%w: %w", ErrInvalidTestTable, ds.list[0])
	}
	root := documentRoot(&doc)
	if root == nil {
		ds.errorf(Pos{File: path, Line: 1}, CodeSchema, "empty test table").
			fix("add a tests: list of rows")
		return nil, ds.list, fmt.Errorf("%w: %w", ErrInvalidTestTable, ds.list[0])
	}
	parseTestTable(&ds, t, path, root)
	SortDiagnostics(ds.list, path)
	if err := firstTestError(ds.list); err != nil {
		return nil, ds.list, err
	}
	return t, ds.list, nil
}

// Run evaluates every row against the compiled table and reports one result
// per row, in file order. cwd is the directory a relative row path resolves
// against — the same directory Compile resolved the contract's entries
// against (E28); "" takes the process's working directory.
//
// A row is evaluated in each of tiers and passes only when its expectation
// holds in all of them (ADR 0019): with none given, in every tier a run of
// the table can be given (RuleTable.Reach). A row's own tier: narrows it to
// that tier alone. Rows ran in rt.Tier alone, the tier auto compiled to, so
// a refusal the run's own tier does not make was certified (limits-check-doctor-cli.md R28).
//
// It is deprecated with RuleTable.Evaluate (ADR 0031 (1)): call RunBy with internal/policy/decide.Evaluate,
// which this delegates to through the registered core (RegisterDecider). External
// callers use pkg/policy/evaluate.Run, or RunBy with evaluate.Evaluate.
func (t *TestTable) Run(rt *RuleTable, cwd string, tiers ...backend.Tier) []TestResult {
	return t.RunBy((*RuleTable).Evaluate, rt, cwd, tiers...)
}

// Evaluator is the verdict one tier gives a hypothetical action: internal/policy/decide.Evaluate.
type Evaluator func(rt *RuleTable, a Action, tier backend.Tier) EvalResult

// RunBy is Run with the evaluator named: `compile --test` passes the decision core's Evaluate (ADR 0028), so
// the table is answered by the one model every runtime component shares.
func (t *TestTable) RunBy(eval Evaluator, rt *RuleTable, cwd string, tiers ...backend.Tier) []TestResult {
	return t.run(eval, rt, cwd, nil, tiers)
}

// RunResolved is RunBy with each row's paths first landed by land, the kernel's walk the run decides its own
// lines on (ADR 0019, amended 2026-09-29 and 2026-10-17): `compile --test` runs a table this way, so a row through
// a symlink the contract does not declare is answered on the file the kernel would reach, and an exec of a symlink
// to a granted binary on that binary (a hard link under another name stays itself). A row's path is walked as the
// agent's syscall would spell it from cwd, uncleaned, so "lk/.." is taken physically; the part of a path that does
// not exist yet (a rename's new name, a directory the agent makes later, the target of a dangling symlink) is
// evaluated where the walk lands once it is made. The evaluator stays pure; the walk is land's I/O, and each landed
// path that differs from the row's is reported on its TestResult. A connect's or a datagram's unix pathname keeps its
// name and is landed by land.Unix, the run's own unix walk, which also says what that walk met (Action.Walk). A nil
// lander evaluates the rows it would land as written. cwd "" is the working directory as getcwd(2) reports it, every
// symlink resolved, which is what the run joins an agent's relative names to.
func (t *TestTable) RunResolved(eval Evaluator, rt *RuleTable, cwd string, land Landers, tiers ...backend.Tier) []TestResult {
	return t.run(eval, rt, cwd, &land, tiers)
}

// run answers the table's rows; land, when not nil, lands each row's paths first (RunResolved).
func (t *TestTable) run(eval Evaluator, rt *RuleTable, cwd string, land *Landers, tiers []backend.Tier) []TestResult {
	if t == nil {
		return nil
	}
	if cwd == "" {
		// A landed table joins the directory the run joins relative names to, symlinks resolved (RunResolved); an
		// unlanded one the spelling Compile joins the contract's relative entries to (E28).
		getwd := os.Getwd
		if land != nil {
			getwd = unix.Getwd
		}
		if wd, err := getwd(); err == nil {
			cwd = wd
		}
	}
	// A nil table has no home to expand ~ against; the evaluator answers it (invalid action, never allow).
	home := ""
	if rt != nil {
		home = rt.Home
	}
	if len(tiers) == 0 && rt != nil {
		tiers = rt.Reach
		if len(tiers) == 0 {
			tiers = []backend.Tier{rt.Tier}
		}
	}
	out := make([]TestResult, 0, len(t.Rows))
	for _, row := range t.Rows {
		cols := tiers
		if row.Tier != "" {
			cols = []backend.Tier{row.Tier}
		}
		if len(cols) == 0 {
			// A nil table and no tiers: evaluate once with no tier, so the row gets the evaluator's
			// answer (invalid action) rather than passing with no column at all.
			cols = []backend.Tier{""}
		}
		res := TestResult{Row: row, Pass: true}
		a := row.build(cwd, home, land != nil)
		if land != nil {
			a, res.Resolved = resolveAction(a, *land)
		}
		for _, tier := range cols {
			got := EvaluateGateRow(rt, a, eval(rt, a, tier))
			c := TestColumn{Tier: tier, Got: got, Pass: row.matches(got), BestEffort: rt.BestEffortCellsFor(a, got, tier)}
			res.Columns = append(res.Columns, c)
			if res.Pass {
				res.Tier, res.Got = tier, got
			}
			res.Pass = res.Pass && c.Pass
		}
		out = append(out, res)
	}
	return out
}

// Label names a row in output: its own name, else its action and target.
func (r TestRow) Label() string {
	if r.Name != "" {
		return r.Name
	}
	return strings.TrimSpace(r.Action + " " + r.target())
}

// target is the row's subject: a path, a command or a host:port; a socket's triple; nothing for an anonymous image.
func (r TestRow) target() string {
	switch {
	case r.Kind == ActionNetSocket:
		t := record.SocketTriple(r.Socket.Family, r.Socket.Type, r.Socket.Protocol)
		if r.Socket.Pair {
			return "socketpair " + t
		}
		return t
	case r.Path != "" && r.Dest != "":
		return r.Path + " -> " + r.Dest
	case r.Path != "":
		return r.Path
	case len(r.Argv) > 0:
		return strings.Join(r.Argv, " ")
	case r.Host != "":
		return net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	}
	return ""
}

// build builds the Action a row describes, resolving relative filesystem and exec paths against cwd, and "~"
// against home, so the evaluator sees the absolute paths Compile resolved entries to (E28). A row's `~/.ssh/id_rsa`
// named <cwd>/~/.ssh/id_rsa, so a row asserting a refusal under a `~/...` entry passed against a path no rule covers.
// Each path comes back cleaned, or, when spelled is set, kept as the agent's syscall would spell it, uncleaned: a
// Lander walks it ("lk/.." is physical), and resolveAction cleans what it does not land.
func (r TestRow) build(cwd, home string, spelled bool) Action {
	join, abs := joinAgainst, absAgainst
	expand := expandHome
	if spelled {
		join, abs, expand = spellAgainst, spellCommand, spellHome
	}
	a := Action{Kind: r.Kind, Argv: r.Argv, Host: r.Host, Port: r.Port, Proto: r.Proto, Method: r.Method}
	switch r.Kind {
	case ActionNetHTTP:
		a.Path = r.Path
	case ActionNetSocket:
		a.Socket = r.Socket
	case ActionExecAnon:
		// No path: the image is anonymous.
	case ActionNetConnect, ActionNetBind, ActionNetSend:
		// A unix socket. An abstract name (@...) is a name, not a path, and stays as written. A pathname is the one
		// the agent's connect, sendto or bind passes: "~/" expands as Compile expands a `unix:~/...` entry, and a
		// relative name joins cwd as the run joins a relative sun_path to the agent's cwd (supervisor R6, R11), so a
		// connect row's unix:out/s.sock is the socket in cwd's out/, not a name no entry can match. RunResolved then
		// lands it (resolveAction). A net.bind row's name is absolute or ~/ already (ParseEndpoint). The row's own
		// "unix:" prefix, written or not, is kept: the evaluator reads a path with no host as a unix socket either way.
		// A datagram's absolute name is also asked whether the run's kernel programs admit its spelling
		// (Action.Uncanonical), on the bytes the agent passes: "~/" expanded as written, nothing cleaned.
		a.Path = r.Path
		if p, prefixed := strings.CutPrefix(r.Path, "unix:"); p != "" && !strings.HasPrefix(p, "@") {
			a.Path = join(cwd, expand(home, p))
			if prefixed {
				a.Path = "unix:" + a.Path
			}
			if passed := spellHome(home, p); r.Kind == ActionNetSend && filepath.IsAbs(passed) {
				a.Uncanonical = !UnixCanonical(passed)
			}
		}
	case ActionExec:
		// "~/" expands first, as Compile expands exec.allow: absAgainst joined `~/bin/tool` under
		// cwd, so a row naming an allowed ~/ binary was refused and a refused row passed.
		a.Path = abs(cwd, expand(home, r.Path))
		if a.Path == "" && len(r.Argv) > 0 && strings.ContainsRune(r.Argv[0], filepath.Separator) {
			a.Path = abs(cwd, expand(home, r.Argv[0]))
			a.Argv = r.Argv
		}
		a.Script = abs(cwd, expand(home, r.Script))
		a.ScriptArg = r.ScriptArg
	default:
		// Filesystem rows always join: a single-component path is a file in cwd
		// (`report.md`, `.env`), never a name to match. absAgainst's bare-name arm exists
		// for `argv: [rg]` alone; applying it here handed Evaluate a relative string that
		// decide's cleanPath does not resolve (I6) and no absolute entry can cover, so the row
		// landed in the unmatched bucket whatever the contract said about that file.
		a.Path = join(cwd, expand(home, r.Path))
		a.DestPath = join(cwd, expand(home, r.Dest))
		a.Dir = r.Dir
	}
	return a
}

// expandHome expands a leading "~" or "~/" against home, as Compile does for the contract's entries; ""
// home leaves p as written.
func expandHome(home, p string) string {
	if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		return filepath.Join(home, p[1:])
	}
	return p
}

// joinAgainst resolves a filesystem row's path against cwd: "" stays "", an absolute path is
// only cleaned, everything else is joined, so Evaluate sees the absolute form Compile resolved
// the contract's entries to (E28).
func joinAgainst(cwd, p string) string {
	switch {
	case p == "":
		return ""
	case filepath.IsAbs(p):
		return filepath.Clean(p)
	case cwd == "":
		return filepath.Clean(p)
	}
	return filepath.Join(cwd, p)
}

// spellHome is expandHome with the rest of p kept as written: "~/a/../b" is home + "/a/../b", for the walk to take
// physically.
func spellHome(home, p string) string {
	if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		return home + p[1:]
	}
	return p
}

// spellAgainst is joinAgainst with p kept as the agent's syscall spells it from cwd: an absolute path as written,
// anything else appended to cwd, nothing cleaned.
func spellAgainst(cwd, p string) string {
	if p == "" || filepath.IsAbs(p) || cwd == "" {
		return p
	}
	return strings.TrimSuffix(cwd, "/") + "/" + p
}

// spellCommand is absAgainst with p kept as written: a bare command name stays one.
func spellCommand(cwd, p string) string {
	if !strings.ContainsRune(p, filepath.Separator) {
		return p
	}
	return spellAgainst(cwd, p)
}

// matches reports whether a result satisfies the row's expectations.
func (r TestRow) matches(got EvalResult) bool {
	if got.Verdict != r.Expect {
		return false
	}
	return r.Rule == "" || r.Rule == got.Rule
}

// absAgainst resolves an exec row's path against cwd; "" stays "", an absolute
// path is only cleaned, and a bare command name ("rg") is left alone so the
// evaluator still recognises it as a command rather than a file in cwd. Use
// joinAgainst for filesystem rows, where a single component is a file name.
func absAgainst(cwd, p string) string {
	switch {
	case p == "":
		return ""
	case filepath.IsAbs(p):
		return filepath.Clean(p)
	case !strings.ContainsRune(p, filepath.Separator):
		return p
	case cwd == "":
		return filepath.Clean(p)
	}
	return filepath.Join(cwd, p)
}

// parseTestTable walks the document's mapping: version, tests.
func parseTestTable(ds *diags, t *TestTable, file string, root *yaml.Node) {
	if root.Kind != yaml.MappingNode {
		ds.errorf(nodePos(file, root), CodeSchema, "test table must be a mapping with a tests: list")
		return
	}
	seenTests := false
	seen := map[string]bool{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], root.Content[i+1]
		// A repeated top-level key kept its last value: a second tests: list replaced the first, whose rows
		// then never ran (limits-check-doctor-cli.md R28).
		if seen[key.Value] {
			ds.errorf(nodePos(file, key), CodeSchema, "key %s appears twice in the test table", key.Value).
				fix("keep one %s:", key.Value)
			continue
		}
		seen[key.Value] = true
		switch key.Value {
		case "version":
			// The contract's version rule (checkVersion), with its refusal of a tag and of quotes: `version: "0"`
			// and `version: 00` were read as 0 here while a contract refuses both.
			if val.Kind != yaml.ScalarNode || val.Style&yaml.TaggedStyle != 0 || val.ShortTag() != "!!int" {
				ds.errorf(nodePos(file, val), CodeSchema, "version must be the number 0, got %s", describe(val)).
					fix("write version: 0, without quotes or a tag")
				continue
			}
			if msg, fix := checkVersion(val.Value); msg != "" {
				ds.errorf(nodePos(file, val), CodeSchema, "%s", msg).fix("%s", fix)
				continue
			}
			t.Version = 0
		case "tests":
			seenTests = true
			parseTestRows(ds, t, file, val)
		default:
			ds.errorf(nodePos(file, key), CodeSchema, "unknown field %q", key.Value).
				fix("the table's fields are version and tests")
		}
	}
	if !seenTests {
		ds.errorf(nodePos(file, root), CodeSchema, "no tests: list").
			fix("add a tests: list of rows")
	}
}

// parseTestRows walks the tests: sequence.
func parseTestRows(ds *diags, t *TestTable, file string, seq *yaml.Node) {
	if seq.Kind != yaml.SequenceNode {
		ds.errorf(nodePos(file, seq), CodeSchema, "tests must be a list of rows")
		return
	}
	// A check that checked nothing must not pass: `tests: []` exited 0 with no row run.
	if len(seq.Content) == 0 {
		ds.errorf(nodePos(file, seq), CodeSchema, "tests: is empty; there are no rows to check").
			fix("add at least one row with action: and expect:")
		return
	}
	for _, item := range seq.Content {
		if row, ok := parseTestRow(ds, file, item); ok {
			t.Rows = append(t.Rows, row)
		}
	}
}

// parseTestRow walks one row's mapping and validates it (R28).
func parseTestRow(ds *diags, file string, node *yaml.Node) (TestRow, bool) {
	row := TestRow{Line: node.Line}
	var endpointProto string
	var hostNode *yaml.Node
	var socketKeys []string // the net.socket keys the row gave, in file order
	if node.Kind != yaml.MappingNode {
		ds.errorf(nodePos(file, node), CodeSchema, "each test must be a mapping")
		return row, false
	}
	ok := true
	seen := map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, val := node.Content[i], node.Content[i+1]
		pos := nodePos(file, val)
		// A repeated key kept its last value silently (expect: refused, then expect: allow read as allow),
		// and an alias read as the anchor's name; a row must read as written.
		if seen[key.Value] {
			ds.errorf(nodePos(file, key), CodeSchema, "key %s appears twice in this test", key.Value)
			ok = false
			continue
		}
		seen[key.Value] = true
		if val.Kind == yaml.AliasNode || val.Anchor != "" {
			ds.errorf(pos, CodeSchema, "%s: anchors and aliases are not accepted in a test table", key.Value).
				fix("write the value out in every row")
			ok = false
			continue
		}
		// Every key but argv takes one value. A list or a mapping there read as its empty Value, so
		// `path: [a, b]` evaluated the working directory and `expect: {x: 1}` failed as an unknown "".
		if scalarRowKeys[key.Value] && !scalarRowValue(ds, file, key.Value, val) {
			ok = false
			continue
		}
		switch key.Value {
		case "name":
			row.Name = val.Value
		case "action":
			row.Action = val.Value
			kind, known := actionKinds[val.Value]
			if !known {
				ds.errorf(pos, CodeSchema, "unknown action %q", val.Value).
					fix("one of %s", strings.Join(actionNames, ", "))
				ok = false
				continue
			}
			row.Kind = kind
		case "path", "dest", "script":
			// A row's path is checked as a contract's path entry is (checkPath): a newline or a ~user form is
			// refused, so a row cannot name a path no contract entry can.
			if msg, fix := checkPath(val.Value); msg != "" {
				ds.errorf(pos, CodeSchema, "%s: %s", key.Value, msg).fix("%s", fix)
				ok = false
				continue
			}
			switch key.Value {
			case "path":
				row.Path = val.Value
			case "dest":
				row.Dest = val.Value
			default:
				row.Script = val.Value
			}
		case "script_arg":
			// The #! line's argument (`#!/usr/bin/env node` has node), which binfmt_script passes the interpreter
			// before the script (ADR 0048 (4)).
			row.ScriptArg = val.Value
		case "proto":
			row.Proto = strings.ToLower(val.Value)
			if row.Proto != ProtoTCP && row.Proto != ProtoUDP && row.Proto != ProtoUnix {
				ds.errorf(pos, CodeSchema, "unknown proto %q", val.Value).fix("one of tcp, udp, unix (net.bind only)")
				ok = false
				continue
			}
		case "method":
			row.Method = val.Value
		case "argv":
			if val.Kind != yaml.SequenceNode {
				ds.errorf(pos, CodeSchema, "argv must be a list")
				ok = false
				continue
			}
			argvOK := true
			for _, a := range val.Content {
				if !scalarRowValue(ds, file, "argv entry", a) {
					argvOK = false
					continue
				}
				row.Argv = append(row.Argv, a.Value)
			}
			if !argvOK {
				ok = false
				continue
			}
		case "host_port":
			hostNode = val
		case "tier":
			tier, err := backend.ParseTier(val.Value)
			if err != nil {
				ds.errorf(pos, CodeSchema, "unknown tier %q", val.Value).
					fix("one of landlock, cgroup, bpflsm, observe")
				ok = false
				continue
			}
			row.Tier = tier
		case "expect":
			switch Verdict(val.Value) {
			case VerdictAllow, VerdictAsk, VerdictRefused:
				row.Expect = Verdict(val.Value)
			default:
				ds.errorf(pos, CodeSchema, "unknown expect %q", val.Value).
					fix("one of allow, ask, refused")
				ok = false
			}
		case "rule":
			row.Rule = val.Value
		case "dir":
			switch val.Value {
			case "true":
				row.Dir = true
			case "false":
			default:
				ds.errorf(pos, CodeSchema, "dir %q: want true or false", val.Value)
				ok = false
			}
		case "family", "type", "protocol":
			socketKeys = append(socketKeys, key.Value)
			named := record.SocketFamilyNumber
			switch key.Value {
			case "type":
				named = record.SocketTypeNumber
			case "protocol":
				named = protocolNumber
			}
			n, known := socketNumber(val.Value, named)
			if !known {
				ds.errorf(pos, CodeSchema, "%s %q: want a number or a name such as %s", key.Value, val.Value,
					map[string]string{"family": "AF_INET", "type": "SOCK_STREAM", "protocol": "IPPROTO_TCP"}[key.Value])
				ok = false
				continue
			}
			switch key.Value {
			case "family":
				row.Socket.Family = n
			case "type":
				row.Socket.Type = n
			default:
				row.Socket.Protocol = n
			}
		case "socketpair":
			socketKeys = append(socketKeys, key.Value)
			switch val.Value {
			case "true":
				row.Socket.Pair = true
			case "false":
			default:
				ds.errorf(pos, CodeSchema, "socketpair %q: want true or false", val.Value)
				ok = false
			}
		default:
			ds.errorf(nodePos(file, key), CodeSchema, "unknown field %q", key.Value).
				fix("a row's fields are name, action, path, dest, script, script_arg, argv, host_port, proto, method, " +
					"tier, expect, rule, dir, and for net.socket family, type, protocol, socketpair")
			ok = false
		}
	}
	if len(socketKeys) > 0 && row.Kind != ActionNetSocket && row.Kind != "" {
		ds.errorf(nodePos(file, node), CodeSchema, "%s: family, type, protocol and socketpair belong to net.socket rows",
			strings.Join(socketKeys, ", "))
		ok = false
	}
	if row.Kind == ActionNetSocket && (row.Path != "" || row.Dest != "" || row.Script != "" || row.ScriptArg != "" ||
		len(row.Argv) != 0 || hostNode != nil || row.Proto != "" || row.Method != "" || row.Dir) {
		ds.errorf(nodePos(file, node), CodeSchema, "a net.socket test takes family, type, protocol and socketpair, "+
			"not a path, dest, script, argv, host_port, proto, method or dir")
		ok = false
	}
	if row.Kind == ActionExecAnon && (row.Path != "" || row.Dest != "" || row.Script != "" || row.ScriptArg != "" ||
		len(row.Argv) != 0 || hostNode != nil || row.Proto != "" || row.Method != "" || row.Dir) {
		// The image is a memfd or an unlinked file: no path names it, and its argv would be read by command rules
		// keyed on facts (the image's name) a row cannot give as the run reads them.
		ds.errorf(nodePos(file, node), CodeSchema, "an exec.anonymous test names no image: it takes no path, dest, "+
			"script, argv, host_port, proto, method or dir")
		ok = false
	}
	// Bind addresses use the listener grammar, including ephemeral port zero.
	// Parse after all keys so selector/proto validation is independent of YAML order.
	if row.Kind == ActionNetBind {
		ok = parseBindTestRow(ds, file, node, hostNode, &row) && ok
	} else if hostNode != nil {
		pos := nodePos(file, hostNode)
		text := hostNode.Value
		if strings.Contains(text, "://") {
			e, err := ParseEndpoint(text)
			if err != nil || e.Kind != EndpointHost {
				ds.errorf(pos, CodeSchema, "host_port %q: want a TCP or UDP host destination", text)
				ok = false
			} else {
				endpointProto = e.Proto
				text = net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
			}
		}
		host, port, err := hostPort(text)
		if err != nil {
			ds.errorf(pos, CodeSchema, "host_port %q: %v", hostNode.Value, err).
				fix("write host:port, for example api.example.com:443")
			ok = false
		} else {
			row.Host, row.Port = host, port
		}
	}
	if row.Proto == ProtoUnix && row.Kind != ActionNetBind {
		ds.errorf(nodePos(file, node), CodeSchema, "proto unix is only supported for net.bind test rows")
		ok = false
	}
	if endpointProto != "" {
		if row.Proto != "" && row.Proto != endpointProto {
			ds.errorf(nodePos(file, node), CodeSchema, "host_port transport %s contradicts proto %s", endpointProto, row.Proto)
			ok = false
		}
		row.Proto = endpointProto
	}
	if row.Kind == ActionNetSend {
		// An unconnected send is a datagram's (supervisor R13b): UDP to a host, a unix datagram to a unix: path. A
		// stream socket's send without a peer is decided as its connect (R12), which a net.connect row asks.
		switch {
		case row.Proto != "" && row.Proto != ProtoUDP:
			ds.errorf(nodePos(file, node), CodeSchema, "net.send is a datagram send: proto %s is not one", row.Proto).
				fix("leave proto out (udp to a host_port, a unix datagram to a unix: path); a net.connect row asks a stream")
			ok = false
		case row.Host != "":
			row.Proto = ProtoUDP
		}
	}
	if row.Kind == ActionNetHTTP && row.Proto == ProtoUDP {
		ds.errorf(nodePos(file, node), CodeSchema, "net.http requires TCP, not UDP")
		ok = false
	}
	return row, ok && validTestRow(ds, file, node, row)
}

// parseBindTestRow validates only the listening endpoints the compiler supports.
// A bare IP host_port uses proto (TCP by default); a Unix name may use path or
// host_port. Port zero is an ephemeral bind, never a wildcard for fixed ports.
func parseBindTestRow(ds *diags, file string, node, hostNode *yaml.Node, row *TestRow) bool {
	pos := nodePos(file, node)
	if (hostNode != nil && row.Path != "") || row.Dest != "" || row.Script != "" || len(row.Argv) != 0 || row.Method != "" {
		ds.errorf(pos, CodeSchema, "net.bind test needs one host_port or Unix path, without dest, script, argv or method")
		return false
	}
	text := row.Path
	if hostNode != nil {
		text, pos = hostNode.Value, nodePos(file, hostNode)
	} else if text != "" && !strings.HasPrefix(text, "unix:") {
		text = "unix:" + text
	}
	if text == "" {
		ds.errorf(pos, CodeSchema, "net.bind test needs host_port or a Unix path")
		return false
	}
	if !strings.Contains(text, "://") && !strings.HasPrefix(text, "unix:") {
		proto := row.Proto
		if proto == "" {
			proto = ProtoTCP
		}
		if proto != ProtoTCP && proto != ProtoUDP {
			ds.errorf(pos, CodeSchema, "net.bind host_port needs a TCP/UDP literal address or an explicit unix: name")
			return false
		}
		text = proto + "://" + text
	}
	e, err := ParseListenEndpoint(text)
	if err != nil {
		ds.errorf(pos, CodeSchema, "net.bind endpoint %q: %v", text, err)
		return false
	}
	if row.Proto != "" && row.Proto != e.Proto {
		ds.errorf(pos, CodeSchema, "net.bind transport %s contradicts proto %s", e.Proto, row.Proto)
		return false
	}
	row.Proto = e.Proto
	if e.Kind == EndpointUnix {
		row.Path = "unix:" + e.UnixPath
		if e.Abstract {
			row.Path = "unix:@" + e.UnixPath
		}
	} else {
		row.Host, row.Port = e.Host, e.Port
	}
	return true
}

// scalarRowKeys are a row's keys that take one value (every key but argv, which takes a list).
var scalarRowKeys = map[string]bool{
	"name": true, "action": true, "path": true, "dest": true, "script": true, "script_arg": true, "proto": true,
	"host_port": true, "tier": true, "expect": true, "rule": true, "method": true, "dir": true,
	"family": true, "type": true, "protocol": true, "socketpair": true,
}

// scalarRowValue reports whether val is one plain value, and reports it when it is not. A null (an
// unquoted `~`, or nothing after the key) is refused as the contract refuses a null list entry: the
// contract reads `~` as the home directory only when it is quoted, and a row read the unquoted one as
// home, so the two disagreed on the same spelling (limits-check-doctor-cli.md R28).
func scalarRowValue(ds *diags, file, what string, val *yaml.Node) bool {
	pos := nodePos(file, val)
	switch {
	case val.Kind != yaml.ScalarNode:
		ds.errorf(pos, CodeSchema, "%s must be a single value, got %s", what, describe(val))
		return false
	case val.Style&yaml.TaggedStyle != 0:
		// An explicit tag changes what the value is: `path: !!binary L2V0Yy9zaGFkb3c=` is /etc/shadow once
		// decoded, while the row read the base64 text. A contract accepts no tag (walker.walk), nor does a row.
		ds.errorf(pos, CodeSchema, "%s: explicit YAML tag %s is not accepted in a test table", what, val.Tag).
			fix("remove the tag; quote the value if it should be a string")
		return false
	case isNull(val):
		ds.errorf(pos, CodeSchema, "%s: empty value", what).
			fix(`write "~" in quotes for the home directory, or give the value`)
		return false
	case strings.ContainsRune(val.Value, 0):
		ds.errorf(pos, CodeSchema, "%s contains NUL", what)
		return false
	}
	return true
}

// validTestRow checks a row carries what its action needs.
func validTestRow(ds *diags, file string, node *yaml.Node, row TestRow) bool {
	pos := nodePos(file, node)
	switch {
	case row.Action == "":
		ds.errorf(pos, CodeSchema, "test has no action").
			fix("one of %s", strings.Join(actionNames, ", "))
		return false
	case row.Expect == "":
		ds.errorf(pos, CodeSchema, "test %q has no expect", row.Label()).
			fix("one of allow, ask, refused")
		return false
	}
	switch row.Kind {
	case ActionExec:
		if row.Path == "" && len(row.Argv) == 0 {
			ds.errorf(pos, CodeSchema, "exec test needs path or argv")
			return false
		}
	case ActionNetConnect:
		if row.Host == "" && row.Path == "" {
			ds.errorf(pos, CodeSchema, "net.connect test needs host_port or a unix: path")
			return false
		}
	case ActionNetBind:
		// parseBindTestRow has already required one supported listener endpoint.
		if row.Host == "" && row.Path == "" {
			ds.errorf(pos, CodeSchema, "net.bind test needs host_port or a Unix path")
			return false
		}
	case ActionNetHTTP:
		if row.Host == "" || row.Port < 1 || row.Path == "" || row.Method == "" {
			ds.errorf(pos, CodeSchema, "net.http test needs host_port, method and path")
			return false
		}
	case ActionFSRename, ActionFSLink:
		if row.Path == "" || row.Dest == "" {
			ds.errorf(pos, CodeSchema, "%s test needs path and dest", row.Action)
			return false
		}
	case ActionNetSend:
		if row.Host == "" && row.Path == "" {
			ds.errorf(pos, CodeSchema, "net.send test needs host_port or a unix: path")
			return false
		}
	case ActionNetSocket:
		if !slices.Contains(socketKeysOf(node), "family") || !slices.Contains(socketKeysOf(node), "type") {
			ds.errorf(pos, CodeSchema, "net.socket test needs family and type (protocol defaults to 0)")
			return false
		}
	case ActionExecAnon:
		// Nothing names the image: the row is the exec of an anonymous one.
	default:
		if row.Path == "" {
			ds.errorf(pos, CodeSchema, "%s test needs a path", row.Action)
			return false
		}
	}
	return true
}

// socketKeysOf is the net.socket keys a row's mapping node gives.
func socketKeysOf(node *yaml.Node) []string {
	var out []string
	for i := 0; i+1 < len(node.Content); i += 2 {
		if socketRowKeys[node.Content[i].Value] {
			out = append(out, node.Content[i].Value)
		}
	}
	return out
}

// hostPort parses a row's host_port through the same splitter the contract's
// endpoints use; the port is required because the root tiers decide host:port
// in the kernel (SEMANTICS §5).
func hostPort(s string) (string, int, error) {
	host, portText, err := splitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := parsePort(portText)
	if err != nil {
		return "", 0, err
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	// A zone is refused here as in a contract entry (ParseEndpoint): no tier matches on it.
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() != "" {
		return "", 0, fmt.Errorf("%w: %q has an IPv6 zone (%%%s), which no tier matches on; write [%s]:%s",
			ErrEndpoint, host, ip.Zone(), ip.WithZone(""), portText)
	}
	return host, port, nil
}

// documentRoot unwraps a yaml document node; nil for an empty document.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return nil
		}
		return doc.Content[0]
	}
	if doc.Kind == 0 {
		return nil
	}
	return doc
}

// nodePos is a node's position as a Diagnostic position.
func nodePos(file string, n *yaml.Node) Pos {
	if n == nil {
		return Pos{File: file, Line: 1}
	}
	return Pos{File: file, Line: n.Line, Col: n.Column}
}

// firstTestError returns ErrInvalidTestTable wrapping the first error
// diagnostic, or nil when every diagnostic is a warning.
func firstTestError(ds []Diagnostic) error {
	for _, d := range ds {
		if d.IsError() {
			return fmt.Errorf("%w: %w", ErrInvalidTestTable, d)
		}
	}
	return nil
}
