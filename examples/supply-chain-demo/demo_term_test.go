// SPDX-License-Identifier: Apache-2.0

//go:build integration

package supplychain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestProofShowsTheAttackRowsWhole: in a real take the enforced run's refusals start with Codex's own
// connections, so proof printed the first twelve refusals cut at 200 characters and the key's path fell off the
// screen. Here the enforced run makes 30 unrelated refused connects before the poisoned import: proof still shows
// the key, the token and the send to the right attacker, each line whole, and says how many refusals there were in
// all. After backup has cleared the attacker logs, proof says why they are empty.
func TestProofShowsTheAttackRowsWhole(t *testing.T) {
	w := newWorld(t)
	w.mustDemo("setup")
	noise := freePort(t) // nothing listens there, and the contract allows only the API
	initPy := filepath.Join(w.stage, "with", "proj", "tests", "__init__.py")
	extra := fmt.Sprintf(`
import socket as _s
for _i in range(30):
    _c = _s.socket()
    try:
        _c.settimeout(0.5)
        _c.connect(("127.0.0.1", %d))
    except OSError:
        pass
    finally:
        _c.close()
`, noise)
	b := readFile(t, initPy)
	if err := os.WriteFile(initPy, []byte(b+extra), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := w.demoEnv([]string{"DEMO_BACKUP_KEEP_LOGS=0"}, "backup"); code != 0 {
		t.Fatalf("backup: exit %d\n%s", code, out)
	}
	out := w.mustDemo("proof")
	right := strconv.Itoa(w.right)
	mustContain(t, "proof", out,
		"(empty: nothing reached it since the last reset or backup)",
		"fs.deny_read[<stage>/with/home/.ssh/]", "open <stage>/with/home/.ssh/id_rsa\n",
		"open <stage>/with/home/.config/telemetry/token\n",
		"net 127.0.0.1:"+right+"\n",
		"refusals in all (the rest are not the attack: Codex's own connections and any command the take refused; see the dashboard Logs)",
		"open <stage>/without/home/.ssh/id_rsa\n",
		"<stage> is "+w.stage)
	if strings.Contains(out, "127.0.0.1:"+strconv.Itoa(noise)) {
		t.Errorf("proof shows the unrelated connects:\n%s", out)
	}
	if strings.Contains(out, "left received, right did not") {
		t.Errorf("proof claims the left attacker received something though its log is empty:\n%s", out)
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "SEQ ") || strings.Contains(line, "refusals in all") {
			n++
		}
	}
	if n < 2 {
		t.Errorf("proof lacks the RIGHT table or its count:\n%s", out)
	}
}

// TestCheckKnowsTheDemosOwnDashboard: a retake used to FAIL check on the demo's own dashboard, forcing a
// Ctrl-C and a new sign-in in front of the audience. A tego-control serve of the demo's config on the dashboard
// address is ok, and stays ok across a reset; any other program there, or a dashboard of another config, still fails.
func TestCheckKnowsTheDemosOwnDashboard(t *testing.T) {
	if _, err := exec.LookPath("ss"); err != nil {
		t.Skip("ss (iproute2) is not installed")
	}
	w := newWorld(t)
	w.mustDemo("setup")
	addr := "127.0.0.1:" + strconv.Itoa(w.dash)

	startIn := func(dir, name string, env []string, args ...string) func() {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env, cmd.Dir = env, dir
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatalf("%s: %v", name, err)
		}
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
				_ = c.Close()
				return func() { cancel(); _ = cmd.Wait() }
			}
		}
		cancel()
		_ = cmd.Wait()
		t.Fatalf("%s did not listen on %s", name, addr)
		return nil
	}
	start := func(name string, env []string, args ...string) func() {
		t.Helper()
		return startIn("", name, env, args...)
	}
	// w.envList is newWorld's testutil environment: TEGO_TEST_CHAIN_ANCHOR and the own log stay in the test's folder,
	// and tego-control is built with the test hooks, so the dashboards here never read the invoking user's anchor.
	ours := append(append([]string{}, w.envList...), "TEGO_CONFIG="+w.cfg)

	stop := start(w.ctl, ours, "serve", "--addr", addr)
	out, code := w.demo("check")
	if code != 0 || !strings.Contains(out, "ok    the demo's dashboard is running (reset keeps it; it follows the new ledger)") {
		t.Errorf("check with the demo's dashboard: exit %d\n%s", code, out)
	}
	w.mustDemo("reset")
	if out, code := w.demo("check"); code != 0 || !strings.Contains(out, "the demo's dashboard is running") || !strings.Contains(out, "READY") {
		t.Errorf("check after a reset with the dashboard up: exit %d\n%s", code, out)
	}
	stop()

	// A relative --ledger is the dashboard's own, read against its working directory, not against demo.sh's.
	stop = startIn(w.base, w.ctl, ours, "serve", "--addr", addr, "--ledger", filepath.Base(w.ledger))
	if out, code := w.demo("check"); code != 0 || !strings.Contains(out, "the demo's dashboard is running") {
		t.Errorf("check with the demo's dashboard on a relative --ledger: exit %d\n%s", code, out)
	}
	stop()

	other := filepath.Join(w.base, "other.yaml")
	if err := os.WriteFile(other, []byte("version: 0\nledger_root: "+filepath.Join(w.base, "other-ledger")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func() func(){
		"python http.server": func() func() {
			return start("python3", w.envList, "-m", "http.server", "--bind", "127.0.0.1", strconv.Itoa(w.dash))
		},
		"a dashboard of another config": func() func() {
			return start(w.ctl, append(append([]string{}, w.envList...), "TEGO_CONFIG="+other), "serve", "--addr", addr)
		},
		"a dashboard of another ledger": func() func() {
			return start(w.ctl, ours, "serve", "--addr", addr, "--ledger", filepath.Join(w.base, "other-ledger"))
		},
		"a relative --ledger that is another folder's": func() func() {
			sub := filepath.Join(w.base, "sub")
			if err := os.MkdirAll(filepath.Join(sub, filepath.Base(w.ledger)), 0o700); err != nil {
				t.Fatal(err)
			}
			return startIn(sub, w.ctl, ours, "serve", "--addr", addr, "--ledger", filepath.Base(w.ledger))
		},
	} {
		stop := run()
		out, code := w.demo("check")
		stop()
		if code != 1 || !strings.Contains(out, "something already listens on the dashboard address") || strings.Contains(out, "the demo's dashboard is running") {
			t.Errorf("%s: check exit %d\n%s", name, code, out)
		}
	}
}

// TestStaleCheckIgnoresDocsOnlyCommits: check called bin/tego stale after any later commit, a docs-only one
// included, which is likely right after a merge's doc commits. A build whose commit differs from HEAD only in docs/
// and Markdown is ok; a code change since, or a commit the checkout does not know, is still stale.
func TestStaleCheckIgnoresDocsOnlyCommits(t *testing.T) {
	for _, tool := range []string{"git", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	kit := filepath.Join(root, "repo", "examples", "supply-chain-demo")
	for _, d := range []string{home, kit, filepath.Join(root, "repo", "docs"), filepath.Join(root, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"demo.sh", "demo.env"} {
		if err := os.WriteFile(filepath.Join(kit, f), []byte(readFile(t, f)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	repo := filepath.Join(root, "repo")
	env := []string{"HOME=" + home, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid"}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(path, body, msg string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, path), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", "-A")
		git("commit", "-q", "-m", msg)
		return git("rev-parse", "HEAD")
	}
	git("init", "-q")
	built := commit("main.go", "package main\n", "code")

	check := func(have string) string {
		t.Helper()
		fake := filepath.Join(root, "bin", "tego")
		body := "#!/bin/sh\nif [ \"$1\" = version ]; then echo commit=" + have + "; fi\nexit 0\n"
		if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", filepath.Join(kit, "demo.sh"), "check")
		cmd.Env = append(append([]string{}, env...),
			"TEGO="+fake, "TEGO_CONTROL="+fake, "DEMO_CONFIG="+filepath.Join(root, "demo.yaml"), "DEMO_LEDGER="+filepath.Join(root, "ledger"),
			"DEMO_STAGE="+filepath.Join(root, "stage"), "DEMO_OFFLINE=1", "DEMO_UNIT_PREFIX=tego-sctest-stale",
			"DEMO_PORT_LEFT="+strconv.Itoa(freePort(t)), "DEMO_PORT_RIGHT="+strconv.Itoa(freePort(t)),
			"DEMO_PORT_API="+strconv.Itoa(freePort(t)), "DEMO_DASH_ADDR=127.0.0.1:"+strconv.Itoa(freePort(t)),
			"DEMO_SYSTEMD_RUNTIME="+filepath.Join(root, "no-systemd"))
		out, _ := cmd.CombinedOutput() // check fails for the rest of this bare world; only the binaries' lines matter
		return string(out)
	}

	commit("docs/notes.md", "# notes\n", "docs only")
	commit("README.md", "readme\n", "a top-level Markdown file")
	out := check(built)
	mustContain(t, "docs-only change", out, "ok    tego built from "+built[:8]+"; only docs changed since",
		"ok    tego-control built from "+built[:8]+"; only docs changed since")
	if strings.Contains(out, "is stale") {
		t.Errorf("a docs-only change made the binary stale:\n%s", out)
	}

	commit("main.go", "package main\n\nfunc main() {}\n", "code again")
	mustContain(t, "code change", check(built), "bin/tego is stale: it was built from "+built[:8])
	mustContain(t, "unknown commit", check("0123456789abcdef0123456789abcdef01234567"), "bin/tego is stale: it was built from 01234567")
}

// TestProofRowsKeepTwoSpacesWhole: proof read the text table of `tego events`, whose cells are split by two spaces,
// so a rule and a path holding two spaces in a row (a folder with a double space, say) printed split at them. It
// reads the stored lines now: both print whole, with the stage folder as <stage>, an unrelated refusal is still left
// out, and a control character the agent put in a path is escaped as `tego events` escapes it, never written raw.
func TestProofRowsKeepTwoSpacesWhole(t *testing.T) {
	odd := "/st/with/odd  dir/home/.ssh/"
	refused := slices.Concat(
		recordLine(t, 4, "refused", "", "", "net-not-allowed", map[string]any{"op": "net", "dst": "127.0.0.1:9"}),
		recordLine(t, 9, "refused", "fs.deny_read["+odd+"]", "", "read-denied", map[string]any{"op": "open", "target": odd + "id_rsa"}),
		recordLine(t, 12, "refused", "", "", "net-not-allowed", map[string]any{"op": "net", "dst": "127.0.0.1:8802"}),
		recordLine(t, 14, "refused", "fs.ask_read[/st/with/home/.config/telemetry/]", "", "ask-denied",
			map[string]any{"op": "open", "target": "/st/with/home/.config/telemetry/token\x1b[2J"}),
	)
	out := proofRows(t, refused, "/st", "refused", "8802", "Codex")
	want := [][]string{
		{"9", "read-denied", "fs.deny_read[<stage>/with/odd  dir/home/.ssh/]", "open <stage>/with/odd  dir/home/.ssh/id_rsa"},
		{"12", "net-not-allowed", "-", "net 127.0.0.1:8802"},
		{"14", "ask-denied", "fs.ask_read[<stage>/with/home/.config/telemetry/]", `open <stage>/with/home/.config/telemetry/token\x1b[2J`},
	}
	if got := tableCells(t, withoutLastLine(out), "SEQ", "VERDICT", "RULE", "DETAIL"); !reflect.DeepEqual(got, want) {
		t.Errorf("PROOF_ROWS rows:\n got %q\nwant %q\n%s", got, want, out)
	}
	mustContain(t, "PROOF_ROWS", out, "\n4 refusals in all (the rest are not the attack: Codex's own connections and any command the take refused; see the dashboard Logs)\n")
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("PROOF_ROWS wrote the agent's escape byte to the terminal:\n%q", out)
	}

	// The watched run: only the key's read and the sends to the attacker's port are kept, not the tests' exec nor a
	// send to a port that merely starts with the attacker's digits.
	watched := slices.Concat(
		recordLine(t, 3, "exec", "unmatched", "observed", "", map[string]any{"path": "/usr/bin/python3", "argv": []any{"python3", "-m", "unittest"}}),
		recordLine(t, 5, "fs", "unmatched", "observed", "", map[string]any{"op": "open", "path": "/st/without/home/.ssh/id_rsa"}),
		recordLine(t, 6, "net", "unmatched", "observed", "", map[string]any{"proto": "tcp", "dst": "127.0.0.1:8801"}),
		recordLine(t, 7, "net", "unmatched", "observed", "", map[string]any{"proto": "tcp", "dst": "127.0.0.1:88010"}),
	)
	out = proofRows(t, watched, "/st", "watched", "8801", "Codex")
	want = [][]string{
		{"5", "observed", "unmatched", "open <stage>/without/home/.ssh/id_rsa"},
		{"6", "observed", "unmatched", "tcp 127.0.0.1:8801"},
	}
	if got := tableCells(t, withoutLastLine(out), "SEQ", "VERDICT", "RULE", "DETAIL"); !reflect.DeepEqual(got, want) {
		t.Errorf("PROOF_ROWS watched rows:\n got %q\nwant %q\n%s", got, want, out)
	}
	mustContain(t, "PROOF_ROWS watched", out, "\n4 recorded events in all (the rest are the run's ordinary work; see the dashboard Logs)\n")
}

// TestProofRowsReadLikeTheEventsTable: proof prints each attack row's verdict, rule and detail as the table of `tego
// events` writes them, so the take's proof reads as it did when it read that table. PROOF_ROWS rebuilds the cells from
// the stored lines (events.Summary and the verdict and rule cells, through record.Printable); here every kind
// Summary words, each number form, two spaces in a row, the controls and invisible characters Printable escapes and
// the spaces TrimSpace drops (and one it keeps) go through both, and each row must read the same in both.
func TestProofRowsReadLikeTheEventsTable(t *testing.T) {
	// deny keeps a row in refused mode whatever its detail. U+E0002 is unassigned: Printable escapes the tag block by
	// code point, not only by category.
	deny := "fs.deny_read[/w/a  b/]"
	invisible := "/w/home/.ssh/id_rsa\x1b[2J\u202e\u200b\U000e0041\U000e0002\ufeff\u0085x\u2066\x7f\u0085"
	type ev struct {
		kind, rule, verdict, reason string
		payload                     map[string]any
	}
	evs := []ev{
		{"run_start", deny, "", "", map[string]any{"tier": "landlock", "capture": "full", "kernel": "6.17.0  x",
			"run_command_grant": "g", "best_effort": []any{"a", 3, "b"}}},
		{"run_end", deny, "", "agent-exit", map[string]any{"exit_code": 0}},
		{"exec", "", "observed", "", map[string]any{"path": "/bin/cat", "argv": []any{"cat", "/w/home/.ssh/id_rsa", 7},
			"command_rule": "r", "command_list": "allow", "command_match": "ambiguous", "command_via": "path"}},
		{"exec", deny, "allow", "exec-allowed", map[string]any{"path": "/bin/true", "command_rule": "t", "command_list": "allow", "command_via": "name"}},
		{"fs", "", "observed", "", map[string]any{"op": "open", "path": "/w/home/.ssh/id_rsa", "count": 3, "alternate_for": "/w/x  y"}},
		{"fs", deny, "", "", map[string]any{"path": "/w/p", "count": json.Number("2.5")}},
		{"fs", deny, "", "", map[string]any{"op": "write", "path": "/w/q", "count": 0}},
		{"net", "", "observed", "", map[string]any{"proto": "tcp", "dst": "127.0.0.1:8801", "host": "sink  host"}},
		{"ssl_request", "", "", "", map[string]any{"method": "POST", "host": "127.0.0.1:8801", "path": "/exfil"}},
		{"ssl_response", deny, "", "", map[string]any{"model": "m", "status": 200, "usage": map[string]any{"input": 10, "output": 0}}},
		{"ssl_response", deny, "", "", map[string]any{"model": "m", "usage": map[string]any{"input": 0}}},
		{"decision", deny, "", "", map[string]any{"tool": "Bash", "why": "w"}},
		{"decision", deny, "", "", map[string]any{"why": "because"}},
		{"gap", deny, "", "", map[string]any{"what": "capture", "why": "no tls"}},
		{"limit", deny, "", "", map[string]any{"which": "tokens", "value": json.Number("12345678901234567890"), "ceiling": json.Number("1e400")}},
		{"limit", deny, "", "", map[string]any{"which": "wall", "value": json.Number("1.5e-7"), "ceiling": json.Number("1e21")}},
		{"limit", deny, "", "", map[string]any{"which": "cost", "value": json.Number("-0"), "ceiling": json.Number("4.0E2")}},
		{"limit", deny, "", "", map[string]any{"which": "big", "value": json.Number("1.2345678901234567e30")}},
		{"gap", deny, "", "", map[string]any{"what": "a\tb\nc\rd", "why": "e\vf\fg\ah\bi"}},
		{"refused", "fs.deny_read[/w/home/.ssh/]", "", "read-denied", map[string]any{"op": "open", "target": invisible}},
		{"refused", "", "", "net-not-allowed", map[string]any{"op": "net", "dst": "127.0.0.1:8801\u2028"}},
		{"refused", "", "", "", map[string]any{"op": "open", "path": "/w/home/.config/telemetry/token\x1c"}},
		{"refused", deny, "", "", map[string]any{"op": "open", "target": "a SURROGATE b"}},
		{"refused", deny, "", "", map[string]any{"op": "open", "target": 12, "path": "/w/p2"}}, // a number is no target
		{"mcp", deny, "", "", map[string]any{"name": "srv", "transport": "stdio", "tool": "read"}},
		{"ask", deny, "ask", "", map[string]any{"hold": "open", "op": "read", "target": "/w/home/.config/telemetry/token"}},
		{"answer", deny, "", "", map[string]any{"approved": false, "answer_reason": "timeout", "by": "me", "after_s": json.Number("4.25")}},
		{"answer", deny, "", "", map[string]any{"alternate": "/alt", "by": "me"}},
		{"answer", deny, "", "", map[string]any{"approved": true, "after_s": 3}},
		{"answer", deny, "", "", map[string]any{"approved": false}},
		{"answer", deny, "", "", map[string]any{"by": "nobody"}},
		{"answer", deny, "", "", map[string]any{"approved": "yes", "by": "x"}}, // not a bool: neither approved nor not
		{"answer", deny, "", "", map[string]any{"approved": 0, "by": "y"}},
		{"boundary", deny, "", "", map[string]any{"dst": "d", "propagated": "yes"}},
		{"later_kind", deny, "", "", map[string]any{"x": "y"}},
	}
	var lines []byte
	for i, e := range evs {
		line := recordLine(t, i+1, e.kind, e.rule, e.verdict, e.reason, e.payload)
		// A lone surrogate escape: no Go string marshals to one, and Go decodes it as U+FFFD.
		lines = append(lines, bytes.ReplaceAll(line, []byte("SURROGATE"), []byte(`\ud800`))...)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), lines, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	var table strings.Builder
	if n, err := events.TableOf(context.Background(), &table, r, r.Entries(), events.Filter{}); err != nil || n != len(evs) {
		t.Fatalf("events.TableOf: %d rows, %v\n%s", n, err, table.String())
	}
	want := map[string][]string{}
	for _, row := range tableCells(t, table.String(), "SEQ", "TIME", "KIND", "SOURCE", "VERDICT", "RULE", "DETAIL") {
		want[row[0]] = []string{row[4], row[5], row[6]}
	}

	out := proofRows(t, lines, "/no-such-stage", "refused", "8801", "Codex")
	got := map[string][]string{}
	for _, row := range tableCells(t, withoutLastLine(out), "SEQ", "VERDICT", "RULE", "DETAIL") {
		got[row[0]] = row[1:]
	}
	if len(want) != len(evs) || !reflect.DeepEqual(got, want) {
		for seq, cells := range want {
			if !reflect.DeepEqual(got[seq], cells) {
				t.Errorf("row %s: PROOF_ROWS %q, tego events %q", seq, got[seq], cells)
			}
		}
		t.Fatalf("PROOF_ROWS reads %d rows unlike the table of %d:\n%s\n%s", len(got), len(want), out, table.String())
	}
	mustContain(t, "PROOF_ROWS", out, fmt.Sprintf("\n%d refusals in all\n", len(evs)))
	if strings.ContainsFunc(out, func(r rune) bool { return r < 0x20 && r != '\n' || r == 0x7f || unicode.Is(unicode.Cf, r) }) {
		t.Errorf("PROOF_ROWS wrote a control or invisible character:\n%q", out)
	}
}

// TestAttackerPanelAndTheStageUnderHome: two of the take's screens had no test. attacker runs watch -t, so the panel
// has no header line (user name, host, stage folder, clock), only the two logs; and proof writes a stage under HOME
// from ~, as its user reads it, never with the home folder's own path. The stage here is under the world's HOME.
func TestAttackerPanelAndTheStageUnderHome(t *testing.T) {
	w := newWorld(t)
	w.stage = filepath.Join(w.base, "home", "stage")
	w.envList = append(w.envList, "DEMO_STAGE="+w.stage) // the last value wins, for the cleanup's reset too
	w.mustDemo("setup")

	t.Run("attacker", func(t *testing.T) {
		left := filepath.Join(w.stage, "without", "sink.log")
		f, err := os.OpenFile(left, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString("[sink] an agent reached the sink: POST /exfil, 12 bytes\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatal(err)
		}
		// A watch that records its arguments, then shows the panel once, as watch's first screen would.
		args := filepath.Join(w.base, "watch-args")
		stub := filepath.Join(w.stub, "watch")
		body := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\0' \"$a\"; done >'" + args + "'\nshift 3\nexec sh -c \"$1\"\n"
		if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Remove(stub) }()

		out := w.mustDemo("attacker")
		got := strings.Split(strings.TrimSuffix(readFile(t, args), "\x00"), "\x00")
		if len(got) != 4 || got[0] != "-t" || got[1] != "-n" || got[2] != "1" {
			t.Fatalf("attacker ran watch %q; want -t -n 1 and the panel", got)
		}
		mustContain(t, "attacker", out, "$ watch -t -n 1 '",
			"== LEFT attacker ==\n"+lastLines(t, left, 4)+"\n== RIGHT attacker ==\n"+lastLines(t, filepath.Join(w.stage, "with", "sink.log"), 4))
	})

	t.Run("proof", func(t *testing.T) {
		w.mustDemo("right") // the stub Codex: an enforced run, so proof prints its rows' line
		out := w.mustDemo("proof")
		mustContain(t, "proof", out, "; <stage> is ~/stage)\n")
		if strings.Contains(out, "<stage> is "+w.stage) {
			t.Errorf("proof names the stage by its full path under HOME:\n%s", out)
		}
	})
}

// proofRows runs demo.sh's PROOF_ROWS, as proof does, on stdin, the lines of `tego events --json`; args are the stage,
// the mode, the attacker's port and the agent's name.
func proofRows(t *testing.T, stdin []byte, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	const open = "PROOF_ROWS='\n"
	script := readFile(t, "demo.sh")
	start := strings.Index(script, open)
	if start < 0 {
		t.Fatal("PROOF_ROWS not found in demo.sh")
	}
	src, _, ok := strings.Cut(script[start+len(open):], "\n'\n")
	if !ok {
		t.Fatal("PROOF_ROWS does not end in demo.sh")
	}
	var stderr bytes.Buffer
	cmd := exec.Command("python3", append([]string{"-I", "-c", src}, args...)...)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Stdin, cmd.Stderr = bytes.NewReader(stdin), &stderr
	out, err := cmd.Output()
	if err != nil || stderr.Len() > 0 {
		t.Fatalf("PROOF_ROWS: %v\n%s%s", err, out, stderr.String())
	}
	return string(out)
}

// recordLine is one line of a run's events.jsonl, as `tego events --json` prints it: the common fields, the rule,
// verdict and reason when given, then the payload's fields.
func recordLine(t *testing.T, seq int, kind, rule, verdict, reason string, payload map[string]any) []byte {
	t.Helper()
	line := map[string]any{"v": 1, "seq": seq, "id": strings.Repeat("0", 64), "prev": strings.Repeat("0", 64),
		"ts": "2026-11-02T10:00:00Z", "mono_ns": seq, "run": "r-test", "agent": contractName, "pid": 7, "tid": 7,
		"cgroup": 1, "kind": kind, "source": "supervisor"}
	for k, v := range map[string]string{"rule": rule, "verdict": verdict, "reason": reason} {
		if v != "" {
			line[k] = v
		}
	}
	maps.Copy(line, payload)
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// tableCells reads a table whose rows align their cells under its first line, the header: each row is the text
// under each named column, a cell's padding cut and the last column the rest of the line. A cell is found where its
// header word starts, never by the spaces in it.
func tableCells(t *testing.T, table string, columns ...string) [][]string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(table, "\n"), "\n")
	starts := make([]int, len(columns))
	for i, c := range columns {
		at := strings.Index(lines[0], c)
		if at < 0 || i > 0 && utf8.RuneCountInString(lines[0][:at]) <= starts[i-1] {
			t.Fatalf("no column %s after %v in the header %q", c, columns[:i], lines[0])
		}
		starts[i] = utf8.RuneCountInString(lines[0][:at])
	}
	rows := make([][]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		r := []rune(line)
		row := make([]string, len(columns))
		for i, s := range starts {
			end := len(r)
			if i+1 < len(starts) {
				end = min(starts[i+1], len(r))
			}
			row[i] = string(r[min(s, end):end])
			if i+1 < len(starts) {
				row[i] = strings.TrimRight(row[i], " ")
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// withoutLastLine is out without its last line: PROOF_ROWS's table without the count under it.
func withoutLastLine(out string) string {
	out = strings.TrimSuffix(out, "\n")
	return out[:max(strings.LastIndexByte(out, '\n'), 0)]
}

// lastLines is the last n lines of the file at path, as tail -n prints them.
func lastLines(t *testing.T, path string, n int) string {
	t.Helper()
	lines := strings.SplitAfter(readFile(t, path), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines[max(len(lines)-n, 0):], "")
}
