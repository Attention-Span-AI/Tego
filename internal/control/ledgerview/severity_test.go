// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestSeverity: where an action happened and what it was decide its severity; how often it happened does not.
func TestSeverity(t *testing.T) {
	for _, c := range []struct {
		name string
		g    Group
		want Severity
	}{
		{"routine stays routine", Group{Class: "net", Subject: "github.com", Background: true}, SevRoutine},
		{"a secret", Group{Class: "fs", Subject: "/home/u/.netrc", Secret: true}, SevHigh},
		{"a connect off the policy", Group{Class: "net", Subject: "140.82.114.4"}, SevHigh},
		{"netlink", Group{Class: "net", Subject: "netlink"}, SevLow},
		{"another non-IP family", Group{Class: "net", Subject: "family(16)"}, SevLow},
		{"ssh", Group{Class: "exec", Subject: "ssh"}, SevHigh},
		{"grep", Group{Class: "exec", Subject: "grep"}, SevMedium},
		{"a shell startup file", Group{Class: "fs", Subject: "/home/u/.bashrc"}, SevHigh},
		{"a git hook", Group{Class: "fs", Subject: "/home/u/p/.git/hooks/pre-commit"}, SevHigh},
		{"claude's cache", Group{Class: "fs", Subject: "/home/u/.cache/claude-cli-nodejs/x"}, SevLow},
		{"claude's state", Group{Class: "fs", Subject: "/home/u/.local/state/claude/locks"}, SevLow},
		{"another folder", Group{Class: "fs", Subject: "/etc/hosts"}, SevMedium},
	} {
		if got := groupSeverity(&c.g, "claude", nil); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if s := secretSeverity(&SecretTouch{Path: "/home/u/try/.claude-state/.credentials.json"}, "claude", nil); s != SevLow {
		t.Errorf("the agent's own login: %v, want Low", s)
	}
	if s := secretSeverity(&SecretTouch{Path: "/home/u/try/.claude-state/.credentials.json"}, "codex", nil); s != SevHigh {
		t.Errorf("another agent's login: %v, want High", s)
	}
	if s := secretSeverity(&SecretTouch{Path: "/home/u/try/.claude-state/.credentials.json", NearSend: true}, "claude", nil); s != SevHigh {
		t.Errorf("the agent's own login before a send: %v, want High", s)
	}
	if s := secretSeverity(&SecretTouch{Path: "/home/u/.ssh/id_rsa"}, "claude", nil); s != SevHigh {
		t.Errorf("an SSH key: %v, want High", s)
	}
}

// TestAgentFiles: an agent reading its own files is Low and so is one writing its caches. A change to what runs code
// later is High for any agent, its own or another's, as a line in .bashrc is: hooks in its settings run at its next
// start. Any other change in its folder stays Medium, and another agent's folder is never "own". A secret in one stays High.
func TestAgentFiles(t *testing.T) {
	fs := func(subject string, write bool) Group { return Group{Class: "fs", Subject: subject, Write: write} }
	for _, c := range []struct {
		name  string
		g     Group
		agent string
		want  Severity
	}{
		{"its settings, read", fs("/home/u/.claude/settings.json", false), "claude", SevLow},
		{"its settings, written", fs("/home/u/.claude/settings.json", true), "claude", SevHigh},
		{"the project's settings, written", fs("/w/proj/.claude/settings.json", true), "claude", SevHigh},
		{"the project's hooks, written", fs("/w/proj/.claude/settings.local.json", true), "claude", SevHigh},
		{"the project's settings as a relative path", fs(".claude/settings.json", true), "claude", SevHigh},
		{"the project's settings as ./", fs("./.claude/settings.local.json", true), "claude", SevHigh},
		{"a hook's script, written", fs("/w/proj/.claude/hooks/pre-tool.sh", true), "claude", SevHigh},
		{"its top settings, written", fs("/home/u/.claude.json", true), "claude", SevHigh},
		{"the project's MCP servers, written", fs("/w/proj/.mcp.json", true), "claude", SevHigh},
		{"the project's MCP servers, read", fs("/w/proj/.mcp.json", false), "claude", SevMedium},
		{"MCP servers under no agent", fs(".mcp.json", true), "", SevHigh},
		{"its config, read", fs("/home/u/.codex/config.toml", false), "codex", SevLow},
		{"its config, written", fs("/home/u/.codex/config.toml", true), "codex", SevHigh},
		{"its hooks, written", fs("/home/u/.codex/hooks.json", true), "codex", SevHigh},
		{"the project's codex config, written", fs("/w/proj/.codex/config.toml", true), "codex", SevHigh},
		{"its cache, written", fs("/home/u/.cache/claude-cli-nodejs/x", true), "claude", SevLow},
		{"its state, written", fs("/home/u/.local/state/claude/locks", true), "claude", SevLow},
		{"another agent's cache, written", fs("/home/u/.cache/codex/x", true), "claude", SevMedium},
		{"its session log, written", fs("/home/u/.claude/projects/x/y.jsonl", true), "claude", SevMedium},
		{"its version file, written", fs("/home/u/.codex/version.json", true), "codex", SevMedium},
		{"its own program, read", fs("/home/u/.local/share/claude/versions/2.1.0", false), "claude", SevLow},
		{"its own program, written", fs("/home/u/.local/share/claude/versions/2.1.0", true), "claude", SevMedium},
		{"another agent's settings, read", fs("/home/u/.claude/settings.json", false), "codex", SevMedium},
		{"another agent's settings, written", fs("/home/u/.claude/settings.json", true), "codex", SevHigh},
		{"another agent's config, written", fs("/home/u/.codex/config.toml", true), "claude", SevHigh},
		{"any agent's settings, under an agent nobody knows", fs("/home/u/.claude/settings.json", true), "", SevHigh},
		{"Cursor's MCP servers, written", fs("/w/proj/.cursor/mcp.json", true), "codex", SevHigh},
		{"Gemini's settings, written", fs("/home/u/.gemini/settings.json", true), "claude", SevHigh},
		{"an editor's tasks, written", fs("/w/proj/.vscode/tasks.json", true), "codex", SevHigh},
		{"git's config, written", fs("/w/proj/.git/config", true), "claude", SevHigh},
		{"git's config, read", fs("/w/proj/.git/config", false), "claude", SevMedium},
		{"a repository's hooks folder, written", fs("/w/proj/.husky/pre-commit", true), "claude", SevHigh},
		{"a shell's other startup file, written", fs("/home/u/.zlogin", true), "claude", SevHigh},
		{"a rename's source is a change too", fs("/home/u/.claude/settings.json → /tmp/x", true), "claude", SevHigh},
		{"settings of something else, written", fs("/w/proj/settings.json", true), "claude", SevMedium},
		{"a config.toml elsewhere, written", fs("/w/proj/config.toml", true), "codex", SevMedium},
		{"a name that only starts the same, written", fs("/w/proj/.mcp.json.bak", true), "claude", SevMedium},
		{"an agent's name in a path, written", fs("/w/my.claude/settings.json", true), "claude", SevMedium},
		{"an agent the run is not known to be", fs("/home/u/.codex/config.toml", false), "", SevMedium},
		{"the demo's folder is nobody's", fs("/w/with/claude-home/settings.json", false), "claude", SevMedium},
		{"a secret in its folder", Group{Class: "fs", Subject: "/home/u/.codex/auth.json", Secret: true}, "codex", SevHigh},
	} {
		if got := groupSeverity(&c.g, c.agent, nil); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRefusedWritesOfAgentFiles: a refused write reads as one from the lines themselves, a mirror by its action, since
// a mirror has no flags and fs-gate does not say what was opened how; a refused read stays a read.
func TestRefusedWritesOfAgentFiles(t *testing.T) {
	r := burstRun(t, time.Minute,
		[2]string{"fs", `"rule":"held-unsupported","verdict":"refused","reason":"fs-gate","op":"open","flags":577,"path":"/home/u/.codex/config.toml"`},
		[2]string{"refused", `"rule":"held-unsupported","reason":"fs-gate","op":"open","target":"/home/u/.codex/config.toml"`},
		[2]string{"fs", `"rule":"held-unsupported","verdict":"refused","reason":"fs-gate","op":"open","flags":0,"path":"/home/u/.codex/version.json"`},
		[2]string{"refused", `"rule":"held-unsupported","reason":"fs-gate","op":"open","target":"/home/u/.codex/version.json"`},
		[2]string{"refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/home/u/.codex/hooks.json"`},
	)
	r.Command = "codex --no-daemon"
	s := computeSignal(r, Sensitive{Cwd: r.Cwd})
	got := map[string]Severity{}
	for _, g := range s.Groups {
		got[g.Subject] = g.Severity
	}
	if got["/home/u/.codex/config.toml"] != SevHigh || got["/home/u/.codex/version.json"] != SevLow || got["/home/u/.codex/hooks.json"] != SevHigh {
		t.Errorf("severities %v: want the writes High and the read Low", got)
	}
}

// TestRefusedRenameOntoAFileThatRunsLater: an atomic write is a rename, and the mirror of a refused rename or link names
// only where it came from (the lines are the real engine's, tier landlock), so what makes it High is read from its
// action. The row says where it was going, and its text still finds its lines; the same rename anywhere else stays what
// it was, and a symlink's second name is where it points, not a file it changes.
func TestRefusedRenameOntoAFileThatRunsLater(t *testing.T) {
	two := func(op, reason, from, to string) [][2]string {
		return [][2]string{
			{"fs", `"rule":"unmatched","verdict":"refused","reason":"` + reason + `","op":"` + op + `","path":"` + from + `","path2":"` + to + `"`},
			{"refused", `"rule":"unmatched","reason":"` + reason + `","op":"` + op + `","target":"` + from + `"`},
		}
	}
	rename := func(from, to string) [][2]string { return two("rename", "rename-outside-contract", from, to) }
	lines := append(rename("/w/proj/a.tmp", "/home/u/.claude/settings.json"), rename("/w/proj/b.tmp", "/home/u/.bashrc")...)
	lines = append(lines, rename("/w/proj/c.tmp", "/w/other/plain.txt")...)
	lines = append(lines, two("link", "write-outside-contract", "/w/proj/d.tmp", "/w/proj/.mcp.json")...)
	lines = append(lines, two("symlink", "write-outside-contract", "/w/proj/e.tmp", "/home/u/.claude/settings.json")...)
	r := burstRun(t, time.Minute, lines...)
	r.Command = "claude"
	s := computeSignal(r, Sensitive{Cwd: r.Cwd})
	got := map[string]Group{}
	for _, g := range s.Groups {
		got[g.LogsText()] = g
	}
	for from, want := range map[string]struct {
		subject string
		sev     Severity
	}{
		"/w/proj/a.tmp": {"/w/proj/a.tmp → /home/u/.claude/settings.json", SevHigh},
		"/w/proj/b.tmp": {"/w/proj/b.tmp → /home/u/.bashrc", SevHigh},
		"/w/proj/c.tmp": {"/w/proj/c.tmp", SevMedium},
		"/w/proj/d.tmp": {"/w/proj/d.tmp → /w/proj/.mcp.json", SevHigh},
		"/w/proj/e.tmp": {"/w/proj/e.tmp", SevMedium},
	} {
		if g := got[from]; g.Subject != want.subject || g.Severity != want.sev {
			t.Errorf("%s: %q reads %v, want %q at %v", from, g.Subject, g.Severity, want.subject, want.sev)
		}
	}
	for i := range r.Events {
		e := &r.Events[i]
		if !e.Refused() {
			continue
		}
		want := SevHigh
		if strings.Contains(e.Target, "c.tmp") || strings.Contains(e.Target, "e.tmp") {
			want = SevMedium
		}
		if s.SeverityOf(e) != want {
			t.Errorf("line %d (%s %s) reads %v, want %v", e.Seq, e.Kind, e.Target, s.SeverityOf(e), want)
		}
	}
}

func TestCommandAgent(t *testing.T) {
	for cmd, want := range map[string]string{
		"codex --no-daemon":                 "codex",
		"/usr/local/bin/claude":             "claude",
		"env FOO=1 -i claude --dangerously": "claude",
		"node /opt/claude-code/cli.js":      "claude",
		"bash -c codex":                     "",
		"python3 agent.py":                  "",
		"":                                  "",
	} {
		if got := CommandAgent(cmd); got != want {
			t.Errorf("CommandAgent(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// TestOwnSeverity: a person's rule comes before the built-in ones, in its channel only, and never lifts routine.
func TestOwnSeverity(t *testing.T) {
	rules := []SevRule{{Channel: "Programs", Match: "grep", Severity: SevLow}, {Match: "/prod-config/", Severity: SevHigh}}
	for _, c := range []struct {
		name string
		g    Group
		want Severity
	}{
		{"grep lowered", Group{Class: "exec", Subject: "grep"}, SevLow},
		{"grep as a file is not a program", Group{Class: "fs", Subject: "/tmp/grep"}, SevMedium},
		{"any channel", Group{Class: "fs", Subject: "/w/prod-config/db.yaml"}, SevHigh},
		{"routine stays", Group{Class: "exec", Subject: "grep", Background: true}, SevRoutine},
	} {
		if got := groupSeverity(&c.g, "", rules); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if v, ok := ParseSeverity(" medium "); !ok || v != SevMedium {
		t.Error("ParseSeverity(medium)")
	}
}

// TestOwnRulesNeverLowerASecret: a person's rule sorts a program or a path as they see it, but a secret touch and a
// send next to one stay High under any rule; raising one still works, and so does the rule on anything else.
func TestOwnRulesNeverLowerASecret(t *testing.T) {
	everything := []SevRule{{Match: "/", Severity: SevLow}, {Match: "203.0.113", Severity: SevLow}}
	for _, c := range []struct {
		name string
		g    Group
		want Severity
	}{
		{"a secret", Group{Class: "fs", Subject: "/home/u/.ssh/id_rsa", Secret: true}, SevHigh},
		{"a send after a secret", Group{Class: "net", Subject: "203.0.113.9", NearSecret: true}, SevHigh},
		{"a connect with no secret near", Group{Class: "net", Subject: "203.0.113.9"}, SevLow},
		{"another path", Group{Class: "fs", Subject: "/etc/hosts"}, SevLow},
	} {
		if got := groupSeverity(&c.g, "", everything); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	key := &SecretTouch{Path: "/home/u/.ssh/id_rsa"}
	if got := secretSeverity(key, "", everything); got != SevHigh {
		t.Errorf("a touched key under a lowering rule: %v, want High", got)
	}
	login := &SecretTouch{Path: "/home/u/.claude/.credentials.json"}
	if got := secretSeverity(login, "claude", []SevRule{{Match: ".credentials", Severity: SevMedium}}); got != SevMedium {
		t.Errorf("a rule raising the agent's own login: %v, want Medium", got)
	}
}

// TestOwnRulesAreTheirOwnSignal: rules come with the Sensitive, so two sets read side by side do not mix and a change
// reads again at once, with no process-wide state between them.
func TestOwnRulesAreTheirOwnSignal(t *testing.T) {
	r := burstRun(t, time.Minute, [2]string{"refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/grep"`})
	plain := Sensitive{Cwd: r.Cwd}
	lowered := Sensitive{Cwd: r.Cwd, Rules: []SevRule{{Match: "grep", Severity: SevLow}}}
	for range 2 {
		if s := Signal(r, plain); s.Medium != 1 || s.Low != 0 {
			t.Errorf("no rules: %d Medium, %d Low", s.Medium, s.Low)
		}
		if s := Signal(r, lowered); s.Low != 1 || s.Medium != 0 || s.SeverityOf(&r.Events[1]) != SevLow {
			t.Errorf("a rule: %d Medium, %d Low", s.Medium, s.Low)
		}
	}
}

// TestRepeatsKeepSeverity: severity comes from place and operation, never from how often (Severity, the Glossary). An
// outbound connect, a refused ssh and a .bashrc write repeated 50 times read as they do once, High and not folded, on
// the run's counts and on every one of their lines, and a program stays Medium however often it is refused.
func TestRepeatsKeepSeverity(t *testing.T) {
	const connect = `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`
	const ssh = `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/ssh"`
	const bashrc = `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/home/u/.bashrc"`
	const grep = `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/grep"`
	want := map[string]Severity{"203.0.113.9": SevHigh, "ssh": SevHigh, "/home/u/.bashrc": SevHigh, "grep": SevMedium}
	for _, n := range []int{1, 50} {
		root, id := t.TempDir(), "r-aaaa-0009-repeat"
		t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
		ls := []string{line(id, "agent", 0, t0, "run_start", `"tier":"landlock","command":["agent"],"cwd":"/w/proj"`)}
		for i := range n {
			for _, extra := range []string{connect, ssh, bashrc, grep} {
				ls = append(ls, line(id, "agent", len(ls), t0.Add(time.Duration(i+1)*time.Hour), "refused", extra))
			}
		}
		writeRun(t, root, id, ls...)
		r, err := LoadRun(root, id)
		if err != nil {
			t.Fatal(err)
		}
		s := Signal(r, Sensitive{Cwd: r.Cwd})
		if s.High != 3 || s.Medium != 1 || s.Background != 0 || s.Real != 4 {
			t.Errorf("%d times: %d High, %d Medium, %d routine, %d real; want 3, 1, 0, 4", n, s.High, s.Medium, s.Background, s.Real)
		}
		for _, g := range s.Groups {
			if g.Severity != want[g.Subject] || g.Background || g.Count != n {
				t.Errorf("%d times: %s is %v, background %v, count %d; want %v", n, g.Subject, g.Severity, g.Background, g.Count, want[g.Subject])
			}
		}
		for i := range r.Events {
			e := &r.Events[i]
			if !e.Refused() {
				continue
			}
			if _, subject, _ := groupSubject(e); s.SeverityOf(e) != want[subject] {
				t.Errorf("%d times: line %d (%s) reads %v", n, e.Seq, subject, s.SeverityOf(e))
			}
		}
	}
}

// TestStandardDevicesAreRoutine: a refused /dev/tty is routine by place, once or fifty times, and a device that is not
// a terminal or a standard stream, a rule that names the device, and a file beside them are not.
func TestStandardDevicesAreRoutine(t *testing.T) {
	for _, c := range []struct {
		name string
		g    Group
		want bool
	}{
		{"the terminal", Group{Class: "fs", Subject: "/dev/tty", Event: Event{Rule: "held-unsupported"}}, true},
		{"a pseudo-terminal", Group{Class: "fs", Subject: "/dev/pts/4", Event: Event{Rule: "unmatched"}}, true},
		{"a disk", Group{Class: "fs", Subject: "/dev/sda", Event: Event{Rule: "unmatched"}}, false},
		{"shared memory", Group{Class: "fs", Subject: "/dev/shm/x", Event: Event{Rule: "unmatched"}}, false},
		{"a contract entry", Group{Class: "fs", Subject: "/dev/tty", Event: Event{Rule: "fs.deny_read[/dev/tty]"}}, false},
	} {
		classify(&c.g, nil, nil)
		if c.g.Background != c.want {
			t.Errorf("%s: background %v, want %v", c.name, c.g.Background, c.want)
		}
	}
}

// burstRun is a run of the given lines after its start, gap apart.
func burstRun(t *testing.T, gap time.Duration, extras ...[2]string) *Run {
	t.Helper()
	root, id := t.TempDir(), "r-aaaa-0010-bursts"
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	ls := []string{line(id, "agent", 0, t0, "run_start", `"tier":"landlock","command":["agent"],"cwd":"/w/proj"`)}
	for _, x := range extras {
		ls = append(ls, line(id, "agent", len(ls), t0.Add(time.Duration(len(ls))*gap), x[0], x[1]))
	}
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func refusedConnect(rule, target string) [2]string {
	return [2]string{"refused", `"rule":"` + rule + `","reason":"net-not-allowed","op":"net","target":"` + target + `"`}
}

// TestBurstsReadAsOneRow: one name's addresses are one row, by the range they share or by the rule that names the
// destination. Every line stays counted, each still reads High, and an address outside the range keeps its own row.
func TestBurstsReadAsOneRow(t *testing.T) {
	r := burstRun(t, time.Minute,
		refusedConnect("unmatched", "185.199.108.133:443"), refusedConnect("unmatched", "185.199.111.133:443"),
		refusedConnect("unmatched", "185.199.109.133:80"), refusedConnect("unmatched", "185.199.109.133:443"),
		refusedConnect("unmatched", "[2606:50c0:8000::154]:443"), refusedConnect("unmatched", "[2606:50c0:8003::154]:443"),
		refusedConnect("live.block[net:chatgpt.com:443]", "104.18.32.47:443"),
		refusedConnect("live.block[net:chatgpt.com:443]", "172.64.155.209:443"),
		refusedConnect("unmatched", "203.0.113.9:443"),
	)
	s := Signal(r, Sensitive{Cwd: r.Cwd})
	bySubject := map[string]Group{}
	lines := 0
	for _, g := range s.Groups {
		bySubject[g.Subject] = g
		lines += g.Count
		if g.Severity != SevHigh {
			t.Errorf("%s reads %v, want High", g.Subject, g.Severity)
		}
	}
	if len(s.Groups) != 4 || s.High != 4 || s.Real != 4 || lines != r.Refusals {
		t.Fatalf("%d rows, %d High, %d real, %d of %d lines: %+v", len(s.Groups), s.High, s.Real, lines, r.Refusals, s.Groups)
	}
	if g := bySubject["185.199.0.0/16"]; g.Hosts != 3 || g.Count != 4 || g.LogsText() != "185.199." || !slices.Equal(g.Ports, []string{"443", "80"}) {
		t.Errorf("the IPv4 range: %+v", g)
	}
	if g := bySubject["2606:50c0::/32"]; g.Hosts != 2 || g.Count != 2 || g.LogsText() != "2606:50c0:" {
		t.Errorf("the IPv6 range: %+v", g)
	}
	if g := bySubject["chatgpt.com:443"]; g.Hosts != 2 || g.Count != 2 || g.LogsText() != "live.block[net:chatgpt.com:443]" {
		t.Errorf("the live block: %+v", g)
	}
	if g := bySubject["203.0.113.9"]; g.Hosts != 0 || g.Count != 1 || g.LogsText() != "203.0.113.9" {
		t.Errorf("a lone address: %+v", g)
	}
	for i := range r.Events {
		if e := &r.Events[i]; e.Refused() && s.SeverityOf(e) != SevHigh {
			t.Errorf("line %d (%s) reads %v", e.Seq, e.Target, s.SeverityOf(e))
		}
	}
}

// scanLines is n refused connects to host, each on a port of its own.
func scanLines(host string, n int) [][2]string {
	out := make([][2]string, n)
	for i := range out {
		out[i] = refusedConnect("unmatched", fmt.Sprintf("%s:%d", host, 19100+i))
	}
	return out
}

// TestPortScanReadsAsOneRow: 150 refused connects to one host, each on its own port and 2.5 s apart, are one row that
// holds all of them. A browser test's agent did this to 127.0.0.1 and got a row per port: Detections read 158 rows, 151
// of them High. Time never came into it: a group on this machine is one port (groupSubject) and no row held those
// groups, while a remote host's group already held its ports. Every line still reads High on its own, and Outbound still
// names every port.
func TestPortScanReadsAsOneRow(t *testing.T) {
	for _, c := range []struct{ name, host, logs string }{
		{"this machine", "127.0.0.1", "127.0.0.1:"},
		{"this machine over IPv6", "[::1]", "[::1]:"},
		{"another machine", "203.0.113.9", "203.0.113.9"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := burstRun(t, 2500*time.Millisecond, scanLines(c.host, 150)...)
			s := Signal(r, Sensitive{Cwd: r.Cwd})
			if len(s.Groups) != 1 || s.High != 1 || s.Real != 1 || s.RealLines != 150 {
				t.Fatalf("%d rows, %d High, %d real, %d lines: want one High row of 150 lines", len(s.Groups), s.High, s.Real, s.RealLines)
			}
			g := s.Groups[0]
			if g.Subject != c.host || g.Count != 150 || len(g.Ports) != 150 || len(g.Targets) != 150 || g.Hosts != 0 || g.Severity != SevHigh {
				t.Errorf("the row: %s, %d attempts, %d ports, %d targets, %d addresses, %v", g.Subject, g.Count, len(g.Ports), len(g.Targets), g.Hosts, g.Severity)
			}
			if g.LogsText() != c.logs {
				t.Errorf("the row's Logs text is %q, want %q", g.LogsText(), c.logs)
			}
			if g.FirstSeq != r.Events[1].Seq || g.Seq != r.Events[len(r.Events)-1].Seq {
				t.Errorf("the row runs from line %d to %d", g.FirstSeq, g.Seq)
			}
			if len(s.Outbound) != 150 {
				t.Errorf("%d destinations, want every port", len(s.Outbound))
			}
			for i := range r.Events {
				if e := &r.Events[i]; e.Refused() && s.SeverityOf(e) != SevHigh {
					t.Errorf("line %d (%s) reads %v", e.Seq, e.Target, s.SeverityOf(e))
				}
			}
		})
	}
}

// TestScanLeavesASendNextToASecret: a key read in the middle of a scan leaves the connects next to it on their own rows,
// marked and High, as one with no scan around it; the rest fold.
func TestScanLeavesASendNextToASecret(t *testing.T) {
	lines := slices.Insert(scanLines("127.0.0.1", 150), 100,
		[2]string{"fs", `"rule":"unmatched","verdict":"allow","op":"open","path":"/w/home/.ssh/id_rsa"`})
	r := burstRun(t, 2500*time.Millisecond, lines...)
	s := Signal(r, Sensitive{Cwd: r.Cwd})
	var near []string
	var rest []Group
	for _, g := range s.Groups {
		if g.Severity != SevHigh {
			t.Errorf("%s reads %v", g.Subject, g.Severity)
		}
		if g.NearSecret {
			near = append(near, g.Subject)
		} else {
			rest = append(rest, g)
		}
	}
	// 5 s and 2 lines on each side of the read.
	want := []string{"127.0.0.1:19198", "127.0.0.1:19199", "127.0.0.1:19200", "127.0.0.1:19201"}
	if slices.Sort(near); !slices.Equal(near, want) {
		t.Errorf("next to the key: %v, want %v", near, want)
	}
	if len(rest) != 1 || rest[0].Subject != "127.0.0.1" || rest[0].Count != 146 || len(rest[0].Ports) != 146 {
		t.Errorf("the rest of the scan: %+v", rest)
	}
	if s.High != 5 {
		t.Errorf("%d High, want the four sends and the scan", s.High)
	}
}

// TestOneHostRowKeepsItsHighest: a row of one host reads at the highest severity of what it holds, in any order, and a
// line keeps its own: a person who calls one port Low has not lowered the scan around it, and has not been overruled on
// that port's lines. Another host at another severity is still another row.
func TestOneHostRowKeepsItsHighest(t *testing.T) {
	conn := func(subject, port string, sev Severity) Group {
		return Group{Event: Event{Rule: "unmatched", Reason: "net-not-allowed", Op: "net"}, Class: "net", Subject: subject, Severity: sev,
			Count: 1, Targets: []string{subject}, Ports: []string{port}}
	}
	for _, sevs := range [][2]Severity{{SevHigh, SevLow}, {SevLow, SevHigh}, {SevMedium, SevHigh}} {
		m := mergeBursts([]Group{conn("127.0.0.1:1", "1", sevs[0]), conn("127.0.0.1:2", "2", sevs[1]), conn("127.0.0.2:3", "3", SevLow)})
		if len(m) != 2 || m[0].Subject != "127.0.0.1" || m[0].Severity != SevHigh || m[0].Count != 2 || m[1].Subject != "127.0.0.2:3" {
			t.Errorf("%v: %+v", sevs, m)
		}
	}

	r := burstRun(t, 2500*time.Millisecond, scanLines("127.0.0.1", 3)...)
	s := Signal(r, Sensitive{Cwd: r.Cwd, Rules: []SevRule{{Channel: "Network", Match: "127.0.0.1:19101", Severity: SevLow}}})
	if len(s.Groups) != 1 || s.Groups[0].Severity != SevHigh || s.High != 1 || s.Low != 0 {
		t.Fatalf("%d High, %d Low: %+v", s.High, s.Low, s.Groups)
	}
	if got := s.SeverityOf(&r.Events[2]); got != SevLow {
		t.Errorf("the port the rule names reads %v on its own line, want Low", got)
	}
	if got := s.SeverityOf(&r.Events[3]); got != SevHigh {
		t.Errorf("the port after it reads %v", got)
	}
}

// TestRefusedActionKeepsItsOwnSeverity: a refused connect's action line reads as its mirror does, at its own group's
// severity and not the row's, and a port is never taken for a longer one that starts the same: port 80 is not 8080.
func TestRefusedActionKeepsItsOwnSeverity(t *testing.T) {
	const action = `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:%d"`
	var lines [][2]string
	for _, port := range []int{8080, 80, 8081} {
		lines = append(lines, [2]string{"net", fmt.Sprintf(action, port)}, refusedConnect("unmatched", fmt.Sprintf("127.0.0.1:%d", port)))
	}
	r := burstRun(t, time.Second, lines...)
	s := Signal(r, Sensitive{Cwd: r.Cwd, Rules: []SevRule{{Channel: "Network", Match: "127.0.0.1:8080", Severity: SevLow}}})
	want := map[string]Severity{"127.0.0.1:8080": SevLow, "127.0.0.1:80": SevHigh, "127.0.0.1:8081": SevHigh}
	for i := range r.Events {
		if e := &r.Events[i]; e.Refused() && s.SeverityOf(e) != want[e.Target] {
			t.Errorf("line %d (%s, %s) reads %v, want %v", e.Seq, e.Kind, e.Target, s.SeverityOf(e), want[e.Target])
		}
	}
}

// TestOneHostRowHoldsOnlyThatHost: a port alone keeps its subject; port 65535 joins its host's row on a connect that is no
// route probe, and a row counts addresses, not the groups that made it; the probe stays routine and apart; and two of
// this machine's addresses are two hosts, as a unix socket beside them is no host at all.
func TestOneHostRowHoldsOnlyThatHost(t *testing.T) {
	s := func(lines ...[2]string) *RunSignal {
		r := burstRun(t, time.Minute, lines...)
		return Signal(r, Sensitive{Cwd: r.Cwd})
	}
	if lone := s(refusedConnect("unmatched", "127.0.0.1:8802")); len(lone.Groups) != 1 || lone.Groups[0].Subject != "127.0.0.1:8802" || lone.Groups[0].LogsText() != "127.0.0.1:8802" {
		t.Errorf("one port: %+v", lone.Groups)
	}
	top := s(refusedConnect("unmatched", "203.0.113.9:443"), refusedConnect("unmatched", "203.0.113.9:65535"))
	if len(top.Groups) != 1 || top.Groups[0].Subject != "203.0.113.9" || !slices.Equal(top.Groups[0].Ports, []string{"443", "65535"}) || top.Groups[0].Hosts != 0 {
		t.Errorf("a host's last port: %+v", top.Groups)
	}
	two := s(refusedConnect("unmatched", "203.0.113.9:443"), refusedConnect("unmatched", "203.0.113.9:65535"), refusedConnect("unmatched", "203.0.113.10:443"))
	if len(two.Groups) != 1 || two.Groups[0].Subject != "203.0.0.0/16" || two.Groups[0].Hosts != 2 || two.Groups[0].Count != 3 {
		t.Errorf("two addresses of a range: %+v", two.Groups)
	}
	probe := s([2]string{"net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"203.0.113.9:65535"`},
		refusedConnect("unmatched", "203.0.113.9:65535"), refusedConnect("unmatched", "203.0.113.9:443"))
	if len(probe.Groups) != 2 || probe.Background != 1 || probe.High != 1 {
		t.Errorf("a route probe beside a connect: %+v", probe.Groups)
	}
	local := s(refusedConnect("unmatched", "127.0.0.1:1"), refusedConnect("unmatched", "127.0.0.1:2"), refusedConnect("unmatched", "127.0.0.2:1"),
		refusedConnect("unmatched", "127.0.0.2:2"), refusedConnect("unmatched", "unix:/run/a.sock"), refusedConnect("unmatched", "unix:/run/b.sock"))
	if len(local.Groups) != 4 {
		t.Errorf("two local addresses and two sockets: %+v", local.Groups)
	}
	named := s(refusedConnect("live.block[net:127.0.0.1:1]", "127.0.0.1:1"), refusedConnect("unmatched", "127.0.0.1:2"), refusedConnect("unmatched", "127.0.0.1:3"))
	if len(named.Groups) != 2 || named.Groups[0].Rule != "live.block[net:127.0.0.1:1]" {
		t.Errorf("a person's block beside a scan keeps its row: %+v", named.Groups)
	}
}

// TestSensKeyAllocations: a Signal's key is built on every read of a run, so its cost must not grow with the square of
// the rules: joined with +=, 20,000 rules allocated 6 GB for each run on each page.
func TestSensKeyAllocations(t *testing.T) {
	rs := make([]SevRule, 5_000)
	for i := range rs {
		rs[i] = SevRule{Channel: "Files", Match: fmt.Sprintf("/some/path/number/%d/", i), Severity: SevMedium}
	}
	s := Sensitive{Entries: []string{"/w/a", "/w/b"}, Cwd: "/w/proj", Rules: rs}
	if n := testing.AllocsPerRun(1, func() { sensKey(s) }); n > 64 {
		t.Errorf("%d rules took %.0f allocations for one key", len(rs), n)
	}
	want := "/w/a\x00/w/b\x01/w/proj\x01Files\x00/x\x00High"
	if got := sensKey(Sensitive{Entries: []string{"/w/a", "/w/b"}, Cwd: "/w/proj", Rules: []SevRule{{Channel: "Files", Match: "/x", Severity: SevHigh}}}); got != want {
		t.Errorf("sensKey = %q, want %q", got, want)
	}
}

// TestBurstCostGrowsWithItsAddresses: an agent spraying a range must not slow the pages that read its run, and
// mergeBursts runs for each new version of the run. Scanning the row for each target made 20 times the addresses cost
// 400 times as much: 7 s at 60,000.
func TestBurstCostGrowsWithItsAddresses(t *testing.T) {
	groups := func(n int) []Group {
		gs := make([]Group, n)
		for i := range gs {
			host := fmt.Sprintf("10.9.%d.%d", i>>8&255, i&255)
			gs[i] = Group{Event: Event{Rule: "unmatched", Reason: "net-not-allowed", Op: "net"}, Class: "net", Subject: host,
				Severity: SevHigh, Count: 1, Targets: []string{host + ":443"}, Ports: []string{"443"}}
		}
		return gs
	}
	small, large := groups(2_000), groups(40_000)
	sample := func(gs []Group) func() {
		return func() {
			if out := mergeBursts(gs); len(out) != 1 || out[0].Hosts != len(gs) || len(out[0].Targets) != len(gs) || len(out[0].Ports) != 1 {
				t.Errorf("%d addresses folded to %d rows", len(gs), len(out))
			}
		}
	}
	m := testutil.MinOf(testutil.ThreadCPU, 5, sample(small), sample(large))
	t.Logf("%v at %d addresses, %v at %d", m[0], len(small), m[1], len(large))
	if m[1] > 100*m[0]+10*time.Millisecond {
		t.Errorf("a burst costs %v at %d addresses against %v at %d: its cost grows faster than its addresses",
			m[1], len(large), m[0], len(small))
	}
}

// linearCost fails when twenty times the work costs a hundred times as much or more: sample(n) is the work for n.
func linearCost(t *testing.T, what string, sample func(n int) func()) {
	t.Helper()
	const small, large = 2_000, 40_000
	m := testutil.MinOf(testutil.ThreadCPU, 5, sample(small), sample(large))
	t.Logf("%s: %v at %d, %v at %d", what, m[0], small, m[1], large)
	if m[1] > 100*m[0]+10*time.Millisecond {
		t.Errorf("%s costs %v at %d against %v at %d: its cost grows faster than its size", what, m[1], large, m[0], small)
	}
}

// TestPortCostGrowsWithItsPorts: a scan of one host costs by its ports at each step a page pays for it, on this machine,
// where each port is a group, and on another, where one group holds them. Each is read again for each new version of a
// live run, and a scan is what an agent can make as long as it likes.
func TestPortCostGrowsWithItsPorts(t *testing.T) {
	groups := func(n int) []Group {
		gs := make([]Group, n)
		for i := range gs {
			target := fmt.Sprintf("127.0.0.1:%d", 1024+i)
			gs[i] = Group{Event: Event{Rule: "unmatched", Reason: "net-not-allowed", Op: "net"}, Class: "net", Subject: target,
				Severity: SevHigh, Count: 1, Targets: []string{target}, Ports: []string{strconv.Itoa(1024 + i)}}
		}
		return gs
	}
	linearCost(t, "folding the rows", func(n int) func() {
		gs := groups(n)
		return func() {
			if out := mergeBursts(gs); len(out) != 1 || out[0].Count != n || len(out[0].Ports) != n {
				t.Errorf("%d ports folded to %d rows", n, len(out))
			}
		}
	})
	pairs := func(host string, n int) []Event {
		evs := make([]Event, 0, 2*n)
		for i := range n {
			// Every port one width: 1234 is the start of 12345, which would end a scan of the targets early.
			target := fmt.Sprintf("%s:%d", host, 10000+i)
			evs = append(evs, Event{Kind: "net", Op: "connect", Verdict: "refused", Rule: "unmatched", Reason: "net-not-allowed", Target: target},
				Event{Kind: "refused", Op: "net", Rule: "unmatched", Reason: "net-not-allowed", Target: target, Mirror: true})
		}
		return evs
	}
	linearCost(t, "reading the lines of one group", func(n int) func() {
		evs := pairs("203.0.113.9", n)
		return func() {
			f := newSignalFold(Sensitive{})
			f.add(evs)
			if len(f.groupL) != 1 || f.groupL[0].Count != n || len(f.groupL[0].Ports) != n {
				t.Errorf("%d ports read as %d groups", n, len(f.groupL))
			}
		}
	})
	linearCost(t, "the severity of each line", func(n int) func() {
		evs := pairs("127.0.0.1", n)
		f := newSignalFold(Sensitive{})
		f.add(evs)
		s := f.finish(&Run{})
		return func() {
			for i := range evs {
				if s.SeverityOf(&evs[i]) != SevHigh {
					t.Fatalf("line %d reads %v", i, s.SeverityOf(&evs[i]))
				}
			}
		}
	})
}

// TestBurstsNeverHideAnAttack: a send next to a secret read keeps its own row and its mark, inside a range the others
// fold into; a host's ports stay on its row by name, however many; and the Outbound and verdict read every address as
// before.
func TestBurstsNeverHideAnAttack(t *testing.T) {
	r := burstRun(t, time.Minute,
		refusedConnect("unmatched", "185.199.108.133:443"), refusedConnect("unmatched", "185.199.109.133:443"),
		refusedConnect("unmatched", "127.0.0.1:8802"), refusedConnect("unmatched", "127.0.0.1:8803"),
	)
	s := Signal(r, Sensitive{Cwd: r.Cwd})
	if len(s.Groups) != 2 {
		t.Fatalf("%d rows: %+v", len(s.Groups), s.Groups)
	}
	if g := s.Groups[0]; g.Subject != "127.0.0.1" || !slices.Equal(g.Ports, []string{"8802", "8803"}) || g.Hosts != 0 || g.Severity != SevHigh {
		t.Errorf("this machine's row: %+v", g)
	}
	if len(s.Outbound) != 4 {
		t.Errorf("%d destinations, want every address: %+v", len(s.Outbound), s.Outbound)
	}

	// 4 s after the key's read, inside NearSecretWindow; the two later connects are outside it.
	near := burstRun(t, 4*time.Second,
		[2]string{"fs", `"rule":"unmatched","verdict":"allow","op":"open","path":"/w/home/.ssh/id_rsa"`},
		refusedConnect("unmatched", "185.199.109.133:443"),
		refusedConnect("unmatched", "185.199.108.133:443"), refusedConnect("unmatched", "185.199.110.133:443"),
	)
	sn := Signal(near, Sensitive{Cwd: near.Cwd})
	if len(sn.Groups) != 2 || sn.High != 2 {
		t.Fatalf("%d rows, %d High: %+v", len(sn.Groups), sn.High, sn.Groups)
	}
	if g := sn.Groups[0]; g.Subject != "185.199.109.133" || !g.NearSecret || g.Severity != SevHigh || g.Hosts != 0 {
		t.Errorf("the send after the key's read: %+v", g)
	}
	if g := sn.Groups[1]; g.Subject != "185.199.0.0/16" || g.Hosts != 2 || g.NearSecret {
		t.Errorf("the others: %+v", g)
	}

	// A group at another severity (a person's rule) stays apart, and the merge writes on nothing it read.
	gs := []Group{
		{Event: Event{Rule: "unmatched", Op: "net"}, Class: "net", Subject: "185.199.109.133", NearSecret: true, Severity: SevHigh, Count: 1, Targets: []string{"185.199.109.133:443"}},
		{Event: Event{Rule: "unmatched", Op: "net"}, Class: "net", Subject: "185.199.108.133", Severity: SevHigh, Count: 1, Targets: []string{"185.199.108.133:443"}},
		{Event: Event{Rule: "unmatched", Op: "net"}, Class: "net", Subject: "185.199.110.133", Severity: SevHigh, Count: 1, Targets: []string{"185.199.110.133:443"}},
		{Event: Event{Rule: "unmatched", Op: "net"}, Class: "net", Subject: "185.199.111.133", Severity: SevMedium, Count: 1, Targets: []string{"185.199.111.133:443"}},
	}
	m := mergeBursts(gs)
	if len(m) != 3 || !m[0].NearSecret || m[0].Subject != "185.199.109.133" || m[1].Hosts != 2 || m[2].Severity != SevMedium {
		t.Fatalf("merged %+v: want the near-secret send and the other severity on their own rows", m)
	}
	if len(gs[1].Targets) != 1 {
		t.Error("the merge wrote into the group it read")
	}
}
