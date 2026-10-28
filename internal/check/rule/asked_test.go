// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// askBase is the probe contract: one entry in each ask list.
const askBase = `version: 0
name: demo
fs:
  write: ["./src/"]
  deny_read: ["/h/.ssh/"]
  ask_read: ["/h/.config/telemetry/", "./confidential/"]
  ask: ["./held/"]
net:
  allow: ["127.0.0.1:8803"]
  ask: ["api.example.com:443"]
exec:
  allow: [sh]
tier: landlock
`

// TestAskedLines: a line an ask entry decided becomes a rule whatever the person answered (F1, F4). Block is
// "never": at the entry's own scope fs.ask_read moves to deny_read with the same spelling, fs.ask and net.ask go;
// a narrower scope refuses that path alone.
func TestAskedLines(t *testing.T) {
	tok := ev(t, record.KindFS, record.VerdictRefused, "fs.ask_read[/h/.config/telemetry/]", record.ReasonAskDenied,
		record.FSPayload{Op: "open", Path: "/h/.config/telemetry/token"})
	approved := ev(t, record.KindFS, record.VerdictAllow, "fs.ask_read[/h/.config/telemetry/]", "",
		record.FSPayload{Op: "open", Path: "/h/.config/telemetry/token"})
	timedOut := ev(t, record.KindRefused, "", "fs.ask_read[/h/.config/telemetry/]", record.ReasonAskTimeout,
		record.RefusedPayload{Op: "open", Target: "/h/.config/telemetry/token"})
	held := ev(t, record.KindRefused, "", "fs.ask[./held/]", record.ReasonWriteOutsideContract,
		record.RefusedPayload{Op: "open", Target: "/p/proj/held/x.md"})
	heldDenied := ev(t, record.KindRefused, "", "fs.ask[./held/]", record.ReasonAskDenied,
		record.RefusedPayload{Op: "open", Target: "/p/proj/held/x.md"})
	netAsked := ev(t, record.KindRefused, "", "net.ask[api.example.com:443]", record.ReasonNetNotAllowed,
		record.RefusedPayload{Op: "connect", Target: "api.example.com:443"})
	netFirst := ev(t, record.KindRefused, "", "net.ask[api.example.com:443]", record.ReasonAskDenied,
		record.RefusedPayload{Op: "first_write", Target: "93.184.216.34:443"})
	netApproved := ev(t, record.KindNet, record.VerdictAllow, "net.ask[api.example.com:443]", "",
		record.NetPayload{Proto: "tcp", Dst: "93.184.216.34:443", Host: "api.example.com"})
	key := ev(t, record.KindFS, record.VerdictRefused, "fs.deny_read[/h/.ssh/]", record.ReasonReadDenied,
		record.FSPayload{Op: "open", Path: "/h/.ssh/id_rsa"})
	sink := ev(t, record.KindRefused, "", "unmatched", record.ReasonNetNotAllowed,
		record.RefusedPayload{Op: "connect", Target: "127.0.0.1:8802"})
	profile := ev(t, record.KindFS, record.VerdictRefused, "fs.ask_read[/h/.config/other/]", record.ReasonAskDenied,
		record.FSPayload{Op: "open", Path: "/h/.config/other/f"})
	const comment = " # from run r-1 line #7, 2026-10-26"
	cases := []struct {
		name      string
		e         *record.Event
		a         Action
		level     int
		host      bool
		want      []string // entries the lists hold after, "key=entry"
		gone      []string // entries they no longer hold
		effect    string   // a word the effect holds
		direction Direction
		err       error
	}{
		{"token never at the entry's scope", tok, Block, 1, false,
			[]string{"fs.deny_read=/h/.config/telemetry/"}, []string{"fs.ask_read=/h/.config/telemetry/"},
			"without asking", Narrows, nil},
		{"token never for the file alone", tok, Block, 0, false,
			[]string{"fs.deny_read=/h/.config/telemetry/token", "fs.ask_read=/h/.config/telemetry/"}, nil,
			"still asks", Narrows, nil},
		{"token never wider", tok, Block, 2, false,
			[]string{"fs.deny_read=/h/.config/"}, []string{"fs.ask_read=/h/.config/telemetry/"}, "without asking", Narrows, nil},
		{"token ask is already", tok, Ask, 0, false, nil, nil, "", "", ErrNothing},
		{"token allow lifts the ask", tok, Allow, 1, false, nil, []string{"fs.ask_read=/h/.config/telemetry/"},
			"allow reads", Widens, nil},
		{"approved token never", approved, Block, 1, false,
			[]string{"fs.deny_read=/h/.config/telemetry/"}, []string{"fs.ask_read=/h/.config/telemetry/"}, "without asking", Narrows, nil},
		{"approved token allow always", approved, Allow, 1, false, nil, []string{"fs.ask_read=/h/.config/telemetry/"},
			"allow reads", Widens, nil},
		{"timed-out refusal never", timedOut, Block, 1, false,
			[]string{"fs.deny_read=/h/.config/telemetry/"}, []string{"fs.ask_read=/h/.config/telemetry/"}, "without asking", Narrows, nil},
		{"held write never at the scope", held, Block, 1, false, nil, []string{"fs.ask=./held/"}, "without asking", Narrows, nil},
		{"held write never for the file", held, Block, 0, false,
			[]string{"fs.deny_write=./held/x.md", "fs.ask=./held/"}, nil, "still asks", Narrows, nil},
		{"denied held write never", heldDenied, Block, 1, false, nil, []string{"fs.ask=./held/"}, "without asking", Narrows, nil},
		{"asked connect never", netAsked, Block, 0, false, nil, []string{"net.ask=api.example.com:443"}, "without asking", Narrows, nil},
		{"denied first write never", netFirst, Block, 0, false, nil, []string{"net.ask=api.example.com:443"}, "without asking", Narrows, nil},
		{"denied first write allow", netFirst, Allow, 0, false, []string{"net.allow=api.example.com:443"},
			[]string{"net.ask=api.example.com:443"}, "allow connections", Widens, nil},
		{"approved connect never, whole host", netApproved, Block, 0, true, nil, []string{"net.ask=api.example.com:443"},
			"every port", Narrows, nil},
		{"key allow is refused: the built-in ~/.ssh still refuses", key, Allow, 1, false, nil, nil, "", "", ErrRefused},
		{"sink block is already", sink, Block, 0, false, nil, nil, "", "", ErrNothing},
		{"a profile's ask entry is never changed", profile, Block, 1, false, nil, nil, "", "", ErrRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Apply(Request{Contract: []byte(askBase), ContractPath: "/p/proj/agent.yaml", Cwd: "/p/proj", Home: "/h",
				Event: c.e, Action: c.a, Level: c.level, HostOnly: c.host, Date: "2026-10-26"})
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err = %v, want %v", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, top, perr := parse(res.Text)
			if perr != nil {
				t.Fatal(perr)
			}
			for _, w := range c.want {
				k, e, _ := strings.Cut(w, "=")
				if !hasString(top, k, e) {
					t.Errorf("%s lacks %q:\n%s", k, e, res.Text)
				}
			}
			for _, g := range c.gone {
				k, e, _ := strings.Cut(g, "=")
				if hasString(top, k, e) {
					t.Errorf("%s still holds %q:\n%s", k, e, res.Text)
				}
			}
			if !strings.Contains(res.Effect, c.effect) {
				t.Errorf("effect %q lacks %q", res.Effect, c.effect)
			}
			if res.Direction != c.direction {
				t.Errorf("direction = %s, want %s", res.Direction, c.direction)
			}
			if len(c.want) > 0 && c.want[0] != "net.allow=api.example.com:443" && !strings.Contains(string(res.Text), comment) {
				t.Errorf("no comment on the added line:\n%s", res.Text)
			}
		})
	}
}

// relaxBase holds an fs.ask_read entry that relaxes a built-in protection (ADR 0057 D4), one nested in a wider ask
// entry, and a deny_read entry beside no built-in.
const relaxBase = `version: 0
name: demo
fs:
  write: ["./src/"]
  deny_read: ["./secret/"]
  ask_read: ["~/.aws/credentials", "/h/notes/", "/h/notes/today.md"]
tier: landlock
`

// TestAllowReadSaysWhatHappens: "Always allow" on a read says "allow reads" only when the next run allows it; an
// ask entry whose removal brings back a built-in refusal, or leaves a wider ask deciding, is refused instead.
func TestAllowReadSaysWhatHappens(t *testing.T) {
	read := func(v record.Verdict, rule string, reason record.Reason, p string) *record.Event {
		return ev(t, record.KindFS, v, rule, reason, record.FSPayload{Op: "open", Path: p})
	}
	cases := []struct {
		name string
		e    *record.Event
		want error
	}{
		{"approved credentials", read(record.VerdictAllow, "fs.ask_read[~/.aws/credentials]", "", "/h/.aws/credentials"), ErrRefused},
		{"denied credentials", read(record.VerdictRefused, "fs.ask_read[~/.aws/credentials]", record.ReasonAskDenied,
			"/h/.aws/credentials"), ErrRefused},
		{"nested ask still asks", read(record.VerdictAllow, "fs.ask_read[/h/notes/today.md]", "", "/h/notes/today.md"), ErrRefused},
		{"the wider ask lifts", read(record.VerdictAllow, "fs.ask_read[/h/notes/]", "", "/h/notes/x.md"), nil},
		{"a plain deny lifts", read(record.VerdictRefused, "fs.deny_read[./secret/]", record.ReasonReadDenied,
			"/p/proj/secret/a"), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lv := 0
			if strings.HasSuffix(strings.TrimSuffix(c.e.Rule, "]"), "/") {
				lv = 1
			}
			res, err := Apply(Request{Contract: []byte(relaxBase), ContractPath: "/p/proj/agent.yaml", Cwd: "/p/proj",
				Home: "/h", Event: c.e, Action: Allow, Level: lv, Date: "2026-10-26"})
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("err = %v, want %v (effect %+v)", err, c.want, res)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Direction != Widens || !strings.HasPrefix(res.Effect, "allow reads") {
				t.Errorf("result %s %q", res.Direction, res.Effect)
			}
		})
	}
}

// TestTargetOfAskRefusals: an ask-* refusal's target comes from the rule's family, a network operation's from the
// operation; one that names neither is unsupported, said with the right article.
func TestTargetOfAskRefusals(t *testing.T) {
	cases := []struct {
		rule   string
		reason record.Reason
		op     string
		kind   Kind
		err    string
	}{
		{"fs.ask_read[~/.config/telemetry/]", record.ReasonAskTimeout, "open", KindRead, ""},
		{"fs.ask[./held/]", record.ReasonAskDenied, "open", KindWrite, ""},
		{"net.ask[tcp://api.example.com:443]", record.ReasonAskUnavailable, "connect", KindNet, ""},
		{"gate.net[score]", record.ReasonAskDenied, "first_write", KindNet, ""},
		{"gate.fs[score]", record.ReasonAskTimeout, "open", "", "an ask-timeout refusal"},
		{"net.ask[api.example.com:443]", record.ReasonAskDenied, "http_request", "", "net.http"},
	}
	for _, c := range cases {
		target := "/p/proj/held/x.md"
		if c.kind == KindNet || c.op == "http_request" {
			target = "93.184.216.34:443"
		}
		e := ev(t, record.KindRefused, "", c.rule, c.reason, record.RefusedPayload{Op: c.op, Target: target})
		got, err := TargetOf(e)
		if c.err != "" {
			if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err = %v, want %q", c.rule, err, c.err)
			}
			continue
		}
		if err != nil || got.Kind != c.kind || !got.Refused {
			t.Errorf("%s: target %+v, err %v", c.rule, got, err)
		}
	}
	gap := &record.Event{Seq: 1, Run: "r-1", Kind: record.KindAsk}
	if _, err := TargetOf(gap); err == nil || !strings.Contains(err.Error(), "an ask line") {
		t.Errorf("ask line: %v", err)
	}
}

// TestEntryLevel: the level a page opens "Never allow" on is the deciding ask entry's own folder.
func TestEntryLevel(t *testing.T) {
	cases := []struct {
		rule, path string
		kind       Kind
		want       int
	}{
		{"fs.ask_read[~/.config/telemetry/]", "/h/.config/telemetry/token", KindRead, 1},
		{"fs.ask_read[/h/.config/telemetry/token]", "/h/.config/telemetry/token", KindRead, 0},
		{"fs.ask[./held/]", "/p/proj/held/sub/x.md", KindWrite, 2},
		{"fs.deny_read[/h/.ssh/]", "/h/.ssh/id_rsa", KindRead, -1},
		{"fs.ask_read[/elsewhere/]", "/h/.config/telemetry/token", KindRead, -1},
		{"net.ask[h:443]", "", KindNet, -1},
	}
	for _, c := range cases {
		if got := EntryLevel(Target{Kind: c.kind, Path: c.path, Rule: c.rule}, "/p/proj", "/h"); got != c.want {
			t.Errorf("%s at %s: level %d, want %d", c.rule, c.path, got, c.want)
		}
	}
}

// compileHome writes the demo's held-read fixture under a temporary home and returns a compiler for it.
func compileHome(t *testing.T) (home, proj, cpath string, check func([]byte) (*agent.RuleTable, error)) {
	t.Helper()
	dir := t.TempDir()
	home, proj = filepath.Join(dir, "home"), filepath.Join(dir, "proj")
	for _, d := range []string{filepath.Join(home, ".config", "telemetry"), filepath.Join(proj, "out"), filepath.Join(proj, "docs")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(home, ".config", "telemetry", "token"), filepath.Join(proj, "docs", "a.md")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cpath = filepath.Join(proj, "agent.yaml")
	check = func(b []byte) (*agent.RuleTable, error) {
		c, _, err := agent.LoadBytes(cpath, b, nil)
		if err != nil {
			return nil, err
		}
		rt, _, err := agent.Compile(c, config.Builtin(), agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(proj),
			agent.WithHome(home), agent.WithTiers(backend.TierLandlock), agent.Offline())
		return rt, err
	}
	return home, proj, cpath, check
}

// heldContract is the demo's shape: the token's folder asked about, the project written.
const heldContract = `version: 0
name: demo
command: [sh, agent.sh]
fs:
  write:
    - ./out/ # outputs
  ask_read:
    - ~/.config/telemetry/ # the demo's held read
exec:
  allow: [sh]
tier: landlock
`

// TestNeverMoveNarrows: the token line's "Never allow" compiles, and the next run refuses the token read by the
// deny_read entry without asking anyone (the ask→never move never leaves the path readable or asked).
func TestNeverMoveNarrows(t *testing.T) {
	home, proj, cpath, compile := compileHome(t)
	token := filepath.Join(home, ".config", "telemetry", "token")
	rt, err := compile([]byte(heldContract))
	if err != nil {
		t.Skipf("the fixture does not compile here: %v", err)
	}
	if got := decide.Evaluate(rt, agent.Action{Kind: agent.ActionFSRead, Path: token}, backend.TierLandlock); got.Rule != "fs.ask_read[~/.config/telemetry/]" {
		t.Fatalf("before: %+v", got)
	}
	check := func(b []byte) error { _, err := compile(b); return err }
	e := ev(t, record.KindFS, record.VerdictRefused, "fs.ask_read[~/.config/telemetry/]", record.ReasonAskDenied,
		record.FSPayload{Op: "open", Path: token})
	res, err := Apply(Request{Contract: []byte(heldContract), ContractPath: cpath, Cwd: proj, Home: home, Event: e,
		Action: Block, Level: 1, Date: "2026-10-26", Check: check})
	if err != nil {
		t.Fatal(err)
	}
	if res.Direction != Narrows || strings.Contains(string(res.Text), "ask_read") {
		t.Fatalf("direction %s, text:\n%s", res.Direction, res.Text)
	}
	if !strings.Contains(string(res.Text), "  deny_read:\n    - ~/.config/telemetry/ # from run r-1 line #7, 2026-10-26\n") {
		t.Errorf("no deny_read entry with the same spelling:\n%s", res.Text)
	}
	// The line's rule says its change in the words the Change rules form says it (the event page leads with them).
	if want := (Sentence{Before: "Asks you before it reads ~/.config/telemetry/", After: "Can never read ~/.config/telemetry/",
		Direction: Narrows}); len(res.Sentences) != 1 || res.Sentences[0] != want {
		t.Errorf("sentences %+v, want [%+v]", res.Sentences, want)
	}
	rt, err = compile(res.Text)
	if err != nil {
		t.Fatal(err)
	}
	got := decide.Evaluate(rt, agent.Action{Kind: agent.ActionFSRead, Path: token}, backend.TierLandlock)
	if got.Verdict != agent.Verdict(record.VerdictRefused) || got.Rule != "fs.deny_read[~/.config/telemetry/]" {
		t.Errorf("after: %+v, want refused by fs.deny_read[~/.config/telemetry/]", got)
	}
	// The same move through the edit core, from the line's rule.
	never, err := NeverOf("fs.ask_read[~/.config/telemetry/]")
	if err != nil {
		t.Fatal(err)
	}
	er, err := ApplyEdits(EditRequest{Contract: []byte(heldContract), ContractPath: cpath, Cwd: proj, Home: home,
		Edits: []Edit{never}, Via: "dashboard", Date: "2026-10-26", Check: check})
	if err != nil {
		t.Fatal(err)
	}
	if er.Direction != Narrows || len(er.Changes) != 2 || len(er.Sentences) != 1 ||
		er.Sentences[0].Before != "Asks you before it reads ~/.config/telemetry/" ||
		er.Sentences[0].After != "Can never read ~/.config/telemetry/" {
		t.Errorf("edit result: %+v", er)
	}
}
