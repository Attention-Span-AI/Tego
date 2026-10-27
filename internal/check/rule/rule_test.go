// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const base = `version: 0
name: demo
# the agent's own command
command:
  - sh
  - agent.sh
fs:
  write:
    - ./out/ # outputs
  deny_read:
    - ../secrets/
net:
  allow:
    - api.example.com:443 # the API
exec:
  allow:
    - sh
    - cat
tier: landlock
`

const cpath = "/p/proj/agent.yaml"

func ev(t *testing.T, kind record.Kind, verdict record.Verdict, rule string, reason record.Reason, payload any) *record.Event {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &record.Event{Seq: 7, Run: "r-1", Kind: kind, Verdict: verdict, Rule: rule, Reason: reason, Payload: b}
}

func apply(t *testing.T, e *record.Event, a Action, folder bool) (*Result, error) {
	t.Helper()
	return Apply(Request{Contract: []byte(base), ContractPath: cpath, Home: "/home/u", Event: e, Action: a, Folder: folder,
		Date: "2026-10-25"})
}

func TestEachKindAndAction(t *testing.T) {
	readOK := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: "/p/proj/notes.txt"})
	readNo := ev(t, record.KindRefused, "", "fs.deny_read[../secrets/]", record.ReasonReadDenied,
		record.RefusedPayload{Op: "open", Target: "/p/secrets/.env"})
	writeOK := ev(t, record.KindFS, record.VerdictAllow, "fs.write[./out/]", "", record.FSPayload{Op: "open", Path: "/p/proj/out/a.txt", Flags: 0o1101})
	writeNo := ev(t, record.KindRefused, "", "unmatched", record.ReasonWriteOutsideContract, record.RefusedPayload{Op: "open", Target: "/p/proj/log.txt"})
	execOK := ev(t, record.KindExec, record.VerdictAllow, "exec[cat]", "", record.ExecPayload{Path: "/usr/bin/cat", Argv: []string{"cat"}})
	execNo := ev(t, record.KindRefused, "", "unmatched", record.ReasonExecNotAllowed, record.RefusedPayload{Op: "exec", Target: "/usr/bin/curl"})
	netOK := ev(t, record.KindNet, record.VerdictAllow, "net[api.example.com:443]", "", record.NetPayload{Proto: "tcp", Dst: "1.2.3.4:443", Host: "api.example.com"})
	netNo := ev(t, record.KindRefused, "", "unmatched", record.ReasonNetNotAllowed, record.RefusedPayload{Op: "connect", Target: "evil.example:443"})
	cases := []struct {
		name   string
		e      *record.Event
		a      Action
		folder bool
		want   []string // lines the new text holds
		gone   []string // lines it no longer holds
		err    error
	}{
		{"read block", readOK, Block, false, []string{"    - ./notes.txt # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"read block folder", readOK, Block, true, []string{"    - ./ # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"read ask", readOK, Ask, false, []string{"  ask_read:", "    - ./notes.txt # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"read allow, already", readOK, Allow, false, nil, nil, ErrNothing},
		{"refused read allow, file only would widen", readNo, Allow, false, nil, nil, ErrRefused},
		{"refused read allow folder", readNo, Allow, true, nil, []string{"    - ../secrets/"}, nil},
		{"refused read block, already", readNo, Block, false, nil, nil, ErrNothing},
		{"write block", writeOK, Block, false, []string{"  deny_write:", "    - ./out/a.txt # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"write ask under a write dir", writeOK, Ask, false, nil, nil, ErrRefused},
		{"refused write allow", writeNo, Allow, false, []string{"    - ./log.txt # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"refused write ask", writeNo, Ask, false, []string{"  ask:", "    - ./log.txt # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"exec block removes the allow entry", execOK, Block, false, nil, []string{"    - cat"}, nil},
		{"exec ask not in the grammar", execOK, Ask, false, nil, nil, ErrRefused},
		{"refused exec allow", execNo, Allow, false, []string{"    - /usr/bin/curl # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"net block", netOK, Block, false, nil, []string{"    - api.example.com:443 # the API"}, nil},
		{"net ask", netOK, Ask, false, []string{"  ask:", "    - api.example.com:443 # from run r-1 line #7, 2026-10-25"}, []string{"    - api.example.com:443 # the API"}, nil},
		{"refused net allow", netNo, Allow, false, []string{"    - evil.example:443 # from run r-1 line #7, 2026-10-25"}, nil, nil},
		{"refused net ask", netNo, Ask, false, []string{"    - evil.example:443 # from run r-1 line #7, 2026-10-25"}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := apply(t, c.e, c.a, c.folder)
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err = %v, want %v", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := string(res.Text)
			for _, w := range c.want {
				if !strings.Contains(got, w+"\n") {
					t.Errorf("new text lacks %q:\n%s", w, got)
				}
			}
			for _, g := range c.gone {
				if strings.Contains(got, g+"\n") {
					t.Errorf("new text still holds %q:\n%s", g, got)
				}
			}
			// Comments and order kept: every comment of the old file is still there, in the same order.
			for _, keep := range []string{"# the agent's own command", "# outputs"} {
				if !strings.Contains(got, keep) {
					t.Errorf("comment %q lost:\n%s", keep, got)
				}
			}
			if strings.Index(got, "command:") > strings.Index(got, "fs:") || strings.Index(got, "fs:") > strings.Index(got, "tier:") {
				t.Errorf("key order changed:\n%s", got)
			}
			if res.Diff == "" || res.Summary == "" || res.Effect == "" {
				t.Errorf("empty diff, summary or effect: %+v", res)
			}
		})
	}
}

// TestSpliceKeepsOtherBytes: adding one entry to a block list changes one line and keeps every other byte, odd
// indentation included.
func TestSpliceKeepsOtherBytes(t *testing.T) {
	odd := strings.Replace(base, "  deny_read:\n    - ../secrets/\n", "  deny_read:\n      -   ../secrets/\n", 1)
	e := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: "/p/proj/notes.txt"})
	res, err := Apply(Request{Contract: []byte(odd), ContractPath: cpath, Event: e, Action: Block, Date: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(res.Diff, "\n+") != 2 || strings.Count(res.Diff, "\n-") != 0 { // the "+++" header and one line
		t.Errorf("diff is not one added line:\n%s", res.Diff)
	}
}

// TestDenyReadNeverEmptied: removing the last deny_read entry drops the key, since `deny_read: []` turns the
// built-in list off.
func TestDenyReadNeverEmptied(t *testing.T) {
	e := ev(t, record.KindRefused, "", "fs.deny_read[../secrets/]", record.ReasonReadDenied, record.RefusedPayload{Target: "/p/secrets/.env"})
	res, err := apply(t, e, Allow, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Text), "deny_read") {
		t.Errorf("deny_read still in the file:\n%s", res.Text)
	}
}

// TestNeverWidenOrTouchBuiltins: a read refused by a built-in entry is never lifted, a folder of / is refused, and a
// deny-list switch of exec is refused.
func TestNeverWidenOrTouchBuiltins(t *testing.T) {
	builtin := ev(t, record.KindRefused, "", "fs.deny_read[~/.ssh]", record.ReasonReadDenied, record.RefusedPayload{Target: "/home/u/.ssh/id_ed25519"})
	if _, err := apply(t, builtin, Allow, false); !errors.Is(err, ErrRefused) {
		t.Errorf("built-in lifted: %v", err)
	}
	root := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: "/etc"})
	if _, err := apply(t, root, Block, true); !errors.Is(err, ErrRefused) {
		t.Errorf("folder / accepted: %v", err)
	}
	noExec := strings.Replace(base, "exec:\n  allow:\n    - sh\n    - cat\n", "", 1)
	e := ev(t, record.KindExec, record.VerdictAllow, "exec[cat]", "", record.ExecPayload{Path: "/usr/bin/cat"})
	if _, err := Apply(Request{Contract: []byte(noExec), ContractPath: cpath, Event: e, Action: Block}); !errors.Is(err, ErrRefused) {
		t.Errorf("exec.deny added to a contract with no exec lists: %v", err)
	}
	own := ev(t, record.KindExec, record.VerdictAllow, "exec[sh]", "", record.ExecPayload{Path: "/usr/bin/sh"})
	if _, err := apply(t, own, Block, false); !errors.Is(err, ErrRefused) {
		t.Errorf("the run's own command blocked: %v", err)
	}
	noNet := strings.Replace(base, "net:\n  allow:\n    - api.example.com:443 # the API\n", "", 1)
	n := ev(t, record.KindNet, record.VerdictAllow, "", "", record.NetPayload{Proto: "tcp", Dst: "1.2.3.4:443"})
	if _, err := Apply(Request{Contract: []byte(noNet), ContractPath: cpath, Event: n, Action: Block}); !errors.Is(err, ErrRefused) {
		t.Errorf("a net: section made from one event: %v", err)
	}
}

// TestCheckRefuses: a text the compiler refuses is never returned.
func TestCheckRefuses(t *testing.T) {
	e := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: "/p/proj/notes.txt"})
	_, err := Apply(Request{Contract: []byte(base), ContractPath: cpath, Event: e, Action: Block,
		Check: func([]byte) error { return errors.New("no") }})
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v", err)
	}
}

// TestCompiles: the real compiler takes what a block of a read makes.
func TestCompiles(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "proj")
	for _, d := range []string{filepath.Join(proj, "out"), filepath.Join(dir, "secrets")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(proj, "notes.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(proj, "agent.yaml")
	text := base
	check := func(b []byte) error {
		c, _, err := agent.LoadBytes(cp, b, nil)
		if err != nil {
			return err
		}
		_, _, err = agent.Compile(c, config.Builtin(), agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(proj), agent.Offline())
		return err
	}
	if err := check([]byte(text)); err != nil {
		t.Skipf("the fixture does not compile here: %v", err)
	}
	e := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: secret})
	res, err := Apply(Request{Contract: []byte(text), ContractPath: cp, Cwd: proj, Event: e, Action: Block, Date: "d", Check: check})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Text), "- ./notes.txt") {
		t.Errorf("no entry:\n%s", res.Text)
	}
	if _, err := Apply(Request{Contract: res.Text, ContractPath: cp, Cwd: proj, Event: e, Action: Allow, Check: check}); !errors.Is(err, ErrNothing) {
		t.Errorf("allow of an allowed read: %v", err)
	}
}

func TestOptions(t *testing.T) {
	e := ev(t, record.KindExec, record.VerdictAllow, "exec[cat]", "", record.ExecPayload{Path: "/usr/bin/cat"})
	opts, tg, err := Options(Request{Contract: []byte(base), ContractPath: cpath, Event: e})
	if err != nil {
		t.Fatal(err)
	}
	if tg.Kind != KindExec || len(opts) != 2 || opts[0].Action != Block || !opts[0].OK || opts[1].OK {
		t.Errorf("exec options = %+v", opts)
	}
	r := ev(t, record.KindFS, record.VerdictAllow, "unmatched", "", record.FSPayload{Op: "open", Path: "/p/proj/notes.txt"})
	if opts, _, _ = Options(Request{Contract: []byte(base), ContractPath: cpath, Event: r}); len(opts) != 6 {
		t.Errorf("read options = %+v", opts)
	}
}

// flowBase is a contract with one-line flow lists and aligned comments, the way tego init writes them.
const flowBase = `version: 0
name: demo
command: ["sh", "agent.sh"]
fs:
  write: ["./out/", "/dev/null"]   # everything else is read-only
                                   # a second comment line
net:
  allow: []                  # nothing
exec:
  allow: ["sh", 'cat', date]       # binaries the agent may run
                             # a second comment line
tier: landlock               # auto | landlock
`

// TestSpliceFlowListKeepsOtherBytes: a rule on a one-line flow list changes only that list's lines; the aligned
// comments and every other line are kept byte for byte.
func TestSpliceFlowListKeepsOtherBytes(t *testing.T) {
	execOK := ev(t, record.KindExec, record.VerdictAllow, "exec[cat]", "", record.ExecPayload{Path: "/usr/bin/cat", Argv: []string{"cat"}})
	execNo := ev(t, record.KindRefused, "", "unmatched", record.ReasonExecNotAllowed, record.RefusedPayload{Op: "exec", Target: "/usr/bin/curl"})
	netNo := ev(t, record.KindRefused, "", "unmatched", record.ReasonNetNotAllowed, record.RefusedPayload{Op: "connect", Target: "evil.example:443"})
	cases := []struct {
		name      string
		e         *record.Event
		a         Action
		old, repl string
	}{
		{"exec block", execOK, Block, `  allow: ["sh", 'cat', date]       # binaries`, `  allow: ["sh", date]       # binaries`},
		{"exec allow", execNo, Allow, `  allow: ["sh", 'cat', date]       # binaries the agent may run` + "\n",
			"  allow:       # binaries the agent may run\n    - \"sh\"\n    - 'cat'\n    - date\n" +
				"    - /usr/bin/curl # from run r-1 line #7, d\n"},
		{"net allow into []", netNo, Allow, "  allow: []                  # nothing\n",
			"  allow:                  # nothing\n    - evil.example:443 # from run r-1 line #7, d\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Apply(Request{Contract: []byte(flowBase), ContractPath: cpath, Event: c.e, Action: c.a, Date: "d"})
			if err != nil {
				t.Fatal(err)
			}
			if want := strings.Replace(flowBase, c.old, c.repl, 1); string(res.Text) != want {
				t.Errorf("new text:\n%s\nwant:\n%s", res.Text, want)
			}
		})
	}
}
