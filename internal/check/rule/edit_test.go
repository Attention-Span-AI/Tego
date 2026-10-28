// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// editBase has an entry in every list the form edits, comments on some lines.
const editBase = `version: 0
name: demo
# the agent's own command
command: [sh, agent.sh]
fs:
  write:
    - ./out/ # outputs
  deny_read:
    - ./secrets/
  ask_read:
    - ./confidential/
  ask:
    - ./held/
net:
  allow:
    - api.example.com:443 # the API
  ask:
    - tcp://upload.example.com:443
exec:
  allow: [sh, cat, ls]   # programs
tier: landlock
`

const editPath = "/p/proj/agent.yaml"

func okCheck([]byte) error { return nil }

func applyEdits(t *testing.T, text string, home string, edits ...Edit) (*EditResult, error) {
	t.Helper()
	return ApplyEdits(EditRequest{Contract: []byte(text), ContractPath: editPath, Cwd: "/p/proj", Home: home, Edits: edits,
		Via: "dashboard", Date: "2026-10-26", Check: okCheck})
}

// TestDirectionTable: a deny added narrows and removed widens; a grant added widens and removed narrows; an ask entry
// goes by what it covers (a question where the run could act narrows, one where it was refused widens, one that
// relaxes a built-in protection widens); a "never" narrows; two edits that disagree are Mixed.
func TestDirectionTable(t *testing.T) {
	add := func(k, e string) Edit { return Edit{Op: OpAdd, Key: k, Entry: e} }
	rm := func(k, e string) Edit { return Edit{Op: OpRemove, Key: k, Entry: e} }
	never := func(k, e string) Edit { return Edit{Op: OpNever, Key: k, Entry: e} }
	cases := []struct {
		name          string
		home          string
		edits         []Edit
		want          Direction
		before, after string // the first sentence
	}{
		{"deny_read add", "/h", []Edit{add("fs.deny_read", "./notes/")}, Narrows, "May read ./notes/", "Can never read ./notes/"},
		{"deny_read remove", "/h", []Edit{rm("fs.deny_read", "./secrets/")}, Widens, "Can never read ./secrets/", "May read ./secrets/"},
		{"write add", "/h", []Edit{add("fs.write", "./tmp/")}, Widens, "Cannot change ./tmp/", "May change ./tmp/"},
		{"write remove", "/h", []Edit{rm("fs.write", "./out/")}, Narrows, "May change ./out/", "Cannot change ./out/"},
		{"deny_write add", "/h", []Edit{add("fs.deny_write", "./out/gen/")}, Narrows, "May change ./out/gen/", "Can never change ./out/gen/"},
		{"exec add", "/h", []Edit{add("exec.allow", "git")}, Widens, "Cannot run git", "May run git"},
		{"exec remove", "/h", []Edit{rm("exec.allow", "ls")}, Narrows, "May run ls", "Cannot run ls"},
		{"net add", "/h", []Edit{add("net.allow", "pypi.org:443")}, Widens, "Cannot connect to pypi.org:443", "May connect to pypi.org:443"},
		{"net remove", "/h", []Edit{rm("net.allow", "api.example.com:443")}, Narrows, "May connect to api.example.com:443", "Cannot connect to api.example.com:443"},
		{"ask_read add where reads go ahead", "/h", []Edit{add("fs.ask_read", "./docs/")}, Narrows, "May read ./docs/", "Asks you before it reads ./docs/"},
		{"ask_read add relaxing a built-in", "/h", []Edit{add("fs.ask_read", "~/.ssh/")}, Widens, "Can never read ~/.ssh/", "Asks you before it reads ~/.ssh/"},
		{"ask_read add inside a built-in", "/h", []Edit{add("fs.ask_read", "/h/.aws/config")}, Widens, "Can never read /h/.aws/config", "Asks you before it reads /h/.aws/config"},
		{"ask_read add relaxing the built-in .env scan", "/h", []Edit{add("fs.ask_read", "./.env")}, Widens, "Can never read ./.env", "Asks you before it reads ./.env"},
		{"ask_read add with no home", "", []Edit{add("fs.ask_read", "./docs/")}, Mixed, "May read ./docs/", "Asks you before it reads ./docs/"},
		{"ask_read remove", "/h", []Edit{rm("fs.ask_read", "./confidential/")}, Widens, "Asks you before it reads ./confidential/", "May read ./confidential/"},
		{"fs.ask add outside the write entries", "/h", []Edit{add("fs.ask", "./drafts/")}, Widens, "Cannot change ./drafts/", "Asks you before it changes ./drafts/"},
		{"fs.ask add beneath a write entry", "/h", []Edit{add("fs.ask", "./out/sub/")}, Narrows, "May change ./out/sub/", "May change ./out/sub/"},
		{"fs.ask remove", "/h", []Edit{rm("fs.ask", "./held/")}, Narrows, "Asks you before it changes ./held/", "Cannot change ./held/"},
		{"net.ask add", "/h", []Edit{add("net.ask", "tcp://new.example.com:443")}, Widens, "Cannot connect to tcp://new.example.com:443", "Asks you before it connects to tcp://new.example.com:443"},
		{"net.ask add where an allow decides", "/h", []Edit{add("net.ask", "tcp://api.example.com:443")}, Narrows, "May connect to tcp://api.example.com:443", "May connect to tcp://api.example.com:443"},
		{"net.ask remove", "/h", []Edit{rm("net.ask", "tcp://upload.example.com:443")}, Narrows, "Asks you before it connects to tcp://upload.example.com:443", "Cannot connect to tcp://upload.example.com:443"},
		{"never ask_read", "/h", []Edit{never("fs.ask_read", "./confidential/")}, Narrows, "Asks you before it reads ./confidential/", "Can never read ./confidential/"},
		{"never fs.ask", "/h", []Edit{never("fs.ask", "./held/")}, Narrows, "Asks you before it changes ./held/", "Cannot change ./held/"},
		{"never net.ask", "/h", []Edit{never("net.ask", "tcp://upload.example.com:443")}, Narrows, "Asks you before it connects to tcp://upload.example.com:443", "Cannot connect to tcp://upload.example.com:443"},
		{"deny_read over an ask_read drops it", "/h", []Edit{add("fs.deny_read", "./")}, Narrows, "Asks you before it reads ./confidential/", "Can never read ./confidential/"},
		{"a grant and a removal", "/h", []Edit{add("fs.write", "./tmp/"), rm("exec.allow", "ls")}, Mixed, "May run ls", "Cannot run ls"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := applyEdits(t, editBase, c.home, c.edits...)
			if err != nil {
				t.Fatal(err)
			}
			if res.Direction != c.want {
				t.Errorf("direction = %s, want %s (why: %s)", res.Direction, c.want, res.Why)
			}
			if len(res.Sentences) == 0 || res.Sentences[0].Before != c.before || res.Sentences[0].After != c.after {
				t.Errorf("sentences = %+v, want %q -> %q", res.Sentences, c.before, c.after)
			}
			if res.Why == "" || res.Diff == "" {
				t.Errorf("no why or diff: %+v", res)
			}
		})
	}
}

// TestNeverUnderWriteGrant: an fs.ask scope beneath a write entry never asked (ADR 0057 D3), so never is a
// deny_write there.
func TestNeverUnderWriteGrant(t *testing.T) {
	text := strings.Replace(editBase, "  ask:\n    - ./held/\n", "  ask:\n    - ./out/held/\n", 1)
	res, err := applyEdits(t, text, "/h", Edit{Op: OpNever, Key: "fs.ask", Entry: "./out/held/"})
	if err != nil {
		t.Fatal(err)
	}
	_, top, _ := parse(res.Text)
	if hasString(top, "fs.ask", "./out/held/") || !hasString(top, "fs.deny_write", "./out/held/") || res.Direction != Narrows {
		t.Errorf("direction %s, text:\n%s", res.Direction, res.Text)
	}
}

// TestEditRefusesAbsentSection: the first entry of an absent net: section or exec.allow list would refuse every
// other destination or program, so it is refused; a removal from a present one is not.
func TestEditRefusesAbsentSection(t *testing.T) {
	noNet := strings.Replace(editBase, "net:\n  allow:\n    - api.example.com:443 # the API\n  ask:\n    - tcp://upload.example.com:443\n", "", 1)
	nullNet := strings.Replace(noNet, "exec:\n", "net:\nexec:\n", 1)
	denyExec := strings.Replace(editBase, "  allow: [sh, cat, ls]   # programs\n", "  deny: [curl]\n", 1)
	noExec := strings.Replace(editBase, "exec:\n  allow: [sh, cat, ls]   # programs\n", "", 1)
	cases := []struct {
		name, text string
		e          Edit
	}{
		{"net.allow with no net", noNet, Edit{OpAdd, "net.allow", "pypi.org:443"}},
		{"net.ask with no net", noNet, Edit{OpAdd, "net.ask", "tcp://pypi.org:443"}},
		{"net.allow with a null net", nullNet, Edit{OpAdd, "net.allow", "pypi.org:443"}},
		{"exec.allow in deny-list mode", denyExec, Edit{OpAdd, "exec.allow", "git"}},
		{"exec.allow with no exec", noExec, Edit{OpAdd, "exec.allow", "git"}},
	}
	for _, c := range cases {
		if _, err := applyEdits(t, c.text, "/h", c.e); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "yourself") {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
	if _, err := applyEdits(t, editBase, "/h", Edit{OpRemove, "net.allow", "api.example.com:443"}); err != nil {
		t.Errorf("removal from a present net: %v", err)
	}
}

// TestEditKeepsComments: an added entry changes one line, carries its comment, and every other byte is kept; a
// removal drops one line.
func TestEditKeepsComments(t *testing.T) {
	res, err := applyEdits(t, editBase, "/h", Edit{OpAdd, "fs.deny_read", "./notes/"})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(editBase, "    - ./secrets/\n", "    - ./secrets/\n    - ./notes/ # added via dashboard, 2026-10-26\n", 1)
	if string(res.Text) != want {
		t.Errorf("text:\n%s\nwant:\n%s", res.Text, want)
	}
	res, err = applyEdits(t, editBase, "/h", Edit{OpRemove, "exec.allow", "ls"})
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(editBase, "[sh, cat, ls]", "[sh, cat]", 1); string(res.Text) != want {
		t.Errorf("text:\n%s\nwant:\n%s", res.Text, want)
	}
	if !strings.Contains(res.Diff, "-  allow: [sh, cat, ls]   # programs\n+  allow: [sh, cat]   # programs\n") {
		t.Errorf("diff does not read old before new:\n%s", res.Diff)
	}
}

// TestEditNeverWritesUncompilable: a text the compiler refuses is never returned, no compiler is no edit, and the
// real compiler's refusal (an fs.ask_read entry beneath a write entry, which Landlock could not hold) refuses.
func TestEditNeverWritesUncompilable(t *testing.T) {
	_, err := ApplyEdits(EditRequest{Contract: []byte(editBase), ContractPath: editPath, Edits: []Edit{{OpAdd, "fs.write", "./x/"}},
		Check: func([]byte) error { return errors.New("no") }})
	if !errors.Is(err, ErrRefused) {
		t.Errorf("check refusal: %v", err)
	}
	if _, err := ApplyEdits(EditRequest{Contract: []byte(editBase), ContractPath: editPath, Edits: []Edit{{OpAdd, "fs.write", "./x/"}}}); err == nil {
		t.Error("no compiler accepted")
	}
	home, proj, cpath, compile := compileHome(t)
	if _, err := compile([]byte(heldContract)); err != nil {
		t.Skipf("the fixture does not compile here: %v", err)
	}
	check := func(b []byte) error { _, err := compile(b); return err }
	req := EditRequest{Contract: []byte(heldContract), ContractPath: cpath, Cwd: proj, Home: home, Check: check}
	req.Edits = []Edit{{OpAdd, "fs.ask_read", "./out/"}}
	if _, err := ApplyEdits(req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "does not compile") {
		t.Errorf("ask_read beneath a write entry: %v", err)
	}
	req.Edits = []Edit{{OpAdd, "fs.ask_read", "./docs/"}}
	res, err := ApplyEdits(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Direction != Narrows {
		t.Errorf("ask_read on readable docs: %s", res.Direction)
	}
	req.Edits = []Edit{{OpAdd, "fs.deny_read", filepath.Join(home, ".config")}}
	if res, err = ApplyEdits(req); err != nil || strings.Contains(string(res.Text), "ask_read") {
		t.Errorf("deny_read over the ask_read entry: %v\n%s", err, res.Text)
	}
}

// TestEditEntryQuoting: an entry YAML would read as something else (null, a bool, a number, a comment, a mapping) is
// written quoted and reads back as the same string; an entry that would break its line is refused.
func TestEditEntryQuoting(t *testing.T) {
	for _, e := range []string{"null", "yes", "123", "0o7", "#hash", "a: b", "- dash", "'quote", `"dq"`, "*glob", "~/x y",
		"[x]", "{x}", "@at", "%pct", "!bang", "&anchor", "|pipe", ">gt", "./naïve/", "a #b"} {
		res, err := applyEdits(t, editBase, "/h", Edit{OpAdd, "fs.deny_read", e})
		if err != nil {
			t.Errorf("%q: %v", e, err)
			continue
		}
		var c struct {
			FS struct {
				DenyRead []string `yaml:"deny_read"`
			} `yaml:"fs"`
		}
		if err := yaml.Unmarshal(res.Text, &c); err != nil {
			t.Errorf("%q: %v", e, err)
			continue
		}
		if n := len(c.FS.DenyRead); n != 2 || c.FS.DenyRead[1] != e {
			t.Errorf("%q reads back as %q:\n%s", e, c.FS.DenyRead, res.Text)
		}
	}
	for _, e := range []string{"", " x", "x ", "x\ny", "x\ty", "x\x00", "x\u2028y", "\xff", strings.Repeat("a", MaxEntry+1)} {
		if _, err := applyEdits(t, editBase, "/h", Edit{OpAdd, "fs.deny_read", e}); !errors.Is(err, ErrRefused) {
			t.Errorf("%q accepted: %v", e, err)
		}
	}
	if _, err := applyEdits(t, editBase, "/h", Edit{OpAdd, "net.allow", "a b:443"}); !errors.Is(err, ErrRefused) {
		t.Errorf("a net entry with a space: %v", err)
	}
	// On a flow list (deny_read: [a, b]), an entry that would read as list syntax adds exactly one entry and keeps the
	// others, in order (SEC-5): "x, ~/.ssh/" is one entry, never two; "a]" does not close the list early; "b # c" is
	// not cut at a comment; "- d" is not a nested block item.
	flow := strings.Replace(editBase, "  deny_read:\n    - ./secrets/\n", "  deny_read: [a, b]\n", 1)
	for _, e := range []string{"x, ~/.ssh/", "a]", "b # c", "- d", "[c", "{k: v}"} {
		res, err := applyEdits(t, flow, "/h", Edit{OpAdd, "fs.deny_read", e})
		if err != nil {
			t.Errorf("flow %q: %v", e, err)
			continue
		}
		var c struct {
			FS struct {
				DenyRead []string `yaml:"deny_read"`
			} `yaml:"fs"`
		}
		if err := yaml.Unmarshal(res.Text, &c); err != nil {
			t.Errorf("flow %q: %v\n%s", e, err, res.Text)
			continue
		}
		if want := []string{"a", "b", e}; !slices.Equal(c.FS.DenyRead, want) {
			t.Errorf("flow %q reads back as %q, want %q:\n%s", e, c.FS.DenyRead, want, res.Text)
		}
	}
}

// TestEditRefusals: only entries the file spells are removed or turned to never, only the form's lists are edited,
// the run's own command is never removed, a date or via cannot break the comment line, and an entry already there
// is nothing to change.
func TestEditRefusals(t *testing.T) {
	cases := []struct {
		name string
		req  EditRequest
		err  error
	}{
		{"remove an unspelled entry", EditRequest{Edits: []Edit{{OpRemove, "fs.deny_read", "~/.ssh"}}}, ErrRefused},
		{"remove another spelling", EditRequest{Edits: []Edit{{OpRemove, "fs.write", "./out"}}}, ErrRefused},
		{"never an unspelled entry", EditRequest{Edits: []Edit{{OpNever, "fs.ask_read", "./other/"}}}, ErrRefused},
		{"never a non-ask list", EditRequest{Edits: []Edit{{OpNever, "fs.write", "./out/"}}}, ErrRefused},
		{"a list the form does not edit", EditRequest{Edits: []Edit{{OpAdd, "limits.tokens", "5"}}}, ErrRefused},
		{"the run's own command", EditRequest{Edits: []Edit{{OpRemove, "exec.allow", "sh"}}}, ErrRefused},
		{"a date with a newline", EditRequest{Edits: []Edit{{OpAdd, "fs.write", "./x/"}}, Date: "2026\nfs: {}"}, ErrRefused},
		{"no edits", EditRequest{}, ErrRefused},
		{"already listed", EditRequest{Edits: []Edit{{OpAdd, "exec.allow", "cat"}}}, ErrNothing},
		{"already listed, resolved", EditRequest{Edits: []Edit{{OpAdd, "fs.write", "out"}}}, ErrNothing},
	}
	for _, c := range cases {
		r := c.req
		r.Contract, r.ContractPath, r.Check = []byte(editBase), editPath, okCheck
		if _, err := ApplyEdits(r); !errors.Is(err, c.err) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.err)
		}
	}
	if _, err := ApplyEdits(EditRequest{Contract: []byte(editBase), ContractPath: "agent.yaml", Edits: []Edit{{OpAdd, "fs.write", "./x/"}}, Check: okCheck}); err == nil {
		t.Error("a relative contract path accepted")
	}
}

func TestNeverOf(t *testing.T) {
	for rule, want := range map[string]Edit{
		"fs.ask_read[~/.config/telemetry/]": {OpNever, "fs.ask_read", "~/.config/telemetry/"},
		"fs.ask[./held/]":                   {OpNever, "fs.ask", "./held/"},
		"net.ask[tcp://upload.example:443]": {OpNever, "net.ask", "tcp://upload.example:443"},
	} {
		if got, err := NeverOf(rule); err != nil || got != want {
			t.Errorf("%s: %+v, %v", rule, got, err)
		}
	}
	for _, rule := range []string{"fs.deny_read[x]", "exec[sh]", "net[h:443]", "unmatched", "fs.ask_read"} {
		if _, err := NeverOf(rule); !errors.Is(err, ErrRefused) {
			t.Errorf("%s accepted: %v", rule, err)
		}
	}
	if s := (Edit{OpNever, "fs.ask", "./held/"}).String(); s != "never fs.ask[./held/]" {
		t.Errorf("String = %q", s)
	}
}

// FuzzApplyEdits: whatever the contract text and entry, the edit core never panics, and what it returns parses,
// carries the entry as a string, and was what the compiler saw.
func FuzzApplyEdits(f *testing.F) {
	f.Add(editBase, "./notes/", 0)
	f.Add("fs:\n  deny_read: [a]\n", "a #b", 1)
	f.Add("net: {allow: [x:1]}\n", "y:2", 6)
	keys := EditKeys()
	f.Fuzz(func(t *testing.T, text, entry string, k int) {
		if k < 0 {
			k = -k
		}
		key := keys[k%len(keys)]
		var seen []byte
		res, err := ApplyEdits(EditRequest{Contract: []byte(text), ContractPath: editPath, Home: "/h", Edits: []Edit{{OpAdd, key, entry}},
			Check: func(b []byte) error { seen = b; return nil }})
		if err != nil {
			return
		}
		_, top, err := parse(res.Text)
		if err != nil {
			t.Fatalf("returned text does not parse: %v\n%s", err, res.Text)
		}
		if !hasString(top, key, entry) || string(seen) != string(res.Text) {
			t.Fatalf("%s %q not in the text, or the compiler saw another:\n%s", key, entry, res.Text)
		}
	})
}

// TestRelaxesHookWidens: an fs.ask_read entry the lexical model reads as a narrowing (./lnk/credentials, ./lnk a
// link to ~/.aws) is Widens once the compiler says the new text relaxes more built-in deny_read entries.
func TestRelaxesHookWidens(t *testing.T) {
	relaxes := func(b []byte) (int, error) { return strings.Count(string(b), "./lnk/"), nil }
	edit := Edit{Op: OpAdd, Key: "fs.ask_read", Entry: "./lnk/credentials"}
	req := EditRequest{Contract: []byte(editBase), ContractPath: editPath, Cwd: "/p/proj", Home: "/h", Edits: []Edit{edit},
		Check: okCheck}
	res, err := ApplyEdits(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Direction != Narrows {
		t.Fatalf("lexical direction = %s, want narrows", res.Direction)
	}
	req.Relaxes = relaxes
	if res, err = ApplyEdits(req); err != nil {
		t.Fatal(err)
	}
	if res.Direction != Mixed || !strings.Contains(res.Why, "relaxes 1 built-in") {
		t.Errorf("direction = %s, why %q; want mixed (narrows by the file, widens by the compiler)", res.Direction, res.Why)
	}
	req.Edits = []Edit{{Op: OpAdd, Key: "fs.write", Entry: "./tmp/"}}
	if res, err = ApplyEdits(req); err != nil || res.Direction != Widens || strings.Contains(res.Why, "relaxes") {
		t.Errorf("an edit relaxing nothing more: %v %+v", err, res)
	}
}
