// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRemoveDoubledEntry: an entry the file lists more than once (compile warns redundant-rule, "remove the
// duplicate") is removed in every copy, since a copy left would keep the rule: from a block list or a flow list, by
// a removal, a never or a deny_read over an ask entry. Every other byte is kept, a list of copies only goes or is
// left `[]` as a one-entry list does, and the preview's Why says every copy goes.
func TestRemoveDoubledEntry(t *testing.T) {
	repeat := func(line string, n int) string { return strings.Replace(editBase, line, strings.Repeat(line, n), 1) }
	noAsk := strings.Replace(editBase, "  ask_read:\n    - ./confidential/\n", "", 1)
	denied := func(text, entry string) string {
		return strings.Replace(text, "    - ./secrets/\n", "    - ./secrets/\n    - "+entry+" # added via dashboard, 2026-10-26\n", 1)
	}
	cases := []struct {
		name, text, want string
		edit             Edit
		dir              Direction
		why              string // the removal's clause
	}{
		{"block list, another entry kept",
			strings.Replace(editBase, "    - ./secrets/\n", "    - ./secrets/\n    - ./notes/\n    - ./secrets/ # again\n", 1),
			strings.Replace(editBase, "    - ./secrets/\n", "    - ./notes/\n", 1),
			Edit{OpRemove, "fs.deny_read", "./secrets/"}, Widens,
			"fs.deny_read -= ./secrets/ widens (the file lists it twice: every copy goes)"},
		{"block list of copies only, its key goes",
			repeat("    - ./secrets/\n", 3),
			strings.Replace(editBase, "  deny_read:\n    - ./secrets/\n", "", 1),
			Edit{OpRemove, "fs.deny_read", "./secrets/"}, Widens,
			"fs.deny_read -= ./secrets/ widens (the file lists it 3 times: every copy goes)"},
		{"block list of copies only, left empty",
			strings.Replace(editBase, "    - ./out/ # outputs\n", "    - ./out/ # outputs\n    - './out/'\n", 1),
			strings.Replace(editBase, "  write:\n    - ./out/ # outputs\n", "  write: []\n", 1),
			Edit{OpRemove, "fs.write", "./out/"}, Narrows,
			"fs.write -= ./out/ narrows (the file lists it twice: every copy goes)"},
		{"flow list",
			strings.Replace(editBase, "[sh, cat, ls]", "[sh, cat, ls, cat]", 1),
			strings.Replace(editBase, "[sh, cat, ls]", "[sh, ls]", 1),
			Edit{OpRemove, "exec.allow", "cat"}, Narrows,
			"exec.allow -= cat narrows (the file lists it twice: every copy goes)"},
		{"never on a doubled ask entry",
			repeat("    - ./confidential/\n", 2), denied(noAsk, "./confidential/"),
			Edit{OpNever, "fs.ask_read", "./confidential/"}, Narrows,
			"fs.ask_read -= ./confidential/ narrows (the file lists it twice: every copy goes)"},
		{"a deny_read over a doubled ask entry",
			repeat("    - ./confidential/\n", 2), denied(noAsk, "./"),
			Edit{OpAdd, "fs.deny_read", "./"}, Narrows,
			"fs.ask_read -= ./confidential/ narrows (the file lists it twice: every copy goes)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := applyEdits(t, c.text, "/h", c.edit)
			if err != nil {
				t.Fatal(err)
			}
			if string(res.Text) != c.want {
				t.Errorf("text:\n%s\nwant:\n%s", res.Text, c.want)
			}
			if res.Direction != c.dir {
				t.Errorf("direction = %s, want %s (why: %s)", res.Direction, c.dir, res.Why)
			}
			if !slices.Contains(strings.Split(res.Why, "; "), c.why) {
				t.Errorf("why = %q, want the clause %q", res.Why, c.why)
			}
		})
	}
	// An entry listed once says nothing of copies.
	res, err := applyEdits(t, editBase, "/h", Edit{OpRemove, "fs.deny_read", "./secrets/"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Why != "fs.deny_read -= ./secrets/ widens" {
		t.Errorf("one copy: why %q", res.Why)
	}
}

// TestApplyRemovesDoubledEntry: tego rule's removals take every copy too. A block of a program a doubled exec.allow
// entry allowed refuses it (one copy left still let it run, under "refuse to run"), and a host block over a doubled
// net.allow entry removes it once, every copy, where the list walk would ask for it twice.
func TestApplyRemovesDoubledEntry(t *testing.T) {
	cat := ev(t, record.KindExec, record.VerdictAllow, "exec[cat]", "", record.ExecPayload{Path: "/usr/bin/cat", Argv: []string{"cat"}})
	res, err := scoped(t, strings.Replace(base, "    - cat\n", "    - cat\n    - cat\n", 1), cat, Block, func(*Request) {})
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(base, "    - cat\n", "", 1); string(res.Text) != want {
		t.Errorf("block of a program a doubled entry allowed:\n%s\nwant:\n%s", res.Text, want)
	}
	conn := ev(t, record.KindNet, record.VerdictAllow, "net[api.example.com:443]", "", record.NetPayload{Op: "connect", Dst: "1.2.3.4:443", Host: "api.example.com"})
	text := strings.Replace(netContract, "    - api.example.com:443\n", "    - api.example.com:443\n    - api.example.com:443\n", 1)
	if res, err = scoped(t, text, conn, Block, func(r *Request) { r.HostOnly = true }); err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(netContract, "    - api.example.com:443\n    - api.example.com:80\n", "", 1); string(res.Text) != want ||
		len(res.Changes) != 2 {
		t.Errorf("host block over a doubled entry: %s\n%s\nwant:\n%s", res.Summary, res.Text, want)
	}
}
