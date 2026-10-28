// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestBlockOf is the table of every editable key (and exec.deny, which Never allow writes) × add and remove: each
// narrowing maps to the live block that refuses no more than the new contract does, and every other change says why
// it has none. rest is the contract's entries after the change (nil: not known); an addition rest no longer holds has
// none.
func TestBlockOf(t *testing.T) {
	rest := map[string][]string{
		"fs.write":   {"./", "./out/"},
		"fs.ask":     {"./drafts/"},
		"exec.allow": {"git push", "/usr/bin/python3", "./tools/"},
		"net.allow":  {"api.example.com:443", "*.cdn.example.net"},
		"net.ask":    {"pypi.org"},
	}
	none := map[string][]string{}
	cases := []struct {
		remove     bool
		key, entry string
		rest       map[string][]string
		want       string // kind:value, or "!" plus a word of the reason
	}{
		// exec.allow removed, exec.deny added: a program.
		{true, "exec.allow", "cat", none, "exec:cat"},
		{true, "exec.allow", "/usr/bin/cat", none, "exec:/usr/bin/cat"},
		{true, "exec.allow", "./bin/", none, "exec:/p/proj/bin/"},
		{true, "exec.allow", "git push", none, "!command"},
		{true, "exec.allow", "git", rest, "!git push"},             // a command entry still admits git
		{true, "exec.allow", "python3", rest, "!/usr/bin/python3"}, // the absolute entry still allows it
		{true, "exec.allow", "/p/proj/tools/x", rest, "!./tools/"},
		{false, "exec.allow", "git", nil, "!do more"},
		{false, "exec.deny", "curl", none, "exec:curl"},
		{true, "exec.deny", "curl", none, "!do more"},
		// net.allow or net.ask removed: a destination.
		{true, "net.allow", "api.example.com:443", none, "net:api.example.com:443"},
		{true, "net.ask", "api.example.com:443", none, "net:api.example.com:443"},
		{true, "net.allow", "api.example.com", rest, "!api.example.com:443"},
		{true, "net.allow", "img.cdn.example.net:443", rest, "!*.cdn.example.net"},
		{true, "net.allow", "other.example.com:443", rest, "net:other.example.com:443"},
		{false, "net.allow", "x:443", nil, "!do more"},
		{false, "net.ask", "x:443", nil, "!ask"},
		// fs.deny_read added: reads only.
		{false, "fs.deny_read", "./secrets/", nil, "read:/p/proj/secrets"},
		{false, "fs.deny_read", "~/.config/telemetry/", nil, "read:/h/.config/telemetry"},
		{false, "fs.deny_read", "**/.env", nil, "!pattern"},
		{true, "fs.deny_read", "./secrets/", none, "!do more"},
		// fs.deny_write added: changes only.
		{false, "fs.deny_write", "./out/", nil, "write:/p/proj/out"},
		{false, "fs.deny_write", "**/*.lock", nil, "!pattern"},
		{true, "fs.deny_write", "./out/", none, "!do more"},
		// fs.write removed: changes only, unless another entry still covers it or a part of it.
		{true, "fs.write", "./tmp/", none, "write:/p/proj/tmp"},
		{true, "fs.write", "/dev/tty", none, "write:/dev/tty"},
		{true, "fs.write", "./tmp/", rest, "!./"}, // ./ still allows writes under it
		{true, "fs.write", "./tmp/", map[string][]string{"fs.write": {"./tmp/keep/"}}, "!./tmp/keep/"},
		{true, "fs.write", "./drafts/x/", map[string][]string{"fs.ask": {"./drafts/"}}, "!./drafts/"},
		{true, "fs.write", "./tmp/", map[string][]string{"fs.write": {"./src/", "./tmp2/"}}, "write:/p/proj/tmp"},
		{true, "fs.write", "./tmp/", map[string][]string{"fs.write": {"./tmp/**/*.log"}}, "!./tmp/**/*.log"},
		{true, "fs.write", "./build/*.o", none, "!pattern"},
		{false, "fs.write", "./out/", nil, "!do more"},
		// fs.ask removed (Never allow on a write ask, or Remove): changes only, as an fs.write removal.
		{true, "fs.ask", "./held/", none, "write:/p/proj/held"},
		{true, "fs.ask", "~/notes/", none, "write:/h/notes"},
		{true, "fs.ask", "./held/", map[string][]string{"fs.write": {"./"}}, "!another fs.write entry (./) still covers it"},
		{true, "fs.ask", "./held/", map[string][]string{"fs.ask": {"./held/sub/"}}, "!another fs.ask entry (./held/sub/) still covers it"},
		{true, "fs.ask", "./held/", map[string][]string{"fs.write": {"./held/**/*.md"}}, "!./held/**/*.md"},
		{true, "fs.ask", "./held/*.md", none, "!pattern"},
		// Read asks: added or removed, none live; a write ask added, none live.
		{false, "fs.ask", "./x/", nil, "!asks from its next run"},
		{false, "fs.ask_read", "./x/", nil, "!asks from its next run"},
		{true, "fs.ask_read", "./x/", none, "!keeps asking"},
		{false, "env.pass", "X", none, "!no live block"},
		// An addition the contract no longer holds: a later change took it back, so it has none.
		{false, "fs.deny_read", "./vault/", none, "!took this entry back"},
		{false, "fs.deny_read", "./vault/", map[string][]string{"fs.deny_read": {"./vault"}}, "read:/p/proj/vault"},
		{false, "fs.deny_write", "./out/", map[string][]string{"fs.deny_write": {"./src/"}}, "!took this entry back"},
		{false, "fs.deny_write", "./out/", map[string][]string{"fs.deny_write": {"./out/"}}, "write:/p/proj/out"},
		{false, "fs.ask", "./x/", none, "!took this entry back"},
		{false, "exec.deny", "curl", map[string][]string{"exec.allow": {"sh"}}, "exec:curl"}, // exec.deny is not an edited list
	}
	for _, c := range cases {
		k, v, why := blockOf(rule.Change{Remove: c.remove, Key: c.key, Entry: c.entry}, "/p/proj", "/h", c.rest)
		switch {
		case strings.HasPrefix(c.want, "!"):
			if k != "" || !strings.Contains(why, c.want[1:]) {
				t.Errorf("%v %s %s: %s:%s (%q), want no block, a reason with %q", c.remove, c.key, c.entry, k, v, why, c.want[1:])
			}
		case string(k)+":"+v != c.want || why != "":
			t.Errorf("%v %s %s: %s:%s (%q), want %s", c.remove, c.key, c.entry, k, v, why, c.want)
		}
	}
}

// TestNowOptionsMarksAndDedupes: on a watched run every offer is marked Observe; a read block waits for held reads
// (its reason when they are not); and "Never allow" (ask_read removed, deny_read added) offers the deny_read's block
// alone, never a "keeps asking" row for the same entry beside it.
func TestNowOptionsMarksAndDedupes(t *testing.T) {
	held := true
	s := &Service{Home: "/h",
		readsHeld: func(string) (bool, string) { return held, "this run reads files directly" },
		facts: func(run string) livestatus.Facts {
			return livestatus.Facts{Observe: run == "r-watch", RecordMinor: record.Minor}
		},
	}
	now := map[string][]string{"fs.deny_read": {"./docs/"}, "net.allow": {"x.example.com:443"}}
	never := []rule.Change{{Remove: true, Key: "fs.ask_read", Entry: "./docs/"}, {Key: "fs.deny_read", Entry: "./docs/"}}
	opts := s.nowOptions(context.Background(), []string{"r-run", "r-watch"}, never, "/p", now)
	if len(opts) != 2 {
		t.Fatalf("options = %+v, want one per run", opts)
	}
	for _, o := range opts {
		if !o.OK || o.Block != "read:/p/docs" || o.Change != "fs.deny_read += ./docs/" {
			t.Errorf("option %+v", o)
		}
		if o.Observe != (o.Run == "r-watch") {
			t.Errorf("run %s: Observe = %v", o.Run, o.Observe)
		}
	}
	held = false
	opts = s.nowOptions(context.Background(), []string{"r-run"}, never, "/p", now)
	if len(opts) != 1 || opts[0].OK || !strings.Contains(opts[0].Why, "reads files directly") {
		t.Errorf("without held reads: %+v", opts)
	}
	// A write block never waits for reads; a widening beside it says why it waits for the next run.
	mixed := []rule.Change{{Remove: true, Key: "fs.write", Entry: "./tmp/"}, {Key: "net.allow", Entry: "x.example.com:443"}}
	opts = s.nowOptions(context.Background(), []string{"r-run"}, mixed, "/p", now)
	if len(opts) != 2 || !opts[0].OK || opts[0].Block != "write:/p/tmp" || opts[1].OK || !strings.Contains(opts[1].Why, "do more") {
		t.Errorf("mixed: %+v", opts)
	}
	if !slices.ContainsFunc(opts, func(o NowOption) bool { return o.Change == "net.allow += x.example.com:443" }) {
		t.Errorf("the widening's row does not name its change: %+v", opts)
	}
}

// TestNowOptionsOlderLauncher: a run whose launcher predates read and write blocks (record_minor below 24) is offered
// what that launcher enforces, a path block for an added deny_read (still only while it holds its reads) and no write
// block; a run whose kernel plane decides file changes is offered no write block. Both say why in plain words.
func TestNowOptionsOlderLauncher(t *testing.T) {
	facts := map[string]livestatus.Facts{
		"r-r6":    {RecordMinor: record.MinorLiveControl - 1},
		"r-plane": {RecordMinor: record.Minor, KernelDecidesChanges: true},
	}
	held := true
	s := &Service{Home: "/h",
		readsHeld: func(string) (bool, string) { return held, "this run reads files directly" },
		facts:     func(run string) livestatus.Facts { return facts[run] },
	}
	changes := []rule.Change{{Remove: true, Key: "fs.write", Entry: "./tmp/"}, {Key: "fs.deny_read", Entry: "./docs/"}, {Key: "fs.deny_write", Entry: "./src/"},
		{Remove: true, Key: "fs.ask", Entry: "./held/"}}
	rest := map[string][]string{"fs.deny_read": {"./docs/"}, "fs.deny_write": {"./src/"}}
	opts := s.nowOptions(context.Background(), []string{"r-r6", "r-plane"}, changes, "/p", rest)
	got := map[string]NowOption{}
	for _, o := range opts {
		got[o.Run+" "+o.Change] = o
	}
	for key, want := range map[string]string{
		"r-r6 fs.write -= ./tmp/":         "!older tego that has no write blocks",
		"r-r6 fs.deny_read += ./docs/":    "path:/p/docs",
		"r-r6 fs.deny_write += ./src/":    "!older tego that has no write blocks",
		"r-r6 fs.ask -= ./held/":          "!older tego that has no write blocks",
		"r-plane fs.write -= ./tmp/":      "!the kernel decides file changes itself",
		"r-plane fs.ask -= ./held/":       "!the kernel decides file changes itself",
		"r-plane fs.deny_read += ./docs/": "read:/p/docs",
		"r-plane fs.deny_write += ./src/": "!the kernel decides file changes itself",
	} {
		o, ok := got[key]
		switch {
		case !ok:
			t.Errorf("%s: no option in %+v", key, opts)
		case strings.HasPrefix(want, "!"):
			if o.OK || o.Block != "" || !strings.Contains(o.Why, want[1:]) {
				t.Errorf("%s: %+v, want no block, why with %q", key, o, want[1:])
			}
		case !o.OK || o.Block != want:
			t.Errorf("%s: %+v, want %s", key, o, want)
		}
	}
	held = false
	opts = s.nowOptions(context.Background(), []string{"r-r6"}, changes[1:2], "/p", rest)
	if len(opts) != 1 || opts[0].OK || !strings.Contains(opts[0].Why, "reads files directly") {
		t.Errorf("an older launcher's path block without held reads: %+v", opts)
	}
}
