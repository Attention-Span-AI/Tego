// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

func TestRound2CorrectedExternalTarget(t *testing.T) {
	row := rows.Builtin().Lookup("git")
	if _, ok := row.Root.Subs["widget"]; ok {
		t.Fatal("target must be absent from Subs")
	}
	if _, ok := row.Root.Alias["widget"]; ok {
		t.Fatal("target must be absent from Alias")
	}
	cand := execmatch.NewCandidates(append(slices.Clone(row.Builtins), "widget"), row.Common)
	if got, ok := execmatch.Autocorrect("widgte", cand); !ok || got != "widget" {
		t.Fatalf("correction=%q %v", got, ok)
	}
	rs := execmatch.NewNormalizer(row, cand).Normalize([]string{"widgte", "--no-pager"})
	if len(rs) != 2 {
		t.Errorf("literal and corrected required: %+v", rs)
	}
	for _, r := range rs {
		want := "widgte"
		if r.Corrected {
			want = "widget"
		}
		if !slices.Equal(r.Path, []string{want}) || !r.Located || len(r.Hits) != 1 {
			t.Errorf("unknown leaf lost target or persistent grammar: %+v", r)
		}
	}
	custom := &execmatch.Row{Tool: "tool", Autocorrect: true, Builtins: []string{"widget"}, Root: &execmatch.Level{Subs: map[string]*execmatch.Level{}, Opts: []execmatch.Opt{{Name: "sticky", Long: []string{"sticky"}, Persistent: true}}}}
	for _, r := range execmatch.NewNormalizer(custom, nil).Normalize([]string{"widgte", "--sticky"}) {
		if len(r.Hits) != 1 || r.Hits[0].Opt == nil {
			t.Errorf("lost inherited persistent grammar: %+v", r)
		}
	}

	for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
		entry := "git widget"
		if list == execmatch.ListAllow {
			entry = "git widgte"
		}
		p, err := execmatch.Parse(entry, list, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{Candidates: cand})
		f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", "widgte"}, ArgvComplete: true}
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("%s: %+v", list, r)
		}
	}
}

func TestRound2StrippedAppletRejectsExactGrant(t *testing.T) {
	for _, stage := range []bool{false, true} {
		f := execmatch.Facts{Requested: "coreutils", Image: "coreutils", Argv0: "lt-rm", Argv: []string{"lt-rm", "-r"}, ArgvComplete: true}
		grant := execmatch.ExactPattern("hook", "rm", f.Argv)
		if stage {
			f = execmatch.Facts{Requested: "script", Image: "script", Path: "script", Argv0: "script", Argv: []string{"script"}, ArgvComplete: true, Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: "/tmp/lt-rm", Image: "coreutils"}}}
			grant = execmatch.ExactPattern("hook", "rm", []string{"script", "script"})
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{grant}, execmatch.IndexOptions{})
		r := ix.Decide(&f)
		if r.Outcome != execmatch.OutcomeRefused || !r.Unlisted || r.Via != execmatch.ViaMulticall {
			t.Errorf("stage=%v: %+v", stage, r)
		}
		for _, inv := range ix.Interpretations(&f) {
			if inv.Tool == "rm" && (inv.Via != execmatch.ViaMulticall || inv.Argv0 != "") {
				t.Errorf("stage=%v: derived applet is direct: %+v", stage, inv)
			}
		}
	}
}

func TestRound2NegatedPatternAbbreviation(t *testing.T) {
	for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk, execmatch.ListAllow} {
		p, err := execmatch.Parse("git add --no-f", list, rows.Builtin())
		if err != nil {
			t.Errorf("%s: %v", list, err)
			continue
		}
		if len(p.Opts) != 1 || p.Opts[0].Opt == nil || !p.Opts[0].Neg {
			t.Errorf("%s: negated option unresolved: %+v", list, p.Opts)
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
		for _, spelling := range []string{"--no-force", "--force", "--no-", "--no"} {
			f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", "add", spelling}, ArgvComplete: true}
			r := ix.Decide(&f)
			if list == execmatch.ListAllow {
				if (r.Outcome == execmatch.OutcomeAllowed) != (spelling == "--no-force") {
					t.Errorf("%s %s: %+v", list, spelling, r)
				}
			} else if (r.Outcome == execmatch.OutcomeRefused) != (spelling != "--force") {
				t.Errorf("%s %s: %+v", list, spelling, r)
			}
		}
		if list != execmatch.ListAllow {
			positive := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", "--for", "add"}, ArgvComplete: true}
			if r := ix.Decide(&positive); r.Outcome != execmatch.OutcomeNone {
				t.Errorf("%s raw positive matched negation: %+v", list, r)
			}
			negative := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", "add", "--no"}, ArgvComplete: true}
			for _, inv := range ix.Interpretations(&negative) {
				if n := testing.AllocsPerRun(50, func() { p.Match(&inv) }); n != 0 {
					t.Errorf("negative raw match allocates %v", n)
				}
			}
			for _, raw := range []string{"--n", "--no", "--no-", "-no-f"} {
				f := execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: []string{"git", raw, "add"}, ArgvComplete: true}
				if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
					t.Errorf("%s lost unknown negative prefix %s: %+v", list, raw, r)
				}
			}
		}
	}
}

func TestRound2AllowNamedSelector(t *testing.T) {
	for _, entry := range []string{"cargo +nightly build", "cargo +stable build", "gcloud alpha compute instances delete", "gcloud beta compute instances delete", "gcloud preview compute instances delete"} {
		if _, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin()); err == nil {
			t.Errorf("allow silently discards selector: %s", entry)
		}
		for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
			if _, err := execmatch.Parse(entry, list, rows.Builtin()); err != nil {
				t.Errorf("%s: %v", list, err)
			}
		}
	}
}

func TestRound2OptionIntroducers(t *testing.T) {
	for _, entry := range []string{"git push ---force", "go test ---v", "go test --v"} {
		_, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin())
		if entry == "go test --v" {
			if err != nil {
				t.Errorf("two-dash spelling should resolve v: %v", err)
			}
		} else if err == nil {
			t.Errorf("allow deleted name dash: %s", entry)
		}
	}
	for _, tool := range []string{"git", "go"} {
		sub, ordinary, extra := "push", "--force", "---force"
		if tool == "go" {
			sub, ordinary, extra = "test", "-v", "---v"
		}
		for _, list := range []execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
			p, err := execmatch.Parse(tool+" "+sub+" "+extra, list, rows.Builtin())
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Opts) != 1 || p.Opts[0].Opt != nil || p.Opts[0].Long != extra[2:] {
				t.Errorf("name not literal: %+v", p.Opts)
			}
			ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{})
			for _, spelling := range []string{ordinary, extra} {
				f := execmatch.Facts{Requested: tool, Image: tool, Argv0: tool, Argv: []string{tool, sub, spelling}, ArgvComplete: true}
				if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused {
					t.Errorf("%s %s against %s: %+v", list, p.Entry, spelling, r)
				}
			}
		}
	}
}

func TestRound2StageInvokedAsOrigin(t *testing.T) {
	id := execmatch.ID{Dev: 3, Ino: 4}
	for _, mapped := range []bool{false, true} {
		p, err := execmatch.Parse("systemctl reboot", execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{Identities: map[execmatch.ID]string{id: "systemctl"}})
		image := "systemctl"
		if mapped {
			image = "x"
		}
		f := execmatch.Facts{Requested: "script", Image: "script", Path: "script", Argv0: "script", Argv: []string{"script"}, ArgvComplete: true, Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: "/tmp/xrebootx", Image: image, ID: id, HasID: mapped}}}
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Via != execmatch.ViaShebang {
			t.Errorf("mapped=%v stage origin lost: %+v", mapped, r)
		}
	}
}

func TestRound2MappedDispatcherStrip(t *testing.T) {
	id := execmatch.ID{Dev: 1, Ino: 2}
	for _, stage := range []bool{false, true} {
		p, err := execmatch.Parse("rm -r", execmatch.ListDeny, rows.Builtin())
		if err != nil {
			t.Fatal(err)
		}
		ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{Identities: map[execmatch.ID]string{id: "coreutils"}})
		f := execmatch.Facts{Requested: "x", Image: "x", Argv0: "lt-rm", Argv: []string{"lt-rm", "-r"}, ArgvComplete: true, ID: id, HasID: true}
		if stage {
			f = execmatch.Facts{Requested: "script", Image: "script", Path: "script", Argv0: "script", Argv: []string{"script", "-r"}, ArgvComplete: true, Form: execmatch.FormScript, Interp: []execmatch.Stage{{Path: "/tmp/lt-rm", Image: "x", ID: id, HasID: true}}}
		}
		if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeRefused || r.Via != execmatch.ViaMulticall {
			t.Errorf("stage=%v: mapped strip omitted: %+v", stage, r)
		}
	}
}
