// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rowsText is rows as seq×count, in row order.
func rowsText(rows []Row) string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = fmt.Sprintf("%d×%d", r.Seq, r.Count)
	}
	return "[" + strings.Join(out, " ") + "]"
}

// TestLandlockRefusalIsOneRefusal: a read open the Landlock ruleset refuses at tier landlock (ADR 0077, record_minor
// 23) is two lines, as every refused action is: the supervisor's fs line, refused read-denied under the deny_read entry
// with mechanism landlock (written before the kernel answered, so it holds no errno), and the kind=refused line that
// mirrors it and names the mechanism too (internal/runtime pipeline.go mirrorRefusals). The dashboard shows it as one
// refusal wherever it counts or lists one: the run's Refused, the Refusals tab, the Overview's recent refusals (not
// routine), the run page's refusal groups and secret touches, the timeline (every line, and refusals only) and Logs
// (its rows, verdict counts and Verdict facet, and the verdict:, path: and kind:refused searches, the last listing the
// refused line itself); the line page puts the mechanism in words and links the two lines. It holds on the record's
// own example (spec/record/v1/fixtures/reason-reads.jsonl, whose mirror is the line after its action) and on a ledger
// as the engine writes it, whose mirror copies its action's envelope (pid and monotonic clock), here with another
// process's line slipped in between, which only that envelope pairs (pair.go). The read's line and its mirror both
// write op open, but the dashboard reads the line's as "read" (fsOp) and the mirror's as written, so a pairing that
// compared ops would count this refusal twice, where a refused connect's pair (TestFoldPairs) would still count once.
func TestLandlockRefusalIsOneRefusal(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "reason-reads.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	const engine, key = "r-aaaa-0006-landlk", "/home/u/.ssh/id_ed25519"
	read := `"rule":"fs.deny_read[~/.ssh]","verdict":"refused","authority":"rule","reason":"read-denied","flags":524288,"mechanism":"landlock","op":"open","path":"` + key + `"`
	mirror := `"rule":"fs.deny_read[~/.ssh]","reason":"read-denied","mechanism":"landlock","op":"open","target":"` + key + `"`
	for _, tc := range []struct {
		name, run, key, ledger string
		action, mirror         uint64 // the refused read's line and its mirror
		lines                  int
	}{
		{"record fixture", "r-3f9c2a1b-0dllq06ts7400-r3as23", "/srv/u/.ssh/id_ed25519", string(fixture), 2, 3, 6},
		{"engine shape", engine, key, strings.Join([]string{
			qline(engine, "a", 0, 0, 100, "run_start", "supervisor", `"tier":"landlock","command":["sh"],"cwd":"/home/u/proj","reads_notified":{"notified":true,"why":"reason"},"record_minor":23`),
			qline(engine, "a", 1, 1, 7, "exec", "supervisor", `"rule":"exec[cat]","verdict":"allow","authority":"rule","argv":["cat","`+key+`"],"path":"/usr/bin/cat"`),
			qline(engine, "a", 2, 2, 7, "fs", "seccomp", read),
			// Another process's line, written between the refused read and its mirror.
			qline(engine, "a", 3, 3, 9, "exec", "supervisor", `"rule":"exec[ls]","verdict":"allow","authority":"rule","argv":["ls"],"path":"/usr/bin/ls"`),
			qline(engine, "a", 4, 2, 7, "refused", "seccomp", mirror),
			qline(engine, "a", 5, 4, 100, "run_end", "supervisor", `"reason":"exit","exit_code":1`),
		}, ""), 2, 4, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeRun(t, root, tc.run, tc.ledger)
			s, err := Load(root)
			if err != nil {
				t.Fatal(err)
			}
			r := s.Find(tc.run)
			if r == nil || len(r.Events) != tc.lines {
				t.Fatalf("run %s not read whole", tc.run)
			}
			at := findSeq(r.Events, tc.action)
			if at < 0 {
				t.Fatalf("no line %d", tc.action)
			}
			act := &r.Events[at]
			if act.Kind != "fs" || act.Op != "read" || act.Target != tc.key || act.Reason != "read-denied" || !act.Refusal() {
				t.Fatalf("line %d: %s %s %s %s, refusal %v; want the refused read of %s", act.Seq, act.Kind, act.Op, act.Target,
					act.Reason, act.Refusal(), tc.key)
			}
			once := fmt.Sprintf("[%d×1]", tc.action)
			isMirror := func(row Row) bool { return row.Seq == tc.mirror }
			seqText := func(p *uint64) string {
				if p == nil {
					return "none"
				}
				return fmt.Sprint(*p)
			}

			// The counts.
			var marks []uint64
			for _, e := range r.Events {
				if e.Mirror {
					marks = append(marks, e.Seq)
				}
			}
			if fmt.Sprint(marks) != fmt.Sprint([]uint64{tc.mirror}) || r.Refusals != 1 {
				t.Errorf("mirrors %v, Refusals %d; want [%d] and 1", marks, r.Refusals, tc.mirror)
			}
			if rows := RunRefusals(r); rowsText(rows) != once {
				t.Errorf("the Refusals tab lists %s, want %s", rowsText(rows), once)
			}
			sig := Signal(r, Sensitive{})
			if rows := s.Refusals(0); len(rows) != 1 || !isMirror(rows[0]) || rows[0].Count != 1 || sig.IsBackground(&rows[0].Event) {
				t.Errorf("the Overview's recent refusals: %s, want the refused line %d once, not routine", rowsText(rows), tc.mirror)
			}
			var groups, secrets []string
			for _, g := range sig.Groups {
				groups = append(groups, fmt.Sprintf("%s×%d secret %v", g.Subject, g.Count, g.Secret))
			}
			for _, st := range sig.Secrets {
				secrets = append(secrets, fmt.Sprintf("%s refused %d allowed %d", st.Path, st.Refused, st.Allowed))
			}
			if want := []string{tc.key + "×1 secret true"}; !slices.Equal(groups, want) || sig.RealLines != 1 {
				t.Errorf("refusal groups %q, real lines %d; want %q and 1", groups, sig.RealLines, want)
			}
			if want := []string{tc.key + " refused 1 allowed 0"}; !slices.Equal(secrets, want) {
				t.Errorf("secret touches %q, want %q", secrets, want)
			}

			// The timeline.
			tl := TimelineOf(r, false)
			rows := tl.Rows(0, tl.Len())
			refused := slices.DeleteFunc(slices.Clone(rows), func(row Row) bool { return !row.Refused() })
			if len(rows) != tc.lines-1 || slices.ContainsFunc(rows, isMirror) || rowsText(refused) != once {
				t.Errorf("timeline %s, refused %s; want %d rows without line %d, the read's once", rowsText(rows), rowsText(refused),
					tc.lines-1, tc.mirror)
			}
			if only := TimelineOf(r, true); rowsText(only.Rows(0, only.Len())) != once {
				t.Errorf("refusals-only timeline %s, want %s", rowsText(only.Rows(0, only.Len())), once)
			}

			// Logs.
			all := s.Query(Filter{Facets: true})
			if all.Matched != tc.lines-1 || all.Counts["refused"] != 1 || slices.ContainsFunc(all.Rows, isMirror) {
				t.Errorf("Logs: %d lines, %d refused, rows %s; want %d lines, 1 refused, no line %d", all.Matched,
					all.Counts["refused"], rowsText(all.Rows), tc.lines-1, tc.mirror)
			}
			if i := slices.IndexFunc(all.Facets.Verdict.Values, func(v FacetValue) bool { return v.Value == "refused" }); i < 0 ||
				all.Facets.Verdict.Values[i].Count != 1 {
				t.Errorf("Logs' Verdict facet %v, want refused 1", all.Facets.Verdict.Values)
			}
			for q, want := range map[string]string{
				"verdict:refused":          once,
				"path:" + path.Dir(tc.key): once,
				"kind:refused":             fmt.Sprintf("[%d×1]", tc.mirror),
			} {
				f, _, err := ParseQuery(q)
				if err != nil {
					t.Fatal(err)
				}
				if pg := s.Query(f); pg.Matched != 1 || rowsText(pg.Rows) != want {
					t.Errorf("Logs %q: %d lines, rows %s; want %s", q, pg.Matched, rowsText(pg.Rows), want)
				}
			}

			// The line page.
			lv, err := Explain(root, r, tc.action)
			if err != nil {
				t.Fatal(err)
			}
			mech := Field{}
			if i := slices.IndexFunc(lv.Fields, func(f Field) bool { return f.Key == "mechanism" }); i >= 0 {
				mech = lv.Fields[i]
			}
			if mech.Label != "Refused by" || mech.Value != "the kernel's Landlock rules" {
				t.Errorf("the read's mechanism: %q %q, want Refused by the kernel's Landlock rules", mech.Label, mech.Value)
			}
			if seqText(lv.MirroredBy) != fmt.Sprint(tc.mirror) || !strings.Contains(lv.Sentence, "tried to read "+tc.key) {
				t.Errorf("the read's line page: mirrored by %s, %q; want line %d, a refused read of %s", seqText(lv.MirroredBy),
					lv.Sentence, tc.mirror, tc.key)
			}
			mv, err := Explain(root, r, tc.mirror)
			if err != nil {
				t.Fatal(err)
			}
			if seqText(mv.MirrorOf) != fmt.Sprint(tc.action) {
				t.Errorf("the mirror's line page mirrors line %s, want %d", seqText(mv.MirrorOf), tc.action)
			}
		})
	}
}
