// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pair is a record and the bound receipt `tego receipt --json` made from it, as files.
type pair struct {
	dir, receipt string
}

// boundPair writes lines as a record and its bound receipt beside it.
func boundPair(t *testing.T, lines []line) pair {
	t.Helper()
	r := ledgerOf(t, lines)
	return pair{dir: r.Dir(), receipt: receiptOf(t, r.Dir(), testBy)}
}

// fixturePair copies a frozen fixture record into a folder and makes its bound receipt.
func fixturePair(t *testing.T, name string) pair {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return pair{dir: dir, receipt: receiptOf(t, dir, testBy)}
}

// receiptOf makes the record in dir's bound receipt (receiptAt with no clock).
func receiptOf(t *testing.T, dir string, by MadeBy) string {
	t.Helper()
	return receiptAt(t, dir, by, 0)
}

// receiptAt makes the record in dir's bound receipt as `tego receipt --json` makes it (newer lines skipped, a price
// table and the clock in play), written to a file beside the test's other files.
func receiptAt(t *testing.T, dir string, by MadeBy, nowMono uint64) string {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	rc, err := Compute(context.Background(), r, Options{Bind: &by, Prices: flatPrices{}, Home: "/home/u", NowMonoNS: nowMono})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := rc.JSON(&buf); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// editReceipt rewrites the receipt file through edit, on its decoded form.
func editReceipt(t *testing.T, path string, edit func(m map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func obj(m map[string]any, key string) map[string]any { return m[key].(map[string]any) }

// checked runs the check and returns its result, failing the test when the words overclaim.
func checked(t *testing.T, p pair, by MadeBy) *CheckResult {
	t.Helper()
	res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: by})
	var text, js bytes.Buffer
	if err := res.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := res.JSON(&js); err != nil {
		t.Fatal(err)
	}
	if overclaims(text.String()) || overclaims(js.String()) {
		t.Errorf("the check's words overclaim:\n%s\n%s", text.String(), js.String())
	}
	return res
}

// step is the result of the check named name.
func step(res *CheckResult, name string) CheckStep {
	for _, s := range res.Checks {
		if s.Name == name {
			return s
		}
	}
	return CheckStep{}
}

func wantResult(t *testing.T, res *CheckResult, result string, exit int) {
	t.Helper()
	if res.Result != result || res.ExitCode() != exit {
		var b bytes.Buffer
		_ = res.Text(&b)
		t.Fatalf("result %s exit %d, want %s exit %d\n%s", res.Result, res.ExitCode(), result, exit, b.String())
	}
}

// TestCheckMatchesARealRecordedFixture is the happy path on a record the real Writer wrote: every check passes, the
// result is match, exit 0, and the text says what it does not show.
func TestCheckMatchesARealRecordedFixture(t *testing.T) {
	for _, name := range []string{"run-fixture.jsonl", "reason-reads.jsonl", "held-reads.jsonl", "live-control.jsonl"} {
		t.Run(name, func(t *testing.T) {
			p := fixturePair(t, name)
			res := checked(t, p, testBy)
			wantResult(t, res, CheckMatch, identity.ExitOK)
			for _, s := range res.Checks {
				if s.Result != StepPass {
					t.Errorf("check %s: %s (%s)", s.Name, s.Result, s.Why)
				}
			}
			var b bytes.Buffer
			_ = res.Text(&b)
			for _, want := range []string{"The receipt matches the record: run ", "no chain.log was read",
				"This does not show that the record is complete"} {
				if !strings.Contains(b.String(), want) {
					t.Errorf("the text lacks %q:\n%s", want, b.String())
				}
			}
		})
	}
}

// TestCheckEditedPathWithReceiptByChangedCannotCheck is the check's M1: a receipt whose path or host was edited and
// whose receipt_by now names another tego cannot be checked by this one (exit 125), never a pass; the same edit with
// receipt_by kept is a mismatch naming the field.
func TestCheckEditedPathWithReceiptByChangedCannotCheck(t *testing.T) {
	edits := map[string]func(m map[string]any){
		"a refused path": func(m map[string]any) {
			obj(m, "refusals")["list"].([]any)[0].(map[string]any)["target"] = "/home/u/notes.txt"
		},
		"a host": func(m map[string]any) {
			m["connections"].([]any)[0].(map[string]any)["destination"] = "example.org (93.184.216.34:443)"
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			p := boundPair(t, boundRun())
			editReceipt(t, p.receipt, func(m map[string]any) {
				edit(m)
				obj(obj(m, "binding"), "receipt_by")["tego_version"] = "v0.0.9"
			})
			res := checked(t, p, testBy)
			wantResult(t, res, CheckCannot, identity.ExitError)
			if s := step(res, "facts"); s.Result != StepNotChecked || !strings.Contains(s.Why, "v0.0.9") {
				t.Errorf("facts: %+v", s)
			}

			p = boundPair(t, boundRun())
			editReceipt(t, p.receipt, edit)
			res = checked(t, p, testBy)
			wantResult(t, res, CheckMismatch, identity.ExitFinding)
			if s := step(res, "facts"); s.Result != StepFail {
				t.Errorf("facts: %+v", s)
			}
		})
	}
}

// TestCheckUnknownBuildCannotCheck (S6): a development build with no commit cannot say it computes as the receipt's
// tego did, even when the two name the same unknown build.
func TestCheckUnknownBuildCannotCheck(t *testing.T) {
	dev := MadeBy{TegoVersion: "dev", Commit: "none"}
	r := ledgerOf(t, boundRun())
	p := pair{dir: r.Dir(), receipt: receiptOf(t, r.Dir(), dev)}
	wantResult(t, checked(t, p, dev), CheckCannot, identity.ExitError)
	dirty := MadeBy{TegoVersion: "v0.1.2+dirty", Commit: testBy.Commit}
	p = pair{dir: r.Dir(), receipt: receiptOf(t, r.Dir(), dirty)}
	wantResult(t, checked(t, p, dirty), CheckCannot, identity.ExitError)
}

// TestCheckReceiptNamingNoBuildSaysSo (receiptbind review 4 S1): a receipt whose binding.receipt_by is missing, null or
// empty, or whose tego_version or commit is "", could not be checked (exit 125) with blank words: "the receipt was made
// by tego  (commit ) ... rerun the check with tego ". It still cannot be checked, never a match, and the words name
// what the receipt lacks; a receipt made by a build that is no exact one (+dirty, commit none) says so, not "rerun the
// check with tego v0.1.2+dirty".
func TestCheckReceiptNamingNoBuildSaysSo(t *testing.T) {
	const (
		neither   = "binding.receipt_by names no tego_version and no commit"
		noVersion = "binding.receipt_by names no tego_version"
		noCommit  = "binding.receipt_by names no commit"
	)
	by := func(m map[string]any) map[string]any { return obj(obj(m, "binding"), "receipt_by") }
	for name, c := range map[string]struct {
		edit func(m map[string]any)
		want string
	}{
		"removed":              {func(m map[string]any) { delete(obj(m, "binding"), "receipt_by") }, neither},
		"null":                 {func(m map[string]any) { obj(m, "binding")["receipt_by"] = nil }, neither},
		"emptied":              {func(m map[string]any) { obj(m, "binding")["receipt_by"] = map[string]any{} }, neither},
		"empty tego_version":   {func(m map[string]any) { by(m)["tego_version"] = "" }, noVersion},
		"tego_version removed": {func(m map[string]any) { delete(by(m), "tego_version") }, noVersion},
		"empty commit":         {func(m map[string]any) { by(m)["commit"] = "" }, noCommit},
		"commit null":          {func(m map[string]any) { by(m)["commit"] = nil }, noCommit},
		"blank tego_version":   {func(m map[string]any) { by(m)["tego_version"] = " " }, noVersion},
		"blank commit":         {func(m map[string]any) { by(m)["commit"] = "\t " }, noCommit},
		"dirty":                {func(m map[string]any) { by(m)["tego_version"] = "v0.1.2+dirty" }, "which is no exact build"},
		"commit none":          {func(m map[string]any) { by(m)["commit"] = "none" }, "tego v0.1.2 (commit none), which is no exact build"},
	} {
		t.Run(name, func(t *testing.T) {
			p := boundPair(t, boundRun())
			editReceipt(t, p.receipt, c.edit)
			res := checked(t, p, testBy)
			wantResult(t, res, CheckCannot, identity.ExitError)
			mb, facts := step(res, "made_by"), step(res, "facts")
			if mb.Result != StepNotChecked || !strings.Contains(mb.Why, c.want) || !strings.Contains(facts.Why, c.want) {
				t.Errorf("made_by %+v, facts %+v; want both to say %q", mb, facts, c.want)
			}
			for _, blank := range []string{"tego  ", "(commit )", "(commit \t )", "with tego ;", "rerun the check with tego"} {
				if strings.Contains(mb.Why, blank) {
					t.Errorf("made_by says %q: %s", blank, mb.Why)
				}
			}
		})
	}
	// A receipt of another exact build still names it, to rerun the check with.
	p := boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) { obj(obj(m, "binding"), "receipt_by")["tego_version"] = "v0.1.9" })
	res := checked(t, p, testBy)
	wantResult(t, res, CheckCannot, identity.ExitError)
	if mb := step(res, "made_by"); !strings.Contains(mb.Why, "rerun the check with tego v0.1.9") {
		t.Errorf("made_by %+v", mb)
	}
}

// TestCheckFindsAnAddedKey (M2): a key the record's own receipt does not have is a mismatch.
func TestCheckFindsAnAddedKey(t *testing.T) {
	for _, edit := range []func(m map[string]any){
		func(m map[string]any) { m["verified"] = true },
		func(m map[string]any) { obj(m, "binding")["note"] = "checked by the CI job" },
	} {
		p := boundPair(t, boundRun())
		editReceipt(t, p.receipt, edit)
		res := checked(t, p, testBy)
		wantResult(t, res, CheckMismatch, identity.ExitFinding)
		if s := step(res, "facts"); s.Result != StepFail || !strings.Contains(s.Why, "not in the record's receipt") {
			t.Errorf("facts: %+v", s)
		}
	}
}

// TestCheckRefusesADuplicateKey (M2): a second refusals object, which one JSON reader keeps and another drops, is a
// mismatch however the rest reads.
func TestCheckRefusesADuplicateKey(t *testing.T) {
	p := boundPair(t, boundRun())
	data, err := os.ReadFile(p.receipt)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.Replace(data, []byte(`"refusals": {`), []byte(`"refusals": {"total": 0, "by_rule": [], "list": []}, "refusals": {`), 1)
	if err := os.WriteFile(p.receipt, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "receipt"); s.Result != StepFail || !strings.Contains(s.Why, "refusals") {
		t.Errorf("receipt: %+v", s)
	}
}

// TestCheckFindsAnEditedReceiptNumber: a number edited with the binding kept is a mismatch naming the field.
func TestCheckFindsAnEditedReceiptNumber(t *testing.T) {
	p := boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) { obj(m, "refusals")["total"] = 0 })
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "facts"); !strings.Contains(s.Why, "refusals.total: receipt 0, record 1") {
		t.Errorf("facts: %+v", s)
	}
}

// TestCheckFindsAnEditedLine: a record edited after its receipt was made breaks the chain at that line.
func TestCheckFindsAnEditedLine(t *testing.T) {
	p := boundPair(t, boundRun())
	path := filepath.Join(p.dir, ledger.EventsFile)
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(data, []byte("/home/u/.bashrc"), []byte("/home/u/.zshrc_"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "chain"); s.Result != StepFail || !strings.Contains(s.Why, "line 2") {
		t.Errorf("chain: %+v", s)
	}
}

// TestCheckTruncatedRecordWithARecomputedReceipt is the cheap forgery: cut the record at a line boundary and make a
// new receipt from it. The pair matches itself, so it gets its own result, match-unended, and a first line saying
// there is no run_end; the original receipt against the cut record is a mismatch.
func TestCheckTruncatedRecordWithARecomputedReceipt(t *testing.T) {
	p := boundPair(t, boundRun())
	original := p.receipt
	dropLast(t, filepath.Join(p.dir, ledger.EventsFile))

	res := checked(t, pair{dir: p.dir, receipt: original}, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)

	p.receipt = receiptOf(t, p.dir, testBy)
	res = checked(t, p, testBy)
	wantResult(t, res, CheckMatchUnended, identity.ExitOK)
	var b bytes.Buffer
	_ = res.Text(&b)
	if first, _, _ := strings.Cut(b.String(), "\n"); !strings.HasPrefix(first, "The record has no run_end") {
		t.Errorf("first line %q", first)
	}
	if res.Ended {
		t.Error("an unended pair says ended")
	}
}

// TestCheckLiveReceiptAgainstALongerRecord: a receipt made while the run was live does not match the record the run
// went on to write.
func TestCheckLiveReceiptAgainstALongerRecord(t *testing.T) {
	lines := boundRun()
	short := ledgerOf(t, lines[:len(lines)-1])
	receipt := receiptOf(t, short.Dir(), testBy)
	long := ledgerOf(t, lines)
	res := checked(t, pair{dir: long.Dir(), receipt: receipt}, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
}

// TestCheckLiveReceiptMatchesItsRecord (S5): a receipt made while the run was live measures its time, its quiet tail
// and its per-minute refusals to the clock of that moment; the check computes the receipt again at the reading its
// time taken stands for, so the pair matches itself rather than failing on the clock.
func TestCheckLiveReceiptMatchesItsRecord(t *testing.T) {
	lines := boundRun()
	r := ledgerOf(t, lines[:len(lines)-1])
	p := pair{dir: r.Dir(), receipt: receiptAt(t, r.Dir(), testBy, t0+uint64(17*time.Minute))}
	wantResult(t, checked(t, p, testBy), CheckMatchUnended, identity.ExitOK)
}

// TestCheckLimitsAreTheRecords: the limits a check prints come from the record's tier, not the receipt's word, even
// when it cannot compare the numbers.
func TestCheckLimitsAreTheRecords(t *testing.T) {
	lines := boundRun()
	lines[0] = watchedStart()
	p := boundPair(t, lines)
	editReceipt(t, p.receipt, func(m map[string]any) {
		m["tier"] = "landlock"
		obj(obj(m, "binding"), "receipt_by")["tego_version"] = "v0.0.9"
	})
	res := checked(t, p, testBy)
	wantResult(t, res, CheckCannot, identity.ExitError)
	found := false
	for _, l := range res.Limits {
		found = found || l.Code == LimitRecordOnly
	}
	if !found {
		t.Errorf("limits %+v, want record-only for a watched record", res.Limits)
	}
}

// TestCheckFindsARecordOfAnotherRun: a receipt checked against another run's record fails the run check.
func TestCheckFindsARecordOfAnotherRun(t *testing.T) {
	a := fixturePair(t, "run-fixture.jsonl")
	b := fixturePair(t, "reason-reads.jsonl")
	res := checked(t, pair{dir: b.dir, receipt: a.receipt}, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "run"); s.Result != StepFail {
		t.Errorf("run: %+v", s)
	}
}

// TestCheckFindsAChangedTornTail: bytes the chain does not cover (a torn last line) are still bound by the sha256, so
// changing them is a mismatch of the bytes check alone.
func TestCheckFindsAChangedTornTail(t *testing.T) {
	r := ledgerOf(t, boundRun()[:4])
	path := filepath.Join(r.Dir(), ledger.EventsFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"v":1,"seq":4,"id":"ab`)
	_ = f.Close()
	p := pair{dir: r.Dir(), receipt: receiptOf(t, r.Dir(), testBy)}
	wantResult(t, checked(t, p, testBy), CheckMatchUnended, identity.ExitOK)

	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(data, []byte(`"id":"ab`), []byte(`"id":"cd`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "bytes"); s.Result != StepFail {
		t.Errorf("bytes: %+v", s)
	}
	if s := step(res, "chain"); s.Result != StepPass {
		t.Errorf("chain: %+v", s)
	}
}

// TestCheckOlderReceiptCannotCheck: a receipt with no binding (an older tego, or one made without --json) and one of
// a binding version this tego does not read cannot be checked; a receipt whose binding says its record did not bind is
// a finding.
func TestCheckOlderReceiptCannotCheck(t *testing.T) {
	p := boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) { delete(m, "binding") })
	res := checked(t, p, testBy)
	wantResult(t, res, CheckCannot, identity.ExitError)
	if s := step(res, "receipt"); s.Result != StepNotChecked || !strings.Contains(s.Why, "no binding") {
		t.Errorf("receipt: %+v", s)
	}

	p = boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) { obj(m, "binding")["v"] = 2 })
	wantResult(t, checked(t, p, testBy), CheckCannot, identity.ExitError)

	p = boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) {
		b := obj(m, "binding")
		delete(b, "chain")
		b["error"] = "line 2: id does not match"
	})
	wantResult(t, checked(t, p, testBy), CheckMismatch, identity.ExitFinding)
}

// TestCheckUnreadableInputCannotCheck: a receipt that is not JSON, or no record at the path, is exit 125.
func TestCheckUnreadableInputCannotCheck(t *testing.T) {
	p := boundPair(t, boundRun())
	if err := os.WriteFile(p.receipt, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantResult(t, checked(t, p, testBy), CheckCannot, identity.ExitError)

	p = boundPair(t, boundRun())
	p.dir = filepath.Join(t.TempDir(), "nothing-here")
	wantResult(t, checked(t, p, testBy), CheckCannot, identity.ExitError)
}

// TestCheckJSONShape: the --json form is one object with check_v 1, the result, each check, the limits and what the
// check does not show.
func TestCheckJSONShape(t *testing.T) {
	res := checked(t, boundPair(t, boundRun()), testBy)
	var b bytes.Buffer
	if err := res.JSON(&b); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"check_v", "result", "run", "lines", "head", "ended", "checks", "limits", "not_shown", "checked_by"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %q in %s", k, b.String())
		}
	}
	if m["result"] != CheckMatch || m["check_v"] != float64(1) {
		t.Errorf("result %v check_v %v", m["result"], m["check_v"])
	}
}

// dropLast truncates the file at path at the start of its final line.
func dropLast(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.LastIndexByte(bytes.TrimSuffix(b, []byte("\n")), '\n')
	if err := os.WriteFile(path, b[:i+1], 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCheckFindsAnEditPastALongStringsStart: facts compares every value whole, so a refused path longer than the line
// its message prints, edited past that point, is a mismatch naming the field, never a match.
func TestCheckFindsAnEditPastALongStringsStart(t *testing.T) {
	dir := "/home/u/" + strings.Repeat("a", 80)
	lines := boundRun()
	lines[2].payload = record.FSPayload{Op: record.FSOpen, Path: dir + "/.aws/credentials", Flags: 0o1101}
	p := boundPair(t, lines)
	editReceipt(t, p.receipt, func(m map[string]any) {
		obj(m, "refusals")["list"].([]any)[0].(map[string]any)["target"] = dir + "/notes.txt"
	})
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "facts"); s.Result != StepFail || !strings.HasPrefix(s.Why, "refusals.list[0].target: ") ||
		!strings.HasSuffix(s.Why, "(they differ from byte 91 of their JSON)") {
		t.Errorf("facts: %+v", s)
	}
}

// TestCheckHoldsCompleteToTheGaps: coverage.complete is compared with the record's like every value, so complete set
// to true on a receipt that lists a gap is a mismatch on facts naming the key.
func TestCheckHoldsCompleteToTheGaps(t *testing.T) {
	p := boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) {
		c := obj(m, "coverage")
		if gaps, _ := c["gaps"].([]any); len(gaps) == 0 {
			t.Fatalf("the run's receipt lists no gap: %v", c)
		}
		c["complete"] = true
	})
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "facts"); s.Result != StepFail || !strings.Contains(s.Why, "coverage.complete: receipt true, record false") {
		t.Errorf("facts: %+v", s)
	}
}

// TestCheckUnreadRecordSaysSo: with no events.jsonl the check never read the record, so facts says the record could
// not be read, not that its chain does not hold.
func TestCheckUnreadRecordSaysSo(t *testing.T) {
	p := boundPair(t, boundRun())
	if err := os.Remove(filepath.Join(p.dir, ledger.EventsFile)); err != nil {
		t.Fatal(err)
	}
	res := checked(t, p, testBy)
	wantResult(t, res, CheckCannot, identity.ExitError)
	if s := step(res, "facts"); s.Result != StepNotChecked || !strings.HasPrefix(s.Why, "the record could not be read") ||
		strings.Contains(s.Why, "chain") {
		t.Errorf("facts: %+v", s)
	}
}

// BenchmarkComputeWithBind is what binding costs `tego receipt --json`: one pass over a 20,002-line record, unbound and
// bound (each line also checked as Verify checks it and hashed).
func BenchmarkComputeWithBind(b *testing.B) {
	lines := []line{start("off", true)}
	for i := 0; i < 20_000; i++ {
		lines = append(lines, line{kind: record.KindFS, at: time.Duration(i) * time.Millisecond, verdict: record.VerdictAllow,
			rule: "fs.write[./out/]", payload: record.FSPayload{Op: record.FSOpen,
				Path: "/p/out/" + strings.Repeat("x", i%40) + ".txt", Flags: 0o1101}})
	}
	lines = append(lines, end(30*time.Second, 0))
	dir := ledgerOf(b, lines).Dir()
	for _, bc := range []struct {
		name string
		bind *MadeBy
	}{{"unbound", nil}, {"bound", &testBy}} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r, err := ledger.OpenReader(dir)
				if err != nil {
					b.Fatal(err)
				}
				r.SkipNewerVersions()
				if _, err := Compute(context.Background(), r, Options{Bind: bc.bind}); err != nil {
					b.Fatal(err)
				}
				_ = r.Close()
			}
		})
	}
}

// TestCheckHeadComparesTheWholeHead: the head check compares the receipt's head whole, not the 12 characters it
// prints, so a head edited in its last character fails the head check as well as the chain.
func TestCheckHeadComparesTheWholeHead(t *testing.T) {
	p := boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) {
		c := obj(obj(m, "binding"), "chain")
		h := c["head"].(string)
		last := byte('0')
		if h[len(h)-1] == '0' {
			last = '1'
		}
		c["head"] = h[:len(h)-1] + string(last)
	})
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	if s := step(res, "head"); s.Result != StepFail || !strings.Contains(s.Why, "head: record ") {
		t.Errorf("head: %+v", s)
	}
}
