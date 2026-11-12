// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// CheckVersion is the check's JSON version (check_v). Keys only grow within it.
const CheckVersion = 1

// MaxReceiptBytes bounds the receipt file a check reads: a receipt is bytes anyone can hand it.
const MaxReceiptBytes = 64 << 20

// maxReceiptDepth bounds how deep the receipt's JSON nests: the receipt's own is four deep.
const maxReceiptDepth = 64

// The check's results.
const (
	// CheckMatch: every check passed, and the record ends in run_end.
	CheckMatch = "match"
	// CheckMatchUnended: every check passed, and the record has no run_end: the run had not ended, or lost its end. A
	// record cut at a line boundary with a receipt made again from it is this, so a caller that wants a whole run
	// refuses it.
	CheckMatchUnended = "match-unended"
	// CheckMismatch: a check failed.
	CheckMismatch = "mismatch"
	// CheckCannot: a check that must run could not, and none failed.
	CheckCannot = "cannot-check"
)

// The result of one check.
const (
	StepPass       = "pass"
	StepFail       = "fail"
	StepNotChecked = "not-checked"
)

// notShown is what a match does not show, as codes (CheckResult.NotShown).
var notShown = []string{"complete", "honest-host", "who", "when", "expected-job"}

// CheckInput is what Check compares: a receipt file and the record it names, a run folder under any name or its
// events.jsonl, and the tego checking (By), whose build must be the receipt's for the numbers to be compared.
type CheckInput struct {
	Receipt string
	Record  string
	By      MadeBy
}

// CheckStep is one check: its name, pass, fail or not-checked, and why.
type CheckStep struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Why    string `json:"why,omitempty"`
}

// CheckResult is what `tego receipt --check` found. Run, Lines, Head and Ended are the record's, as this check read
// it.
type CheckResult struct {
	V         int         `json:"check_v"`
	Result    string      `json:"result"`
	Run       string      `json:"run"`
	Lines     uint64      `json:"lines"`
	Head      string      `json:"head"`
	Ended     bool        `json:"ended"`
	Checks    []CheckStep `json:"checks"`
	Limits    []Limit     `json:"limits"`
	NotShown  []string    `json:"not_shown"`
	ReceiptBy *MadeBy     `json:"receipt_by,omitempty"`
	CheckedBy MadeBy      `json:"checked_by"`
	// NotCompared names the receipt's values facts took as given rather than compared, once each was what this tego
	// writes for the record: what only the price table or clock of the machine that made the receipt gives. [] when
	// facts compared every value, null when facts compared nothing.
	NotCompared []string `json:"not_compared"`
}

// ExitCode is the check's exit: 0 for a match (ended or not), 1 for a mismatch, 125 when it could not check.
func (c *CheckResult) ExitCode() int {
	switch c.Result {
	case CheckMatch, CheckMatchUnended:
		return identity.ExitOK
	case CheckMismatch:
		return identity.ExitFinding
	}
	return identity.ExitError
}

// boundReceipt is the part of a receipt the check reads by name.
type boundReceipt struct {
	V       *int   `json:"receipt_v"`
	Run     string `json:"run"`
	Tier    string `json:"tier"`
	Binding *struct {
		V         int         `json:"v"`
		Chain     *BoundChain `json:"chain"`
		ReceiptBy MadeBy      `json:"receipt_by"`
		Error     string      `json:"error"`
	} `json:"binding"`
}

// checker holds one check's state.
type checker struct {
	in    CheckInput
	res   *CheckResult
	dir   string
	given map[string]any
	rc    boundReceipt
	chain *BoundChain
	// madeByWhy is why made_by did not pass, which facts repeats.
	madeByWhy string
	// unread is why the record could not be read, which facts repeats; "" when it was read.
	unread string
}

func (k *checker) step(name, result, why string) {
	k.res.Checks = append(k.res.Checks, CheckStep{Name: name, Result: result, Why: why})
}

// Check compares a receipt with a record, from the two files alone: it never reads chain.log, and it puts the
// receipt's head where chain.log's would stand. In order:
//   - receipt: the file is one JSON object with no duplicate key, receipt_v 1 and a binding this tego reads, with no
//     error;
//   - made_by: the receipt's tego (binding.receipt_by) is this one, an exact build; else the numbers cannot be
//     compared, and the check cannot say they match;
//   - run: the record is the run the receipt names;
//   - chain: the record's hash chain holds, as `tego events --verify` walks it, and ends at the receipt's head;
//   - head: the record's line count, head, end, torn tail and newer lines are the receipt's;
//   - bytes: events.jsonl is the receipt's byte count and sha256;
//   - facts: the receipt computed again from the record is the receipt given, the whole of it, but for the values only
//     the maker's price table and clock give, each held to what this tego writes (NotCompared).
//
// A failed check makes the result a mismatch; otherwise one that did not run makes it cannot-check. It never says
// match when a check that must run did not.
func Check(ctx context.Context, in CheckInput) *CheckResult {
	k := &checker{in: in, res: &CheckResult{V: CheckVersion, Checks: []CheckStep{}, NotShown: notShown,
		CheckedBy: in.By}, dir: recordDir(in.Record)}
	k.run(ctx)
	k.res.Result = verdict(k.res.Checks, k.res.Ended)
	return k.res
}

func (k *checker) run(ctx context.Context) {
	names := []string{"made_by", "run", "chain", "head", "bytes", "facts"}
	if !k.receipt() {
		k.res.Limits = limitsFor("")
		for _, n := range names {
			k.step(n, StepNotChecked, "the receipt binds no record to check")
		}
		return
	}
	k.res.Limits = limitsFor(k.rc.Tier)
	sameBuild := k.madeBy()
	chained := k.chainChecks(ctx)
	k.bytesCheck()
	k.facts(ctx, sameBuild, chained)
}

// recordDir is the run folder path names: its parent for events.jsonl itself, so the run is named by the folder, as
// `tego events --verify` names it, never by the file.
func recordDir(path string) string {
	if filepath.Base(path) == ledger.EventsFile {
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			return filepath.Dir(path)
		}
	}
	return path
}

// receipt is the receipt check: read, strictly decoded, and its binding read.
func (k *checker) receipt() bool {
	data, err := readReceipt(k.in.Receipt)
	if err != nil {
		k.step("receipt", StepNotChecked, err.Error())
		return false
	}
	if err := strictJSON(data); err != nil {
		var dup *duplicateKeyError
		if errors.As(err, &dup) {
			k.step("receipt", StepFail, err.Error())
		} else {
			k.step("receipt", StepNotChecked, "the receipt is not one JSON object: "+err.Error())
		}
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&k.given); err != nil || k.given == nil {
		k.step("receipt", StepNotChecked, "the receipt is not one JSON object")
		return false
	}
	if err := json.Unmarshal(data, &k.rc); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" && k.boundShape() {
			k.step("receipt", StepFail, fmt.Sprintf("%s: receipt %s, which no receipt_v %d receipt with a binding of v %d "+
				"has there", te.Field, k.givenAt(te.Field, te.Value), Version, BindingVersion))
			return false
		}
		k.step("receipt", StepNotChecked, "the receipt does not read as a receipt: "+err.Error())
		return false
	}
	b := k.rc.Binding
	switch {
	case k.rc.V == nil || *k.rc.V != Version:
		k.step("receipt", StepNotChecked, fmt.Sprintf("this tego reads receipt_v %d, and the file has no such receipt_v", Version))
		return false
	case b == nil:
		k.step("receipt", StepNotChecked, "the receipt has no binding: a tego from before receipts were bound made it, "+
			"or it was made without --json; make it again with tego receipt --json")
		return false
	case b.V != BindingVersion:
		k.step("receipt", StepNotChecked, fmt.Sprintf("binding v %d: this tego reads binding v %d", b.V, BindingVersion))
		return false
	case b.Error != "":
		k.step("receipt", StepFail, "the receipt says its own record did not hold together: "+b.Error)
		return false
	case b.Chain == nil:
		k.step("receipt", StepFail, "the binding names no record")
		return false
	}
	k.chain = b.Chain
	by := b.ReceiptBy
	k.res.ReceiptBy = &by
	k.step("receipt", StepPass, "")
	return true
}

// boundShape reports whether the receipt given says it is receipt_v 1 with a binding of v 1 (each written 1), or
// receipt_v 1 with a binding that is no object: the shape of every bound field is then fixed, so a field of another type
// is an edit, not a receipt this tego does not read.
func (k *checker) boundShape() bool {
	if n, ok := k.given["receipt_v"].(json.Number); !ok || n.String() != strconv.Itoa(Version) {
		return false
	}
	switch b := k.given["binding"].(type) {
	case map[string]any:
		n, ok := b["v"].(json.Number)
		return ok && n.String() == strconv.Itoa(BindingVersion)
	case nil:
		return false
	}
	return true
}

// givenAt is the receipt given's value at path (keys joined by "."), as a message prints it, or what if there is none.
func (k *checker) givenAt(path, what string) string {
	var v any = k.given
	for _, key := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return what
		}
		if v, ok = m[key]; !ok {
			return what
		}
	}
	return brief(v)
}

// readReceipt reads the receipt file: a regular file of at most MaxReceiptBytes.
func readReceipt(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("the receipt: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("the receipt: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("the receipt %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxReceiptBytes+1))
	if err != nil {
		return nil, fmt.Errorf("the receipt: %w", err)
	}
	if len(data) > MaxReceiptBytes {
		return nil, fmt.Errorf("the receipt %s is longer than %d bytes", path, MaxReceiptBytes)
	}
	return data, nil
}

// madeBy is the made_by check: whether this tego is the exact build that made the receipt. A receipt that names no
// build, or one that is no exact build, cannot be checked by any tego, so its words name what it lacks rather than a
// tego to rerun with: review 4 S1 printed "made by tego  (commit ) ... rerun the check with tego " for a receipt_by
// that was missing, null or empty. A field of only spaces names nothing either (review 1 S3 printed "made by tego   ...
// rerun the check with tego  " for one). Each is still could-not-check, never a pass.
func (k *checker) madeBy() bool {
	by, mine := k.rc.Binding.ReceiptBy, k.in.By
	var missing []string
	if strings.TrimSpace(by.TegoVersion) == "" {
		missing = append(missing, "no tego_version")
	}
	if strings.TrimSpace(by.Commit) == "" {
		missing = append(missing, "no commit")
	}
	switch {
	case !mine.Exact():
		k.madeByWhy = fmt.Sprintf("this tego (%s, commit %s) is no exact build, so it cannot say it computes the "+
			"receipt as the tego that made it did; check with a released tego", mine.TegoVersion, mine.Commit)
	case len(missing) > 0:
		k.madeByWhy = "the receipt names no tego build: binding.receipt_by names " + strings.Join(missing, " and ") +
			", so no tego can say it computes the receipt as the one that made it did; make the receipt again with " +
			"tego receipt --json"
	case !by.Exact():
		k.madeByWhy = fmt.Sprintf("the receipt was made by tego %s (commit %s), which is no exact build, so no tego can "+
			"say it computes the receipt as that one did; make the receipt again with a released tego", by.TegoVersion, by.Commit)
	case by != mine:
		k.madeByWhy = fmt.Sprintf("the receipt was made by tego %s (commit %s) and this is tego %s (commit %s); rerun "+
			"the check with tego %s", by.TegoVersion, by.Commit, mine.TegoVersion, mine.Commit, by.TegoVersion)
	default:
		k.step("made_by", StepPass, "")
		return true
	}
	k.step("made_by", StepNotChecked, k.madeByWhy)
	return false
}

// receiptAnchor is the receipt standing where chain.log stands: the head it binds for its run, and no line for any
// other.
type receiptAnchor struct{ run, head string }

func (a receiptAnchor) Append(string, string) error {
	return errors.New("receipt: a receipt's binding is read, never appended to")
}

func (a receiptAnchor) Head(run string) (string, bool, error) {
	if run == a.run {
		return a.head, true, nil
	}
	return "", false, nil
}

// chainChecks are the run, chain and head checks: the record's chain walked as `tego events --verify` walks it, with
// the receipt as its anchor. It reports whether the chain held to the receipt's head.
func (k *checker) chainChecks(ctx context.Context) bool {
	c := k.chain
	rep, err := ledger.VerifyRunDir(ctx, k.dir, receiptAnchor{run: c.Run, head: c.Head})
	if err != nil && !errors.Is(err, ledger.ErrUnverified) {
		k.unread = "the record could not be read: " + err.Error()
		why := k.unread
		if errors.Is(err, os.ErrNotExist) {
			why = "no record at " + k.dir
			k.unread = "the record could not be read: " + why
		}
		for _, n := range []string{"run", "chain", "head"} {
			k.step(n, StepNotChecked, why)
		}
		return false
	}
	k.res.Run, k.res.Lines, k.res.Head, k.res.Ended = rep.Run, rep.Lines, rep.Head, rep.Ended
	if rep.Run != c.Run || k.rc.Run != c.Run {
		k.step("run", StepFail, fmt.Sprintf("the record is run %s and the receipt names run %s", rep.Run, c.Run))
	} else {
		k.step("run", StepPass, "")
	}
	brokeAtLine := err != nil && rep.AtLine
	switch {
	case err == nil:
		k.step("chain", StepPass, "")
	case !brokeAtLine && rep.Head != c.Head:
		k.step("chain", StepFail, fmt.Sprintf("the record ends at head %s after %d lines; the receipt binds head %s after %d",
			short(rep.Head), rep.Lines, short(c.Head), c.Lines))
	case errors.Is(err, ledger.ErrAnchorMissing):
		k.step("chain", StepFail, fmt.Sprintf("the record is run %s, which the receipt does not bind", rep.Run))
	default:
		k.step("chain", StepFail, strings.TrimPrefix(err.Error(), ledger.ErrUnverified.Error()+": "))
	}
	if brokeAtLine {
		k.step("head", StepNotChecked, fmt.Sprintf("the chain breaks at line %d", rep.BrokenLine))
		return false
	}
	var diffs []string
	add := func(what string, rec, rcpt any) {
		if rec != rcpt {
			diffs = append(diffs, fmt.Sprintf("%s: record %v, receipt %v", what, rec, rcpt))
		}
	}
	add("lines", rep.Lines, c.Lines)
	if rep.Head != c.Head { // compared whole, printed short
		diffs = append(diffs, fmt.Sprintf("head: record %s, receipt %s", short(rep.Head), short(c.Head)))
	}
	add("ended", rep.Ended, c.Ended)
	add("torn_bytes", rep.TornBytes, c.TornBytes)
	add("newer_lines", rep.Newer, c.NewerLines)
	if len(diffs) > 0 {
		k.step("head", StepFail, strings.Join(diffs, "; "))
		return false
	}
	k.step("head", StepPass, "")
	return err == nil
}

// bytesCheck is the bytes check: events.jsonl, opened as Verify opens it, is the receipt's size and sha256.
func (k *checker) bytesCheck() {
	f, err := ledger.OpenRegular(filepath.Join(k.dir, ledger.EventsFile))
	if err != nil {
		k.step("bytes", StepNotChecked, "the record could not be read: "+err.Error())
		return
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		k.step("bytes", StepNotChecked, "the record could not be read: "+err.Error())
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if n != k.chain.Bytes || sum != k.chain.SHA256 {
		k.step("bytes", StepFail, fmt.Sprintf("%s is %d bytes with sha256 %s; the receipt binds %d bytes with sha256 %s",
			ledger.EventsFile, n, short(sum), k.chain.Bytes, short(k.chain.SHA256)))
		return
	}
	k.step("bytes", StepPass, "")
}

// facts is the facts check: the receipt computed again from the record by this tego is the receipt given, the whole
// of it, every key and every value (types included) compared exactly. Only what this tego cannot compute again is
// taken from the receipt given, and only once it has the type and range this tego writes: the two numbers the price
// table of the machine that made the receipt gave (tokens.est_cost_usd and tokens.unpriced_responses), and for a record
// with no run_end the clock reading the receipt was made at (time_taken.seconds); the cost's text, its coverage gap,
// coverage.complete, the quiet tail and the per-minute padding are then made from them as Compute makes them and
// compared like the rest. The result names what was taken (NotCompared). It runs only when this tego is the exact build
// that made the receipt: another build may count differently, and comparing a few fields instead would pass a receipt
// whose other fields were edited.
func (k *checker) facts(ctx context.Context, sameBuild, chained bool) {
	rc, cerr := k.recompute(ctx, 0)
	if rc != nil {
		k.res.Limits = limitsFor(rc.Tier) // the record's tier, not the one the receipt claims
	}
	switch {
	case !sameBuild:
		k.step("facts", StepNotChecked, "the numbers are compared only by the tego that made the receipt: "+k.madeByWhy)
		return
	case k.unread != "":
		k.step("facts", StepNotChecked, k.unread)
		return
	case !chained:
		k.step("facts", StepNotChecked, "the chain and head checks did not both pass, so the record's numbers are not compared")
		return
	case cerr != nil:
		k.step("facts", StepNotChecked, "the receipt could not be computed from the record: "+cerr.Error())
		return
	}
	taken := []string{}
	if now := k.clockOf(rc); now != 0 {
		if rc, cerr = k.recompute(ctx, now); cerr != nil {
			k.step("facts", StepNotChecked, "the receipt could not be computed from the record: "+cerr.Error())
			return
		}
		taken = append(taken, "time_taken.seconds")
	}
	priced, why := k.reprice(rc)
	if why != "" {
		k.step("facts", StepFail, why)
		return
	}
	taken = append(append([]string{}, priced...), taken...)
	var buf bytes.Buffer
	if err := rc.JSON(&buf); err != nil {
		k.step("facts", StepNotChecked, err.Error())
		return
	}
	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	var want map[string]any
	if err := dec.Decode(&want); err != nil {
		k.step("facts", StepNotChecked, err.Error())
		return
	}
	k.res.NotCompared = taken
	if why := firstDiff("", k.given, want); why != "" {
		k.step("facts", StepFail, why)
		return
	}
	k.step("facts", StepPass, takenWords(taken))
}

// takenWords is what a facts pass says beside the pass: which values it took from the receipt without comparing them.
func takenWords(taken []string) string {
	if len(taken) == 0 {
		return "every key and value compared"
	}
	return "every key and value compared but " + strings.Join(taken, ", ") + ", which only the price table or clock of " +
		"the machine that made the receipt gives: each was held to what this tego writes for this record, and what " +
		"is made from it was compared"
}

// recompute is the record's receipt as this tego computes it, bound, with no price table, read at the clock reading
// now (0: none, as for a run that is not live).
func (k *checker) recompute(ctx context.Context, now uint64) (*Receipt, error) {
	r, err := ledger.OpenReader(k.dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	by := k.in.By
	return Compute(ctx, r, Options{Bind: &by, NowMonoNS: now})
}

// clockOf is the clock reading a receipt of a record with no run_end was made at, as its time_taken.seconds counts it
// from run_start (Compute's live run), or 0: for an ended record, a receipt measured to the record's last line, or a
// time_taken that is no reading after that line, whose compare then fails.
func (k *checker) clockOf(rc *Receipt) uint64 {
	if rc.Ended || rc.startMono == 0 {
		return 0
	}
	tt, _ := k.given["time_taken"].(map[string]any)
	n, ok := tt["seconds"].(json.Number)
	if !ok {
		return 0
	}
	s, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsNaN(s) || s <= rc.Time.Seconds || s >= float64(math.MaxInt64)/1e9 {
		return 0
	}
	// Seconds is time.Duration.Seconds of the reading less run_start's: the one whole nanosecond count near s that
	// gives s back.
	d0 := int64(math.Round(s * 1e9))
	for d := d0 - 16; d <= d0+16; d++ {
		if d > 0 && time.Duration(d).Seconds() == s {
			if now := rc.startMono + uint64(d); now > rc.lastMono && now > rc.startMono {
				return now
			}
			return 0
		}
	}
	return 0
}

// reprice prices rc as the receipt given says its maker's table did: its tokens.est_cost_usd and
// tokens.unpriced_responses, once they are what a price table can give for this record (an estimate of 0 or more
// dollars, never written -0 and small enough to round to a micro-dollar, which is 0 when no response was priced, and a
// whole number of the record's metered responses), and with no table at all when it carries the no-price-table gap.
// With no metered response it takes neither: both are the record's. It returns the fields it took ("" names none: the record left
// them nothing to choose), or why the receipt's are not what any price table gives. Values of the wrong type or a
// missing key are left to the compare, which names them.
func (k *checker) reprice(rc *Receipt) ([]string, string) {
	t, _ := k.given["tokens"].(map[string]any)
	estN, okE := t["est_cost_usd"].(json.Number)
	unN, okU := t["unpriced_responses"].(json.Number)
	if !okE || !okU {
		return nil, ""
	}
	metered := rc.Tokens.Metered
	est, err := strconv.ParseFloat(estN.String(), 64)
	// -0 is no sum of prices and tego never writes it; a cost that rounds past the largest float cannot be written.
	if err != nil || math.IsNaN(est) || math.IsInf(est, 0) || est < 0 || math.Signbit(est) ||
		math.IsInf(math.Round(est*1e6), 0) {
		return nil, fmt.Sprintf("tokens.est_cost_usd: receipt %s, which no price table gives", brief(estN))
	}
	unpriced, err := strconv.Atoi(unN.String())
	if err != nil || unpriced < 0 || unpriced > metered {
		return nil, fmt.Sprintf("tokens.unpriced_responses: receipt %s, and the record has %d metered %s",
			brief(unN), metered, plural(metered, "response", "responses"))
	}
	if est != 0 && unpriced == metered {
		return nil, fmt.Sprintf("tokens.est_cost_usd: receipt %s with none of the record's %d metered %s priced",
			brief(estN), metered, plural(metered, "response", "responses"))
	}
	table := true
	c, _ := k.given["coverage"].(map[string]any)
	gs, _ := c["gaps"].([]any)
	for _, g := range gs {
		if gm, ok := g.(map[string]any); ok && gm["code"] == CodeNoPriceTable {
			table = false
		}
	}
	if !table && (unpriced != metered || est != 0) {
		return nil, "coverage.gaps: a no-price-table gap beside a cost a price table gave"
	}
	if metered == 0 {
		// no table had a response to price, so the two numbers are the record's own, never the receipt's
		est, unpriced = rc.Tokens.EstCostUSD, rc.Tokens.Unpriced
	}
	rc.reprice(est, unpriced, table)
	var taken []string
	if metered > 0 {
		taken = append(taken, "tokens.est_cost_usd", "tokens.unpriced_responses")
	} else if rc.price.noPriceLine && rc.Tokens.Recorded && rc.Tokens.ModelCalls > 0 {
		taken = append(taken, "coverage.gaps[no-price-table]")
	}
	return taken, ""
}

// verdict is the result of steps: a failure outranks a check that did not run, and a match on a record with no
// run_end is its own result.
func verdict(steps []CheckStep, ended bool) string {
	result := CheckMatch
	for _, s := range steps {
		switch s.Result {
		case StepFail:
			return CheckMismatch
		case StepNotChecked:
			result = CheckCannot
		}
	}
	if result == CheckMatch && !ended {
		return CheckMatchUnended
	}
	return result
}

// firstDiff names the first place the receipt given (got) and the receipt computed from the record (want) differ,
// keys in sorted order; "" when they are the same.
func firstDiff(path string, got, want any) string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: receipt %s, record an object", where(path), brief(got))
		}
		keys := map[string]bool{}
		for k := range g {
			keys[k] = true
		}
		for k := range w {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			p := k
			if path != "" {
				p = path + "." + k
			}
			gv, gok := g[k]
			wv, wok := w[k]
			switch {
			case !wok:
				return fmt.Sprintf("%s: in the receipt, not in the record's receipt", p)
			case !gok:
				return fmt.Sprintf("%s: in the record's receipt, not in the receipt", p)
			}
			if d := firstDiff(p, gv, wv); d != "" {
				return d
			}
		}
		return ""
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Sprintf("%s: receipt %s, record a list", where(path), brief(got))
		}
		if len(g) != len(w) {
			return fmt.Sprintf("%s: receipt %d items, record %d", where(path), len(g), len(w))
		}
		for i := range w {
			if d := firstDiff(fmt.Sprintf("%s[%d]", path, i), g[i], w[i]); d != "" {
				return d
			}
		}
		return ""
	}
	g, w := whole(got), whole(want)
	if g == w {
		return ""
	}
	d := fmt.Sprintf("%s: receipt %s, record %s", where(path), brief(got), brief(want))
	if brief(got) == brief(want) {
		i := 0
		for i < len(g) && i < len(w) && g[i] == w[i] {
			i++
		}
		d += fmt.Sprintf(" (they differ from byte %d of their JSON)", i+1)
	}
	return d
}

func where(path string) string {
	if path == "" {
		return "the receipt"
	}
	return path
}

// whole is a scalar as JSON, every byte of it: facts compares these, so two values differ wherever they differ.
func whole(v any) string {
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%T %v", v, v)
	}
	return string(b)
}

// brief is a scalar as JSON, cut to a line's worth, for a message only: two values brief prints alike can differ.
func brief(v any) string {
	s := whole(v)
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

// duplicateKeyError is a receipt object that names one key twice: one JSON reader keeps the first, another the last,
// so the receipt does not say one thing.
type duplicateKeyError struct{ path string }

func (e *duplicateKeyError) Error() string {
	return "the receipt names the key " + e.path + " twice"
}

// strictJSON checks that data is one JSON value with no duplicate key in any object, nested at most maxReceiptDepth
// deep, and nothing after it.
func strictJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSON(dec, "", 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("more after the first JSON value")
	}
	return nil
}

func walkJSON(dec *json.Decoder, path string, depth int) error {
	if depth > maxReceiptDepth {
		return fmt.Errorf("nested deeper than %d", maxReceiptDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			p := key
			if path != "" {
				p = path + "." + key
			}
			if seen[key] {
				return &duplicateKeyError{path: p}
			}
			seen[key] = true
			if err := walkJSON(dec, p, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := walkJSON(dec, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// short is a head or digest's first 12 characters, as `tego events --verify` prints a head.
func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// Text writes the check's result for a person: the result first, one line per check, what it rests on and what it
// does not show. Every string from the files goes through record.Printable.
func (c *CheckResult) Text(w io.Writer) error {
	var b strings.Builder
	what := fmt.Sprintf("run %s, %d %s", record.Printable(c.Run), c.Lines, plural(int(c.Lines), "line", "lines"))
	switch c.Result {
	case CheckMatch:
		fmt.Fprintf(&b, "The receipt matches the record: %s, run_start to run_end, head %s.\n", what, short(c.Head))
	case CheckMatchUnended:
		b.WriteString("The record has no run_end: the run had not ended, or lost its end.\n")
		fmt.Fprintf(&b, "The receipt matches the record as far as it goes: %s, head %s.\n", what, short(c.Head))
	case CheckMismatch:
		s := firstWith(c.Checks, StepFail)
		fmt.Fprintf(&b, "The receipt does not match the record: %s: %s.\n", s.Name, record.Printable(s.Why))
	default:
		s := firstWith(c.Checks, StepNotChecked)
		fmt.Fprintf(&b, "Could not check the receipt against the record: %s: %s.\n", s.Name, record.Printable(s.Why))
	}
	if c.ExitCode() == identity.ExitOK {
		b.WriteString("Checked from these files alone; no chain.log was read.\n")
		b.WriteString("This does not show that the record is complete, that the machine or the person who ran it was " +
			"honest, who ran it, or when, or that this is the run you expect.\n")
	}
	for _, s := range c.Checks {
		b.WriteString(strings.TrimRight(fmt.Sprintf("  %-8s %-11s %s", s.Name, s.Result, record.Printable(s.Why)), " ") + "\n")
	}
	codes := make([]string, 0, len(c.Limits))
	for _, l := range c.Limits {
		codes = append(codes, l.Code)
	}
	fmt.Fprintf(&b, "Limits: %s (each one's words are in --json).\n", strings.Join(codes, ", "))
	_, err := io.WriteString(w, b.String())
	return err
}

func firstWith(steps []CheckStep, result string) CheckStep {
	for _, s := range steps {
		if s.Result == result {
			return s
		}
	}
	return CheckStep{}
}

// JSON writes the check's result as one JSON object.
func (c *CheckResult) JSON(w io.Writer) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
