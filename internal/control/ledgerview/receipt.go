// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/pricetable"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Receipt is a run's V1 receipt, the one `tego receipt` prints: the dashboard's Receipt tab shows it from the same
// builder (internal/check/receipt). The dashboard can add contract-sensitive paths
// through LoadReceiptWithSensitive; recorded totals use the same computation.
type Receipt = receipt.Receipt

// ReceiptRuleCount and ReceiptRefusal are the receipt's per-rule count and refused action, for the page (which
// reaches the receipt through this package only).
type (
	ReceiptRuleCount = receipt.RuleCount
	ReceiptRefusal   = receipt.Refusal
)

// ReceiptNoneOverTime is the receipt's refusals-over-time words for a receipt with no refusal (receipt.NoneOverTime).
const ReceiptNoneOverTime = receipt.NoneOverTime

// ReceiptRefusedWords is the receipt's sentence beside a refusal count (receipt.RefusedSentence) for a run that
// refused total lines and whose refused reads leave no line when readsUnrecorded (Run.ReceiptReadsUnrecorded).
func ReceiptRefusedWords(total int, readsUnrecorded bool) string {
	return receipt.RefusedSentence(total, readsUnrecorded)
}

// BuiltInRefusal is line e's built-in kind as the receipt names it ("built in: kernel TLS", receipt.BuiltInRefusal), or
// "" for any other line: the rule every page that names one line's rule reads first, so it says what tego receipt says.
func BuiltInRefusal(e Event) string { return receipt.BuiltInRefusal(e.Op, e.Target, e.Rule, e.Reason) }

// BuiltInWords is line e's built-in refusal in the receipt's own sentence (receipt.BuiltInWords), or "" for any other
// line: what the Logs row says under it.
func BuiltInWords(e Event) string { return receipt.BuiltInWords(e.Op, e.Target, e.Rule, e.Reason) }

// logsRule is the rule Logs counts, groups and queries line e by: its built-in kind (BuiltInRefusal, "built in: kernel
// TLS") for tego's built-in refusal, which the record files under the default deny ("unmatched") and the receipt counts
// apart from it; else its rule key. The Rule facet, By rule and a rule: token all read it, so "Not in contract" counts
// and lists only what the contract's default decided, as the receipt's by-rule table does.
func logsRule(e *Event) string {
	if k := BuiltInRefusal(*e); k != "" {
		return k
	}
	return e.Rule
}

// ReceiptDuration renders seconds as the receipt does ("3m 05s").
func ReceiptDuration(s float64) string { return receipt.Duration(s) }

// receipts keeps each run's receipt while its events file and sensitive context are the same (results.go): a receipt reads only that file,
// and the clock while the run is live (its time taken to now).
var receipts = NewResults[string, *Receipt](64, true)

// LoadReceipt builds run id's receipt from its directory under root, read-only and without the lock, as
// `tego receipt` does. A running run measures its time taken to now. The receipt is kept per run while the run's
// events file is the same (results.go) and is shared: a caller must not modify it.
func LoadReceipt(ctx context.Context, root, id string) (*Receipt, error) {
	return loadReceiptCached(ctx, root, id, Sensitive{}, Pricing{})
}

// Pricing is what a receipt prices its model responses with: the machine's price table, as `tego receipt` prices them
// (internal/pricetable.Lazy), and Key, which names that table's file as it was read (its path, size and time), so a
// receipt kept for a run is built again when the table changes. The zero Pricing prices nothing: every response counts
// unpriced.
type Pricing struct {
	Prices pricetable.Coster
	Key    string
}

// LoadReceiptWithSensitive adds the run's protected contract paths to the
// receipt's sensitive-read activity. Recorded totals keep the same builder.
// Both entries and working directory belong to the cache key.
func LoadReceiptWithSensitive(ctx context.Context, root, id string, sensitive Sensitive) (*Receipt, error) {
	return loadReceiptCached(ctx, root, id, sensitive, Pricing{})
}

// LoadReceiptPriced is LoadReceiptWithSensitive with the machine's prices, which the dashboard passes so its Receipt
// tab prices a run as `tego receipt` does. The price table belongs to the cache key.
func LoadReceiptPriced(ctx context.Context, root, id string, sensitive Sensitive, pricing Pricing) (*Receipt, error) {
	return loadReceiptCached(ctx, root, id, sensitive, pricing)
}

func loadReceiptCached(ctx context.Context, root, id string, sensitive Sensitive, pricing Pricing) (*Receipt, error) {
	if !validRunID(id) {
		return nil, errors.New("not a run id")
	}
	run, ok := StampRun(root, id)
	if !ok {
		return readReceipt(ctx, root, id, sensitive, pricing)
	}
	var err error
	rc := receipts.Get(filepath.Clean(root)+"\x00"+id, run, sensKey(sensitive)+"\x00"+pricing.Key, func() (*Receipt, bool) {
		var rc *Receipt
		rc, err = readReceipt(ctx, root, id, sensitive, pricing)
		return rc, err == nil && ctx.Err() == nil
	})
	return rc, err
}

// readReceipt computes a receipt without the version/context cache.
func readReceipt(ctx context.Context, root, id string, sensitive Sensitive, pricing Pricing) (*Receipt, error) {
	r, err := ledger.OpenReader(filepath.Join(root, id))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	var now uint64
	if st, err := r.State(); err == nil && st == ledger.StateRunning {
		now = ledger.SystemClock{}.Mono()
	}
	opt := receipt.Options{NowMonoNS: now}
	if pricing.Prices != nil {
		opt.Prices = pricing.Prices
	}
	if len(sensitive.Entries) > 0 {
		match := compileSensitive(sensitive)
		opt.SensitivePath = func(p string) bool { _, ok := match.under(p); return ok }
	}
	return receipt.Compute(ctx, r, opt)
}

// ApprovalIdentity is the receipt's authenticated actor/role or system cause.
// It never derives an Owner from the legacy by sentence.
func ApprovalIdentity(a record.AnswerAuthority) string { return receipt.ApprovalIdentity(a) }
