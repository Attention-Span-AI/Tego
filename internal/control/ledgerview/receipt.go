// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
)

// Receipt is a run's V1 receipt, the one `tego receipt` prints: the dashboard's Receipt tab shows it from the same
// builder (internal/check/receipt), so the page and the terminal cannot disagree.
type Receipt = receipt.Receipt

// ReceiptRuleCount and ReceiptRefusal are the receipt's per-rule count and refused action, for the page (which
// reaches the receipt through this package only).
type (
	ReceiptRuleCount = receipt.RuleCount
	ReceiptRefusal   = receipt.Refusal
)

// ReceiptDuration renders seconds as the receipt does ("3m 05s").
func ReceiptDuration(s float64) string { return receipt.Duration(s) }

// receipts keeps each run's receipt while its events file is the same (results.go): a receipt reads only that file,
// and the clock while the run is live (its time taken to now).
var receipts = NewResults[struct{}, *Receipt](64, true)

// LoadReceipt builds run id's receipt from its directory under root, read-only and without the lock, as
// `tego receipt` does. A running run measures its time taken to now. The receipt is kept per run while the run's
// events file is the same (results.go) and is shared: a caller must not modify it.
func LoadReceipt(ctx context.Context, root, id string) (*Receipt, error) {
	if !validRunID(id) {
		return nil, errors.New("not a run id")
	}
	run, ok := StampRun(root, id)
	if !ok {
		return loadReceipt(ctx, root, id)
	}
	var err error
	rc := receipts.Get(filepath.Clean(root)+"\x00"+id, run, struct{}{}, func() (*Receipt, bool) {
		var rc *Receipt
		rc, err = loadReceipt(ctx, root, id)
		return rc, err == nil && ctx.Err() == nil
	})
	return rc, err
}

// loadReceipt is LoadReceipt uncached.
func loadReceipt(ctx context.Context, root, id string) (*Receipt, error) {
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
	return receipt.Compute(ctx, r, receipt.Options{NowMonoNS: now})
}
