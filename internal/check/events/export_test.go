// SPDX-License-Identifier: Apache-2.0

package events

import (
	"context"
	"io"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// JSON is JSONOf over the whole run.
func JSON(ctx context.Context, w io.Writer, r *ledger.Reader, f Filter) (int, error) {
	return JSONOf(ctx, w, r, r.Entries(), f)
}

// Table is TableOf over the whole run.
func Table(ctx context.Context, w io.Writer, r *ledger.Reader, f Filter) (int, error) {
	return TableOf(ctx, w, r, r.Entries(), f)
}
