// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/scan"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var (
	errScanRecordNotLive = errors.New("record is not live")
	errScanRecordStart   = errors.New("invalid record start")
)

// scanRecordProbe confirms a bounded first line and a running state both before
// and after it. State reads only the ledger tail and probes the held writer lock;
// the tail also rejects a run_end whose writer is still inside Close. No record
// payload or operating-system error text reaches an observation.
func scanRecordProbe(ctx context.Context, root, id string, finished time.Time) (bool, string) {
	return scanRecordProbeFor(ctx, root, id, finished, uint32(os.Getuid()))
}

// scanRecordProbeFor checks the recipient-selected ledger after the advanced
// credential drop. Root-owned files remain eligible only if the recipient can
// read them; ownership checks never grant access to private root data.
func scanRecordProbeFor(ctx context.Context, root, id string, finished time.Time, uid uint32) (bool, string) {
	if !identity.RunID(id).Valid() {
		return false, "syntax"
	}
	if err := ctx.Err(); err != nil {
		return false, "deadline"
	}
	err := scan.WithRecordBytes(ctx, root, id, uid, func(dir sys.Lender, events *os.File, readStart func() ([]byte, error)) error {
		return scan.WithRecordLock(ctx, dir, uid, func(lock *os.File) error {
			r, err := ledger.OpenReaderFiles(events, lock, filepath.Join(root, id))
			if err != nil {
				return err
			}
			defer func() { _ = r.Close() }()
			checkState := func() error {
				if err := ctx.Err(); err != nil {
					return err
				}
				state, err := r.State()
				if err != nil {
					return err
				}
				if state != ledger.StateRunning {
					return errScanRecordNotLive
				}
				return ctx.Err()
			}
			if err := checkState(); err != nil {
				return err
			}
			b, err := readStart()
			if err != nil {
				return err
			}
			e, err := record.Decode(b)
			if err != nil || e.Kind != record.KindRunStart || e.Run != id || e.Seq != 0 || e.TS.After(finished) {
				return errScanRecordStart
			}
			return checkState()
		})
	})
	if err == nil {
		return true, "none"
	}
	if errors.Is(err, errScanRecordNotLive) {
		return false, "not-live"
	}
	if errors.Is(err, errScanRecordStart) || errors.Is(err, ledger.ErrCorruptLedger) {
		return false, "syntax"
	}
	return false, scan.RecordReadReason(err)
}
