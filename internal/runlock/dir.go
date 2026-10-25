// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Dir is a run's directory as the lock probe and the lock-holder proof look it up. With At nil every lookup resolves
// Path. A sweep hook is lent the directory itself (ledger.WithSweepHook), and then At is that directory and every
// lookup is an *at() call under it (ADR 0023): the directory the pass decided on, whatever is renamed over Path
// meanwhile. Path names the directory in errors either way.
type Dir struct {
	Path string
	At   sys.Lender
}

// openFile opens the run's file name for reading as the ledger's readers do (ledger.OpenRegular): O_NOFOLLOW,
// O_NONBLOCK, regular files only.
func (d Dir) openFile(name string) (*os.File, error) {
	path := filepath.Join(d.Path, name)
	if d.At == nil {
		return ledger.OpenRegular(path)
	}
	return ledger.OpenRegularAt(d.At, name, path)
}
