// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// maxStopMarker bounds what StopRequestGrace reads from a stop marker: one Go duration and a newline.
const maxStopMarker = 64

// RequestStopGraceThen writes the run's stop marker carrying the grace `tego stop --grace` asked for (R9,
// limits-check-doctor-cli.md R29): the marker holds that duration, and the launcher's stop_grace timer,
// armed by the SIGTERM that follows, runs for it instead of the machine's stop_grace
// (launch.SignalPolicy.RequestedGrace). A grace of 0 writes the empty marker, which leaves stop_grace
// in force. The marker is written to a temporary name and linked into place, so the launcher reads
// either no marker or the whole of it (§3), and only the first of two concurrent stops places one: link(2)
// fails with EEXIST where rename(2) replaced the first stop's marker, and its grace with it. The loser gets
// ErrStopRequested, as a later stop always did.
//
// The run directory is reached by the ledger's walk and every name in it through that descriptor
// (ledger.PlaceNewFileThen): as root, a link in a directory that is not root's alone is refused, never followed. The
// marker was created by path, as root in the run directory of a user's ledger root, so a user who replaced the
// run directory, or the ledger root, with a link had root create a file wherever it pointed.
//
// It publishes the marker before after runs, serializing every supported stop publisher. after is given
// whether an earlier marker existed; returning an error removes only this invocation's own new marker. A nil
// after keeps the ErrStopRequested behavior above. Cancellation and the ledger's bounded publication lock end
// a wait without signalling a target.
func RequestStopGraceThen(ctx context.Context, runDir string, grace time.Duration, after func(bool) error) error {
	if grace < 0 {
		return fmt.Errorf("runtime: stop grace %v is negative", grace)
	}
	var body []byte
	if grace > 0 {
		body = []byte(grace.String() + "\n")
	}
	if after == nil {
		after = func(existing bool) error {
			if existing {
				return ErrStopRequested
			}
			return nil
		}
	}
	err := ledger.PlaceNewFileThen(ctx, runDir, StopRequestFile, body, after)
	if errors.Is(err, ErrStopRequested) {
		return fmt.Errorf("%w: %s", ErrStopRequested, filepath.Join(runDir, StopRequestFile))
	}
	if err != nil {
		return fmt.Errorf("runtime: place stop marker: %w", err)
	}
	return nil
}

// StopRequestGrace is the grace the run's stop marker asks for, 0 when there is no marker, when the
// marker is empty (a `tego stop` without --grace, or one from a binary that wrote none), or when it
// holds anything but one positive duration. It is the launcher's SignalPolicy.RequestedGrace hook, and
// 0 there means the machine's stop_grace: a marker that cannot be read as a request is not one.
//
// The marker is opened without following a symlink and read no further than maxStopMarker bytes: it
// sits in the run directory, and a root launcher reads it.
func StopRequestGrace(runDir string) time.Duration {
	f, err := os.OpenFile(filepath.Join(runDir, StopRequestFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return 0
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStopMarker+1))
	if err != nil || len(b) > maxStopMarker {
		return 0
	}
	g, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil || g <= 0 {
		return 0
	}
	return g
}
