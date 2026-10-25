// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// FileName is the reason file's name, in the run's ledger directory and in its runtime directory alike.
const FileName = "last-refusal.json"

// ErrBadRun is DirFor's refusal of a run that is not one path element.
var ErrBadRun = errors.New("reason: run is not a single path element")

// DirFor is where an unprivileged run's runtime directory is by convention, /run/user/<uid>/tego/<run>/, the
// directory that holds its readable copy of the reason file when $XDG_RUNTIME_DIR is the systemd default
// (TEGO_REASON names the file itself, and wins). The root form is not here: a root launcher makes no runtime
// directory. run must be one path element.
func DirFor(uid uint32, run string) (string, error) {
	if run == "" || run == "." || run == ".." || strings.ContainsAny(run, "/\x00") {
		return "", fmt.Errorf("%w: %q", ErrBadRun, run)
	}
	return "/run/user/" + strconv.FormatUint(uint64(uid), 10) + "/tego/" + run + "/", nil
}
