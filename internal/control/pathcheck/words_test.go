// SPDX-License-Identifier: Apache-2.0

package pathcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// Each way a check can fail to finish has its own words, chosen by type, so a person can act on the page and a bug
// report can name the case.
func TestWordsNameEachCaseOfACheckThatDidNotFinish(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"busy", &RemoteError{Message: Busy + ": x"}, "the checker did not start in time"},
		{"working", &RemoteError{Message: Working + ": x"}, "still working"},
		{"too slow", &RemoteError{Message: TooSlow + ": x"}, "too slow to finish"},
		{"disk", &RemoteError{Message: Disk + ": x"}, "the disk of this computer did not finish writing in time"},
		{"unclear", &RemoteError{Message: Unclear + ": x"}, "cannot tell whether a location is stuck"},
		{"could not start", &RemoteError{Message: StartFailed + ": fork"}, "the checker could not start"},
		{"cancelled", contracts.CompileNotFinished(context.Canceled), "cancelled"},
		{"cancelled check", &RemoteError{Message: contracts.CancelledCheck}, "cancelled"},
		{"stuck", contracts.CheckUnavailable(fmt.Errorf("%w", contracts.ErrHelpersStuck)), "earlier checks are stuck"},
		{"location", contracts.CheckUnavailable(errors.New("open: i/o timeout")), "the location does not answer"},
		{"compile busy", contracts.CompileUnavailable(true, errors.New("slot")), "compiler is busy"},
		{"compile late", contracts.CompileNotFinished(context.DeadlineExceeded), "did not finish in time"},
	} {
		if got := Words(tc.err); !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q lacks %q", tc.name, got, tc.want)
		}
	}
	if Words(errors.New("disk on fire")) != "" || Words(nil) != "" {
		t.Error("an error that is not a check that did not finish got words")
	}
}
