// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"testing"
	"time"
)

func TestAdoptSkipSecondReportAllowsScheduling(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	first := now
	// The next report may be eligible after a minute and observed on a later poll.
	reportAt := first.Add(time.Minute + 250*time.Millisecond)
	reads := 0
	observed := waitAdoptSkipNextReport(func() int {
		reads++
		if !now.Before(reportAt) {
			return 2
		}
		return 1
	}, 1, func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) })
	if !observed {
		t.Fatalf("missed the second report at %v after %d readings", reportAt.Sub(first), reads)
	}
	if now.Before(reportAt) {
		t.Fatal("reported success before the second line existed")
	}
}
