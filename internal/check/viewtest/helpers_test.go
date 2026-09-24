// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"time"
)

func gapsLine(r *drift.Report) string { return gaps.Line(r.Gaps) }

func statusDerive(r *ledger.Reader, now uint64) (string, error) {
	s, err := status.Derive(r, true, time.Now(), 0, status.WithMonoNow(func() uint64 { return now }))
	if err != nil {
		return "", err
	}
	return string(s.St), nil
}
