// SPDX-License-Identifier: Apache-2.0

package web

import (
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
)

// lineHint is where the read model saw line seq of run start in its events file, for the rule service's view of the
// line (rules.ActReq.Hint): it then reads run_start and that one line instead of decoding every line before it, about
// 0.5 s on a run of 100k lines. The service checks the hint and scans when it does not hold; nil when the read model
// does not hold the run's lines.
func lineHint(root, run string, seq uint64) *rules.LineHint {
	at, ok := ledgerview.LineAt(root, run, seq)
	if !ok {
		return nil
	}
	return &rules.LineHint{Off: at.Off, Dev: at.Dev, Ino: at.Ino, Size: at.Size}
}
