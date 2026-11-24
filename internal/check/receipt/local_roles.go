// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"fmt"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ApprovalIdentity is the shared receipt/dashboard projection of authenticated
// answer authority. Legacy by text never supplies missing actor or role facts.
func ApprovalIdentity(a record.AnswerAuthority) string {
	if a.Actor != nil && a.Actor.Validate() == nil {
		return fmt.Sprintf("root (uid 0), role Owner, pid %d", a.Actor.PID)
	}
	switch a.SystemCause {
	case "timeout", "cancelled", "shutdown", "unavailable":
		return "system: " + a.SystemCause
	}
	return "actor and role: not recorded"
}
