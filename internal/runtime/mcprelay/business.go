// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"errors"

	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
)

// ErrBusinessUnavailable forbids legacy routes before any worker is started.
// A business entry must use ADR 0152's trusted pipes and durable owner. Neither
// protocol 3 nor HTTP can supply those authorities on this implementation.
var ErrBusinessUnavailable = errors.New("mcprelay: business rules require the trusted out-of-run worker and durable admission owner; legacy protocol 3 and HTTP are unsupported")

func (c *stdioConn) refuseBusinessLegacy() bool {
	if !c.s.servers[c.server].BusinessRules {
		return false
	}
	// Intake has not authenticated an envelope or its ID. Refuse with null ID
	// rather than guessing one from attacker-controlled bytes. There is no send
	// and no evaluation claim. The ordinary service constructor refuses earlier.
	_ = c.fw.Write(Frame{ToClient: mcptool.Refusal(nil, c.server, "", "mcp["+c.server+"].business_rules", "business-rule-unavailable")})
	return true
}
