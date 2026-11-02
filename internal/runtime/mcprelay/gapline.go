// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// changeEvent is the gap line of one live change put in force: what=enforce, why mcp-tool-changed, with the switch
// as the overlay recorded it (ADR 0126 §5). A reset is decision reset: the contract decides the tool again.
func changeEvent(c mcptools.Change) *record.Event {
	decision := c.Decision
	if c.Op == mcptools.OpReset {
		decision = record.MCPToolReset
	}
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceProxy}
	if err := ev.SetPayload(record.GapPayload{What: record.GapEnforce, Why: record.GapMCPToolChanged,
		MCPTool: &record.MCPToolChange{Server: c.Server, Tool: c.Tool, Decision: decision, By: c.By, Serial: c.Serial, At: c.At}}); err != nil {
		return nil
	}
	return ev
}
