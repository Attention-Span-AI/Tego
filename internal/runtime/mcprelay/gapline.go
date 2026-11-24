// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// HeldByLocked follows the author of a switch the relay did not put in force on a Locked run, in its line's by.
const HeldByLocked = " (not in force: the run is Locked, so the contract decides this tool)"

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

// oversizeEvent is the gap line of one message the relay dropped for its size: what=record, the why of the side
// that lost it, and the server, size and limit as record.OversizeNote writes them.
func oversizeEvent(why, server string, size, limit int64) *record.Event {
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceProxy}
	if err := ev.SetPayload(record.GapPayload{What: record.GapRecord, Why: why, Binary: record.OversizeNote(server, size, limit)}); err != nil {
		return nil
	}
	return ev
}
