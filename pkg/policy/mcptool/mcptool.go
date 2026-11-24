// SPDX-License-Identifier: Apache-2.0

package mcptool

import (
	"bytes"
	"encoding/json"
	"slices"
)

// The three decisions; they are also the live overlay's values (internal/mcptools).
const (
	Allow = "allow"
	Ask   = "ask"
	Deny  = "deny"
)

// The refusal reasons a decision carries on its ledger line (ADR 0126 §5).
const (
	// ReasonDenied is a call the contract or a live switch denies.
	ReasonDenied = "mcp-tool-denied"
)

// RefusalCode is the JSON-RPC error code of a refused call: in the implementation-defined server range, so a client
// reads it as the server's own refusal and goes on.
const RefusalCode = -32001

// Rules are one server's contract lists. Allow present (non-nil, even empty) means every tool not on it is denied;
// nil Allow, Deny and Ask is a server behind the relay with nothing restricted (`tools: {}`).
type Rules struct {
	Allow []string
	Deny  []string
	Ask   []string
}

// Result is a decision and the rule that made it.
type Result struct {
	Decision string
	Rule     string
}

// Decide is ADR 0126 §4's precedence for server's tool: a live switch (live, "" when none) wins; then the contract's
// deny, then its ask, then an allow list that does not name the tool (denied), else the call is allowed.
func Decide(r Rules, live, server, tool string) Result {
	base := "mcp[" + server + "]"
	switch {
	case live == Allow || live == Ask || live == Deny:
		return Result{live, base + ".live[" + tool + "]"}
	case slices.Contains(r.Deny, tool):
		return Result{Deny, base + ".tools.deny[" + tool + "]"}
	case slices.Contains(r.Ask, tool):
		return Result{Ask, base + ".tools.ask[" + tool + "]"}
	case r.Allow != nil && !slices.Contains(r.Allow, tool):
		return Result{Deny, base + ".tools.allow"}
	case r.Allow != nil:
		return Result{Allow, base + ".tools.allow[" + tool + "]"}
	default:
		return Result{Allow, base}
	}
}

// Contract is what the contract alone decides for tool (no live switch).
func Contract(r Rules, server, tool string) Result { return Decide(r, "", server, tool) }

// rank orders decisions from tightest to loosest; an unknown one ranks as deny.
func rank(d string) int {
	switch d {
	case Allow:
		return 2
	case Ask:
		return 1
	default:
		return 0
	}
}

// Loosens reports whether going from one decision to another gives the agent more: deny < ask < allow. A loosening
// needs a person's acknowledgement and is refused from inside a run; a tightening applies at once.
func Loosens(from, to string) bool { return rank(to) > rank(from) }

// WithinContract is the live switch a Locked run keeps: live when it is no looser than the contract's own decision for
// tool, and "" (no switch: the contract decides) when it would give the agent more. A Locked run is never looser than
// its contract while it runs (ADR 0125), so the consumer of the overlay, the relay, applies this to whatever the
// overlay holds, whoever wrote it; the writers refuse such a switch by the same comparison (Loosens). An Adjustable run
// keeps live as it is.
func WithinContract(r Rules, live, server, tool string) string {
	if live == "" {
		return ""
	}
	if Loosens(Contract(r, server, tool).Decision, live) {
		return ""
	}
	return live
}

// FilterToolsList removes the tools denied names from a tools/list result ({"tools":[{"name":...},...], ...}), keeps
// every other member (nextCursor included) and every tool it does not deny, and returns the names it saw in order.
// A result it cannot read is returned untouched with ok false: the caller counts it, and the enforced thing is
// tools/call, never the list (ADR 0126 security argument).
func FilterToolsList(result json.RawMessage, denied func(tool string) bool) (out json.RawMessage, names []string, ok bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil || obj == nil {
		return result, nil, false
	}
	rawTools, has := obj["tools"]
	if !has {
		return result, nil, false
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return result, nil, false
	}
	kept := make([]json.RawMessage, 0, len(tools))
	removed := false
	for _, t := range tools {
		var head struct {
			Name *string `json:"name"`
		}
		if err := json.Unmarshal(t, &head); err != nil || head.Name == nil {
			return result, nil, false
		}
		names = append(names, *head.Name)
		if denied != nil && denied(*head.Name) {
			removed = true
			continue
		}
		kept = append(kept, t)
	}
	if !removed {
		return result, names, true
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return result, names, false
	}
	obj["tools"] = b
	enc, err := json.Marshal(obj)
	if err != nil {
		return result, names, false
	}
	return enc, names, true
}

// Refusal is the JSON-RPC error a refused tools/call is answered with (ADR 0126 §4), one line with no newline:
// {"jsonrpc":"2.0","id":<id>,"error":{"code":-32001,"message":"Tego refused the MCP tool <tool> on <server>: <why>",
// "data":{"tego":{"rule":<rule>,"reason":<reason>}}}}.
func Refusal(id json.RawMessage, server, tool, rule, reason string) []byte {
	return refusal(id, rule, reason, "Tego refused the MCP tool "+tool+" on "+server+": "+why(reason))
}

// refusal is the one shape of a refusal's bytes, whatever its words.
func refusal(id json.RawMessage, rule, reason, message string) []byte {
	if len(bytes.TrimSpace(id)) == 0 {
		id = json.RawMessage("null")
	}
	msg := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Tego struct {
					Rule   string `json:"rule"`
					Reason string `json:"reason"`
				} `json:"tego"`
			} `json:"data"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	msg.Error.Code = RefusalCode
	msg.Error.Message = message
	msg.Error.Data.Tego.Rule = rule
	msg.Error.Data.Tego.Reason = reason
	b, err := json.Marshal(msg)
	if err != nil {
		// Only an id that is not JSON gets here; answer with a null id rather than none.
		msg.ID = json.RawMessage("null")
		b, _ = json.Marshal(msg)
	}
	return b
}

// RefusalBecause is Refusal for a message the relay refuses for a reason that is not a tool's decision (a batch's
// repeated id, a waiting queue that is full): the same code, rule and reason, and because as the words after the colon.
// tool "" is a message that names none (a tools/list, a ping).
func RefusalBecause(id json.RawMessage, server, tool, rule, reason, because string) []byte {
	what := "message"
	if tool != "" {
		what = "MCP tool " + tool
	}
	return refusal(id, rule, reason, "Tego refused the "+what+" on "+server+": "+because)
}

// why is a reason in the words the agent's model reads.
func why(reason string) string {
	switch reason {
	case ReasonDenied:
		return "the run's rules deny this tool"
	case "ask-denied":
		return "a person denied this call"
	case "ask-timeout":
		return "nobody answered the approval request in time"
	case "business-rule-unavailable":
		return "business rules require a trusted out-of-run worker and durable admission owner; this relay cannot establish them"
	case "ask-unavailable":
		return "this call needs a person's approval and none can be asked"
	default:
		return reason
	}
}
