// SPDX-License-Identifier: Apache-2.0

package derive

import "github.com/attention-span-ai/tego/pkg/spec/record"

// Parser turns one provider's request/response pair into the facts an ssl_response carries and the
// decisions the response asked for. One Parser per provider; parsers never import each other
// (docs/REPO-LAYOUT.md §Import direction).
//
// Parse never panics on input and never returns an error for a body it simply does not recognise: it
// returns an error wrapping ErrSchema, ErrEncoding or ErrH2, which the Dispatcher turns into exactly one
// decision: unparsed with the matching why (R29). Both arguments are non-nil when Parse is called.
type Parser interface {
	// Provider is the models[] provider name this parser claims (R25).
	Provider() string
	// Hosts are the upstream hosts this parser claims when no provider matched (R25).
	Hosts() []string
	// Version is the parser_version stamped on every ssl_response it produces (R32, I6).
	Version() string
	// Parse reads the pair. req is the request as capture assembled it, resp the response.
	Parse(req, resp *Message) (Facts, error)
}

// Facts are what a Parser read out of a response: the fields an ssl_response carries beyond what the
// transport already knew, plus the decisions the response contained.
type Facts struct {
	Model         string
	ResponseID    string
	StopReason    string
	Usage         *record.Usage
	ParserVersion string
	// Stream reports that the response was a server-sent event stream, assembled from its events.
	Stream bool
	// Decisions are the tool_use blocks, in wire order, or the single unparsed marker (R29, R30).
	Decisions []Decision
	// Unmetered says the exchange is a model call that may have spent tokens Usage does not count: a
	// successful answer on a declared model endpoint whose body could not be read for usage, or the creation
	// of a message batch, which spends later where no exchange shows it (R25). A capture source
	// reports it to its sink (source.ReportUnmetered), and a run with a token or cost budget ends there,
	// since that budget can no longer see what the run spends. It is never written to the ledger itself: the
	// unparsed decision beside it is the record.
	Unmetered bool
	// IncompleteUsage means an accounting frame was unreadable, so known counters are lower bounds.
	// A request's max_tokens bounds output alone and cannot make this exchange metered.
	IncompleteUsage bool
}

// Apply writes the facts onto an ssl_response payload the capture source built. It never clears a field
// the source already knew (status, latency, request id) and always sets ParserVersion, which is never
// empty on an ssl_response derive touched (I6).
func (f Facts) Apply(p *record.SSLResponsePayload) {
	if p == nil {
		return
	}
	if f.Model != "" {
		p.Model = f.Model
	}
	if f.ResponseID != "" {
		p.ResponseID = f.ResponseID
	}
	if f.StopReason != "" {
		p.StopReason = f.StopReason
	}
	if f.Usage != nil {
		u := *f.Usage
		p.Usage = &u
	}
	p.ParserVersion = f.ParserVersion
	if p.ParserVersion == "" {
		p.ParserVersion = NoParser
	}
}

// Decision is one entry of a response's decision set: a tool_use block (R30) or the single unparsed
// marker a body derive could not read produces (R29).
type Decision struct {
	ToolUseID string `json:"tool_use_id,omitempty"`
	Tool      string `json:"tool,omitempty"`
	// InputHash is the sha256 of the tool input's exact wire bytes, never of a re-marshaling (R31).
	InputHash string `json:"input_hash,omitempty"`
	Text      bool   `json:"text"`
	Unparsed  bool   `json:"unparsed"`
	// Why is the closed reason set of an unparsed decision: encoding | schema | h2.
	Why string `json:"why,omitempty"`
}

// Unparsed why values (spec/record/v1/README.md, the closed set).
const (
	WhyEncoding = "encoding"
	WhySchema   = "schema"
	WhyH2       = "h2"
)

// NoParser is the parser_version of an exchange no Parser claimed. I6 requires the field to be set on
// every ssl_response derive produced, and a provider with no parser is still an exchange derive saw
// (R25: the absence of a parser is a decision: unparsed, never a silent drop and never a capture gap).
const NoParser = "none"

// event turns one Decision into a decision event.
func (d Decision) event(meta Meta) *record.Event {
	ev := meta.event(record.KindDecision)
	payload := record.DecisionPayload{
		ToolUseID: d.ToolUseID,
		Tool:      d.Tool,
		InputHash: d.InputHash,
		Text:      d.Text,
		Unparsed:  d.Unparsed,
		Why:       d.Why,
	}
	// SetPayload cannot fail for this struct: every field is a string, an int or a bool.
	_ = ev.SetPayload(payload)
	return ev
}
