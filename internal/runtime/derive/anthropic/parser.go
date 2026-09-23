// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Parser reads Anthropic Messages API exchanges. It is stateless and safe for concurrent use.
type Parser struct {
	hosts []string
	// declared is set on the parser ForHost scoped to a host that is not one of DefaultHosts: a path
	// outside /v1 is not silent there (classifyPathOn).
	declared bool
}

// ForHost is the parser as it reads an exchange with host (derive.HostScoped): Anthropic's own host reads
// every path outside /v1 as silent, any other host, an unknown one included, only the root path (R25).
func (p *Parser) ForHost(host string) derive.Parser {
	return &Parser{hosts: p.hosts, declared: !slices.Contains(DefaultHosts, agent.CanonicalHost(host))}
}

// New returns the parser, claiming hosts in addition to DefaultHosts. A run that declared a models[]
// entry with provider anthropic on some other host passes that host here, so an exchange still dispatches
// by host when no provider reached the Dispatcher (R25).
func New(hosts ...string) *Parser {
	all := slices.Clone(DefaultHosts)
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !slices.Contains(all, h) {
			all = append(all, h)
		}
	}
	return &Parser{hosts: all}
}

// Provider is the models[] provider name this parser claims.
func (p *Parser) Provider() string { return Provider }

// Hosts are the upstream hosts this parser claims.
func (p *Parser) Hosts() []string { return slices.Clone(p.hosts) }

// Version is the parser_version stamped on every ssl_response this parser produces (R32).
func (p *Parser) Version() string { return ParserVersion }

// Parse reads one request/response pair.
//
// /v1/messages carries a model turn, and so does /v1/chat/completions, the OpenAI-compatible endpoint, whose
// usage is read in its own shape (parseChat). An endpoint that spends nothing (model listing, token counting,
// a batch's status, the Files API) parses to the version stamp alone, with no decisions. Creating a message
// batch spends later, where no exchange shows it: it is one unparsed decision and Facts.Unmetered. Any other
// path is an unparsed body, spend unknown, rather than a silent one (R25): every path but
// /v1/messages used to parse to the stamp alone, so a turn through another endpoint cost the budgets nothing. A response body that should have been a model turn and
// was not returns an error wrapping ErrSchema or ErrEncoding, which the Dispatcher turns into exactly one
// decision: unparsed (R29). A response body a capture cap cut short fails the same way, from its own
// truncation, which is edge case #8's "attempt the prefix, report unparsed" rather than a special case.
//
// The two halves fail independently. R29 makes an unreadable *body* one unparsed decision; it does not
// make an unreadable request discard a response that parsed. The request is the half the agent under
// enforcement writes: were its failure allowed to void the pair, an agent could pad its own body past
// capture's cap (R6/R14, forwarder DefaultMaxBody) and every turn's usage, model and tool_use decisions
// would vanish, leaving limits' token and cost ceilings at zero however much the run actually spent. So
// the response is read first and is the only half whose failure voids the exchange; a request this
// parser could not read becomes its own unparsed decision alongside the response's facts.
func (p *Parser) Parse(req, resp *derive.Message) (derive.Facts, error) {
	facts := derive.Facts{ParserVersion: ParserVersion}
	if req == nil || resp == nil {
		return facts, fmt.Errorf("%w: parse needs both halves of the exchange", ErrSchema)
	}
	switch classifyPathOn(req.Method, req.Path, p.declared) {
	case pathSilent:
		return facts, nil
	case pathChat:
		return parseChat(req, resp)
	case pathBatchCreate:
		if resp.Status < 200 || resp.Status > 299 {
			return facts, nil // refused: no batch, nothing to spend
		}
		facts.Unmetered = true
		facts.Decisions = []derive.Decision{{Unparsed: true, Why: derive.WhySchema}}
		return facts, nil
	case pathMessages:
		// A model turn is a POST. A HEAD, OPTIONS or GET answered with no body at all (a 204, a preflight)
		// spent nothing and has no turn to read; one that carries a body is still read, and fails closed.
		if req.Method != http.MethodPost && len(resp.Body) == 0 && !resp.Truncated {
			return facts, nil
		}
	case pathOther:
		return facts, fmt.Errorf("%w: %s %s is not an endpoint this parser reads usage from", ErrSchema,
			req.Method, normalizePath(req.Path))
	}
	if resp.ContentEncoding != "" && !resp.Decoded {
		return facts, fmt.Errorf("%w: response body is %s and was not decoded", ErrEncoding, resp.ContentEncoding)
	}

	var (
		response *Response
		err      error
	)
	var streamErr error
	if isStream(resp) {
		response, err = parseStreamResponse(resp.Body, resp.WireSSE)
		if err != nil && response != nil {
			// The stream failed after message_start (an error event, a cut body, a close): what it reported
			// is kept, its usage above all, and the failure becomes an unparsed decision beside it. Returning
			// the error dropped the usage, so a truncated or failed stream cost nothing to the budgets.
			streamErr, err = err, nil
		}
	} else {
		response, err = ParseResponse(resp.Status, resp.Body)
	}
	if err != nil {
		return facts, err
	}

	// The request contributes the model an error body carries nowhere else (R28, T-anthropic-4). Its own
	// failure is recorded as an unparsed decision ahead of the response's, so the unreadable half is still
	// in the ledger rather than silently dropped (R25, R29, edge case #8) — and the tool_use decisions of
	// R30 keep their wire order relative to each other. The model is read exactly as written (R29),
	// and only when the response names none: a request naming model twice, or in another case, has no model
	// this parser can say the API priced, and is unparsed.
	reqErr := parseRequestHalf(req)
	facts.Model = response.Model
	switch {
	case reqErr != nil:
		facts.Decisions = append(facts.Decisions, unparsedDecision(reqErr))
	case response.Model != "":
	default:
		if m, ok := requestModel(req.Body); ok {
			facts.Model = m
		} else {
			facts.Decisions = append(facts.Decisions, derive.Decision{Unparsed: true, Why: derive.WhySchema})
		}
	}

	facts.IncompleteUsage = response.incompleteUsage
	facts.Unmetered = facts.IncompleteUsage && derive.Success(resp.Status)
	if facts.IncompleteUsage && !response.Stream {
		facts.Decisions = append(facts.Decisions, derive.Decision{Unparsed: true, Why: derive.WhySchema})
	}
	facts.Stream = response.Stream
	facts.ResponseID = response.ID
	facts.StopReason = response.StopReason
	usage := response.Usage.Record()
	if !facts.IncompleteUsage && response.Stream && !response.FinalUsage && !response.ErrorAnswer && derive.Success(resp.Status) {
		// The stream ended before its final message_delta, the one event that carries the message's output
		// count: message_start's output is a placeholder, so counting it charged a cut stream its input alone
		// (R29). The request's max_tokens is the most the model could have produced, and it is charged
		// instead, marked as a bound (docs/adr/0036-cut-stream-charges-max-tokens.md). A request whose
		// max_tokens this parser could not read leaves no bound at all, and the exchange is unmetered; so does
		// one that names max_tokens twice or in another case, which encoding/json would have folded into
		// whichever came last (R29). A stream that was an error answer from its first event (an
		// overloaded_error on a 200) began no message and spent nothing, so it takes no bound.
		maxTokens, ok := 0, false
		if reqErr == nil {
			maxTokens, ok = RequestMaxTokens(req.Body)
		}
		if ok {
			usage.Output = max(usage.Output, maxTokens)
			usage.OutputBound = true
		} else {
			facts.Unmetered = true
		}
	}
	facts.Usage = &usage
	facts.Decisions = append(facts.Decisions, decisions(response)...)
	if streamErr != nil {
		facts.Decisions = append(facts.Decisions, unparsedDecision(streamErr))
	}
	return facts, nil
}

// parseRequestHalf reads the request body, refusing bytes capture never decoded before they are read as
// JSON. A Content-Encoding capture could not undo is an encoding failure on the request just as it is on
// the response (R29 why=encoding); reading compressed bytes as JSON would report the wrong reason —
// why=schema — for a body whose structure was never in question.
func parseRequestHalf(req *derive.Message) error {
	if req.ContentEncoding != "" && !req.Decoded {
		return fmt.Errorf("%w: request body is %s and was not decoded", ErrEncoding, req.ContentEncoding)
	}
	return validateRequest(req.Body)
}

// unparsedDecision is the marker for one half of an exchange this parser could not read, carrying the
// closed why the error maps to (R29): encoding for bytes that never became text, schema for everything
// structural — which includes a body a capture cap cut short (edge case #8).
func unparsedDecision(err error) derive.Decision {
	why := derive.WhySchema
	if errors.Is(err, derive.ErrEncoding) {
		why = derive.WhyEncoding
	}
	return derive.Decision{Unparsed: true, Why: why}
}

// decisions extracts one decision per tool_use block, in wire order. A text block produces none: the
// full body is already a blob the ledger references (R30).
func decisions(resp *Response) []derive.Decision {
	var out []derive.Decision
	for _, b := range resp.Content {
		if b.Type != BlockToolUse {
			continue
		}
		out = append(out, derive.Decision{
			ToolUseID: b.ID,
			Tool:      b.Name,
			InputHash: InputHash(b.Input),
		})
	}
	return out
}

// InputHash is the sha256 of a tool_use input's exact wire bytes, hex encoded. The bytes are never
// re-marshaled or key-sorted first: byte identity is what makes limits.repeats match true repeats and
// nothing else (R31).
func InputHash(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

// isStream reports whether the response body is an event stream: capture said so, the content type says
// so, or the bytes themselves open with an SSE field.
func isStream(resp *derive.Message) bool {
	if resp.SSE {
		return true
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(strings.ToLower(ct), "text/event-stream") {
		return true
	}
	body := bytes.TrimLeft(resp.Body, " \r\n\t")
	return bytes.HasPrefix(body, []byte("event:")) || bytes.HasPrefix(body, []byte("data:"))
}

// ensure Parser satisfies the dispatcher's contract at compile time.
var _ derive.Parser = (*Parser)(nil)
