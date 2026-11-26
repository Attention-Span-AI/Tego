// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Parser reads OpenAI-style exchanges. It is stateless and safe for concurrent use.
type Parser struct {
	hosts []string
}

// New returns the parser, claiming the declared hosts of models[] entries whose provider is openai, so an exchange
// still dispatches by host when no provider reached the Dispatcher (R25). It claims no host of its own: a contract
// says which endpoints are OpenAI-style, and Tego does not guess it from a host name.
func New(hosts ...string) *Parser {
	var all []string
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

// Silent reports that the request spends nothing whatever its answer (a health check, a model listing), by the
// classification Parse applies to an answered one (ADR 0037). A path it cannot place is not silent.
func (p *Parser) Silent(method, target string) bool {
	return classifyPath(method, target) == pathSilent
}

// Parse reads one request/response pair.
//
// POST /v1/chat/completions and POST /v1/responses carry a model turn, whole or streamed; a path that spends nothing
// parses to the version stamp alone; any other path is an error wrapping ErrSchema, which the Dispatcher turns into one
// unparsed decision and, answered 2xx, an unmetered exchange (R25). A 2xx answer that states no usage is the same
// (a body without a usage object spent what nothing here can read: counted as zero it would let a budget pass it
// unseen); a non-2xx answer that states none spent nothing. The request contributes only the model an answer names
// none of.
func (p *Parser) Parse(req, resp *derive.Message) (derive.Facts, error) {
	facts := derive.Facts{ParserVersion: ParserVersion}
	if req == nil || resp == nil {
		return facts, fmt.Errorf("%w: parse needs both halves of the exchange", ErrSchema)
	}
	kind := classifyPath(req.Method, req.Path)
	switch kind {
	case pathSilent:
		return facts, nil
	case pathOther:
		return facts, fmt.Errorf("%w: %s is not an endpoint this parser reads usage from", ErrSchema,
			derive.Route(req.Method, req.Path))
	}
	if resp.ContentEncoding != "" && !resp.Decoded {
		return facts, fmt.Errorf("%w: response body is %s and was not decoded", ErrEncoding, resp.ContentEncoding)
	}
	if resp.Truncated {
		// A body a capture cap or an early close cut short is a prefix of the answer, never the answer: a usage found
		// in it may be an earlier count of a server that states usage in every chunk, so nothing in it is read.
		return facts, errCutOff{route: derive.Route(req.Method, req.Path)}
	}
	if len(resp.Body) > MaxBody {
		return facts, fmt.Errorf("%w: response body is %d bytes, past the %d this parser reads", ErrSchema, len(resp.Body), MaxBody)
	}
	stream := isStream(resp.SSE, resp.Header.Get("Content-Type"), resp.Body)
	var (
		id, model string
		usage     *record.Usage
		err       error
	)
	switch {
	case kind == pathChat && stream:
		id, model, usage, err = chatStream(resp.Body, resp.WireSSE)
	case kind == pathChat:
		id, model, usage, err = chatWhole(resp.Body)
	case stream:
		id, model, usage, err = responsesStream(resp.Body, resp.WireSSE)
	default:
		id, model, usage, err = responsesWhole(resp.Body)
	}
	if err != nil {
		return facts, err
	}
	if usage == nil {
		if resp.Status < 200 || resp.Status > 299 {
			facts.Stream = stream
			return facts, nil // an error answer: the status is the fact, and nothing was spent
		}
		if stream && kind == pathChat {
			return facts, errStreamNoUsage{}
		}
		return facts, fmt.Errorf("%w: %s answer without usage", ErrSchema, derive.Route(req.Method, req.Path))
	}
	if model == "" {
		model, _ = requestModel(req.Body) // as written: encoding/json folds key case (R29)
	}
	facts.Stream, facts.Model, facts.ResponseID, facts.Usage = stream, model, id, usage
	return facts, nil
}

// payload is a frame's data as an object to decode: empty data and the [DONE] terminator are skipped,
// and anything that is not an object is a malformed accounting frame.
func payload(data []byte) (obj []byte, skip bool, err error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return nil, true, nil
	}
	if data[0] != '{' {
		return nil, false, fmt.Errorf("%w: stream payload is not an object", ErrSchema)
	}
	return data, false, nil
}

var _ derive.Parser = (*Parser)(nil)
var _ derive.SilentPaths = (*Parser)(nil)
