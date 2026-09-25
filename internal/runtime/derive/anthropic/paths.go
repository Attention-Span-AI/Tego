// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// ChatCompletionsPath is the OpenAI-compatible endpoint Anthropic serves on its own host. A turn through it
// spends tokens exactly as /v1/messages does, reported in the OpenAI usage shape (R25).
const ChatCompletionsPath = "/v1/chat/completions"

// BatchesPath is the Message Batches API. Creating a batch spends tokens later, upstream, outside any
// exchange capture sees, so its creation is an exchange whose spend no usage in it counts (R25).
const BatchesPath = "/v1/messages/batches"

// pathKind is what a request's path says its response carries.
type pathKind int

const (
	// pathOther is a path this parser does not know: its response is not read, and it is one unparsed
	// decision, spend unknown (fail closed, R25).
	pathOther pathKind = iota
	// pathMessages is the Messages API: a model turn with its usage.
	pathMessages
	// pathChat is the OpenAI-compatible chat completions endpoint: a model turn with OpenAI-shaped usage.
	pathChat
	// pathBatchCreate is a Message Batches creation: spend that happens later, with no usage here.
	pathBatchCreate
	// pathSilent is an endpoint that spends no tokens: model listing, token counting, a batch's status, the
	// Files API. It parses to the version stamp alone.
	pathSilent
)

// classifyPathOn names what a request reaches. The path is normalized first (normalizePath), so an encoded or
// dotted spelling of an endpoint reaches the same answer the upstream does.
//
// The silent list is an allow-list: every path not on it, and not read for usage, is an unparsed decision.
// Before R25, every path but /v1/messages parsed to the version stamp alone, so POST /v1/chat/completions on
// api.anthropic.com spent 155000 tokens that no budget counted and no line said were uncounted.
//
// An absolute-form target is read by its path (RFC 9112 §3.2.2), and a target that is neither origin-form, "*"
// nor an http(s) URL is pathOther: normalized as a path, "https:/api.anthropic.com/v1/messages" fell outside
// /v1 and was silent, so a Messages call the capture path saw in absolute form spent nothing (R10).
//
// declared false is the reading for Anthropic's own host (DefaultHosts); declared true is the reading for a host
// the run declared rather than Anthropic's own. The rule that everything outside /v1 is silent is a fact about api.anthropic.com, whose billed API is versioned
// under /v1. A gateway or cloud front door a models[] entry names serves Claude under a prefix of its own
// (/anthropic/v1/messages, Bedrock's /model/<id>/invoke), and there the rule metered a model turn at zero with
// nothing to say so. On a declared host the silent paths outside /v1 are the root path and a harness's
// telemetry and account calls under /api/ with no segment that could open a versioned API (declaredSilent);
// every other path is one this parser does not read, which fails closed (R25).
func classifyPathOn(method, target string, declared bool) pathKind {
	_, target, ok := derive.SplitTarget(target)
	if !ok {
		return pathOther
	}
	p := normalizePath(target)
	switch {
	case p == MessagesPath:
		return pathMessages
	case p == ChatCompletionsPath:
		return pathChat
	case declared && outsideV1(p):
		if declaredSilent(p) {
			return pathSilent
		}
		return pathOther
	case outsideV1(p):
		// The billed API is versioned under /v1. What a harness calls outside it on the same host is not a
		// model call: the health check (R22), its telemetry and account endpoints under /api. Failing those
		// closed would end every budgeted run of a harness that reports telemetry.
		return pathSilent
	case ambiguousSegments(p):
		// Inside /v1, no silent subpath is read from a spelling a server may resolve differently: "..;" as a
		// dot segment or a backslash as a slash serves /v1/models/..;/messages as /v1/messages, a model turn
		// that would be recorded as silent (R25).
		return pathOther
	case p == MessagesPath+"/count_tokens":
		return pathSilent
	case p == "/v1/models" || strings.HasPrefix(p, "/v1/models/"):
		return pathSilent
	case p == "/v1/files" || strings.HasPrefix(p, "/v1/files/"):
		return pathSilent
	case p == BatchesPath && strings.EqualFold(method, http.MethodPost):
		return pathBatchCreate
	case p == BatchesPath || strings.HasPrefix(p, BatchesPath+"/"):
		rest := strings.TrimPrefix(strings.TrimPrefix(p, BatchesPath), "/")
		switch {
		case strings.HasSuffix(rest, "/results"):
			// A batch's results carry the usage of every request in it; this parser does not read them.
			return pathOther
		case strings.EqualFold(method, http.MethodGet), strings.EqualFold(method, http.MethodDelete):
			return pathSilent // listing, a batch's status, deleting one: no tokens
		case strings.EqualFold(method, http.MethodPost) && strings.HasSuffix(rest, "/cancel"):
			return pathSilent
		}
		return pathOther
	}
	return pathOther
}

// outsideV1 reports that a normalized path is plainly outside the versioned API, which is the one ground for
// calling it silent without naming it. It is decided on the first segment lowercased, with any ;params cut
// off, because a server may route /V1/messages or /v1;x/messages to the Messages API; compared as written,
// both were outside /v1 and spent nothing (R25). A first segment that begins with v1 in any case
// is inside, and so is one holding a backslash, a percent left after one decode, or a byte a server might
// drop or rewrite (a control byte, space, a non-ASCII byte): those are ambiguous, and an ambiguous path fails closed as a path this parser
// does not read. The root path, the health check's, stays outside.
func outsideV1(p string) bool {
	seg := strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	if i := strings.IndexByte(seg, ';'); i >= 0 {
		seg = seg[:i]
	}
	if seg == "" {
		return p == "" || p == "/" // "/;x/v1/messages" has an empty first segment a server may drop
	}
	for i := 0; i < len(seg); i++ {
		if c := seg[i]; c == '\\' || c == '%' || c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return !strings.HasPrefix(strings.ToLower(seg), "v1")
}

// ambiguousSegments reports that a normalized path holds a backslash, a ; (a path parameter), a % left after the one decode (a double-encoded spelling a gateway may decode again), or a control,
// space or non-ASCII byte anywhere: bytes a server may drop, rewrite or read as a separator.
func ambiguousSegments(p string) bool {
	for i := 0; i < len(p); i++ {
		if c := p[i]; c == '\\' || c == ';' || c == '%' || c <= ' ' || c >= 0x7f {
			return true
		}
	}
	return false
}

// declaredSilent reports that a normalized path outside /v1 on a declared host spends nothing: the root path,
// or a path under /api/ none of whose segments is inside /v1 by outsideV1's reading of a first segment (so
// /api/event_logging/batch is silent, and /api/v1/messages, /api/anthropic/V1;x/messages are not).
func declaredSilent(p string) bool {
	if p == "" || p == "/" {
		return true
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) < 2 || !strings.EqualFold(segs[0], "api") {
		return false
	}
	for _, seg := range segs[1:] {
		if !outsideV1("/" + seg) {
			return false
		}
	}
	return true
}

// normalizePath is a request target as the upstream reads it: no query or fragment, percent-encoding undone,
// repeated slashes collapsed, dot segments resolved and no trailing slash.
func normalizePath(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if u, err := url.PathUnescape(path); err == nil {
		path = u
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if path != "" {
		path = pathpkg.Clean("/" + path)
	}
	return strings.TrimSuffix(path, "/")
}

// chatUsage is the OpenAI usage object, as Anthropic's compatible endpoint reports it.
type chatUsage struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details,omitempty"`
}

// UnmarshalJSON requires explicit readable counters: an empty usage object is unknown spend, never zero.
func (u *chatUsage) UnmarshalJSON(data []byte) error {
	if err := uniqueAccounting(data, chatUsageAccounting); err != nil {
		return err
	}
	var wire struct {
		PromptTokens        *int `json:"prompt_tokens"`
		CompletionTokens    *int `json:"completion_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	}
	if err := unmarshal(data, &wire); err != nil {
		return err
	}
	if wire.PromptTokens == nil || wire.CompletionTokens == nil {
		return fmt.Errorf("chat completion usage requires prompt_tokens and completion_tokens")
	}
	u.PromptTokens, u.CompletionTokens = *wire.PromptTokens, *wire.CompletionTokens
	u.PromptTokensDetails = wire.PromptTokensDetails
	if u.PromptTokens < 0 || u.CompletionTokens < 0 ||
		u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens < 0 {
		return fmt.Errorf("chat completion usage is negative")
	}
	return nil
}

// chatBody is as much of a chat completion, or of one of its stream's chunks, as the budgets need.
type chatBody struct {
	ID    string     `json:"id"`
	Model string     `json:"model"`
	Usage *chatUsage `json:"usage"`
}

// parseChat reads the model and usage of a chat completion, whole or streamed, and nothing else: its tool
// calls are not decisions this parser derives (that is the openai parser's, P2). A streamed completion
// carries usage in one chunk only when the client asked for it; one without is an unparsed body, spend
// unknown, which is the fail-closed answer rather than a zero. Keys are read exactly as written (keys.go), as the
// Messages API's are: a "USAGE" or a "Model" is an unknown member, never the usage or model charged.
func parseChat(req, resp *derive.Message) (derive.Facts, error) {
	facts := derive.Facts{ParserVersion: ParserVersion}
	if resp.ContentEncoding != "" && !resp.Decoded {
		return facts, fmt.Errorf("%w: response body is %s and was not decoded", ErrEncoding, resp.ContentEncoding)
	}
	var found *chatBody
	if isStream(resp) {
		facts.Stream = true
		if err := scanSSE(resp.Body, resp.WireSSE, func(f frame) error {
			data := bytes.TrimSpace(f.data)
			if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
				return nil
			}
			if data[0] != '{' {
				return fmt.Errorf("%w: chat completion stream payload is not an object", ErrSchema)
			}
			var chunk chatBody
			if err := unmarshal(data, &chunk); err != nil {
				return fmt.Errorf("%w: chat completion stream accounting: %w", ErrSchema, err)
			}
			if found == nil {
				found = &chatBody{}
			}
			// Usage-only final chunks still belong to the response named by earlier chunks. Conflicting
			// identities cannot be priced as one exchange, and the API's one usage report cannot be
			// replaced by a later smaller count.
			if chunk.Model != "" {
				if found.Model != "" && found.Model != chunk.Model {
					return fmt.Errorf("%w: chat completion stream changed model", ErrSchema)
				}
				found.Model = chunk.Model
			}
			if chunk.ID != "" {
				if found.ID != "" && found.ID != chunk.ID {
					return fmt.Errorf("%w: chat completion stream changed response id", ErrSchema)
				}
				found.ID = chunk.ID
			}
			if chunk.Usage != nil {
				if found.Usage != nil {
					return fmt.Errorf("%w: chat completion stream repeated usage", ErrSchema)
				}
				found.Usage = chunk.Usage
			}
			return nil
		}); err != nil {
			return facts, err
		}
	} else {
		var body chatBody
		if err := unmarshal(resp.Body, &body); err != nil {
			return facts, fmt.Errorf("%w: chat completion body (status %d): %w", ErrSchema, resp.Status, err)
		}
		found = &body
	}
	if found == nil || found.Usage == nil {
		if resp.Status < 200 || resp.Status > 299 {
			return facts, nil // an error answer: the status is the fact, and nothing was spent
		}
		return facts, fmt.Errorf("%w: chat completion without usage", ErrSchema)
	}
	u := found.Usage
	if u.PromptTokens < 0 || u.CompletionTokens < 0 {
		return facts, fmt.Errorf("%w: chat completion usage is negative", ErrSchema)
	}
	cached := 0
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens > 0 {
		cached = min(u.PromptTokensDetails.CachedTokens, u.PromptTokens)
	}
	facts.Model, facts.ResponseID = found.Model, found.ID
	if facts.Model == "" {
		if err := parseRequestHalf(req); err == nil {
			facts.Model, _ = requestModel(req.Body) // as written: encoding/json folds key case (R29)
		}
	}
	usage := Usage{InputTokens: u.PromptTokens - cached, OutputTokens: u.CompletionTokens,
		CacheReadInputTokens: cached}.Record()
	facts.Usage = &usage
	return facts, nil
}
