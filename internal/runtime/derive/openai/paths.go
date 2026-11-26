// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// pathKind is what a request's path says its response carries.
type pathKind int

const (
	// pathOther is a path this parser does not read usage from: an unparsed decision, spend unknown (fail closed).
	pathOther pathKind = iota
	// pathChat is POST /v1/chat/completions.
	pathChat
	// pathResponses is POST /v1/responses.
	pathResponses
	// pathSilent spends no tokens: a GET or HEAD of the root path (a health check) and of a model listing.
	pathSilent
)

// classifyPath names what a request reaches. The path is normalized first, so an encoded or dotted spelling of an
// endpoint reaches the same answer the upstream does, and a spelling a server may resolve differently is not read.
// The silent list is an allow-list as the Anthropic parser's is: every path not on it, and not read for usage, is an
// unparsed decision and, answered 2xx, unmetered. A path with a prefix (a gateway's /openai/v1/chat/completions,
// Azure's deployments) is a path this parser does not read.
func classifyPath(method, target string) pathKind {
	_, target, ok := derive.SplitTarget(target)
	if !ok {
		return pathOther
	}
	p := normalizePath(target)
	switch {
	case p == "" || p == "/":
		// The root path is a health check for a GET or HEAD only: a gateway or local server may serve inference at its
		// root, and a POST there that stated usage would count nothing and let the run go on.
		if strings.EqualFold(method, http.MethodGet) || strings.EqualFold(method, http.MethodHead) {
			return pathSilent
		}
		return pathOther
	case ambiguous(p):
		return pathOther
	case p == ChatCompletionsPath && strings.EqualFold(method, http.MethodPost):
		return pathChat
	case p == ResponsesPath && strings.EqualFold(method, http.MethodPost):
		return pathResponses
	case (p == "/v1/models" || strings.HasPrefix(p, "/v1/models/")) &&
		(strings.EqualFold(method, http.MethodGet) || strings.EqualFold(method, http.MethodHead)):
		return pathSilent
	}
	return pathOther
}

// ambiguous reports that a normalized path holds a backslash, a ; (a path parameter), a % left after the one decode,
// or a control, space or non-ASCII byte: bytes a server may drop, rewrite or read as a separator.
func ambiguous(p string) bool {
	for i := 0; i < len(p); i++ {
		if c := p[i]; c == '\\' || c == ';' || c == '%' || c <= ' ' || c >= 0x7f {
			return true
		}
	}
	return false
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
