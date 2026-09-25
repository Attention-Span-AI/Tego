// SPDX-License-Identifier: Apache-2.0

package anthropic

import "github.com/attention-span-ai/tego/internal/runtime/derive"

// BoundCutStream charges a cut stream the max_tokens a capture source read off the request's bytes
// (MaxTokensScanner), where derive could not read it itself because the body was kept only as a prefix (ADR 0036
// (1)). It changes only the one verdict derive reaches for want of the request's
// max_tokens: an Anthropic stream answered 2xx whose final message_delta was never seen, left unmetered with its
// usage beside it. That exchange is charged max(output, maxTokens) as output, marked a bound, and metered. Every
// other exchange, and an unknown max_tokens (ok false), is left as it is. It reports whether it changed f.
func BoundCutStream(f *derive.Facts, maxTokens int, ok bool, status int) bool {
	if !ok || maxTokens <= 0 || f == nil || !f.Unmetered || f.IncompleteUsage || f.Usage == nil || !f.Stream || f.Usage.OutputBound ||
		f.ParserVersion != ParserVersion || !derive.Success(status) {
		return false
	}
	u := *f.Usage
	u.Output, u.OutputBound = max(u.Output, maxTokens), true
	f.Usage, f.Unmetered = &u, false
	return true
}
