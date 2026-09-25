// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"io"
	"sync"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sentScanner reads a request body's max_tokens off the bytes the upstream leg reads past what capture kept
// (anthropic.MaxTokensScanner, R27). The leg reads on the Transport's goroutine and
// derive asks for the result on the handler's, so the scanner is behind a lock; a body the leg had not finished
// reading when derive asks has not ended, and gives no bound.
type sentScanner struct {
	mu sync.Mutex
	s  anthropic.MaxTokensScanner
}

// newSentScanner starts a scanner on the prefix capture kept and returns it with rest wrapped so that every
// byte the upstream leg reads of it is scanned too.
func newSentScanner(kept []byte, rest io.Reader) (*sentScanner, io.Reader) {
	s := &sentScanner{}
	_, _ = s.s.Write(kept)
	return s, io.TeeReader(rest, s)
}

// Write scans relayed bytes. It never fails, so the tee never cuts the upstream leg short.
func (s *sentScanner) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.Write(p)
}

// result is the max_tokens the whole body stated, if it has been read to its end.
func (s *sentScanner) result() (int, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.Result()
}

// wireScanned reports that the parser the Deriver dispatches this listener's exchanges to, by the declared
// provider or failing that the host (R25), is the Anthropic one, whose stream framing
// anthropic.StreamUsageScanner reads. On another provider's stream the scanner's usage and its incomplete
// verdict mean nothing: an OpenAI Responses frame past its 64 KiB line bound read as missing accounting and
// counted a malformed gap on an exchange captured whole. A Deriver that cannot name its parser keeps the
// declared provider's reading.
func (l *Listener) wireScanned() bool {
	d, ok := l.opts.Deriver.(interface {
		Parser(provider, host string) (derive.Parser, bool)
	})
	if !ok {
		return l.model.Provider == anthropic.Provider
	}
	p, ok := d.Parser(l.model.Provider, l.model.Host)
	return ok && p.Provider() == anthropic.Provider
}

// mergeUsage folds the wire usage scanner's reading (anthropic.StreamUsageScanner) into what derive read: each
// counter the larger of the two, since both are totals of the same stream and the scanner saw every byte of it
// where derive saw what capture kept. The two are read by the same code, keys exactly as written (R29),
// so taking the larger never charges a key derive would not read.
//
// One counter is not a total: when derive's copy of the stream ended before its message_delta, derive charged
// the request's max_tokens as output, a bound (OutputBound, R27). If the scanner saw that message_delta
// on the wire, its count is the message's own and replaces the bound; if it did not, the bound stands. A scanned
// usage that is not final, merged where derive read neither a final count nor a bound, holds message_start's
// placeholder output: the caller bounds it (boundPlaceholder) and never charges it as it is.
func mergeUsage(derived, scanned *record.Usage, final bool) *record.Usage {
	switch {
	case scanned == nil:
		return derived
	case derived == nil:
		return scanned
	}
	out := &record.Usage{
		Input:       max(derived.Input, scanned.Input),
		Output:      max(derived.Output, scanned.Output),
		CacheRead:   max(derived.CacheRead, scanned.CacheRead),
		CacheWrite:  max(derived.CacheWrite, scanned.CacheWrite),
		OutputBound: derived.OutputBound,
		// The 1-hour cache writes and the server-tool counts are totals too.
		CacheWrite1h: max(derived.CacheWrite1h, scanned.CacheWrite1h),
		Modified:     derived.Modified || scanned.Modified,
	}
	if len(derived.ServerTool) > 0 || len(scanned.ServerTool) > 0 {
		out.ServerTool = derive.ServerToolUse(nil).Merge(derived.ServerTool).Merge(scanned.ServerTool)
	}
	if derived.OutputBound && final {
		out.Output, out.OutputBound = scanned.Output, false
	}
	return out
}

// boundPlaceholder is what a stream's usage becomes when its output count is message_start's placeholder, read
// off the wire with no message_delta after it and not bounded by derive: charged the request's max_tokens as
// output, marked a bound, when max_tokens is known; otherwise unmetered (reported true), never charged the
// placeholder as if it were the message's count (R27, limits-check-doctor-cli.md R1 (m), (c)). The caller asks
// only for a successful answer.
func boundPlaceholder(u *record.Usage, maxTokens int, ok bool) (*record.Usage, bool) {
	if u == nil || !ok || maxTokens <= 0 {
		return u, true
	}
	b := *u
	b.Output, b.OutputBound = max(b.Output, maxTokens), true
	return &b, false
}
