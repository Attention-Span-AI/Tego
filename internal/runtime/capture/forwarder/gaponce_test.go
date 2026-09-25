// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// gapLines is what a run writes for a listener's gaps: the gap lines the listener emitted as they happened,
// and one line per reason its Gaps report at run_end (internal/runtime's emitSourceGaps), keyed by why.
func gapLines(t *testing.T, h *harness) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, ev := range h.sink.of(record.KindGap) {
		out[payloadOf[record.GapPayload](t, ev).Why]++
	}
	for _, g := range h.listener.Gaps() {
		out[g.Why]++
	}
	return out
}

// gapDeriver derives one gap line for every exchange, as a parser does for a body it cannot read.
type gapDeriver struct{}

func (gapDeriver) Handle(_, _ *derive.Message, meta derive.Meta) (derive.Result, error) {
	ev := &record.Event{V: record.Version, TS: meta.TS, Kind: record.KindGap, Source: meta.Source}
	if err := ev.SetPayload(record.GapPayload{What: record.GapCapture, Why: GapH2, Binary: meta.Binary}); err != nil {
		return derive.Result{}, err
	}
	return derive.Result{Events: []*record.Event{ev}}, nil
}

// TestAGapIsWrittenOnce: a gap the listener wrote as it happened was also counted for the run's gap report, and the
// run writes that report at run_end as gap lines of its own, so one shortfall was two lines: an h2 preface, a request
// never answered, and every gap derive read out of an exchange.
func TestAGapIsWrittenOnce(t *testing.T) {
	t.Run("h2 preface", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }, Options{})
		pri := httptest.NewRequest("PRI", "/", nil)
		pri.RequestURI = "*"
		serveDirect(h.listener, httptest.NewRecorder(), pri)
		if got := gapLines(t, h); got[GapH2] != 1 || len(got) != 1 {
			t.Errorf("gap lines %v, want one h2", got)
		}
	})
	t.Run("never answered", func(t *testing.T) {
		h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{})
		h.upstream.Close()
		resp := h.post("/v1/messages", []byte(`{"model":"m"}`), nil)
		_ = resp.Body.Close()
		h.sink.waitFor(t, record.KindGap, 1)
		if got := gapLines(t, h); got[GapMalformed] != 1 || len(got) != 1 {
			t.Errorf("gap lines %v, want one malformed", got)
		}
	})
	t.Run("derived", func(t *testing.T) {
		h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
			Options{Deriver: gapDeriver{}})
		resp := h.post("/v1/messages", []byte(`{"model":"m"}`), nil)
		_ = resp.Body.Close()
		h.sink.waitFor(t, record.KindGap, 1)
		if got := gapLines(t, h); got[GapH2] != 1 || len(got) != 1 {
			t.Errorf("gap lines %v, want the one derive read", got)
		}
	})
}
