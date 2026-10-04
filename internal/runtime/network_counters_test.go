// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type finalNetworkHandle struct {
	fakeHandle
	counts backend.NetworkCounters
	err    error
}

func (h *finalNetworkHandle) NetworkCountersSnapshot() (backend.NetworkCounters, error) {
	if h.closed > 0 {
		return backend.NetworkCounters{}, errors.New("snapshot after close")
	}
	return h.counts, h.err
}

func TestFinalNetworkAccountingPreservesUnknownAndMeasuredZero(t *testing.T) {
	zero := uint64(0)
	h := &finalNetworkHandle{counts: backend.NetworkCounters{Available: map[string]bool{"bytes_out": true, "bytes_in": false}, BytesOut: &zero}}
	r := &runner{handle: h, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	end := record.RunEndPayload{Network: r.runNetworkCounters()}
	raw, err := json.Marshal(end)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"bytes_out":0`) || strings.Contains(string(raw), `"bytes_in":0`) {
		t.Fatalf("unknown and zero conflated: %s", raw)
	}
	h.counts.Available = map[string]bool{"bytes_out": false}
	if r.runNetworkCounters() != nil {
		t.Fatal("unavailable measurements appeared as a snapshot")
	}
	h.err = errors.New("map read failed")
	if r.runNetworkCounters() != nil || !strings.Contains(r.detail, "network accounting unavailable: map read failed") {
		t.Fatalf("failure fabricated zero or lost explanation: %s", r.detail)
	}
	if (&runner{handle: &fakeHandle{}}).runNetworkCounters() != nil {
		t.Fatal("backend without reporter claimed accounting")
	}
}
