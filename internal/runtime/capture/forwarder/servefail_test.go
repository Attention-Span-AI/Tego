// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// brokenAccept is a listener whose Accept fails with an error http.Server does not retry.
type brokenAccept struct{ net.Listener }

var errAcceptBroken = errors.New("accept: protocol error")

func (b brokenAccept) Accept() (net.Conn, error) { return nil, errAcceptBroken }

// syncBuffer is a log sink the serving goroutine and the test read and write together.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A listener that stops serving mid-run is logged when it stops and reported as a capture gap naming its
// upstream (R37 mechanism-unavailable), not held back as an error only Stop returns, which the run writes to
// its log and never to its record.
func TestAListenerThatStopsServingIsReportedWhenItStops(t *testing.T) {
	var logged syncBuffer
	m, err := NewManager([]agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com"}},
		Options{Logger: slog.New(slog.NewTextHandler(&logged, nil))})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	l := m.Listeners()[0]
	l.ln = brokenAccept{l.ln}
	if err := m.Start(context.Background(), testRun, &fakeSink{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logged.String(), errAcceptBroken.Error()) {
		if time.Now().After(deadline) {
			t.Fatalf("the failure was not logged while the run went on:\n%s", logged.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	var found bool
	for _, g := range m.Gaps() {
		if g.What == record.GapCapture && g.Why == derive.GapMechanismUnavailable && g.Binary == "api.anthropic.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("gaps %+v carry no mechanism-unavailable gap for the listener that stopped", m.Gaps())
	}
	if err := m.Stop(); !errors.Is(err, errAcceptBroken) {
		t.Errorf("stop = %v, want the serve error", err)
	}
}
