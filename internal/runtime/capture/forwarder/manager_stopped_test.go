// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Manager owns sockets bound at construction; Stop closes them permanently. A later Start cannot claim
// successful capture when every Serve will immediately exit on its already closed listener.
func TestManagerStartAfterStopIsRefused(t *testing.T) {
	m, err := NewManager([]agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background(), testRun, &fakeSink{}); !errors.Is(err, ErrStopped) {
		_ = m.Stop()
		t.Fatalf("Start with permanently closed capture listeners: %v, want ErrStopped", err)
	}
}
