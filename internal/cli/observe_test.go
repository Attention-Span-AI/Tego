// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestObserveOptionsLogAFatalRecorderError is the recorder's fatal read error wired to tego's own log: the
// options set no OnError, so a drain that died mid-run was logged only as a source's Stop
// error at shutdown, however long the run went on unrecorded.
func TestObserveOptionsLogAFatalRecorderError(t *testing.T) {
	var buf bytes.Buffer
	opts := observeOptions(&agent.RuleTable{}, "deadbeef", slog.New(slog.NewTextHandler(&buf, nil)))
	if opts.BPFHash != "deadbeef" || opts.Rules == nil || opts.Logger == nil {
		t.Fatalf("options %+v", opts)
	}
	if opts.OnError == nil {
		t.Fatal("no OnError: a fatal read error reaches no log until the run stops")
	}
	opts.OnError(errors.New("read sample data: unexpected EOF"))
	if line := buf.String(); !strings.Contains(line, "level=ERROR") || !strings.Contains(line, "unexpected EOF") {
		t.Errorf("logged %q, want the error at level ERROR", line)
	}
}
