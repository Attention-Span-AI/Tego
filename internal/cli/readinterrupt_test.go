// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestReadingCommandsStopOnTheFirstSignal: the first SIGINT or SIGTERM only cancels the command's context
// (R29), so events, events --last and measure, which ignored it, streamed a multi-million-event ledger on
// until a second signal. With the context already cancelled each stops within a few thousand lines and
// says interrupted, 125, rather than printing the whole record.
func TestReadingCommandsStopOnTheFirstSignal(t *testing.T) {
	root := gcRoot(t)
	id, err := identity.NewRunID([32]byte{}, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, string(id))
	w, err := ledger.Open(dir, record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	const n = 5000
	for range n {
		e := &record.Event{
			Kind: record.KindFS, Source: record.SourceLandlock, PID: 1, TID: 1,
			Rule: "fs.read[/tmp]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
			Attr: &record.Attribution{Confidence: "unattributed", Method: "none"},
		}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/tmp/x"}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	refused := events.Filter{Kinds: []record.Kind{record.KindRefused, record.KindGap, record.KindLimit}}
	for name, call := range map[string]func(*bytes.Buffer, *bytes.Buffer) int{
		"events": func(out, errs *bytes.Buffer) int {
			return runEvents(ctx, string(id), events.Filter{}, false, false, out, errs)
		},
		"events --json": func(out, errs *bytes.Buffer) int {
			return runEvents(ctx, string(id), events.Filter{}, false, true, out, errs)
		},
		"events --last": func(out, errs *bytes.Buffer) int { return runEvents(ctx, string(id), refused, true, false, out, errs) },
		"measure":       func(out, errs *bytes.Buffer) int { return runMeasure(ctx, string(id), false, out, errs) },
	} {
		var out, errs bytes.Buffer
		code := call(&out, &errs)
		if code != identity.ExitError || !strings.Contains(errs.String(), "interrupted") {
			t.Errorf("%s: exit %d, want %d and \"interrupted\" (stderr %q)", name, code, identity.ExitError, errs.String())
		}
		if rows := strings.Count(out.String(), "\n"); rows >= n {
			t.Errorf("%s: printed %d lines after the signal, the whole record", name, rows)
		}
	}
}
