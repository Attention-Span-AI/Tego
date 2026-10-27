// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mvpDeployment is a deployment block that is well formed: refused in a ledger only for its revision.
func mvpDeployment() *record.Deployment {
	return &record.Deployment{ID: "dep_01hzx3k7q9w8e6r5t4y3v2m1n0", Name: "nightly-triage", Revision: 1,
		RevisionHash: strings.Repeat("ab", 32), Instance: 1, Trigger: record.DeployTriggerStart}
}

// TestWriterRefusesMVPFieldsItsRevisionDoesNotAdmit: the Writer encodes every line at its run's revision
// (record.Event.MarshalLineAt), so run_start, an action line and run_end that carry a reserved-revision field below its
// record minor, or a malformed one at it, are refused by the field's code and nothing reaches events.jsonl.
func TestWriterRefusesMVPFieldsItsRevisionDoesNotAdmit(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	low := startPayload()
	low.RecordMinor = record.Minor
	low.Deployment = mvpDeployment()
	if err := w.WriteRunStart(low); record.FieldCode(err) != "below-minor" {
		t.Fatalf("run_start at %d with a deployment: %v, want [below-minor]", record.Minor, err)
	}
	bad := startPayload()
	bad.RecordMinor = record.MinorShares
	bad.Deployment = mvpDeployment()
	bad.Deployment.ID, bad.Deployment.Revision = "BOGUS", -1
	if err := w.WriteRunStart(bad); record.FieldCode(err) != "deployment-id" {
		t.Fatalf("run_start with deployment id BOGUS: %v, want [deployment-id]", err)
	}
	bad.Deployment = nil
	bad.Shares = []record.ShareUse{{Name: "root", Path: "/", Mode: "rwx"}}
	if err := w.WriteRunStart(bad); record.FieldCode(err) != "share-path" {
		t.Fatalf("run_start with a share of /: %v, want [share-path]", err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, EventsFile)); err != nil || len(data) != 0 {
		t.Fatalf("events.jsonl after the refusals: %q, %v; want it empty", data, err)
	}
	start := startPayload()
	start.RecordMinor = record.Minor
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	e := fsEvent("/home/u/proj/a", struct {
		record.FSPayload
		record.LineRedactions
	}{record.FSPayload{Op: record.FSOpen, Path: "/home/u/proj/a", Flags: 0x241},
		record.LineRedactions{Redactions: []record.Redaction{{Secret: "github", Version: 2, Count: 1}}}})
	if err := w.Append(e); record.FieldCode(err) != "below-minor" {
		t.Fatalf("a line with redactions at %d: %v, want [below-minor]", record.Minor, err)
	}
	err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, StoppedBy: "not-a-principal"})
	if record.FieldCode(err) != "below-minor" {
		t.Fatalf("Close with stopped_by at %d: %v, want [below-minor]", record.Minor, err)
	}
	if got := readAll(t, dir); len(got) != 1 || got[0].Kind != record.KindRunStart {
		t.Fatalf("the ledger holds %d lines, want run_start alone", len(got))
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("Close without the refused field: %v", err)
	}
}

// rewriteLine replaces line i of the run's events.jsonl with e re-encoded by MarshalLine, which applies Validate alone
// (a writer that skipped those rules), relinks every later line to it, and moves the anchor to the new head.
func rewriteLine(t *testing.T, dir string, anchor *memAnchor, i int, edit func(*record.Event)) {
	t.Helper()
	events := readAll(t, dir)
	edit(events[i])
	var out []byte
	prev := ""
	for _, e := range events {
		e.Prev, e.ID = prev, ""
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		out = append(append(out, line...), '\n')
		prev = e.ID
	}
	if err := os.WriteFile(filepath.Join(dir, EventsFile), out, 0o600); err != nil {
		t.Fatal(err)
	}
	if anchor != nil {
		anchor.heads[testRef.ID] = prev
	}
}

// TestVerifyRefusesMVPFieldsItsRevisionDoesNotAdmit: Verify (tego events --verify) holds every line to its schema at
// the run's revision, the run_start's record_minor: a stopped_by in a ledger at record.Minor, or a malformed share at
// MinorShares, fails the run, whose chain and anchor are otherwise whole, by the field's code.
func TestVerifyRefusesMVPFieldsItsRevisionDoesNotAdmit(t *testing.T) {
	for _, c := range []struct {
		name, code string
		minor      int
		line       int
		edit       func(*record.Event)
	}{
		{"stopped_by below 30", "below-minor", record.Minor, 1, func(e *record.Event) {
			e.Payload = mustSet(t, e, record.RunEndPayload{Reason: record.RunEndStopped, StoppedBy: "person:p-0123456789abcdef"})
		}},
		{"a share of /", "share-path", record.MinorShares, 0, func(e *record.Event) {
			p := startPayload()
			p.RecordMinor = record.MinorShares
			p.Shares = []record.ShareUse{{Name: "root", Path: "/", Mode: record.ShareModeRW}}
			e.Payload = mustSet(t, e, p)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, dir, anchor := openTestWriter(t)
			start := startPayload()
			start.RecordMinor = c.minor
			if err := w.WriteRunStart(start); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndStopped}); err != nil {
				t.Fatal(err)
			}
			if rep := verify(t, dir, anchor); rep.Lines != 2 {
				t.Fatalf("the unedited run verifies %d lines, want 2", rep.Lines)
			}
			rewriteLine(t, dir, anchor, c.line, c.edit)
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			_, err = r.Verify(context.Background(), anchor)
			if record.FieldCode(err) != c.code || !errors.Is(err, record.ErrInvalidEvent) {
				t.Fatalf("Verify = %v, want [%s]", err, c.code)
			}
		})
	}
}

// TestResumeRefusesMVPFieldsItsRevisionDoesNotAdmit: a dead writer's ledger whose run_start carries a deployment
// below MinorDeployment is not resumed (ErrUnverified), as a line Validate refuses is not.
func TestResumeRefusesMVPFieldsItsRevisionDoesNotAdmit(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	start := startPayload()
	start.RecordMinor = record.Minor
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	rewriteLine(t, dir, nil, 0, func(e *record.Event) {
		start.Deployment = mvpDeployment()
		e.Payload = mustSet(t, e, start)
	})
	_, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if !errors.Is(err, ErrUnverified) || record.FieldCode(err) != "below-minor" {
		t.Fatalf("resume = %v, want ErrUnverified [below-minor]", err)
	}
}

// TestCloseRefusesARunEndItCannotWriteAndStaysOpen: a run_end the Writer refuses (a stopped_by its revision does not
// admit, a malformed one, an unknown reason) is refused before anything is closed, so the run keeps its lock and its
// descriptors and the caller can Close again with a run_end the Writer can write: the run then ends with that run_end,
// its fsync and its anchor, and a third Close is ErrAlreadyClosed.
func TestCloseRefusesARunEndItCannotWriteAndStaysOpen(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	start := startPayload()
	start.RecordMinor = record.MinorShares
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		end  record.RunEndPayload
		code string
	}{
		{record.RunEndPayload{Reason: record.RunEndStopped, StoppedBy: "service:deploy-" + strings.Repeat("a", 60)}, "stopped-by"},
		{record.RunEndPayload{Reason: record.RunEndExit, StoppedBy: "person:p-0123456789abcdef"}, "stopped-by-reason"},
		{record.RunEndPayload{Reason: "no-such-reason"}, ""},
	} {
		err := w.Close(c.end)
		if err == nil || !errors.Is(err, record.ErrInvalidEvent) || record.FieldCode(err) != c.code {
			t.Fatalf("Close(%+v) = %v, want ErrInvalidEvent [%s]", c.end, err, c.code)
		}
	}
	if anchor.heads[testRef.ID] != "" {
		t.Fatalf("the refused run_ends anchored %q", anchor.heads[testRef.ID])
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndStopped, StoppedBy: "person:p-0123456789abcdef"}); err != nil {
		t.Fatalf("Close with a run_end the Writer can write, after the refusals: %v", err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndStopped}); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("a third Close = %v, want ErrAlreadyClosed", err)
	}
	got := readAll(t, dir)
	if len(got) != 2 || got[1].Kind != record.KindRunEnd || got[1].Seq != 1 || anchor.heads[testRef.ID] != got[1].ID {
		t.Fatalf("the ledger holds %d lines, anchored at %q; want run_start and the run_end anchored", len(got),
			anchor.heads[testRef.ID])
	}
	if rep := verify(t, dir, anchor); rep.Lines != 2 {
		t.Fatalf("Verify read %d lines, want 2", rep.Lines)
	}
}

// TestWriterAndVerifyReadOneRevision: a run_start whose payload spells record_minor twice, record_minor 17 and
// RECORD_MINOR 34, would be read at 34 by a case-insensitive reader taking the last copy as the caller wrote them and at
// 17 once the line's keys are sorted. The Writer refuses it [field-case] and writes nothing, and Verify fails a ledger
// holding one by the same code, so the Writer never keeps a revision its own resume and Verify read otherwise.
func TestWriterAndVerifyReadOneRevision(t *testing.T) {
	twice := func(t *testing.T, e *record.Event) json.RawMessage {
		start := startPayload()
		start.RecordMinor = record.Minor
		start.Deployment = mvpDeployment()
		p := mustSet(t, e, start)
		return append(json.RawMessage(strings.TrimSuffix(string(p), "}")), `,"RECORD_MINOR":34}`...)
	}
	w, dir, anchor := openTestWriter(t)
	e := record.Event{Kind: record.KindRunStart, Source: record.SourceSupervisor, PID: 1, TID: 1}
	e.Payload = twice(t, &e)
	if err := w.Append(&e); record.FieldCode(err) != "field-case" {
		t.Fatalf("a run_start spelling record_minor twice: %v, want [field-case]", err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, EventsFile)); err != nil || len(data) != 0 {
		t.Fatalf("events.jsonl after the refusal: %d bytes, %v; want it empty", len(data), err)
	}
	start := startPayload()
	start.RecordMinor = record.Minor
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	rewriteLine(t, dir, anchor, 0, func(e *record.Event) { e.Payload = twice(t, e) })
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Verify(context.Background(), anchor); record.FieldCode(err) != "field-case" {
		t.Fatalf("Verify = %v, want [field-case]", err)
	}
}

// mustSet is e's payload set to p.
func mustSet(t *testing.T, e *record.Event, p any) json.RawMessage {
	t.Helper()
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	return e.Payload
}
