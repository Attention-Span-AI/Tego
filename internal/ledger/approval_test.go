// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func localAnswerEvent(t *testing.T) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindAnswer, Source: record.SourceSupervisor}
	if err := e.SetPayload(struct {
		record.AnswerPayload
		record.AnswerAuthority
		Approved bool `json:"approved"`
	}{record.AnswerPayload{AskID: "q-00000000000000000000000000000000", By: "uid:0 pid:42"}, record.AnswerAuthority{Actor: &record.LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}}, true}); err != nil {
		t.Fatal(err)
	}
	return e
}

func localWriter(t *testing.T) *Writer {
	t.Helper()
	w, _, _ := openTestWriter(t)
	t.Cleanup(func() { _ = w.Abandon() })
	start := startPayload()
	start.RecordMinor = record.MinorLocalRoles
	start.LocalApprovalAuthority = &record.LocalApprovalAuthority{Mode: "owner_only", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AgentUID: 1001}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestLocalRolesAnswerSyncOrderAndPlacement(t *testing.T) {
	w := localWriter(t)
	oldFile, oldDir := syncApprovalFile, fsyncDir
	defer func() { syncApprovalFile, fsyncDir = oldFile, oldDir }()
	var order []string
	syncApprovalFile = func(f *os.File) error { order = append(order, "events"); return f.Sync() }
	fsyncDir = func(d *sys.FD) error { order = append(order, "directory"); return d.Fsync() }
	if err := w.AppendSync(localAnswerEvent(t)); err != nil {
		t.Fatal(err)
	}
	if len(order) != 3 || order[0] != "events" || order[1] != "directory" || order[2] != "directory" {
		t.Fatalf("durability order %v", order)
	}
}

func TestLocalRolesRequiredSyncFailuresPoisonApprovals(t *testing.T) {
	for _, which := range []string{"file", "run directory", "parent directory", "unsupported directory sync"} {
		t.Run(which, func(t *testing.T) {
			w := localWriter(t)
			oldFile, oldDir := syncApprovalFile, fsyncDir
			defer func() { syncApprovalFile, fsyncDir = oldFile, oldDir }()
			calls := 0
			syncApprovalFile = func(f *os.File) error {
				if which == "file" {
					return syscall.EIO
				}
				return f.Sync()
			}
			fsyncDir = func(d *sys.FD) error {
				calls++
				if which == "run directory" && calls == 1 || which == "parent directory" && calls == 2 {
					return syscall.EIO
				}
				if which == "unsupported directory sync" {
					return syscall.EINVAL
				}
				return d.Fsync()
			}
			if err := w.AppendSync(localAnswerEvent(t)); err == nil {
				t.Fatal("required sync failure acknowledged")
			}
			if err := w.Append(localAnswerEvent(t)); err == nil {
				t.Fatal("poisoned writer granted again")
			}
		})
	}
}

func TestLocalRolesShortWriteAndValidationNeverAcknowledge(t *testing.T) {
	for _, which := range []string{"short write", "invalid actor", "below minor"} {
		t.Run(which, func(t *testing.T) {
			w := localWriter(t)
			e := localAnswerEvent(t)
			switch which {
			case "short write":
				w.out = partialWriter{w.events, 8, io.ErrShortWrite}
			case "invalid actor":
				e.Payload = []byte(`{"ask_id":"q-00000000000000000000000000000000","by":"uid:0 pid:42","approved":true,"actor":{"uid":1001,"pid":42,"start_boot_ns":10,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}}`)
			case "below minor":
				w.minor = record.MinorLearn // a revision before the local roles one
			}
			err := w.AppendSync(e)
			if err == nil {
				t.Fatal("failed record acknowledged")
			}
			if which == "short write" && !errors.Is(err, ErrShortWrite) {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalRolesInitialDurabilityIsRequired(t *testing.T) {
	w := localWriter(t)
	old := syncApprovalFile
	defer func() { syncApprovalFile = old }()
	syncApprovalFile = func(*os.File) error { return syscall.EIO }
	if err := w.Sync(); err == nil {
		t.Fatal("initial record sync failure accepted")
	}
}

// The Writer holds every answer to its run's floor: under it an answer says who decided it, and a run that did not
// start under it never writes an actor or a system cause (a root claim belongs only to the root-only floor).
func TestLocalRolesWriterHoldsAnswersToTheRunsFloor(t *testing.T) {
	plain := func(t *testing.T) *record.Event {
		t.Helper()
		e := localAnswerEvent(t)
		e.Payload = []byte(`{"ask_id":"q-00000000000000000000000000000000","by":"uid:1000","approved":true}`)
		return e
	}
	noFloorWriter := func(t *testing.T) *Writer {
		t.Helper()
		w, _, _ := openTestWriter(t)
		t.Cleanup(func() { _ = w.Abandon() })
		start := startPayload()
		start.RecordMinor = record.MinorLocalRoles
		if err := w.WriteRunStart(start); err != nil {
			t.Fatal(err)
		}
		return w
	}
	if err := localWriter(t).Append(plain(t)); err == nil {
		t.Error("an answer without its actor or cause was written under the floor")
	}
	if err := localWriter(t).AppendSync(localAnswerEvent(t)); err != nil {
		t.Errorf("a root answer under the floor: %v", err)
	}
	if err := noFloorWriter(t).AppendSync(localAnswerEvent(t)); err == nil {
		t.Error("an actor was written in a run that did not start under the floor")
	}
	if err := noFloorWriter(t).Append(plain(t)); err != nil {
		t.Errorf("a plain answer in a run without the floor: %v", err)
	}
}
