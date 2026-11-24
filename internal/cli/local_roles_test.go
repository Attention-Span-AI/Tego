// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runlock"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLocalRolesCLIRefusesSameUID(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the caller is the owner-only deciding role (root outside any governed run), so there is no other uid to refuse")
	}
	const id = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	dir := filepath.Join(t.TempDir(), id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "test"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	start, err := tegoruntime.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteLockInfo([]byte((tegoruntime.LockInfo{PID: os.Getpid(), StartBootNS: start}).String())); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	b, err := ask.New(dir, ask.Options{UID: uint32(os.Getuid()), Timeout: 5 * time.Second, Authorize: func(ask.Peer) error { return nil }, Emit: func(ask.Event) error { return nil }, Pending: func(r ask.Request) { ready <- r.AskID }, OwnerOnly: &ask.OwnerOnlyAuthority{AgentUID: 1001, Check: func() error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	done := make(chan struct{})
	go func() {
		_, _ = b.Request(t.Context(), ask.Request{Op: "connect", Target: "127.0.0.1:443", Hold: "connect", PID: os.Getpid(), TID: os.Getpid()})
		close(done)
	}()
	q := <-ready
	for _, approve := range []bool{false, true} {
		var out, errs bytes.Buffer
		name := "deny"
		if approve {
			name = "approve"
		}
		code := askAt(t.Context(), name, id, dir, q, approve, false, false, "", &out, &errs)
		if code != identity.ExitLauncher || out.Len() != 0 || !strings.Contains(errs.String(), "root from a terminal outside any governed run") || !b.Waiting() {
			t.Fatalf("%s code=%d out=%s err=%s waiting=%v", name, code, &out, &errs, b.Waiting())
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestLocalRolesCLIRecordedIdentity(t *testing.T) {
	actor := &record.LocalApprovalActor{PID: 42, StartBootNS: 10, UserNamespace: record.InitialUserNamespace, Source: "kernel-local-uid", Role: "owner"}
	for _, tc := range []struct {
		a    record.AnswerAuthority
		want string
	}{{record.AnswerAuthority{Actor: actor}, "root (uid 0), role Owner, pid 42"}, {record.AnswerAuthority{SystemCause: "timeout"}, "system: timeout"}} {
		a := askRecord{AnswerSeq: 2, Approved: tc.a.Actor != nil, AnswerAuthority: tc.a}
		if tc.a.SystemCause != "" {
			a.AnswerReason = "ask-timeout"
		}
		if got := a.words(true); !strings.Contains(got, tc.want) {
			t.Fatalf("recorded identity: %s", got)
		}
	}
}

// A caller that cannot prove the run's launcher (root without CAP_SYS_PTRACE, whose proof is refused by the
// launcher's descriptors) is not told it is the wrong role: the refusal wraps fs.ErrPermission, and in a root-only
// (managed) mode that must not read as "only root may answer" (review F1; GAPS C85).
func TestLocalRolesCLIKeepsHiddenLauncherWords(t *testing.T) {
	hidden := fmt.Errorf("%w: pid 4242: %w; the launcher's descriptors are hidden from this user (it is not dumpable)",
		runlock.ErrNotLockHolder, fmt.Errorf("read launcher descriptors: %w", fs.ErrPermission))
	old := askLauncher
	askLauncher = func(string) (*runlock.StopTarget, error) { return nil, hidden }
	t.Cleanup(func() { askLauncher = old })
	for _, managed := range []bool{true, false} {
		var out, errs bytes.Buffer
		code := askAt(t.Context(), "approve", "r-any", t.TempDir(), "a1", true, false, false, "", &out, &errs, managed)
		got := errs.String()
		if code != identity.ExitLauncher || out.Len() != 0 || !strings.Contains(got, "the launcher's descriptors are hidden from this user") ||
			strings.Contains(got, "only root may answer") || strings.Contains(got, "root from a terminal outside any governed run") {
			t.Fatalf("managed=%v code=%d out=%q err=%q", managed, code, &out, got)
		}
	}
}
