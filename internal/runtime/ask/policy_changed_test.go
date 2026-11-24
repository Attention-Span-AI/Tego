// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

func TestLocalRolesRootPolicyChangedRefusal(t *testing.T) {
	for _, approve := range []bool{false, true} {
		b, _ := localBroker(t, func(o *Options) {
			o.OwnerOnly.Check = func() error { return os.ErrNotExist }
		})
		id, done := localHold(t, b)
		_, err := b.answer(t.Context(), id, approve, false, nil, localRoot())
		if askproto.Code(err) != "approval-policy-changed" || errors.Is(err, askproto.ErrOwnerOnly) || !strings.Contains(err.Error(), "the approval policy file changed since this run started") || !b.Waiting() {
			t.Fatalf("approve=%v: root got %v (code %s), pending=%v", approve, err, askproto.Code(err), b.Waiting())
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		if d := <-done; d.Approved {
			t.Fatal("policy drift granted the held action")
		}
	}
}

func TestLocalRolesPostRecordPolicyChangedRefusal(t *testing.T) {
	for _, approve := range []bool{false, true} {
		var lost atomic.Bool
		b, _ := localBroker(t, func(o *Options) {
			o.OwnerOnly.Check = func() error {
				if lost.Load() {
					return os.ErrNotExist
				}
				return nil
			}
			o.Emit = func(e Event) error {
				if e.Kind == "answer" {
					lost.Store(true)
				}
				return nil
			}
		})
		id, done := localHold(t, b)
		d, err := b.answer(t.Context(), id, approve, false, nil, localRoot())
		if askproto.Code(err) != "approval-policy-changed" || b.Waiting() {
			t.Fatalf("approve=%v: post-record drift got %v (code %s), pending=%v", approve, err, askproto.Code(err), b.Waiting())
		}
		for _, got := range []Decision{d, <-done} {
			if got.Approved || got.Actor != nil || got.SystemCause != "unavailable" || got.Reason != ReasonUnavailable {
				t.Fatalf("approve=%v: post-record drift delivered answer: %+v", approve, got)
			}
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// Drift after selection but before append still records a system refusal, and
// the answerer needs the policy remedy rather than a generic unavailable result.
func TestLocalRolesPreRecordPolicyChangedRefusal(t *testing.T) {
	for _, approve := range []bool{false, true} {
		var reads atomic.Int32
		b, _ := localBroker(t, func(o *Options) {
			o.OwnerOnly.Check = func() error {
				if reads.Add(1) >= 5 {
					return os.ErrNotExist
				}
				return nil
			}
		})
		id, done := localHold(t, b)
		result, err := b.answer(t.Context(), id, approve, false, nil, localRoot())
		if !errors.Is(err, askproto.ErrApprovalPolicyChanged) || b.Waiting() {
			t.Fatalf("approve=%v: pre-record policy drift lost recovery: %v, pending=%v", approve, err, b.Waiting())
		}
		for _, got := range []Decision{result, <-done} {
			if got.Approved || got.Actor != nil || got.SystemCause != "unavailable" {
				t.Fatalf("drift released actor decision: %+v", got)
			}
		}
	}
}

// The source can change while the final live peer read is in progress. A policy
// read from before that work cannot authorize delivery afterwards.
func TestLocalRolesPolicyChangeDuringFinalPeerRead(t *testing.T) {
	for _, approve := range []bool{false, true} {
		t.Run(map[bool]string{false: "deny", true: "approve"}[approve], func(t *testing.T) {
			var recorded, changed atomic.Bool
			b, _ := localBroker(t, func(o *Options) {
				o.Emit = func(e Event) error {
					if e.Kind == "answer" {
						recorded.Store(true)
					}
					return nil
				}
				o.Authorize = func(Peer) error {
					if recorded.Load() {
						changed.Store(true)
					}
					return nil
				}
				o.OwnerOnly.Check = func() error {
					if changed.Load() {
						return os.ErrNotExist
					}
					return nil
				}
			})
			id, done := localHold(t, b)
			d, err := b.answer(t.Context(), id, approve, false, nil, localRoot())
			if !errors.Is(err, askproto.ErrApprovalPolicyChanged) {
				t.Fatalf("policy edit during final peer read escaped recheck: decision=%+v err=%v", d, err)
			}
			for _, got := range []Decision{d, <-done} {
				if got.Approved || got.Actor != nil || got.SystemCause != "unavailable" {
					t.Fatalf("changed source delivered: %+v", got)
				}
			}
		})
	}
}
