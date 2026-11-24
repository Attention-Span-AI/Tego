// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"errors"
	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"os"
	"testing"
	"time"
)

func TestBoundedServicePreservesGuardRefusal(t *testing.T) {
	f := newFixture(t)
	svc := &Service{Ledger: f.ledger, Home: f.s.Home}
	entries, err := svc.Contracts()
	if err != nil || len(entries) != 2 {
		t.Fatalf("catalogue=%+v err=%v", entries, err)
	}
	cur, err := svc.Current(entries[0].Ref)
	if err != nil || cur.Base == "" || len(cur.Text) == 0 {
		t.Fatalf("current=%+v err=%v", cur, err)
	}
	if _, err := svc.Current("not-a-recorded-ref"); !errors.Is(err, ErrNoContract) {
		t.Fatalf("lost typed no-contract refusal: %v", err)
	}
	req := ChangeReq{Ref: entries[0].Ref, Base: cur.Base, Edits: []Edit{{Key: "exec.allow", Op: "add", Entry: "false"}}}
	if _, err := svc.PlanChange(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedServicePreviewAndGuardedWrite(t *testing.T) {
	f := newFixture(t)
	machine := config.Builtin()
	machine.Home = f.s.Home
	machine.LedgerRoot.Value = f.ledger
	svc := &Service{Ledger: f.ledger, Home: f.s.Home, Machine: machine, PATH: "/usr/bin:/bin"}
	ctx, closeHelpers := contracts.WithHelperSession(context.Background())
	defer closeHelpers()
	request := svc.ForRequest(ctx)
	current, err := request.Current(RefLexical(f.contract))
	if err != nil {
		t.Fatal(err)
	}
	raw := RawReq{Ref: current.Ref, Base: current.Base, Text: append(append([]byte(nil), current.Text...), []byte("\n# guarded helper write\n")...)}
	plan, err := request.PlanRaw(ctx, raw)
	if err != nil || plan.Err != "" || plan.Ack == "" {
		t.Fatalf("preview=%+v err=%v", plan, err)
	}
	if _, err := request.ApplyRaw(ctx, raw); !errors.Is(err, ErrNeedsAck) {
		t.Fatalf("write without ack: %v", err)
	}
	raw.Ack = plan.Ack
	applied, err := request.ApplyRaw(ctx, raw)
	if err != nil || applied == nil || applied.ID == "" {
		t.Fatalf("applied=%+v err=%v", applied, err)
	}
	text, err := os.ReadFile(f.contract)
	if err != nil || !bytes.Contains(text, []byte("guarded helper write")) {
		t.Fatalf("written=%q err=%v", text, err)
	}
	if _, err := request.ApplyRaw(ctx, raw); !errors.Is(err, ErrReviewGone) {
		t.Fatalf("consumed review replay accepted: %v", err)
	}
}

// A draft compile is not the location (ADR 0144): a compiler child that takes longer to start than the helper's
// whole location budget still answers, because the helper's location clock stops while it compiles and the child's
// start sits under the compile's start-up allowance, not its three seconds.
func TestSlowCompilerChildDoesNotSpendTheLocationsBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("takes longer than the location budget")
	}
	f := newFixture(t)
	machine := config.Builtin()
	machine.Home = f.s.Home
	machine.LedgerRoot.Value = f.ledger
	svc := &Service{Ledger: f.ledger, Home: f.s.Home, Machine: machine, PATH: "/usr/bin:/bin"}
	ctx, closeHelpers := contracts.WithHelperSession(context.Background())
	defer closeHelpers()
	request := svc.ForRequest(ctx)
	current, err := request.Current(RefLexical(f.contract))
	if err != nil {
		t.Fatal(err)
	}
	raw := RawReq{Ref: current.Ref, Base: current.Base, Text: append(append([]byte(nil), current.Text...), []byte("\n"+slowChildMark+"\n")...)}
	begin := time.Now()
	plan, err := request.PlanRaw(ctx, raw)
	if err != nil || plan.Err != "" || plan.Ack == "" {
		t.Fatalf("a slow compiler child was refused after %v: plan=%+v err=%v", time.Since(begin), plan, err)
	}
	if took := time.Since(begin); took < contracts.CheckTimeout {
		t.Fatalf("the child did not take longer than the location budget (%v): the test proves nothing", took)
	}
}
