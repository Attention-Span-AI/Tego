// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestContractsCancelledChecksDoNotRead(t *testing.T) {
	_, o := fixture(t)
	c := Catalog{machine: o.Machine, Contracts: []Entry{
		{Name: "first", Path: "/mnt/dead/first.yaml", LastRun: lastRun(metadataRunID, time.Unix(1, 0).UTC(), "observe", "")},
		{Name: "second", Path: "/mnt/dead/second.yaml"},
		{Name: "third", Path: "/mnt/dead/third.yaml"},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.checkEntries(ctx, o)
	if !c.Incomplete || c.ExitCode() != identity.ExitError {
		t.Fatalf("cancelled catalog: %+v", c)
	}
	for _, e := range c.Contracts {
		if e.State != "incomplete" || len(e.Diagnostics) != 1 || e.Diagnostics[0].Code != "check-interrupted" {
			t.Errorf("cancelled entry: %+v", e)
		}
		if e.LastRun != nil && e.LastRun.Tier == "observe" && e.LastRun.SameContract != "not-enforced" {
			t.Errorf("cancelled observed run acquired an enforcement comparison: %+v", e.LastRun)
		}
	}
}

func TestContractsHungSourceUsesCheckDeadline(t *testing.T) {
	_, o := fixture(t)
	// This unit check covers cooperative cancellation only. Process exit with a
	// non-returning pathname syscall is checked separately.
	path := "/mnt/dead/contract.yaml"
	started := time.Now()
	sawDeadline := false
	c := Catalog{machine: o.Machine}
	e := Entry{Path: path}
	c.checkSource(context.Background(), &e, o, func(ctx context.Context, got string, _ rulefile.Guard) ([]byte, error) {
		if got != path {
			t.Fatalf("path %q", got)
		}
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Sub(started) > CheckTimeout+time.Second {
			t.Fatal("missing per-contract deadline")
		}
		sawDeadline = true
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if !sawDeadline {
		t.Fatal("blocking filesystem stand-in was not called")
	}
	if time.Since(started) > CheckTimeout+2*time.Second {
		t.Fatal("check did not return after its deadline")
	}
	if e.State != "incomplete" || !c.Incomplete {
		t.Fatalf("deadline hidden: %+v", c)
	}
}

func TestContractsCallerDeadlineWins(t *testing.T) {
	_, o := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c := Catalog{machine: o.Machine}
	e := Entry{Path: "/mnt/dead/contract.yaml"}
	c.checkSource(ctx, &e, o, func(ctx context.Context, _ string, _ rulefile.Guard) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if ctx.Err() != context.DeadlineExceeded || e.State != "incomplete" {
		t.Fatalf("caller deadline: %+v", c)
	}
}
