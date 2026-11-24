// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestContractsCommandDeadline(t *testing.T) {
	start := time.Now()
	ctx, cancel := contractsContext(context.Background())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(start.Add(60*time.Second)) || deadline.After(time.Now().Add(60*time.Second)) {
		t.Fatalf("whole-command deadline: %v, present %v", deadline, ok)
	}
	parent, stop := context.WithDeadline(context.Background(), start.Add(time.Second))
	defer stop()
	bounded, done := contractsContext(parent)
	defer done()
	got, _ := bounded.Deadline()
	want, _ := parent.Deadline()
	if !got.Equal(want) {
		t.Fatal("extended caller deadline")
	}
	stop()
	if bounded.Err() != context.Canceled {
		t.Fatal("caller cancellation ignored")
	}
}

func TestContractsCancelledCommandSkipsMachineRead(t *testing.T) {
	newRegistryWorld(t)
	badConfig := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(badConfig, []byte("not_a_config_key: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", badConfig)
	command := cmdContracts()
	fs := flag.NewFlagSet("contracts", flag.ContinueOnError)
	command.Flags(fs)
	if err := fs.Parse([]string{"--json"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errs bytes.Buffer
	code := command.Run(ctx, fs, &out, &errs)
	var c contracts.Catalog
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if code != identity.ExitError || !c.Incomplete || len(c.Issues) != 1 || c.Issues[0].Code != "interrupted" {
		t.Fatalf("read machine context after cancellation: exit %d issues %+v stderr %s", code, c.Issues, errs.String())
	}
}

// From inside a run, or where that cannot be told, tego contracts' helper checks are a governed program's, which
// never take the helper slots kept for a person's own checks; outside every run they are the person's.
func TestContractsChecksInsideARunAreGoverned(t *testing.T) {
	prev := selfAnswer
	t.Cleanup(func() { selfAnswer = prev })
	for _, c := range []struct {
		in   bool
		err  error
		want bool
	}{{false, nil, false}, {true, nil, true}, {true, errors.New("cgroup unreadable"), true}} {
		selfAnswer = func() runscope.Answer {
			switch {
			case c.err != nil:
				return answertest.Recorded(runscope.CauseProbeError, 0)
			case c.in:
				return answertest.Inside(runscope.CauseGoverned)
			}
			return answertest.Outside()
		}
		if got := contracts.GovernedCaller(contractsCaller(context.Background())); got != c.want {
			t.Errorf("in run %v (%v): governed %v, want %v", c.in, c.err, got, c.want)
		}
	}
}
