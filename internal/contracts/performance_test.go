// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestContractsHealthyCommandPerformance is an opt-in ordinary-build measurement.
// The driver creates a fresh test process per command; helper execs run the same
// TestMain dispatch as production. Fixture creation is outside the timed region.
func TestContractsHealthyCommandPerformance(t *testing.T) {
	raw := os.Getenv("ACCFIX_PERF_ENTRIES")
	if raw == "" {
		return
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 2000 {
		t.Fatalf("invalid performance entry count %q", raw)
	}
	f, o := fixture(t)
	o.KeepTableFor = ""
	for i := range n {
		name := fmt.Sprintf("agent%04d", i)
		path := filepath.Join(f.Root, "sources", name+".yaml")
		write(t, path, strings.Replace(simpleContract, "name: fixture", "name: "+name, 1))
		o.Snapshot.Runs = append(o.Snapshot.Runs, run(path, f.Root, name, "", "landlock", fmt.Sprintf("r-fixture-%08d", i)))
	}
	if barrier := os.Getenv("ACCFIX_PERF_BARRIER"); barrier != "" {
		if err := os.WriteFile(barrier+"."+strconv.Itoa(os.Getpid())+".ready", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Minute)
		for {
			if _, err := os.Stat(barrier); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("performance driver did not release barrier")
			}
			time.Sleep(time.Millisecond)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	begin := time.Now()
	c := Discover(ctx, o)
	if err := PrintList(io.Discard, c, false); err != nil {
		t.Fatal(err)
	}
	states := map[string]int{}
	for _, entry := range c.Contracts {
		states[entry.State]++
	}
	fmt.Printf("PERF entries=%d found=%d wall=%.6f exit=%d incomplete=%t states=%v\n", n, len(c.Contracts), time.Since(begin).Seconds(), c.ExitCode(), c.Incomplete, states)
	for _, issue := range c.Issues {
		fmt.Printf("PERF issue=%s %s\n", issue.Code, issue.Message)
	}
	for _, entry := range c.Contracts {
		if entry.State == "incomplete" && len(entry.Diagnostics) > 0 {
			fmt.Printf("PERF refusal=%s\n", entry.Diagnostics[0].Message)
			break
		}
	}
}
