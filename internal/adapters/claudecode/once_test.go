// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hookProcess starts the test binary as the hook over f's run, with stdin, and returns its stdout once it ends.
func hookProcess(t *testing.T, f *fixture, stdin []byte, start <-chan struct{}) (string, error) {
	cmd := exec.Command(os.Args[0], Harness) //nolint:gosec // the test binary itself, as the hook
	cmd.Env = f.env()
	budget := time.Minute // also bound helpers when go test is run with -timeout=0
	if deadline, ok := t.Deadline(); ok {
		budget = time.Until(deadline)
	}
	cmd.Env = append(cmd.Env, helperBudgetEnv+"="+budget.String())
	cmd.Stdin = bytes.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if start != nil {
		<-start
	}
	if err := cmd.Run(); err != nil {
		return "", err
	}
	if e.Len() != 0 {
		t.Errorf("hook stderr: %q", e.String())
	}
	return o.String(), nil
}

// told is, for every refusal a set of hook outputs lists, how many times it was listed (by its target), and how
// many refusals the outputs counted as not listed.
func told(t *testing.T, outputs []string) (listed map[string]int, notListed uint64) {
	t.Helper()
	listed = map[string]int{}
	for _, out := range outputs {
		if out == "" {
			continue
		}
		for _, line := range strings.Split(strings.TrimSuffix(context(t, out, EventPostToolUse), "\n"), "\n") {
			switch {
			case strings.HasPrefix(line, "Tego, "):
			case strings.HasPrefix(line, "- "):
				i := strings.Index(line, "/home/user/out-")
				if i < 0 || strings.HasPrefix(line, "- x") {
					t.Fatalf("line %q is no single refusal of the fixture", line)
				}
				listed[line[i:i+len("/home/user/out-00.txt")]]++
			case strings.HasSuffix(line, " more not listed."):
				n, err := strconv.ParseUint(strings.TrimSuffix(line, " more not listed."), 10, 64)
				if err != nil {
					t.Fatalf("line %q: %v", line, err)
				}
				notListed += n
			default:
				t.Fatalf("unexpected line %q", line)
			}
		}
	}
	return listed, notListed
}

// TestExactlyOnceAcrossProcesses is acceptance (2): 8 hook processes started at once over one state directory and a
// reason file of 50 refusals tell each refusal exactly once between them: one claims the 32 the ring lists and
// counts the 18 it no longer does, and the other seven print nothing.
func TestExactlyOnceAcrossProcesses(t *testing.T) {
	f := newFixture(t)
	f.refusals(t, 50)
	p := payload(t, "post-tool-use-bash")
	start := make(chan struct{})
	outputs := make([]string, 8)
	var wg sync.WaitGroup
	for i := range outputs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := hookProcess(t, f, p, start)
			if err != nil {
				t.Errorf("hook %d: %v", i, err)
			}
			outputs[i] = out
		}()
	}
	close(start)
	wg.Wait()
	listed, notListed := told(t, outputs)
	for i := uint64(18); i < 50; i++ {
		if n := listed[refusalAt(i).Payload.Target]; n != 1 {
			t.Errorf("refusal %d told %d times", i, n)
		}
	}
	if len(listed) != 32 || notListed != 18 {
		t.Errorf("%d listed and %d not listed, want 32 and 18", len(listed), notListed)
	}
	if s := f.state(t); s.Cursor != refusalAt(49).Seq || s.RefusalsDelivered != 50 || s.Deliveries != 1 {
		t.Errorf("state %+v", s)
	}
}

// TestExactlyOnceWhileTheRunRefuses: hook processes started over and over by 8 workers while the reason file grows
// one refusal at a time, as parallel tool calls see it, tell each of the 50 refusals at most once, and between the
// refusals they list and those they count as not listed, every one.
func TestExactlyOnceWhileTheRunRefuses(t *testing.T) {
	f := newFixture(t)
	p := payload(t, "post-tool-use-bash")
	var done atomic.Bool
	var mu sync.Mutex
	var outputs []string
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for last := false; !last; {
				last = done.Load()
				out, err := hookProcess(t, f, p, nil)
				if err != nil {
					t.Errorf("hook: %v", err)
					return
				}
				mu.Lock()
				outputs = append(outputs, out)
				mu.Unlock()
			}
		}()
	}
	for n := uint64(1); n <= 50; n++ {
		f.refusals(t, n)
		time.Sleep(2 * time.Millisecond) // about a hook process's start: refusals land between and during claims
	}
	done.Store(true)
	wg.Wait()
	listed, notListed := told(t, outputs)
	for target, n := range listed {
		if n != 1 {
			t.Errorf("%s told %d times", target, n)
		}
	}
	if uint64(len(listed))+notListed != 50 {
		t.Errorf("%d listed and %d not listed, want 50 in all (%d hook runs)", len(listed), notListed, len(outputs))
	}
	if s := f.state(t); s.Cursor != refusalAt(49).Seq || s.RefusalsDelivered != 50 {
		t.Errorf("state %+v", s)
	}
}
