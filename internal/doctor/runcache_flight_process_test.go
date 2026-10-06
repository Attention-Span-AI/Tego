// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

type flightEvent struct {
	Event    string `json:"event"`
	Programs int    `json:"programs,omitempty"`
	Fanotify int    `json:"fanotify,omitempty"`
	Plane    int    `json:"plane,omitempty"`
	Cached   bool   `json:"cached,omitempty"`
	Offered  bool   `json:"offered,omitempty"`
}

// TestRunProbeFlightProcess runs the real scope/cache path used by ForRun in a
// separate test process. Only the machine's answers are injected; it creates no
// BPF program, fanotify mark, backend or governed actor.
func TestRunProbeFlightProcess(t *testing.T) {
	if os.Getenv("TEGO_DOCTOR_FLIGHT_HELPER") != "1" {
		return
	}
	k := testKey()
	c := &runCache{base: os.Getenv("TEGO_DOCTOR_FLIGHT_DIR"), dir: []string{"run", "tego"}, owner: os.Geteuid(),
		key: func(string, int) (runCacheKey, bool) { return k, true }}
	emit := func(e flightEvent) {
		if err := json.NewEncoder(os.Stdout).Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	var n calls
	ch := passingChecks(&n)
	btf := ch.btf
	ch.btf = func() Result {
		emit(flightEvent{Event: "initial-miss"}) // D1 found no BTF-bearing entry.
		return btf()
	}
	programs := ch.programs
	ch.programs = func(root bool, uid int, v Version, tier, capture []hook) (Result, []HookResult) {
		emit(flightEvent{Event: "probe"})
		var release [1]byte
		if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
			t.Fatal(err)
		}
		p, rows := programs(root, uid, v, tier, capture)
		if os.Getenv("TEGO_DOCTOR_FLIGHT_FAILURE") == "programs" {
			p.OK = false
		}
		return p, rows
	}
	if os.Getenv("TEGO_DOCTOR_FLIGHT_FAILURE") == "plane" {
		plane := ch.plane
		ch.plane = func(root bool, uid int, release, pin string, keep bool) (*PlaneState, []HookResult) {
			p, rows := plane(root, uid, release, pin, keep)
			p.Modes[0].Faulted = true
			return p, rows
		}
	}
	st := scope{reach: backend.TierCgroup, root: true, checks: ch, cache: c}.run(context.Background())
	allBuilt(&st)
	emit(flightEvent{Event: "done", Programs: n.n[CheckPrograms], Fanotify: n.n[CheckFanotify], Plane: n.plane,
		Cached: st.cached != nil, Offered: st.probe()[backend.TierCgroup]})
}

type flightChild struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	events <-chan flightEvent
	err    <-chan error
}

func startFlightChild(t *testing.T, base string, extraEnv ...string) flightChild {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunProbeFlightProcess$")
	cmd.Env = append(os.Environ(), "TEGO_DOCTOR_FLIGHT_HELPER=1", "TEGO_DOCTOR_FLIGHT_DIR="+base)
	cmd.Env = append(cmd.Env, extraEnv...)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	events, finished := make(chan flightEvent, 8), make(chan error, 1)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			var e flightEvent
			if json.Unmarshal(scanner.Bytes(), &e) == nil && e.Event != "" {
				events <- e
			}
		}
		finished <- cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = input.Close()
		_ = cmd.Process.Kill() // the original, still-unreaped owned test child only
	})
	return flightChild{cmd: cmd, input: input, events: events, err: finished}
}

func (c flightChild) next(t *testing.T, event string) flightEvent {
	t.Helper()
	select {
	case e, ok := <-c.events:
		if !ok || e.Event != event {
			t.Fatalf("owned helper event=%+v open=%v; want %s", e, ok, event)
		}
		return e
	case <-time.After(5 * time.Second):
		t.Fatalf("owned helper did not reach %s", event)
	}
	return flightEvent{}
}

func (c flightChild) release(t *testing.T) {
	t.Helper()
	if _, err := c.input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
}

func (c flightChild) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-c.err:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned helper failed to exit")
	}
}

// TestForRunConcurrentColdMissRechecksPublishedAnswer proves both callers have
// missed before the leader publishes. The original path loads D7 twice even if
// the follower reaches D7 after publication; an in-process mutex cannot pass.
func TestForRunConcurrentColdMissRechecksPublishedAnswer(t *testing.T) {
	c, _ := testCache(t)
	leader := startFlightChild(t, c.base)
	leader.next(t, "initial-miss")
	leader.next(t, "probe")
	follower := startFlightChild(t, c.base)
	follower.next(t, "initial-miss")
	// Release both inputs: the follower must not actually read its input because
	// it reuses a validated answer instead of entering the injected expensive probe.
	follower.release(t)
	leader.release(t)
	first := leader.next(t, "done")
	var second flightEvent
	select {
	case e := <-follower.events:
		if e.Event == "probe" {
			second = follower.next(t, "done")
		} else {
			second = e
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follower did not finish")
	}
	leader.wait(t)
	follower.wait(t)
	if first.Programs+second.Programs != 1 || first.Fanotify+second.Fanotify != 1 || first.Plane+second.Plane != 1 ||
		!first.Offered || !second.Offered || first.Cached || !second.Cached {
		t.Fatalf("two cold callers did not share only the validated published probe: leader=%+v follower=%+v", first, second)
	}
}

func TestForRunProbeFlightHolderDeathReprobesWithoutAnswer(t *testing.T) {
	c, _ := testCache(t)
	leader := startFlightChild(t, c.base)
	leader.next(t, "initial-miss")
	leader.next(t, "probe")
	follower := startFlightChild(t, c.base)
	follower.next(t, "initial-miss")
	follower.release(t)
	if err := leader.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	follower.next(t, "probe")
	done := follower.next(t, "done")
	follower.wait(t)
	select {
	case err := <-leader.err:
		if err == nil {
			t.Fatal("terminated leader unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminated owned leader was not reaped")
	}
	if done.Cached || !done.Offered || done.Programs != 1 || done.Fanotify != 1 || done.Plane != 1 {
		t.Fatalf("dead holder was mistaken for a published answer: %+v", done)
	}
}

func TestForRunProbeFlightFailedOrPartialAnswerKeepsOriginalSemantics(t *testing.T) {
	for _, failure := range []string{"programs", "plane"} {
		t.Run(failure, func(t *testing.T) {
			c, _ := testCache(t)
			leader := startFlightChild(t, c.base, "TEGO_DOCTOR_FLIGHT_FAILURE="+failure)
			leader.next(t, "initial-miss")
			leader.next(t, "probe")
			follower := startFlightChild(t, c.base)
			follower.next(t, "initial-miss")
			follower.release(t)
			leader.release(t)
			leader.next(t, "done")
			wantPrograms, wantFan, wantCached := 0, 0, true
			if failure == "programs" {
				follower.next(t, "probe")
				wantPrograms, wantFan, wantCached = 1, 1, false
			}
			done := follower.next(t, "done")
			leader.wait(t)
			follower.wait(t)
			if done.Programs != wantPrograms || done.Fanotify != wantFan || done.Cached != wantCached || done.Plane != 1 || !done.Offered {
				t.Fatalf("%s completion changed original cache authority: %+v", failure, done)
			}
		})
	}
}
