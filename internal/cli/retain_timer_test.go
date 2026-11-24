// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type unitCall struct{ argv []string }

// fakeUnits records the programs ensureRetentionTimer would start; active says the timer exists.
type fakeUnits struct {
	calls  []unitCall
	active bool
	fail   bool
}

func (f *fakeUnits) run(_ context.Context, argv ...string) ([]byte, error) {
	f.calls = append(f.calls, unitCall{argv})
	switch {
	case argv[0] == "systemctl" && !f.active:
		return nil, errors.New("inactive")
	case argv[0] == "systemd-run" && f.fail:
		return nil, errors.New("refused")
	}
	return nil, nil
}

func machineWithGC(d time.Duration) *config.Machine {
	m := &config.Machine{}
	m.GCInterval.Value = d
	return m
}

// TestRetentionRunsWithoutAnyRunStarting: A machine that sets gc_interval gets a user timer that
// runs `tego gc` once a day and makes up a missed day, so a pass no longer waits for a `tego run` start.
func TestRetentionRunsWithoutAnyRunStarting(t *testing.T) {
	f := &fakeUnits{}
	if !ensureRetentionTimer(t.Context(), machineWithGC(time.Hour), "/home/u/.local/bin/tego", "/home/u/always.yaml", f.run) {
		t.Fatal("no timer made for a machine with gc_interval set")
	}
	if len(f.calls) != 2 {
		t.Fatalf("calls %v, want the is-active probe and one systemd-run", f.calls)
	}
	got := f.calls[1].argv
	if got[0] != "systemd-run" {
		t.Fatalf("second call %v, want systemd-run", got)
	}
	for _, want := range []string{"--user", "--unit=tego-gc", "--on-calendar=daily", "--timer-property=Persistent=true",
		"--property=Type=oneshot", "--setenv=TEGO_CONFIG=/home/u/always.yaml"} {
		if !slices.Contains(got, want) {
			t.Errorf("systemd-run argv %v lacks %s", got, want)
		}
	}
	if n := len(got); got[n-2] != "/home/u/.local/bin/tego" || got[n-1] != "gc" {
		t.Errorf("the timer runs %v, want this program with gc and no flag (the start's pass)", got[len(got)-2:])
	}
	if slices.ContainsFunc(got, func(a string) bool { return strings.Contains(a, "--keep") || a == "--dry-run" }) {
		t.Errorf("argv %v changes the pass's retention: the timer must run the machine's own", got)
	}
}

func TestRetentionTimerIsNotMadeWhenItWouldBeWrong(t *testing.T) {
	cases := []struct {
		name string
		m    *config.Machine
		self string
		f    *fakeUnits
	}{
		{"gc_interval 0 means remove nothing unasked", machineWithGC(0), "/bin/tego", &fakeUnits{}},
		{"a timer already active is the person's", machineWithGC(time.Hour), "/bin/tego", &fakeUnits{active: true}},
		{"a program path systemd would expand", machineWithGC(time.Hour), "/opt/$HOME/tego", &fakeUnits{}},
		{"no machine", nil, "/bin/tego", &fakeUnits{}},
		{"systemd-run refused", machineWithGC(time.Hour), "/bin/tego", &fakeUnits{fail: true}},
	}
	for _, c := range cases {
		if ensureRetentionTimer(t.Context(), c.m, c.self, "", c.f.run) {
			t.Errorf("%s: a timer was reported made", c.name)
		}
	}
}
