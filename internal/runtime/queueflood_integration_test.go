// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAFloodOfRefusalsLosesNoLines end to end: eight processes making refused connects
// for 3 s left 17,748 lines and 97,538 drops on one queue every producer shared, so the agent chose which of
// the run's lines were lost. The supervisor now has its own lane and waits for room, which slows the flooding
// agent to the ledger's pace instead: no line is dropped. That includes the lines of the agent's last
// connects, still waiting for room when it exits: shutdown released them before joining the workers, and CI's
// 2-CPU runner lost one per worker (run #33); TestShutdownJoinsWaitingSupervisorWorkersWhileReading pins that
// ordering on its own.
func TestAFloodOfRefusalsLosesNoLines(t *testing.T) {
	py, err := filepath.EvalSymlinks("/usr/bin/python3") // resolved: exec.allow names the binary the kernel runs
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	f := newFixture(t, fmt.Sprintf(`version: 0
name: iflood
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: summary
`, py))
	script := filepath.Join(f.dir, "flood.py")
	body := `import json, os, socket, sys, time
end = time.monotonic() + float(sys.argv[1])
n = 0
errnos = {}
while time.monotonic() < end:
    s = socket.socket()
    try:
        s.connect(("10.255.255.1", 443))
    except OSError as e:
        errnos[e.errno] = errnos.get(e.errno, 0) + 1
    s.close()
    n += 1
print(json.dumps({"pid": os.getpid(), "attempts": n, "errnos": errnos}))
`
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	cmd := fmt.Sprintf("for i in 1 2 3 4 5 6 7 8; do %s %s 3 & done; wait", py, script)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// The terminal is slower than the flood on every machine, as the ledger was on CI's 2-CPU runner (run #33),
	// so the supervisor lane is full and its workers are waiting for room when the agent exits: the state in
	// which shutdown dropped one line per waiting worker. On a fast machine the ledger kept up, the lane was not
	// full at the end, and the test passed whatever shutdown did.
	sink := &slowSink{per: 100 * time.Microsecond}
	deps := f.deps(t, nil)
	deps.Sink = sink
	actorOutput, err := os.CreateTemp(t.TempDir(), "actor-results-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = actorOutput.Close() }()
	deps.Stdio.Out = actorOutput
	var diagnostics floodDiagnostics
	deps.Logger = slog.New(slog.NewJSONHandler(&diagnostics, &slog.HandlerOptions{Level: slog.LevelError}))
	res, err := Run(ctx, f.rt, []string{"/bin/sh", "-c", cmd}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	actorResults, err := os.ReadFile(actorOutput.Name())
	if err != nil {
		t.Fatal(err)
	}
	refused, dropped := 0, 0
	kinds := make(map[string]int)
	gapReasons := make(map[string]int)
	var sampleNet *record.Event
	var sampleGap *record.Event
	for _, e := range sink.all() {
		kinds[fmt.Sprintf("%s/%s/%s", e.Kind, e.Source, e.Verdict)]++
		if sampleNet == nil && e.Kind == record.KindNet {
			sampleNet = e
		}
		if e.Kind == record.KindNet && e.Verdict == record.VerdictRefused {
			refused++
		}
		var g record.GapPayload
		if e.Kind == record.KindGap && e.DecodePayload(&g) == nil {
			gapReasons[g.What+"/"+g.Why]++
			if sampleGap == nil && g.What != record.GapCapture {
				sampleGap = e
			}
			if g.Why == GapChannelFull {
				dropped += g.Count
			}
		}
	}
	t.Logf("result %+v: %d refused net lines written, %d events dropped as channel-full; actor results: %s", res, refused, dropped, actorResults)
	if refused == 0 {
		t.Logf("recorded kinds: %v; gap reasons: %v; first net event: %+v", kinds, gapReasons, sampleNet)
		if sampleGap != nil {
			t.Logf("first gap payload: %s", sampleGap.Payload)
		}
		t.Logf("bounded operational diagnostics: %s", diagnostics.data)
		t.Fatal("the flood wrote no refused connect: the test proves nothing")
	}
	if dropped > 0 {
		t.Errorf("the agent's own syscall flood made the run drop %d events", dropped)
	}
	if panics := gapReasons[record.GapRecord+"/handler-panic"]; panics != 0 {
		t.Errorf("the flood caused %d handler panics: %s", panics, diagnostics.data)
	}
	attempts, actors := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(actorResults)), "\n") {
		var result struct {
			PID      int         `json:"pid"`
			Attempts int         `json:"attempts"`
			Errnos   map[int]int `json:"errnos"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatalf("actor result %q: %v", line, err)
		}
		if result.PID <= 0 || result.Attempts <= 0 || len(result.Errnos) != 1 || result.Errnos[13] != result.Attempts {
			t.Fatalf("actor did not complete solely refused connects: %+v", result)
		}
		actors++
		attempts += result.Attempts
	}
	if actors != 8 || attempts != refused {
		t.Errorf("%d actors attempted %d refused connects; recorded %d refusal action lines", actors, attempts, refused)
	}
}

// floodDiagnostics retains the first errors without allowing a panic flood to
// turn failure diagnostics into an unbounded allocation. slog writes serially;
// the explicit lock also makes that invariant local to this writer.
type floodDiagnostics struct {
	mu   sync.Mutex
	data []byte
}

func (d *floodDiagnostics) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	const max = 64 << 10
	if remaining := max - len(d.data); remaining > 0 {
		d.data = append(d.data, p[:min(len(p), remaining)]...)
	}
	return len(p), nil
}

// slowSink is a pipeline terminal that takes per for every event, standing in for a ledger slower than the
// agent's flood, and collects what it is given.
type slowSink struct {
	per time.Duration
	collectSink
}

func (s *slowSink) Emit(ev *record.Event) {
	time.Sleep(s.per)
	_ = s.append(ev)
}
