// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stallReaderAgent opens and reads data.txt every 50 ms for 5 s, and does nothing else: no exec, no write, no connect.
const stallReaderAgent = `import time
end = time.time() + 5
while time.time() < end:
    with open("data.txt") as f:
        f.read()
    time.sleep(0.05)
`

// TestAReaderTheFilterNotifiesIsNotAStall: at tier landlock a read-open reaches the
// supervisor only when the filter notifies it, which a read gate makes it do for every one. Under record: off each
// notification the supervisor answers is activity, and under summary each read the gate scores is a line, so a pure
// reader under a read gate is not ended by a stall_after shorter than its reading, which is why compile no longer warns
// that it is ([stall-reads-unseen], pkg/spec/agent TestStallWarningFollowsWhatTheFilterNotifies). The same reader with
// no gate is ended limit-stall under off, which is what the warning describes.
func TestAReaderTheFilterNotifiesIsNotAStall(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	const readGate = "gate:\n  rules:\n    - 'fs.read matches \"*.pem\"': 10\n"
	for _, tc := range []struct {
		name, record, gate string
		stalls             bool
	}{
		{"off, read gate", "off", readGate, false},
		{"summary, read gate", "summary", readGate, false},
		{"off, no gate", "off", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := contractFor("stallreads", []string{python, "./agent.py"}, []string{python, resolved})
			c = strings.Replace(c, "  pids: 128", "  pids: 128\n  stall_after: 2s", 1)
			c = strings.Replace(c, "record: summary", "record: "+tc.record+"\n"+tc.gate, 1)
			f := newFixture(t, c)
			for name, body := range map[string]string{"agent.py": stallReaderAgent, "data.txt": strings.Repeat("x", 100)} {
				if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			res, err := Run(context.Background(), f.rt, []string{python, "./agent.py"}, f.deps(t, nil))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			var stalled bool
			for _, ev := range events(t, runDirs(t, f.root)[0]) {
				stalled = stalled || ev.Kind == record.KindLimit
			}
			if tc.stalls {
				if res.Reason != record.RunEndLimit || !stalled {
					t.Fatalf("record: %s with no read gate: a pure reader ended %s (limit line %v), want limit-stall", tc.record, res.Reason, stalled)
				}
				return
			}
			if res.Reason != record.RunEndExit || stalled {
				t.Fatalf("record: %s under a read gate: a pure reader ended %s (limit line %v), want its own exit", tc.record, res.Reason, stalled)
			}
		})
	}
}
