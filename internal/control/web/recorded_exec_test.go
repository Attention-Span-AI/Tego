// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecordedExecPathConsumers: the Block action of an allowed program start names the whole program, and the fold
// key of a program names its base name, when the path holds a space: both read the line's recorded arguments, not the
// first word of the command line the row shows. A command that names its program by a bare name keeps the name block
// it had. The receipt recognises the agent from the recorded command the same way.
func TestRecordedExecPathConsumers(t *testing.T) {
	root := t.TempDir()
	writeLines(t, root, actRun, []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off", ContractHash: strings.Repeat("0", 64), Command: []string{"/opt/my tools/codex"}, Cwd: "/w", Kernel: "6", StopGrace: "1s"}),
		ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/opt/my tools/curl", Argv: []string{"/opt/my tools/curl", "--help"}, ExecID: "x/1/1"}, allowedBy("exec[curl]")),
		ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/opt/my tools/wget", Argv: []string{"wget", "-q"}, ExecID: "x/2/1"}, allowedBy("exec[wget]")),
	})
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	evs := snap.Find(actRun).AllEvents()
	for i, want := range map[int]string{1: "/opt/my tools/curl", 2: "wget"} {
		a := rowActsOf(evs[i], true, true)
		link, err := url.Parse(a.Block)
		if err != nil {
			t.Fatal(err)
		}
		if got := link.Query().Get("value"); got != want || link.Query().Get("block") != string(liveblock.KindExec) {
			t.Errorf("line %d: the Block link names %q (%s), want the program %q", i, got, a.Block, want)
		}
	}
	key, prog := progKey(ledgerview.Row{Event: evs[1]})
	if prog != "/opt/my tools/curl" || !strings.HasSuffix(key, "\x00curl") {
		t.Errorf("program key %q path %q, want the program /opt/my tools/curl folded as curl", key, prog)
	}
	if key, prog := progKey(ledgerview.Row{Event: evs[2]}); key != "" || prog != "" {
		t.Errorf("a program named by a bare name has the fold key %q (%q); it had none", key, prog)
	}
	v := &receiptView{R: &ledgerview.Receipt{Command: []string{"/opt/my tools/codex", "--no-daemon"}}}
	if chips := v.SensChips("/home/u/.codex/auth.json", 0, 1, 0); len(chips) != 1 || chips[0].Class != "b-neutral" {
		t.Errorf("the agent at /opt/my tools/codex is not recognised: its own login reads %+v", chips)
	}
}
