// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// "Never allow" for a held write at a level wider than the fs.ask scope removes the asks at and beneath the wider
// folder. An fs.write entry beneath it decides its own subtree first (the nearest entry wins), so the effect the
// proposal words, "refuse writes to files under ./proj/", would not be true of the next run, and a person who read it
// believed a subtree was shut that stayed open. The proposal is refused instead, naming the entry.
func TestNeverAtAWiderLevelDoesNotClaimWhatANestedWriteEntryOverrides(t *testing.T) {
	const text = `version: 0
name: demo
fs:
  write: ["./proj/out/"]
  ask: ["./proj/held/", "./proj/held/deep/"]
exec:
  allow: [sh]
tier: landlock
`
	held := ev(t, record.KindRefused, "", "fs.ask[./proj/held/]", record.ReasonWriteOutsideContract,
		record.RefusedPayload{Op: "open", Target: "/p/proj/held/x.md"})
	_, err := Apply(Request{Contract: []byte(text), ContractPath: "/p/agent.yaml", Cwd: "/p", Event: held, Action: Block, Level: 2, Date: "2026-11-21"})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "fs.write[./proj/out/]") || !strings.Contains(err.Error(), "still allows its own subtree") {
		t.Fatalf("a wider never over a nested write entry was proposed: %v", err)
	}
	// With no write entry beneath, the same never goes through and takes every ask at and beneath the folder.
	clean := strings.Replace(text, `write: ["./proj/out/"]`, `write: ["./elsewhere/"]`, 1)
	res, err := Apply(Request{Contract: []byte(clean), ContractPath: "/p/agent.yaml", Cwd: "/p", Event: held, Action: Block, Level: 2, Date: "2026-11-21"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Effect, "in a profile this contract extends") {
		t.Fatalf("the effect claims what a profile's write entry could override: %q", res.Effect)
	}
	top := string(res.Text)
	if strings.Contains(top, "held/") {
		t.Fatalf("an ask beneath the wider folder was kept:\n%s", top)
	}
}
