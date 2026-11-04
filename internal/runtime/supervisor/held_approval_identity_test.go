// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An approval never grants an object the contract denies, whatever its access mode (review round 2, finding 3): a
// write-only O_TRUNC open of a hard-link alias of a launch-protected file is refused before anyone is asked, under an
// fs.ask scope (this loop's own pin) and through the open deputy's ask range (a held gate ask), and the protected
// file keeps its bytes. Before, both were asked, approved and truncated the file, while the protected name itself
// was refused for the same write.
func TestHeldWriteOnlyApprovalOfAProtectedAliasIsRefused(t *testing.T) {
	for _, via := range []string{"fs.ask", "held-gate-ask"} {
		t.Run(via, func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
			alias := filepath.Join(x.dir, "alias")
			if via == "fs.ask" {
				scope, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				x.pol.Rules.FSAsk = []agent.FSRule{{Path: scope, Resolved: scope, Kind: agent.FSAsk, Raw: scope}}
				alias = filepath.Join(scope, "notes")
			} else {
				x.pol.Rules.Workdir = filepath.Join(x.dir, "work")
				x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 60).WithHeldCompletion()
			}
			if err := os.Link(secret, alias); err != nil {
				t.Fatal(err)
			}
			l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
			x.openAs(t, l, alias, unix.O_WRONLY|unix.O_TRUNC, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()
			if len(*asked) != 0 || res.Error != -int32(unix.EACCES) || len(x.k.completed) != 0 || len(x.k.heldDelivered) != 0 {
				t.Fatalf("asked %d, answer %+v, completed %v, delivered %q: a write-only alias of a protected file was approved", len(*asked), res, x.k.completed, x.k.heldDelivered)
			}
			if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != "fs.deny_read["+secret+"]" {
				t.Fatalf("lines %+v: want one refusal by the protected target's rule", evs)
			}
			if body, err := os.ReadFile(secret); err != nil || string(body) != "TOKEN=real" {
				t.Fatalf("the protected file now holds %q (%v)", body, err)
			}
		})
	}
}

// A deputy approval rechecks the identities and the names' history once the answer is back, before the deputy opens
// (review round 3, finding 2): the pinned file, put at the protected name while the person decides, is refused and
// keeps its bytes. Before, the approved O_WRONLY|O_TRUNC truncated it and only the descriptor check refused delivery.
func TestHeldGateAskRechecksIdentityAfterTheAnswer(t *testing.T) {
	x, secret := heldReadsFixture(t, agent.RecordFull)
	x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
	x.pol.Rules.Workdir = filepath.Join(x.dir, "work")
	x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 60).WithHeldCompletion()
	target := filepath.Join(x.dir, "notes")
	if err := os.WriteFile(target, []byte("protected-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, sink, asked := x.loop(t, func(ask.Request) ask.Decision {
		if err := os.Rename(target, secret); err != nil {
			t.Error(err)
		}
		return ask.Decision{Approved: true, By: "uid:1 pid:2"}
	})
	x.openAs(t, l, target, unix.O_WRONLY|unix.O_TRUNC, 0)
	res, _ := x.f.lastResp()
	evs := sink.all()
	if len(*asked) != 1 || res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 {
		t.Fatalf("asked %d, answer %+v, delivered %q: the approval opened a file made protected during the wait", len(*asked), res, x.k.heldDelivered)
	}
	if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != "fs.deny_read["+secret+"]" {
		t.Fatalf("lines %+v: want one refusal by the protected target's rule", evs)
	}
	if body, err := os.ReadFile(secret); err != nil || string(body) != "protected-bytes" {
		t.Fatalf("the protected file now holds %q (%v): truncated before the refusal", body, err)
	}
}
