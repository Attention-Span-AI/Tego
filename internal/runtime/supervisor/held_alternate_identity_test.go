// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A person's alternate must obey deny_read even when the secret's new name is
// ordinary, and even when the requested descriptor is write-only (ADR 0057 D2).
func TestHeldReadAlternateFollowsIdentity(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "rename", true: "replace-rename"}[replace], func(t *testing.T) {
			for _, flags := range []int{unix.O_RDONLY, unix.O_RDWR | unix.O_TRUNC, unix.O_WRONLY | unix.O_TRUNC} {
				t.Run(strconv.Itoa(flags), func(t *testing.T) {
					x, secret := heldReadsFixture(t, agent.RecordFull)
					x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "token", 60).WithHeldCompletion()
					if flags&unix.O_ACCMODE == unix.O_WRONLY {
						x.pol.Rules.Workdir = filepath.Join(x.dir, "work")
						x.pol.Rules.Gate = testGate(t, gate.WriteOutsideWorktree, "", 60).WithHeldCompletion()
					}
					x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
					alias := filepath.Join(x.dir, "alternate")
					l, _, asked := x.loop(t, func(req ask.Request) ask.Decision {
						if replace {
							fresh := filepath.Join(x.dir, "fresh")
							if err := os.WriteFile(fresh, []byte("new secret"), 0o600); err != nil {
								t.Fatal(err)
							}
							if err := os.Rename(fresh, secret); err != nil {
								t.Fatal(err)
							}
						}
						if err := os.Rename(secret, alias); err != nil {
							t.Fatal(err)
						}
						if _, err := req.Alternates.Check(altOf(t, alias)); err == nil {
							t.Error("answer-time check accepted a protected identity")
						}
						return alternateDecision(t, alias)
					})
					x.openAs(t, l, x.target, flags, 0)
					res, _ := x.f.lastResp()
					if len(*asked) != 1 || res.Error != -int32(unix.EACCES) || len(x.k.delivered) != 0 {
						t.Fatalf("asked %d, answer %+v, delivered %q: alternate supplied a protected identity", len(*asked), res, x.k.delivered)
					}
					if body, err := os.ReadFile(alias); err != nil || len(body) == 0 {
						t.Fatalf("protected alternate was truncated: %q %v", body, err)
					}
				})
			}
		})
	}
}

type heldAlternateAfterOpen struct {
	*heldAskKernel
	after func()
}

func (k *heldAlternateAfterOpen) OpenAlternate(h *heldAskOpen, a *ask.AlternateFile, flags int, probe bool, refuse func(string) string) (int, string, error) {
	fd, path, err := k.heldAskKernel.OpenAlternate(h, a, flags, probe, refuse)
	if err == nil && !probe {
		k.after()
	}
	return fd, path, err
}

func TestHeldReadAlternateRechecksHistoryAfterOpen(t *testing.T) {
	for _, mode := range []string{"benign", "late", "late-reply-lost"} {
		t.Run(mode, func(t *testing.T) {
			late, lost := mode != "benign", mode == "late-reply-lost"
			x, secret := heldReadsFixture(t, agent.RecordFull)
			x.pol.Rules.Gate = testGate(t, gate.ReadMatches, "token", 60).WithHeldCompletion()
			x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return alternateDecision(t, x.standIn) })
			if late {
				l.k = &heldAlternateAfterOpen{heldAskKernel: x.k, after: func() {
					// The opened alternate itself lands on the protected name: it is pinned there, and refused.
					if err := os.Rename(x.standIn, secret); err != nil {
						t.Fatal(err)
					}
					if lost {
						x.f.sendErrno = unix.ENOENT
					}
				}}
			}
			x.openAs(t, l, x.target, unix.O_RDWR|unix.O_TRUNC, 0)
			if !late {
				if len(x.k.delivered) != 1 {
					t.Fatal("benign alternate was not delivered")
				}
				return
			}
			res, _ := x.f.lastResp()
			if (!lost && res.Error != -int32(unix.EACCES)) || len(x.k.delivered) != 0 {
				t.Fatalf("answer %+v, delivered %q: an alternate moved onto the protected name", res, x.k.delivered)
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Rule != "fs.deny_read["+secret+"]" {
				t.Fatalf("refusal lines %+v", evs)
			}
			var p struct {
				record.FSPayload
				Completed bool   `json:"operation_completed"`
				Delivered bool   `json:"fd_delivered"`
				Unknown   bool   `json:"result_unknown"`
				Ret       *int64 `json:"syscall_ret"`
			}
			if err := json.Unmarshal(evs[0].Payload, &p); err != nil {
				t.Fatal(err)
			}
			if p.Path != x.standIn || p.AlternateFor != x.target || !p.Completed || p.Delivered || p.Unknown != lost ||
				(!lost && (p.Ret == nil || *p.Ret != -int64(unix.EACCES))) || (lost && p.Ret != nil) {
				t.Fatalf("late alternate refusal %s", evs[0].Payload)
			}
			if body, err := os.ReadFile(secret); err != nil || len(body) != 0 {
				t.Fatalf("completed truncation %q %v", body, err)
			}
		})
	}
}

// An approval on this loop's own pin (fs.ask_read here; fs.ask and a copied gate's ask share completeHeldAskOpen)
// reopens the pinned inode, so the retained launch identities decide it too: a preexisting hard link of the nested
// target under an fs.ask_read scope is refused before anyone is asked, and the approved file moved onto the protected
// name while the person decides is pinned there and refused.
func TestHeldReadIdentityHoldsUnderAnOwnPinAsk(t *testing.T) {
	for _, mode := range []string{"preexisting-hardlink", "moved-onto-the-target-while-asking"} {
		t.Run(mode, func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
			scope, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: scope, Resolved: scope, Kind: agent.FSDenyRead, AskRead: true, Raw: scope})
			target := filepath.Join(scope, "notes")
			if mode == "preexisting-hardlink" {
				if err := os.Link(secret, target); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte("benign"), 0o600); err != nil {
				t.Fatal(err)
			}
			l, sink, asked := x.loop(t, func(ask.Request) ask.Decision {
				if mode == "moved-onto-the-target-while-asking" {
					if err := os.Rename(target, secret); err != nil {
						t.Fatal(err)
					}
				}
				return ask.Decision{Approved: true, By: "uid:1 pid:2"}
			})
			x.openAs(t, l, target, unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()
			if len(x.k.completed) != 0 || res.Error != -int32(unix.EACCES) {
				t.Fatalf("completed %v, answer %+v: an approval delivered a protected identity", x.k.completed, res)
			}
			wantAsked, wantRule := 0, "fs.deny_read["+secret+"]"
			if mode == "moved-onto-the-target-while-asking" {
				wantAsked = 1
			}
			if len(*asked) != wantAsked || len(evs) != 1 || evs[0].Verdict != record.VerdictRefused ||
				evs[0].Reason != record.ReasonReadDenied || evs[0].Rule != wantRule {
				t.Fatalf("asked %d, lines %+v: want %d asks and one read-denied refusal by %s", len(*asked), evs, wantAsked, wantRule)
			}
		})
	}
}

// An approval on this loop's own pin is checked again on the descriptor CompleteAskOpen actually reopened, after the
// post-answer check and before ADDFD|SEND (review round 2, finding 2): the approved file put at a protected name
// during the completion is pinned there and refused, and a protected name's history made uncertain then refuses;
// either way the descriptor is not delivered and the line says the open completed.
func TestHeldReadOwnPinAskChecksTheReopenedDescriptor(t *testing.T) {
	for _, mode := range []string{"moved-onto-the-target", "uncertain-history"} {
		t.Run(mode, func(t *testing.T) {
			x, secret := heldReadsFixture(t, agent.RecordFull)
			x.pol.Rules.AskConfig = &agent.AskConfig{Hold: agent.AskHoldConnect, Timeout: agent.Duration(time.Minute), MaxPending: 4}
			scope, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: scope, Resolved: scope, Kind: agent.FSDenyRead, AskRead: true, Raw: scope})
			target := filepath.Join(scope, "notes")
			if err := os.WriteFile(target, []byte("benign"), 0o600); err != nil {
				t.Fatal(err)
			}
			x.k.beforeCheck = func() {
				if mode == "moved-onto-the-target" {
					if err := os.Rename(target, secret); err != nil {
						t.Error(err)
					}
					return
				}
				fresh := filepath.Join(x.dir, "fresh")
				if err := os.WriteFile(fresh, []byte("NEW SECRET"), 0o600); err != nil {
					t.Error(err)
				}
				if err := os.Rename(fresh, secret); err != nil {
					t.Error(err)
				}
				if err := os.Remove(secret); err != nil { // installed and gone before it could be pinned
					t.Error(err)
				}
			}
			l, sink, asked := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{Approved: true, By: "uid:1 pid:2"} })
			x.openAs(t, l, target, unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()
			want := "fs.deny_read[" + secret + "]"
			if mode == "uncertain-history" {
				want = ruleHeldIdentityUnknown
			}
			if len(*asked) != 1 || res.Error != -int32(unix.EACCES) || len(x.k.completed) != 0 || len(evs) != 1 ||
				evs[0].Verdict != record.VerdictRefused || evs[0].Rule != want {
				t.Fatalf("asked %d, answer %+v, completed %v, lines %+v: the reopened descriptor was delivered unchecked (want %s)", len(*asked), res, x.k.completed, evs, want)
			}
			p := decodeHeldOutcome(t, evs[0])
			if p.FDDelivered || p.SyscallRet == nil || *p.SyscallRet != -int64(unix.EACCES) {
				t.Fatalf("payload %s: want an undelivered descriptor and EACCES", evs[0].Payload)
			}
		})
	}
}
