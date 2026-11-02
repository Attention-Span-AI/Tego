// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveAlternateCase is a refusal the live Set holds on a folder, exports, which the compiled table does not protect.
type liveAlternateCase struct {
	name       string
	adjustable bool                                 // the table is an Adjustable run's, with a read fence entry at exports
	entry      func(exports string) liveblock.Entry // nil: nothing in the Set (the fence entry lifted)
	rule       func(exports string) string          // the rule the refusal names, "" when the alternate is delivered
}

func liveAlternateCases() []liveAlternateCase {
	return []liveAlternateCase{
		{"an Adjustable run's read fence entry not lifted", true,
			func(dir string) liveblock.Entry {
				return liveblock.Entry{Kind: liveblock.KindRead, Value: dir, By: "contract", At: time.Now(), Fence: true}
			},
			func(dir string) string { return "live.fence[read:" + dir + "]" }},
		{"a Locked run's live read block", false,
			func(dir string) liveblock.Entry {
				return liveblock.Entry{Kind: liveblock.KindRead, Value: dir, By: "uid:1 pid:2 cli", At: time.Now()}
			},
			func(dir string) string { return "live.block[read:" + dir + "]" }},
		{"a Locked run's live path block", false,
			func(dir string) liveblock.Entry {
				return liveblock.Entry{Kind: liveblock.KindPath, Value: dir, By: "uid:1 pid:2 cli", At: time.Now()}
			},
			func(dir string) string { return "live.block[path:" + dir + "]" }},
		{"an Adjustable run's read fence entry lifted", true, nil, func(string) string { return "" }},
	}
}

// liveAlternateSetup makes exports/q3.csv beneath dir, puts the case's table and Set on pol, and returns the file and
// the Set's loader.
func liveAlternateSetup(t *testing.T, dir string, pol *Policy, tc liveAlternateCase) (string, string, func() *liveblock.Set) {
	t.Helper()
	exports := filepath.Join(dir, "exports")
	q3 := filepath.Join(exports, "q3.csv")
	if err := os.Mkdir(exports, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(q3, []byte("revenue"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tc.adjustable {
		// compile took the entry's deny_read out of the table (ADR 0125 decision 2): only the live Set refuses it.
		pol.Rules.Live = &agent.LiveTable{Mode: agent.LiveAdjustable,
			Entries: []agent.LiveEntry{{Kind: agent.LiveKindRead, Value: exports, Source: agent.LiveSourceNew}}}
	}
	var set *liveblock.Set
	if tc.entry != nil {
		set = liveblock.CompileEntries([]liveblock.Entry{tc.entry(exports)}, 1, liveblock.Resolved{})
	}
	return exports, q3, func() *liveblock.Set { return set }
}

// TestAlternateUnderALiveRefusalIsRefused is a person's alternate inside an unlifted read fence entry, and the same
// gap for a live read or path block in any run: a person's alternate (ADR 0057) for a held read, at a file the live Set
// refuses the agent's own read of, is refused when the person answers, naming the live rule, and again at delivery, so
// nothing is delivered and the open is refused ask-unavailable. The compiled table does not protect the file (a live
// block is not in it; compile took a read fence entry's deny_read out), so without the live check it was handed over.
// It holds for a hold of this loop's own pin (an fs.ask_read entry) and for a gate-held ask on the deputy's pinned
// object. A lifted entry leaves the person's file deliverable.
func TestAlternateUnderALiveRefusalIsRefused(t *testing.T) {
	type outcome struct {
		check     error
		delivered []string
		lines     []*record.Event
		answer    int32
	}
	for _, tc := range liveAlternateCases() {
		t.Run(tc.name, func(t *testing.T) {
			judge := func(t *testing.T, exports string, o outcome) {
				t.Helper()
				want := tc.rule(exports)
				if want == "" {
					if o.check != nil || len(o.delivered) != 1 || o.delivered[0] != "revenue" {
						t.Fatalf("check %v, delivered %q: want the alternate in a lifted entry delivered", o.check, o.delivered)
					}
					return
				}
				if o.check == nil || !strings.Contains(o.check.Error(), want) {
					t.Fatalf("the check at answer time said %v; want the refusal by %s", o.check, want)
				}
				if len(o.delivered) != 0 || o.answer != -int32(unix.EACCES) || len(o.lines) != 1 ||
					o.lines[0].Verdict != record.VerdictRefused || o.lines[0].Reason != record.ReasonAskUnavailable {
					t.Fatalf("delivered %q, answer %d, lines %+v: want nothing delivered, EACCES, refused ask-unavailable",
						o.delivered, o.answer, o.lines)
				}
			}
			t.Run("fs.ask_read hold", func(t *testing.T) {
				x := newAskReadFixture(t)
				exports, q3, live := liveAlternateSetup(t, x.dir, x.pol, tc)
				x.live = live
				var check error
				l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
					_, check = req.Alternates.Check(altOf(t, q3))
					return alternateDecision(t, q3)
				})
				x.open(t, l, x.secret, unix.O_RDONLY)
				if len(*asked) != 1 {
					t.Fatalf("asked %d times, want once", len(*asked))
				}
				res, _ := x.f.lastResp()
				judge(t, exports, outcome{check, x.k.delivered, sink.all(), res.Error})
			})
			t.Run("gate-held ask", func(t *testing.T) {
				x := newHeldAskFixture(t)
				exports, q3, live := liveAlternateSetup(t, x.dir, x.pol, tc)
				x.live = live
				var check error
				l, sink, asked := x.loop(t, func(req ask.Request) ask.Decision {
					if req.Alternates == nil {
						t.Error("the request carried no alternate check")
						return ask.Decision{Reason: ask.ReasonDenied}
					}
					_, check = req.Alternates.Check(altOf(t, q3))
					return alternateDecision(t, q3)
				})
				x.open(t, l, x.target, unix.O_RDONLY)
				if len(*asked) != 1 {
					t.Fatalf("asked %d times, want once", len(*asked))
				}
				if len(x.dep.opened) != 0 || len(x.k.heldDelivered) != 0 {
					t.Fatalf("the deputy opened %v, delivered %q: an alternate never opens the target", x.dep.opened, x.k.heldDelivered)
				}
				res, _ := x.f.lastResp()
				judge(t, exports, outcome{check, x.k.delivered, sink.all(), res.Error})
			})
		})
	}
}

// TestAlternateLiveSetIsLoadedWhenChecked: the live Set an alternate is put to is the one in force when the check runs,
// not when the request was made: a block made after the request refuses the alternate at the answer, and a block made
// after the answer refuses it at delivery, with nothing delivered.
func TestAlternateLiveSetIsLoadedWhenChecked(t *testing.T) {
	for _, tc := range []struct {
		name        string
		blockBefore bool // the block lands after the request, before the person's answer is checked
	}{
		{"blocked between the request and the answer", true},
		{"blocked between the answer and the delivery", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newAskReadFixture(t)
			exports := filepath.Join(x.dir, "exports")
			q3 := filepath.Join(exports, "q3.csv")
			if err := os.Mkdir(exports, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(q3, []byte("revenue"), 0o600); err != nil {
				t.Fatal(err)
			}
			var cur atomic.Pointer[liveblock.Set]
			x.live = cur.Load
			block := liveblock.CompileEntries([]liveblock.Entry{{Kind: liveblock.KindRead, Value: exports, By: "uid:1 pid:2 cli", At: time.Now()}}, 2, liveblock.Resolved{})
			var check error
			l, sink, _ := x.loop(t, func(req ask.Request) ask.Decision {
				if tc.blockBefore {
					cur.Store(block)
				}
				_, check = req.Alternates.Check(altOf(t, q3))
				cur.Store(block)
				return alternateDecision(t, q3)
			})
			x.open(t, l, x.secret, unix.O_RDONLY)
			rule := "live.block[read:" + exports + "]"
			if tc.blockBefore != (check != nil) || check != nil && !strings.Contains(check.Error(), rule) {
				t.Fatalf("the check at answer time said %v; want a refusal by %s: %v", check, rule, tc.blockBefore)
			}
			res, _ := x.f.lastResp()
			evs := sink.all()
			if len(x.k.delivered) != 0 || res.Error != -int32(unix.EACCES) || len(evs) != 1 || evs[0].Reason != record.ReasonAskUnavailable {
				t.Fatalf("delivered %q, answer %+v, lines %+v: want the delivery refused under the block in force then", x.k.delivered, res, evs)
			}
		})
	}
}

// alternateLiveRefusal judges the agent's own open: a read block refuses a read alternate and not a write one, a write
// block the reverse, a path block both, and an O_RDWR alternate meets read and write blocks alike (liveAccess).
func TestAlternateLiveRefusalFollowsTheOpensAccess(t *testing.T) {
	const dir = "/w/exports"
	set := func(k liveblock.Kind) *liveblock.Set {
		return liveblock.CompileEntries([]liveblock.Entry{{Kind: k, Value: dir, By: "uid:1 pid:2 cli", At: time.Now()}}, 1, liveblock.Resolved{})
	}
	for _, tc := range []struct {
		kind  liveblock.Kind
		flags int
		want  bool
	}{
		{liveblock.KindRead, unix.O_RDONLY, true},
		{liveblock.KindRead, unix.O_WRONLY | unix.O_TRUNC, false},
		{liveblock.KindRead, unix.O_RDWR, true},
		{liveblock.KindWrite, unix.O_RDONLY, false},
		{liveblock.KindWrite, unix.O_WRONLY, true},
		{liveblock.KindPath, unix.O_RDONLY, true},
		{liveblock.KindPath, unix.O_WRONLY, true},
	} {
		why := alternateLiveRefusal(set(tc.kind), dir+"/q3.csv", tc.flags)
		if got := why != ""; got != tc.want {
			t.Errorf("a %s block, flags %#x: refusal %q, want refused %v", tc.kind, tc.flags, why, tc.want)
		}
		if why := alternateLiveRefusal(set(tc.kind), "/w/other/q3.csv", tc.flags); why != "" {
			t.Errorf("a %s block refused a file outside it: %q", tc.kind, why)
		}
	}
	if why := alternateLiveRefusal(nil, dir+"/q3.csv", unix.O_RDONLY); why != "" {
		t.Errorf("no Set refused: %q", why)
	}
}
