// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestNoChoiceOffersWhatABuiltinRefusal: the event page's "Act on this" offered Allow, and Ask me, for a connect that a
// built-in refusal always refuses (the session bus, here), and picking either wrote a contract that does not compile
// (an entry no contract lifts, ADR 0113; its amendment of 2026-11-11).
// With the real compiler the choices are checked: Allow and Ask are not possible for such a socket, and say why in the
// words the pages use for that refusal; Block stays (it removes an entry, and there is none); a socket no built-in
// covers keeps all its choices; and picking Allow by hand says the same, with nothing written.
func TestNoChoiceOffersWhatABuiltinRefusal(t *testing.T) {
	f := newFixture(t)
	f.s.Compile = nil
	m := config.Builtin()
	m.Home = f.s.Home
	f.s.Machine = m
	f.s.PATH = "/usr/bin:/bin"
	uid, _ := config.InvokingUID()
	bus := filepath.Join(config.LogindRuntimeRoot, strconv.Itoa(uid), "bus")
	refused := func(target, rule string) *record.Event {
		return ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "connect", Target: target}, func(e *record.Event) {
			e.Rule, e.Reason = rule, record.ReasonNetNotAllowed
		})
	}
	const run = "r-aaaa-0009-rules"
	f.writeRun(t, run, f.contract, 5, refused("unix:"+bus, "builtin.host_ipc"), refused("unix:/srv/ops/restart-app.sock", "unmatched"))
	ctx := context.Background()
	const hostIPC = "Built in (Host IPC refused): this socket is refused in every run, so no contract line can allow it or ask about it"

	p, err := f.s.ActOn(ctx, ActReq{Run: run, Seq: 3})
	if err != nil || p.Err != "" {
		t.Fatalf("ActOn: %+v, %v", p, err)
	}
	for _, c := range p.Choices {
		if c.Scope.Host {
			continue // a unix socket names no host
		}
		switch c.Action {
		case "block":
			if c.OK || !strings.Contains(c.Why, "already refused (builtin.host_ipc)") {
				t.Errorf("block: OK %v, why %q: there is no entry to remove", c.OK, c.Why)
			}
		default:
			if c.OK || c.Why != hostIPC {
				t.Errorf("%s at %+v: OK %v, why %q, want it refused with %q", c.Action, c.Scope, c.OK, c.Why, hostIPC)
			}
		}
	}
	for _, action := range []string{"allow", "ask"} {
		p, err := f.s.ActOn(ctx, ActReq{Run: run, Seq: 3, Action: action})
		if err != nil || p.PickErr != hostIPC || p.Diff != "" || p.Saved {
			t.Errorf("picked by hand, %s: %+v, %v", action, p, err)
		}
	}

	q, err := f.s.ActOn(ctx, ActReq{Run: run, Seq: 4})
	if err != nil || q.Err != "" {
		t.Fatalf("ActOn: %+v, %v", q, err)
	}
	for _, c := range q.Choices {
		if c.Scope.Host || c.Action == "block" {
			continue // a unix socket names no host; the line was refused by default, so there is no entry to remove
		}
		if !c.OK {
			t.Errorf("%s at %+v for a socket no built-in covers: not offered: %q", c.Action, c.Scope, c.Why)
		}
	}
}
