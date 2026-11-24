// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// builtinSockRun is a run whose line 1 is a connect to the session bus, refused by builtin.host_ipc.
const builtinSockRun = "r-aaaaaaaa-0000000000007-sockxx"

// TestActOnThisOffersNoAllowForABuiltinRefusedSocket: the event page of a refused connect to a socket a built-in
// refusal always refuses (the session bus, builtin.host_ipc) offered "Allow next time" and "Ask me next time", and the
// contract either wrote then failed at compile (ADR 0113, amendment of 2026-11-11). The
// page now leads with "Already refused by", offers no Allow and no Ask, says why in the open, and a hand-typed
// ?a=allow shows the same words and no confirm form. The page keeps working with scripts off and under its CSP: the
// explanation is plain markup in a details element (open), which needs no script and no inline style.
func TestActOnThisOffersNoAllowForABuiltinRefusedSocket(t *testing.T) {
	root, contract, proj := askFixture(t)
	bus := "/run/user/1000/bus"
	writeLines(t, root, builtinSockRun, []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
			ContractSource: &record.ContractSource{Path: contract}}),
		ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "connect", Target: "unix:" + bus}, func(e *record.Event) {
			e.Source, e.Rule, e.Reason = record.SourceSeccomp, "builtin.host_ipc", record.ReasonNetNotAllowed
		}),
	})
	s := newServer(t, root)
	// The compiler's verdict on a contract that lists a socket a built-in refuses: tego compile's own contradiction,
	// as the dashboard's nextrun.Compile reports it (the real compiler is held by internal/control/rules' test).
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(_, _ string, text []byte) error {
		if strings.Contains(string(text), "unix:"+bus) {
			return errors.New("error: " + filepath.Base(contract) + ":16:7: net[unix:" + bus + "] is refused by builtin.host_ipc in " +
				"every enforcing run, before net.allow is read: no contract entry lifts a built-in refusal (ADR 0113), so this " +
				"entry admits nothing [contradiction]")
		}
		return nil
	}}
	c := login(t, s)
	line := "/runs/" + builtinSockRun + "/lines/1"
	const why = "Built in (Host IPC refused): this socket is refused in every run, so no contract line can allow it or ask about it"
	page := do(s, "GET", line, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the refused socket's page", page, "Already refused by", "Host IPC refused", why, `<details class="ev-why" open>`)
	mustContain(t, "the fold", page, `<details class="ev-change" open>`)
	for _, bad := range []string{"Allow next time", "Ask me next time", "a=allow", "a=ask"} {
		if strings.Contains(page, bad) {
			t.Errorf("the page offers or carries %q:\n%s", bad, page)
		}
	}
	picked := do(s, "GET", line+"?a=allow", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "a hand-typed allow", picked, why)
	if strings.Contains(picked, `id="act-confirm"`) || strings.Contains(picked, "Confirm: write the contract") {
		t.Errorf("a hand-typed allow offers a confirm:\n%s", picked)
	}
	// Nothing was written either way.
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Errorf("the contract changed:\n%s", b)
	}
}
