// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// probeCounter wraps fakeSyscalls and counts only the ABI-probe form of CreateRuleset (attr == nil,
// R1), so R19's "no *new* syscall per call" claim is checked against an actual call count instead of
// trusted by code inspection. Every other call (real ruleset creation, path/net rules, the ruleset probe)
// passes straight through to the embedded fake.
type probeCounter struct {
	*fakeSyscalls
	probes int
}

func (p *probeCounter) CreateRuleset(attr *unix.LandlockRulesetAttr, flags int) (int, error) {
	if attr == nil {
		p.probes++
	}
	return p.fakeSyscalls.CreateRuleset(attr, flags)
}

// TestBackendABIProbedOnce: "Capabilities() reads the stored ABI, once" — Select probes once
// and threads the result in; every later ABI()/Capabilities() call, and Prepare's own internal ABI()
// read, must be a syscall-free read of the cached value. Nothing in the existing suite counts probe
// calls (TestNewAndTier and TestCapabilitiesPerABI both thread ABI via Options.ABI, which short-
// circuits sync.Once before it ever runs — they cannot see a repeated *probe*). This calls ABI() and
// Capabilities() several times, then Prepare (which reads ABI() again internally), and requires
// exactly one landlock_create_ruleset(NULL, VERSION) call total.
//
// Spec: docs/p0/enforce-landlock.md R1.
func TestBackendABIProbedOnce(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "out/")
	pc := &probeCounter{fakeSyscalls: &fakeSyscalls{abi: 7}}
	b := New(Options{syscalls: pc})

	if abi, err := b.ABI(); err != nil || abi != 7 {
		t.Fatalf("ABI() = %d, %v", abi, err)
	}
	b.Capabilities()
	b.Capabilities()

	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{fsRule(agent.FSWrite, filepath.Join(root, "out"))}}
	h, err := b.Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	b.Capabilities()

	if pc.probes != 1 {
		t.Errorf("R19: ABI probed %d times across ABI()x1 + Capabilities()x3 + Prepare()x1, want exactly 1", pc.probes)
	}
}

// TestCreateRulesetScopeByABI is R7: "handled_access_scope includes SCOPE_SIGNAL and
// SCOPE_ABSTRACT_UNIX_SOCKET ... declared once globally at landlock_create_ruleset" only from ABI 6
// on. profileFor's own Scope bits are already pinned per ABI by TestProfileFor (abi_test.go), but
// nothing exercises createRuleset itself across ABI bands — TestPrepareEmptyTable is the only place
// that reads back attr.Scoped, and only at a fixed ABI 7 (already >= 6). A createRuleset that ignored
// bd.profile.Scope and always declared both scopes (a plausible copy/paste of the ABI-6-and-up value)
// would pass every existing test yet leak SCOPE_SIGNAL/SCOPE_ABSTRACT_UNIX_SOCKET into a ruleset built
// for a pre-ABI-6 kernel, where the kernel header does not define those scope bits at all.
//
// Spec: docs/p0/enforce-landlock.md R2.
func TestCreateRulesetScopeByABI(t *testing.T) {
	cases := []struct {
		abi  int
		want scope
	}{
		{1, 0},
		{5, 0},
		{6, scopeSignal | scopeAbstractUnixSocket},
		{7, scopeSignal | scopeAbstractUnixSocket},
		{11, scopeSignal | scopeAbstractUnixSocket},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("abi%d", tc.abi), func(t *testing.T) {
			_, fake := prepare(t, tc.abi, &agent.RuleTable{})
			if len(fake.created) != 1 {
				t.Fatalf("%d rulesets created, want 1", len(fake.created))
			}
			if got := scope(fake.created[0].Scoped); got != tc.want {
				t.Errorf("ABI %d: landlock_create_ruleset Scoped = %#x, want %#x", tc.abi, got, tc.want)
			}
		})
	}
}

// TestPrepareRecordFull: "rt.Record == agent.RecordFull ⇒ Prepare builds a filter variant with
// the write-flag test removed ... so every open ... notifies." TestFilterGolden/TestFilterDecisions
// (filter_test.go) pin BuildFilter's own full=true/false parameter exhaustively, but nothing threads
// an actual RuleTable.Record value through Prepare and reads the filter back off the resulting Handle
// — the one-line wiring in builder.build() (`bd.rt.Record == agent.RecordFull`) has no test of its
// own. A build() that always requested the summary variant (or always the full one) would pass every
// filter_test.go case yet silently ignore the contract's record: full setting in production.
//
// Spec: docs/p0/enforce-landlock.md R16.
func TestPrepareRecordFull(t *testing.T) {
	// A table with no contract is net-restricted (agent.RuleTable.NetUnrestricted), so both carry the socket
	// arm (ADR 0018) and R11d's pending-frame arms (it decides datagrams).
	restricted := SocketArmFor(&agent.RuleTable{})
	wantFull, err := assembleFilter(NativeArch(), filterOpts{full: true, abi: minTruncateABI, socket: restricted, procScope: true, unixBinds: true, listenControl: true, frames: true})
	if err != nil {
		t.Fatal(err)
	}
	wantSummary, err := assembleFilter(NativeArch(), filterOpts{full: false, abi: minTruncateABI, socket: restricted, procScope: true, unixBinds: true, listenControl: true, frames: true})
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(wantFull, wantSummary) {
		t.Fatal("full and summary filters are identical; this test cannot distinguish the two modes")
	}

	full, _ := prepare(t, 7, &agent.RuleTable{Record: agent.RecordFull})
	gotFull, ok := full.SeccompFilter()
	if !ok || !reflect.DeepEqual(gotFull, wantFull) {
		t.Error("R16: RuleTable.Record = RecordFull did not produce BuildFilter(arch, full=true) on the resulting Handle")
	}

	summary, _ := prepare(t, 7, &agent.RuleTable{Record: agent.RecordSummary})
	gotSummary, ok := summary.SeccompFilter()
	if !ok || !reflect.DeepEqual(gotSummary, wantSummary) {
		t.Error("R16: RuleTable.Record = RecordSummary did not produce BuildFilter(arch, full=false) on the resulting Handle")
	}
}

// TestSiblingVanishedMidWalk is E28: "a name that vanished since the snapshot is skipped ... harmless,
// mirrors E9." R3/enumerate.go's listDir takes one readdir snapshot per level and then opens each
// listed name individually (sibling); the window between those two steps is exactly where a real
// concurrent rename would land. A goroutine-timed rename across that window cannot be driven
// deterministically from outside the package without sleeping to line it up (the kind of flaky test
// this suite's own precedent warns against), so this instead calls the unexported sibling() step
// directly with a name that is provably absent from dirFD — the same outcome a snapshot/open race
// leaves behind — and checks the documented reaction: no error, and no fd is added for it. Existing
// vanished-path coverage (TestEnumerateVanishedTarget) only exercises the deny_read *target* going
// through enumerate()'s kindDenyTarget hold, a different function with different error handling
// (enumerate() tolerates ErrPathVanished; the plain hold() path used elsewhere does not) — nothing
// calls sibling() itself with an absent name.
//
// Spec: docs/p0/enforce-landlock.md E28.
func TestSiblingVanishedMidWalk(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "d/stays")
	dir := filepath.Join(root, "d")
	dirFD, _, err := openAt(unix.AT_FDCWD, dir, true, nil)
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	defer func() { _ = unix.Close(dirFD) }()

	bd := &builder{ctx: context.Background(), profile: profileFor(7), fds: newFDSet()}
	before := len(bd.fds.open)
	if err := bd.sibling(dirFD, dir, "never-existed"); err != nil {
		t.Errorf("E28: sibling() on a name absent from the snapshot's own directory returned %v, want nil (harmless skip)", err)
	}
	if len(bd.fds.open) != before {
		t.Errorf("E28: sibling() held an fd for a name that does not exist: %d open, want %d", len(bd.fds.open), before)
	}
}
