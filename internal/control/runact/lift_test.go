// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// adjustableStart is a run_start of an Adjustable run at record minor 26 whose fence lists a read that is new access
// and a program the contract refused.
var adjustableStart = `"tier":"cgroup","command":["sh"],"record_minor":26,"fs_reads":{"reads":"held","why":"contract"},` +
	`"live_mode":"adjustable","live_fence":{"sha256":"` + strings.Repeat("0a", 32) + `","entries":[` +
	`{"kind":"read","value":"/srv/exports","source":"new","rule":"live.fence[read:/srv/exports]"},` +
	`{"kind":"exec","value":"/usr/bin/psql","source":"deny","rule":"live.fence[exec:/usr/bin/psql]"}]}`

func outsideRun(t *testing.T) {
	t.Helper()
	old := selfInRun
	selfInRun = func() (bool, error) { return false, nil }
	t.Cleanup(func() { selfInRun = old })
}

// TestBlockUntil: a time limit is refused on a run whose launcher predates it (record_minor 25), held to its bounds,
// and written with the block, or as the instant an unblocked block refuses again.
func TestBlockUntil(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	until := time.Now().Add(72 * time.Hour).UTC()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":25`)
	holdRunLock(t, dir)
	if _, err := BlockUntil(ctx, root, liveRun, "exec", "/bin/ls", true, until, "cli"); !errors.Is(err, ErrNoTimeLimits) {
		t.Fatalf("a limit at record_minor 25: %v, want ErrNoTimeLimits", err)
	}
	if _, err := BlockUntil(ctx, root, liveRun, "exec", "/bin/ls", true, time.Time{}, "cli"); err != nil {
		t.Fatalf("no limit at record_minor 25: %v", err)
	}
	root, dir = liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":26`)
	holdRunLock(t, dir)
	if _, err := BlockUntil(ctx, root, liveRun, "exec", "/bin/ls", true, time.Now().Add(10*time.Second), "cli"); !errors.Is(err, liveblock.ErrInvalid) {
		t.Fatalf("a 10 s limit: %v, want ErrInvalid", err)
	}
	b, err := BlockUntil(ctx, root, liveRun, "exec", "/bin/ls", true, until, "cli")
	if err != nil || b.Word != "blocked" || !b.Until.Equal(until) || b.Serial != 1 {
		t.Fatalf("BlockUntil = %+v, %v", b, err)
	}
	back := time.Now().Add(time.Hour).UTC()
	b, err = BlockUntil(ctx, root, liveRun, "exec", "/bin/ls", false, back, "dashboard")
	if err != nil || b.Word != "block removed" || b.Serial != 2 {
		t.Fatalf("an unblock for an hour = %+v, %v", b, err)
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Blocks) != 1 || !o.Blocks[0].Until.Equal(until) || !o.Blocks[0].From.Equal(back) || o.V != liveblock.VersionTimed {
		t.Fatalf("overlay %+v", o)
	}
	if c := o.Changes[0]; !c.Until.Equal(until) || !strings.HasSuffix(c.By, " cli") {
		t.Fatalf("the add %+v", c)
	}
	if c := o.Changes[1]; c.Op != liveblock.OpRemove || !c.Until.Equal(back) || !strings.HasSuffix(c.By, " dashboard") {
		t.Fatalf("the remove %+v", c)
	}
}

// TestLiftRefusals: a lift is refused inside a run (and when that cannot be told), for a Locked run, outside the fence
// and with no key; a restore is refused for a Locked run and outside the fence, but not inside a run.
func TestLiftRefusals(t *testing.T) {
	ctx := context.Background()
	defer func(f func() (bool, error)) { selfInRun = f }(selfInRun)
	root, dir := liveDir(t, adjustableStart)
	holdRunLock(t, dir)
	for _, in := range []func() (bool, error){
		func() (bool, error) { return true, nil },
		func() (bool, error) { return true, errors.New("cgroup namespace") },
	} {
		selfInRun = in
		if _, err := Lift(ctx, root, liveRun, "read", "/srv/exports", time.Time{}, "cli"); !errors.Is(err, ErrGoverned) {
			t.Fatalf("a lift inside a run: %v, want ErrGoverned", err)
		}
	}
	selfInRun = func() (bool, error) { return false, nil }
	if _, err := Lift(ctx, root, liveRun, "read", "/srv/exports", time.Time{}, "cli"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("a lift with no key: %v, want ErrNoKey", err)
	}
	if _, err := Lift(ctx, root, liveRun, "net", "api.stripe.com:443", time.Time{}, "cli"); !errors.Is(err, ErrOutsideFence) {
		t.Fatalf("a lift outside the fence: %v, want ErrOutsideFence", err)
	}
	if _, err := Restore(ctx, root, liveRun, "net", "api.stripe.com:443", "cli"); !errors.Is(err, ErrOutsideFence) {
		t.Fatalf("a restore outside the fence: %v, want ErrOutsideFence", err)
	}
	lroot, ldir := liveDir(t, `"tier":"cgroup","command":["sh"],"record_minor":26`)
	holdRunLock(t, ldir)
	if _, err := Lift(ctx, lroot, liveRun, "read", "/srv/exports", time.Time{}, "cli"); !errors.Is(err, ErrLocked) {
		t.Fatalf("a lift of a Locked run: %v, want ErrLocked", err)
	}
	if _, err := Restore(ctx, lroot, liveRun, "read", "/srv/exports", "cli"); !errors.Is(err, ErrLocked) {
		t.Fatalf("a restore of a Locked run: %v, want ErrLocked", err)
	}
	// An Adjustable run_start below 26 is not read as Adjustable.
	oroot, odir := liveDir(t, strings.Replace(adjustableStart, `"record_minor":26`, `"record_minor":25`, 1))
	holdRunLock(t, odir)
	if _, err := Lift(ctx, oroot, liveRun, "read", "/srv/exports", time.Time{}, "cli"); !errors.Is(err, ErrLocked) {
		t.Fatalf("a lift of a run below 26: %v, want ErrLocked", err)
	}
	sroot, _ := liveDir(t, adjustableStart)
	if _, err := Lift(ctx, sroot, liveRun, "read", "/srv/exports", time.Time{}, "cli"); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("a lift of a run that is not running: %v, want ErrNotRunning", err)
	}
}

// TestLiftAndRestoreWrite: a lift writes op lift with its limit and a MAC that checks under the run's key, worded by
// the entry's source; a restore, allowed from inside a run, writes op restore.
func TestLiftAndRestoreWrite(t *testing.T) {
	outsideRun(t)
	ctx := context.Background()
	root, dir := liveDir(t, adjustableStart)
	holdRunLock(t, dir)
	key, err := liveblock.WriteKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(3 * 24 * time.Hour).UTC()
	l, err := Lift(ctx, root, liveRun, "read", "/srv/exports/", until, "dashboard")
	if err != nil || l.Word != WordGrantAsked || l.Rule != "live.fence[read:/srv/exports]" || l.Serial != 1 || !l.Until.Equal(until) {
		t.Fatalf("Lift = %+v, %v", l, err)
	}
	l, err = Lift(ctx, root, liveRun, "exec", "/usr/bin/psql", time.Time{}, "cli")
	if err != nil || l.Word != WordLiftAsked || l.Source != "deny" || l.Serial != 2 {
		t.Fatalf("Lift of a contract refusal = %+v, %v", l, err)
	}
	selfInRun = func() (bool, error) { return true, nil }
	r, err := Restore(ctx, root, liveRun, "read", "/srv/exports", "cli")
	if err != nil || r.Word != WordRestoreAsked || r.Serial != 3 {
		t.Fatalf("Restore inside a run = %+v, %v", r, err)
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil {
		t.Fatal(err)
	}
	if o.V != liveblock.VersionModes || len(o.Blocks) != 0 || len(o.Changes) != 3 {
		t.Fatalf("overlay %+v", o)
	}
	c := o.Changes[0]
	if c.Op != liveblock.OpLift || c.Value != "/srv/exports" || !c.Until.Equal(until) || !liveblock.LiftMACOK(key, liveRun, c) {
		t.Fatalf("the lift %+v", c)
	}
	if c := o.Changes[2]; c.Op != liveblock.OpRestore || c.MAC != "" {
		t.Fatalf("the restore %+v", c)
	}
}

// TestGovernedBlockCannotShorten: a block from inside a run is allowed because it narrows, so it must never shorten an
// operator's block: a re-add with a limit of a block held with no end leaves it as it was, and only a longer limit
// lengthens one.
func TestGovernedBlockCannotShorten(t *testing.T) {
	defer func(f func() (bool, error)) { selfInRun = f }(selfInRun)
	selfInRun = func() (bool, error) { return false, nil }
	ctx := context.Background()
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":26`)
	holdRunLock(t, dir)
	if _, err := BlockUntil(ctx, root, liveRun, "exec", "/usr/bin/curl", true, time.Time{}, "cli"); err != nil {
		t.Fatal(err)
	}
	selfInRun = func() (bool, error) { return true, nil }
	b, err := BlockUntil(ctx, root, liveRun, "exec", "/usr/bin/curl", true, time.Now().Add(61*time.Second), "cli")
	if err != nil || b.Word != "already blocked" || !b.Until.IsZero() || b.Serial != 1 {
		t.Fatalf("a governed re-add with a limit = %+v, %v; want the operator's block left with no end", b, err)
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := o.Find(liveblock.KindExec, "/usr/bin/curl"); !e.Until.IsZero() || len(o.Changes) != 1 {
		t.Fatalf("the operator's block became %+v, changes %+v", e, o.Changes)
	}
	// A limit on a timed block lengthens it only: the shorter one leaves it, the longer one moves its end.
	week := time.Now().Add(7 * 24 * time.Hour).UTC().Round(time.Millisecond)
	if _, err := BlockUntil(ctx, root, liveRun, "net", "api.example.com", true, week, "cli"); err != nil {
		t.Fatal(err)
	}
	if b, err := BlockUntil(ctx, root, liveRun, "net", "api.example.com", true, time.Now().Add(3*time.Minute), "cli"); err != nil ||
		b.Word != "already blocked" || !b.Until.Equal(week) {
		t.Fatalf("a shorter limit = %+v, %v; want the block to keep its week", b, err)
	}
	later := week.Add(time.Hour)
	if b, err := BlockUntil(ctx, root, liveRun, "net", "api.example.com", true, later, "cli"); err != nil ||
		b.Word != "blocked" || !b.Until.Equal(later) {
		t.Fatalf("a longer limit = %+v, %v", b, err)
	}
}
