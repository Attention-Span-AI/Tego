// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/internal/watch/procconn"
	"github.com/attention-span-ai/tego/internal/watch/watcher"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// guard is `tego agents --follow --adopt --uid <uid>...` (ADR 0055): the detector, adopting each agent
// it reports outside every governed run, as long as the agent's owner is a listed uid. It is a foreground command (ADR
// 0042: no daemon until a named trigger fires); docs/poc/tego-guard.service.example runs it under systemd.
//
// What it never does: adopt a process inside a governed run (the watcher says so, and adopt.Check reads the cgroup
// again), adopt one identity twice (adopt.Registry here, the host-wide lock in the run), adopt a process whose real,
// effective and saved uids are not one listed uid, or retry: each agent is considered once, when the watcher first
// reports it, and a refusal or a failure is a line, never a loop. Memory is bounded by the watcher's caps and the
// registry's (DefaultMaxAdoptions adoptions at once; past it an agent is refused, said so). Its context's end (SIGINT,
// SIGTERM, systemctl stop) releases every agent it adopted before it returns; `tego stop <run>` or `tego adopt
// --release` of one of its adoptions is a release request that adoption alone answers, and the guard runs on.
type guard struct {
	ctx  context.Context
	uids adopt.UIDs
	p    adopt.Proc
	self adopt.Self
	reg  *adopt.Registry
	m    *config.Machine
	o    adoptOptions
	log  *slog.Logger
	// shared are the boundary's compiled tables and backends, one per listed uid, each compiled once at the start
	// against that uid's home (prepareAdoption); nil for record-only adoptions, which compile a contract per agent.
	shared map[int]*preparedAdoption
	// sharedMu guards shared and retired once the guard runs: sharedTable compiles a stale table again and swaps it
	// in; retired are the tables swapped out, whose adoptions may still run, cleaned up with the rest at the end.
	sharedMu sync.Mutex
	retired  []*preparedAdoption
	emit     watcher.Emit
	wg       sync.WaitGroup

	mu sync.Mutex
	// watches are the exit watches of the agents this guard is adopting, by pid, for their run_end: each is fed the
	// watcher's events (the guard is the watcher's Tap) from the moment its agent was identified, and holds an
	// identity, so an exit of an earlier or a later process with that pid is not its agent's. One is kept per adoption,
	// so they are bounded by the registry's cap, and each is dropped when its adoption ends.
	watches map[int][]*exitWatch
	stats   guardStats
}

// guardStats counts what the guard did, for its last line.
type guardStats struct {
	adopted, refused, failed int
}

// newGuard prepares a guard: its own identity, the boundary's table and backend when there is one.
func newGuard(ctx context.Context, m *config.Machine, uids []int, o adoptOptions, emit watcher.Emit, stderr io.Writer) (*guard, error) {
	p := adoptProc()
	self, err := adoptSelf(p)
	if err != nil {
		return nil, err
	}
	g := &guard{ctx: ctx, uids: adopt.UIDs(uids), p: p, self: self, reg: adopt.NewRegistry(0), m: m, o: o,
		log: ownLogger(m), watches: map[int][]*exitWatch{}}
	var mu sync.Mutex
	g.emit = func(s watcher.Sighting) error {
		mu.Lock()
		defer mu.Unlock()
		return emit(s)
	}
	if o.boundary != "" {
		g.shared = map[int]*preparedAdoption{}
		for _, uid := range uids {
			if g.shared[uid] != nil {
				continue
			}
			a, code := adoptPrepare(ctx, m, o, adopt.Process{}, uid, stderr)
			if a == nil {
				g.cleanupShared()
				return nil, fmt.Errorf("the boundary %s cannot be held on uid %d's adopted processes (exit %d above)",
					o.boundary, uid, code)
			}
			g.shared[uid] = a
		}
	}
	return g, nil
}

// observe is the guard's tap on the watcher's report, on the watcher's goroutine: it never blocks it.
func (g *guard) observe(s watcher.Sighting) {
	if s.Event == watcher.EventAgentStarted && s.OutsideGovernedRun != nil && *s.OutsideGovernedRun {
		g.consider(s)
	}
}

// Event is the guard's tap on the watcher's events (watcher.Tap), on the watcher's goroutine: an adopted agent's exit
// watch is fed the events of its pid.
func (g *guard) Event(ev procconn.Event) {
	g.mu.Lock()
	ws := slices.Clone(g.watches[int(ev.TGID)])
	g.mu.Unlock()
	for _, w := range ws {
		w.Event(ev)
	}
}

// Lost tells every exit watch that the kernel dropped events.
func (g *guard) Lost() {
	g.mu.Lock()
	var ws []*exitWatch
	for _, l := range g.watches {
		ws = append(ws, l...)
	}
	g.mu.Unlock()
	for _, w := range ws {
		w.Lost()
	}
}

// refuse reports an agent the guard does not adopt, and why; nothing was done to it.
func (g *guard) refuse(s watcher.Sighting, uid *int, rule, why string) {
	g.mu.Lock()
	g.stats.refused++
	g.mu.Unlock()
	_ = g.emit(watcher.Sighting{Event: watcher.EventAdoptionRefused, Time: now(), Session: s.Session, PID: s.PID,
		Start: s.Start, Exe: s.Exe, UID: uid, Rule: rule, Note: why})
}

// consider decides, once per sighting, whether to adopt the agent it names, and starts the adoption off the watcher's
// goroutine when it does.
func (g *guard) consider(s watcher.Sighting) {
	t, err := adopt.Identify(g.p, int(s.PID))
	if err != nil {
		g.refuse(s, nil, "gone", "it exited, or its pid was reused, before it could be adopted")
		return
	}
	uid := t.Owner()
	uidp := &uid
	if s.Start != 0 && t.Start != s.Start {
		g.refuse(s, uidp, "reused", "its pid names another process than the one the watcher saw start")
		return
	}
	if err := g.uids.Admit(t); err != nil {
		g.refuse(s, uidp, adopt.RefuseUID, refusalDetail(err))
		return
	}
	if err := adopt.Check(t, g.self); err != nil {
		rule, _ := adopt.IsRefusal(err)
		g.refuse(s, uidp, rule, refusalDetail(err))
		return
	}
	if holder, err := g.reg.Claim(t.Identity, "pending"); err != nil {
		why := "this guard is adopting it already (" + holder + ")"
		if errors.Is(err, adopt.ErrRegistryFull) {
			why = fmt.Sprintf("this guard holds %d adoptions already, its cap; the agent is reported and left alone", adopt.DefaultMaxAdoptions)
		}
		g.refuse(s, uidp, "busy", why)
		return
	}
	// Its exit watch is fed from here on, on the watcher's goroutine: no exit of the agent the watcher reads after the
	// read that identified it alive is missed by an adoption that has not begun yet.
	ew := newExitWatch(g.p, t.Identity)
	g.mu.Lock()
	g.watches[t.PID] = append(g.watches[t.PID], ew)
	g.mu.Unlock()
	g.wg.Add(1)
	go g.adopt(t, s, time.Now(), ew)
}

// refusalDetail is a refusal's own sentence, without the pid it is about.
func refusalDetail(err error) string {
	var r *adopt.Refusal
	if errors.As(err, &r) {
		return r.Detail
	}
	return err.Error()
}

// adopt is one adoption, on a goroutine of its own, until its run ends.
func (g *guard) adopt(t adopt.Process, s watcher.Sighting, identified time.Time, ew *exitWatch) {
	defer g.wg.Done()
	defer g.reg.Drop(t.Identity)
	defer g.forget(t.PID, ew)
	uid := t.Owner()
	var a *preparedAdoption
	if g.shared != nil {
		// The table compiled against the agent's owner's home: its ~/.ssh, never the guard's.
		var err error
		if a, err = g.sharedTable(uid); err != nil {
			g.fail(s, &uid, err.Error())
			return
		}
	} else {
		var code int
		if a, code = adoptPrepare(g.ctx, g.m, g.o, t, uid, io.Discard); a == nil {
			g.fail(s, &uid, fmt.Sprintf("its run could not be prepared (exit %d)", code))
			return
		}
		defer a.cleanup()
	}
	spec := tegoruntime.AdoptSpec{Root: t, Env: adopt.Env{Proc: g.p}, Boundary: g.o.boundary != "",
		Recheck: pinnedOwner(adoptionRules(g.self, g.uids), uid), Keyed: a.keyed(),
		Started: func(st tegoruntime.AdoptStarted) {
			g.reg.Rename(t.Identity, st.RunID)
			g.mu.Lock()
			g.stats.adopted++
			g.mu.Unlock()
			w := st.Window.Milliseconds()
			_ = g.emit(watcher.Sighting{Event: watcher.EventAdopted, Time: now(), Session: s.Session, PID: s.PID, Start: t.Start,
				Exe: t.Exe, UID: &uid, Rule: s.Rule, Run: st.RunID, Moved: len(st.Moved), WindowMS: &w, Cgroup: st.From,
				Note: fmt.Sprintf("recorded from the kernel into run %s; what it did in the %d ms before is a gap of the run's", st.RunID, w)})
		},
		ExitStatus: ew.status,
	}
	res, err := adoptRun(g.ctx, a.rt, spec, a.deps(identified, g.log))
	if err != nil {
		g.fail(s, &uid, err.Error())
		return
	}
	_ = g.emit(watcher.Sighting{Event: watcher.EventAdoptionEnded, Time: now(), Session: s.Session, PID: s.PID, Start: t.Start,
		Exe: t.Exe, UID: &uid, Run: res.RunID, Reason: res.Reason})
}

// forget drops an adoption's exit watch once that adoption has ended.
func (g *guard) forget(pid int, ew *exitWatch) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ws := slices.DeleteFunc(g.watches[pid], func(w *exitWatch) bool { return w == ew })
	if len(ws) == 0 {
		delete(g.watches, pid)
		return
	}
	g.watches[pid] = ws
}

// fail reports an adoption that began and did not record. What it moved went back, unless why says otherwise: a
// process no cgroup took back stays in the adoption's scope, released (tegoruntime.ErrAdoptLeftInScope), and why
// names the scope and the release that moves it out later.
func (g *guard) fail(s watcher.Sighting, uid *int, why string) {
	g.mu.Lock()
	g.stats.failed++
	g.mu.Unlock()
	_ = g.emit(watcher.Sighting{Event: watcher.EventAdoptionFailed, Time: now(), Session: s.Session, PID: s.PID, Start: s.Start,
		Exe: s.Exe, UID: uid, Note: why})
}

// wait blocks until every adoption the guard started has ended (each releases its agent once ctx is done).
func (g *guard) wait() guardStats {
	g.wg.Wait()
	g.cleanupShared()
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stats
}

// sharedTable is uid's boundary table. One whose owner's ~/.tego is no longer the directory it denies
// (preparedAdoption.stale: removed, replaced, or no directory now; or the owner's home, missing then, exists now) is
// compiled again first, which makes the directory again where it is missing, and replaces it for every later
// adoption: R6a's deny of the owner's own records attaches
// to the directory a compile found. A table that cannot be compiled again fails the adoption: it is never adopted
// under the old one. Adoptions already running keep the table they started with.
// A table prepared with the decision plane in fmod_ret mode is prepared again, so selected again, when this kernel no
// longer admits that mode (preparedAdoption.fmodRetLapsed, ADR 0024 (16)), and an adoption is never made under it.
// Only that directory is rechecked: a built-in deny_read path made after the start (a new ~/.aws) is not covered
// until the guard restarts, as a deny_read glob covers only the files that exist when it is compiled (SEMANTICS §2).
func (g *guard) sharedTable(uid int) (*preparedAdoption, error) {
	g.sharedMu.Lock()
	defer g.sharedMu.Unlock()
	a := g.shared[uid]
	if a == nil {
		return nil, fmt.Errorf("no boundary table was compiled for uid %d", uid)
	}
	lapsed := a.fmodRetLapsed()
	if !a.stale() && lapsed == "" {
		return a, nil
	}
	fresh, code := adoptPrepare(g.ctx, g.m, g.o, adopt.Process{}, uid, io.Discard)
	if fresh == nil {
		if lapsed != "" {
			return nil, fmt.Errorf("uid %d's boundary table was prepared with the decision plane in fmod_ret mode, which "+
				"this kernel no longer admits (%s), and it could not be prepared again (exit %d)", uid, lapsed, code)
		}
		return nil, fmt.Errorf("uid %d's ~/.tego is no longer the directory its boundary table denies (or its home, "+
			"missing then, exists now), and the table could not be compiled again to deny it (exit %d)", uid, code)
	}
	g.retired = append(g.retired, a)
	g.shared[uid] = fresh
	return fresh, nil
}

// cleanupShared removes what the boundary's tables made, those swapped out by sharedTable too.
func (g *guard) cleanupShared() {
	g.sharedMu.Lock()
	defer g.sharedMu.Unlock()
	for _, a := range g.shared {
		a.cleanup()
	}
	for _, a := range g.retired {
		a.cleanup()
	}
}

// exitStatusWait bounds how long an ended adoption waits for its agent's exit status from the proc connector.
const exitStatusWait = time.Second

// now is the sighting time format.
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
