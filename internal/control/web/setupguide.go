// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/guide"
)

// The Overview's guide (ADR 0142): the six steps `tego setup` prints, each with its
// state and the fact that decided it, the one next step and what is not known, rendered from the object internal/guide
// computes, never from a click and never from a probe of this process (the dashboard runs in its own cgroup, so its
// probe would describe itself). The check step reads the check `tego setup` stored for this boot and this build; with
// none, it says the machine was not checked since it started, and the next step is `tego setup`.
//
// Every text of the object is shown as text through html/template: a fact can be up to a kilobyte of printable words
// a process of the same user chose (ADR 0142 (4)). Only the next step's command, and only when the guide marks it as
// one it built (guide.Next.Built), is shown as a command to copy; a fact that reads like a command stays a sentence.

// setupGuide is the guide as the Overview shows it: the object's words for the serving user's home (guide.State.Words,
// the ones tego setup prints), its next step, and whether every step is done.
type setupGuide struct {
	Words guide.Words
	Next  guide.Next
	// Done is every step done: the guide's last rule, enforce-done. The Overview then folds the guide to one line.
	Done bool
	// AnyAgent is whether the empty Overview also shows the first step for any agent (tego watch) under the guide:
	// always, except when the guide's next step is that step (record-todo), which it then would show twice.
	AnyAgent bool
}

// guideTTL bounds how long the Overview reuses a guide it computed while the runs' shape (guideKey) is unchanged: a
// contract saved to a registry, or a check `tego setup` stored, shows within it. A live run's lines move the
// Overview every second; the guide reads up to 2000 run_starts, verifies up to two runs and compiles up to 20
// contracts, so it is not computed again for each of them.
const guideTTL = 15 * time.Second

// guideCompute bounds one computation of the guide, apart from the request that asked for it (setupGuide). A var
// only so a test can make it run out.
var guideCompute = 20 * time.Second

// guideMemo is the last guide computed, by its key.
type guideMemo struct {
	mu   sync.Mutex
	key  string
	at   time.Time
	last *setupGuide
}

// guideKey is what changes the steps the record decides: how many runs there are, how many have ended or are live,
// and the newest; the stored check's file (its size and modification time); and the build of the tego a person types,
// so a tego reinstalled while the dashboard runs shows at once.
func guideKey(snap *ledgerview.Snapshot, in guide.Inputs) string {
	home := in.Home
	var ended, live int
	for _, r := range snap.Runs {
		if r.Ended {
			ended++
		}
		if r.Live {
			live++
		}
	}
	k := strconv.Itoa(snap.TotalRuns) + "/" + strconv.Itoa(ended) + "/" + strconv.Itoa(live)
	if len(snap.Runs) > 0 {
		k += "/" + snap.Runs[0].ID
	}
	if fi, err := os.Lstat(guide.CheckPath(home)); err == nil {
		k += "/" + strconv.FormatInt(fi.Size(), 10) + "@" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
	}
	return k + "/" + in.Build
}

// setupGuide is the Overview's guide, nil when the server has no guide inputs (Config.Guide).
func (s *Server) setupGuide(ctx context.Context, snap *ledgerview.Snapshot) *setupGuide {
	if s.cfg.Guide == nil {
		return nil
	}
	in := s.cfg.Guide()
	key := guideKey(snap, in)
	m := &s.guide
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last != nil && m.key == key && time.Since(m.at) < guideTTL {
		return m.last
	}
	// The guide is shared by every viewer, so it is not computed under one viewer's request: a request that ends (the
	// viewer leaves, a live refresh is cut short) would make a contract "not compile" and a record "not known", and
	// that would be shown to the next viewer. It gets its own bound instead, and a guide whose bound ran out is shown
	// to this request only, never kept.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), guideCompute)
	defer cancel()
	st := guide.Compute(cctx, in)
	g := &setupGuide{Words: st.Words(in.Home), Next: st.Next, Done: st.Next.Rule == guide.RuleEnforceDone,
		AnyAgent: st.Next.Rule != guide.RuleRecordTodo}
	if cctx.Err() == nil {
		m.key, m.at, m.last = key, time.Now(), g
	}
	return g
}

// stepWord is a step's state as the guide shows it, in words beside its badge (never by colour alone).
func stepWord(state string) string {
	switch state {
	case guide.Done:
		return "Done"
	case guide.Todo:
		return "To do"
	case guide.Waiting:
		return "Waiting"
	case guide.Blocked:
		return "Blocked"
	case guide.Skipped:
		return "Skipped"
	}
	return "Not known"
}

// stepBadge is a step's badge class and icon, by state.
func stepBadge(state string) [2]string {
	switch state {
	case guide.Done:
		return [2]string{"b-verified", "i-check"}
	case guide.Waiting:
		return [2]string{"b-waiting", "i-activity"}
	case guide.Blocked:
		return [2]string{"b-broken", "i-triangle-alert"}
	case guide.NotKnown:
		return [2]string{"b-asked", "i-search"}
	}
	return [2]string{"b-outline", "i-square"}
}
