// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
)

// The Rules page's "Changed since this run started" panel: on a running run whose rules file changed
// after it started, each change says what it is on that run now, from the run's own record and overlay:
//   - Live now (since line #N): every live block the change placed on the run is in force (the launcher's confirming
//     gap line, ledgerview.LiveFacts);
//   - Requested: a block was placed and the launcher has not confirmed it yet (it turns within about a second, over
//     the page's live updates: the panel is inside the "content" region);
//   - Recorded only (watched run): a watched run records what the block names and refuses nothing;
//   - Next run, with why: nothing was placed on the run; a change that maps to live blocks offers Apply now, which
//     posts to POST /rules/change with do=applynow (the rule service places the blocks and journals them; this page
//     decides nothing).
//
// Restarting the run from here is out of scope (it needs authority tego-control does not have): the panel names the
// terminal line that starts the next run with these rules.

// LiveNowService is the rule service's Apply now half (rules.Service.PendingOn and ApplyNow); a Config.Rules without
// it shows the panel's changes without states or Apply now.
type LiveNowService interface {
	PendingOn(ctx context.Context, run string, ids []string) map[string]rules.PendingNow
	ApplyNow(ctx context.Context, r rules.ApplyNowReq) ([]rules.LiveResult, error)
}

// pendingLive is one pending change on the running run: its chip and, when nothing is placed yet, Apply now.
type pendingLive struct {
	// State is "live", "requested", "recorded" or "next"; Label the chip's words, Class its badge class (app.css
	// .b-*), Note the plain line after it.
	State, Label, Class, Note string
	// Blocks are the live blocks the change placed on the run, or that Apply now would place, in words.
	Blocks []pendingBlock
	// CanApply offers Apply now; Observe words it as a mark on a watched run.
	CanApply, Observe bool
}

// pendingBlock is one live block in words (liveWords) and its key as the journal and `tego block` spell it, shortened.
type pendingBlock struct{ Words, Key string }

func pendingBlockOf(key string, sh shortener) pendingBlock {
	return pendingBlock{Words: liveWords(key, sh), Key: sh.text(key)}
}

// liveWords is a live block key ("write:/p/tmp") in plain words, its path shortened: "Changes to ./tmp (reads still go
// through)". It names what the block covers, not a state: the chip beside it says whether it is refused now.
func liveWords(key string, sh shortener) string {
	kind, value, ok := strings.Cut(key, ":")
	if !ok {
		return key
	}
	v := sh.text(value)
	if strings.HasPrefix(v, "/") && sh.cwd != "" && value == strings.TrimSuffix(sh.cwd, "/") {
		v = "." // the run's own folder
	}
	switch kind {
	case "exec":
		if strings.HasSuffix(value, "/") {
			return "Running programs in " + v
		}
		return "Running " + v
	case "net":
		return "Connections to " + v
	case "path":
		return "Opening or changing " + v
	case "read":
		return "Reads of " + v
	case "write":
		return "Changes to " + v + " (reads still go through)"
	}
	return key
}

// fillPendingLive gives each pending change of a running run its state on the run, and the restart line.
func (s *Server) fillPendingLive(ctx context.Context, d *rulesData) {
	p, run := d.Pending, d.Run
	if p == nil || run == nil || !d.Running {
		return
	}
	p.Live = true
	facts := ledgerview.LiveFactsOf(run)
	if !facts.Observe && run.Contract != "" {
		p.Restart = "tego run " + shellArg(run.Contract) + startCommand(run)
	}
	ids := make([]string, 0, len(p.Changes))
	for _, c := range p.Changes {
		if c.ID != "" {
			ids = append(ids, c.ID)
		}
	}
	var pend map[string]rules.PendingNow
	if ls, ok := s.cfg.Rules.(LiveNowService); ok && len(ids) > 0 {
		pend = ls.PendingOn(ctx, run.ID, ids)
	}
	lb, _ := runact.Live(s.cfg.Ledger, run.ID) // no overlay: nothing placed is in force
	sh := shortener{cwd: run.Cwd, home: homeDir()}
	for i := range p.Changes {
		c := &p.Changes[i]
		pn, ok := pend[c.ID]
		c.Now = pendingLiveOf(pn, ok, facts, lb, sh, s.cfg.Now())
	}
}

// pendingLiveOf is one change's state on the run: pn is what the rule service says of it (ok false when it could not
// say), facts the run's live facts, lb its overlay now, and now the instant a block's time limit is judged at.
func pendingLiveOf(pn rules.PendingNow, ok bool, facts ledgerview.LiveFacts, lb runact.LiveBlocks, sh shortener, now time.Time) *pendingLive {
	pl := &pendingLive{Observe: facts.Observe}
	var states []string
	var since uint64
	var resting string // a placed block that refuses nothing now by its time limit: dormant or expired
	for _, b := range pn.Placed {
		serial, in := lb.Serials[b]
		if !in {
			continue // removed from the run since: not in force, and not this change's to offer again
		}
		kind, _, _ := strings.Cut(b, ":")
		e, _ := lb.Entry(b)
		st := facts.StatusAt(kind, serial, now, e.From, e.Until)
		if st.State == ledgerview.LiveDormant || st.State == ledgerview.LiveExpired {
			resting = st.State // refuses nothing now: never counted as live
			continue
		}
		states = append(states, st.State)
		since = max(since, st.Since)
		pl.Blocks = append(pl.Blocks, pendingBlockOf(b, sh))
	}
	switch {
	case len(states) > 0 && facts.Observe:
		pl.State, pl.Label, pl.Class = "recorded", "Recorded only (watched run)", "b-observed"
		pl.Note = "This run is only watched: matching actions are recorded, not stopped."
	case len(states) > 0 && containsState(states, ledgerview.LiveWaiting):
		pl.State, pl.Label, pl.Class = "requested", "Requested", "b-waiting"
		pl.Note = "Putting it in force on this run…"
	case len(states) > 0:
		pl.State, pl.Label, pl.Class = "live", "Live now", "b-active"
		if since > 0 {
			pl.Label += " since line #" + strconv.FormatUint(since, 10)
		}
		if containsState(states, ledgerview.LivePartial) {
			pl.Note = "Changes are refused; this run's reads are not seen, so a read still goes through."
		}
	default:
		pl.State, pl.Label, pl.Class = "next", "Next run", "b-neutral"
		switch {
		case !ok:
			pl.Note = "This run keeps its rules; the change record could not be read for it here."
		case pn.CanApply():
			pl.CanApply = true
			pl.Note = "Not on this run yet."
			for _, o := range pn.Options {
				if o.OK {
					pl.Blocks = append(pl.Blocks, pendingBlockOf(o.Block, sh))
				}
			}
		case resting == ledgerview.LiveDormant:
			pl.Note = "Its live block is unblocked for a while on this run, so it refuses nothing until then; the next run gets the change."
		case resting == ledgerview.LiveExpired:
			pl.Note = "Its live block ended by its time limit on this run; the next run gets the change."
		case len(pn.Placed) > 0:
			// Every block it placed is gone from the run's overlay (removed on the run page or with tego unblock), and
			// the service does not offer a placed block again.
			pl.Note = "Its live block was removed from this run; the next run gets the change."
		default:
			pl.Note = "This run keeps its rules: this change has no live block."
			for _, o := range pn.Options {
				if o.Why != "" {
					pl.Note = "This run keeps its rules: " + sh.text(o.Why) + "."
					break
				}
			}
		}
	}
	return pl
}

func containsState(states []string, s string) bool {
	for _, x := range states {
		if x == s {
			return true
		}
	}
	return false
}

// startCommand is " -- <argv>" of the run's run_start command, each word as a shell reads it, or "" when the line
// has none or cannot be read (a command moved to a blob: the run page shows it).
func startCommand(r *ledgerview.Run) string {
	evs := r.AllEvents()
	if len(evs) == 0 || evs[0].Kind != "run_start" {
		return ""
	}
	var p struct {
		Command []string `json:"command"`
	}
	if json.Unmarshal([]byte(evs[0].Raw), &p) != nil || len(p.Command) == 0 {
		return ""
	}
	words := make([]string, len(p.Command))
	for i, w := range p.Command {
		words[i] = shellArg(w)
	}
	return " -- " + strings.Join(words, " ")
}

// shellArg is s as exactly one word of a POSIX shell line, spaces and all: unlike shellWord it trims nothing, so a
// prompt argument with a leading or trailing space comes back as the run had it; an empty word is a pair of quotes.
func shellArg(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-:@,+=") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// applyNowPost is POST /rules/change with do=applynow (postAllowed has passed it): the rule service places the live
// blocks of journal change id on running run run and journals them. The answer goes back to the run's Rules page,
// whose panel then says Requested, and Live now once the launcher confirms.
func (s *Server) applyNowPost(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	run, id := f.Get("run"), f.Get("id")
	back := "/rules?" + url.Values{"run": {run}}.Encode()
	ls, ok := s.cfg.Rules.(LiveNowService)
	if !ok {
		s.fail(w, http.StatusNotFound, "Apply now", "This dashboard was started without the rule service, so it cannot apply a change now.")
		return
	}
	res, err := ls.ApplyNow(r.Context(), rules.ApplyNowReq{ID: id, Run: run})
	switch {
	case errors.Is(err, rules.ErrNotPending), errors.Is(err, rules.ErrRefused), errors.Is(err, rules.ErrNotWritable):
		s.redirectBack(w, r, back, flash{Text: "Nothing was applied: " + err.Error()})
		return
	case err != nil && len(res) == 0:
		s.serviceFail(w, "Apply now", err)
		return
	}
	n, watched := 0, false
	var failed []string
	for _, l := range res {
		if l.OK {
			n++
			watched = watched || l.Observe
		} else {
			failed = append(failed, l.Block+": "+l.Err)
		}
	}
	text := "Putting it in force on this run now (" + plural4(n, "live block", "live blocks") + ")."
	if watched {
		text = "Recorded only on this run, which is only watched (" + plural4(n, "mark", "marks") + ")."
	}
	if len(failed) > 0 {
		text += " Not placed: " + strings.Join(failed, "; ") + "."
	}
	if err != nil {
		text += " " + err.Error() + "."
	}
	s.redirectBack(w, r, back, flash{OK: n > 0, Text: text})
}
