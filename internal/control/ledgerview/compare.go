// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path"
	"slices"
	"strings"
)

// The classes of a comparison row, in the order the table lists them.
const (
	ClassSecret = "secret"
	ClassAsk    = "ask"
	ClassNet    = "net"
	ClassExec   = "exec"
)

// Tones of a comparison cell: bad is red (a secret or an off-list destination that got through: observed, so nothing
// stopped it), good is green (refused: Tego stopped it), ask is amber, neutral is grey, and the empty tone is
// "not seen". muted is a refusal its run's verdict does not count (a connection that is no send next to a secret):
// grey like neutral, but a row with one is never routine.
const (
	ToneBad     = "bad"
	ToneGood    = "good"
	ToneAsk     = "ask"
	ToneNeutral = "neutral"
	ToneMuted   = "muted"
)

// CmpCell is what one run did with one row's target.
type CmpCell struct {
	Seen bool
	// Word is the cell's verdict word: Got through (a secret or an off-list destination only observed), Stopped
	// (refused: a secret read or a send next to a secret, the attempts the run's verdict counts, or a program), Refused
	// (a refused connection the verdict does not count, ToneMuted), Observed, Asked or Allowed.
	Word string
	Tone string
	// Detail is the count (×3), the mix (2 refused · 1 allowed) or, for an approval, how it ended.
	Detail string
	Count  int
	// Where lists the paths this cell stands for when they differ from the row's merged path.
	Where []string
}

// CmpRow is one target both runs are compared on.
type CmpRow struct {
	Class, Label, Target string
	// Note is extra context for the target: the host name of a destination, the operation of an approval.
	Note string
	A, B CmpCell
	// Hot marks a secret, an approval, or a destination on this computer or its network: the rows read first.
	Hot bool
	// Differs is set when the two runs' verdicts differ in a way that matters (a red, green, amber or muted refused cell
	// against anything else).
	Differs bool
	// Danger marks the attack as either run's Signal reads it: a secret read next to a send, or a destination off the
	// contract next to a secret. These rows come first.
	Danger bool
	// Merged is the one row for the off-list destinations next to a secret when each run sent to its own address
	// (mergeAttacker); Targets are those addresses and each cell's Where names its run's.
	Merged  bool
	Targets []string
}

// CmpSide is one run's totals for the sentence above the table.
type CmpSide struct {
	Run *Run
	// SecretsOpened and SecretsRefused count distinct secret paths the run touched or was refused. SecretsAllowed
	// counts those it read only because a person said yes to the contract's ask (fs.ask_read, fs.ask), which
	// SecretsOpened leaves out, and AllowedNames names them (from the run's working directory when under it).
	SecretsOpened, SecretsRefused, SecretsAllowed int
	AllowedNames                                  []string
	// OffList counts connections the run made to destinations outside the allowed list; OffListRefused those it was
	// refused. OffListTop names the first destinations of OffList.
	OffList, OffListRefused int
	OffListTop              []string
	OffListMore             int
	// Background counts lookups and probes left out of the table (DNS, system sockets, route probes to port 65535).
	Background int
	// Verdict is the run's verdict read from the Signal it was compared with (RunVerdict): the sentence's count of
	// what got out or what Tego refused is its count, the one the run's banner and chip print.
	Verdict Verdict
}

// Comparison is two runs side by side.
type Comparison struct {
	A, B CmpSide
	// Rows are the sensitive actions, differences first; with all, the routine rows follow.
	Rows []CmpRow
	// Routine counts the rows left out because both runs treated them the same and none was refused, observed
	// as sensitive or asked (an allowed program, an allowed destination); they are in Rows when all is set.
	Routine int
	// Folded counts the destination rows left out because every run that saw them calls them background (its own
	// retries and probes, Signal's rule); they are in Rows when all is set.
	Folded  int
	Summary string
	// Home is the path prefix both runs' homes (RunHome) read as once merged ("…/home"), "" when they differ: the
	// web layer shows paths under it as "~/".
	Home string
}

type rowKey struct{ class, target string }

// acc is what one run did with one target.
type acc struct {
	obs, allow, ref, ask int
	// yes counts the allowed lines an ask entry decided: a person said yes to them.
	yes      int
	answer   string
	op, host string
	real     []string
}

func (a *acc) add(verdict string) {
	switch verdict {
	case "observed":
		a.obs++
	case "allow":
		a.allow++
	case "refused":
		a.ref++
	case "ask":
		a.ask++
	}
}

// Compare lines two runs up on what is sensitive in them: secret files touched, destinations reached outside the
// allowed list, approvals and programs, each with both runs' verdict. The destinations a run's contract allows are
// read from both runs (an enforced run records the rule that allowed each); a destination is off the list when
// neither run allowed it. With no list in either run (two observed runs) only destinations on this computer or its
// network are flagged. all keeps the routine and background rows.
func Compare(a, b *Run, all bool) *Comparison {
	return CompareSignals(a, b, computeSignal(a, Sensitive{Cwd: a.Cwd}), computeSignal(b, Sensitive{Cwd: b.Cwd}), all)
}

// CompareSignals is Compare with each run's Signal as the run page reads it (its contract's secret entries), which
// puts the attack's rows first and folds each run's background destinations.
func CompareSignals(a, b *Run, siga, sigb *RunSignal, all bool) *Comparison {
	on, haveList := map[string]bool{}, false
	for _, r := range []*Run{a, b} {
		evs := r.AllEvents()
		for i := range evs {
			e := &evs[i]
			if e.Kind != "net" || background(e) {
				continue
			}
			if e.Verdict == "refused" {
				haveList = true
			}
			if e.Verdict == "allow" && strings.HasPrefix(e.Rule, "net[") {
				_, dst := splitNet(e.Target)
				on[dst], haveList = true, true
			}
		}
	}
	// A destination a run's Signal reads as allowed is on the list too: a watched run's Signal is read against its
	// enforced reference's allow list (RunSignal.Against), so the project's own API it called is not counted as an
	// off-list connection when the enforced run it is set against never called it.
	for _, sig := range []*RunSignal{siga, sigb} {
		if sig == nil {
			continue
		}
		for _, d := range sig.Outbound {
			if d.InContract && !lookupDst(&d) {
				on[d.Key], haveList = true, true
			}
		}
	}
	offList := func(dst string) bool {
		if on[dst] {
			return false
		}
		return haveList || !publicDst(dst)
	}
	ra, rb := rootOf(a), rootOf(b)
	na, nb := normer(ra, rb), normer(rb, ra)
	rowsA, sa := collect(a, na)
	rowsB, sb := collect(b, nb)
	storyA, storyB := storyOf(siga, na), storyOf(sigb, nb)
	keys := map[rowKey]bool{}
	for k := range rowsA {
		keys[k] = true
	}
	for k := range rowsB {
		keys[k] = true
	}
	c := &Comparison{A: sa, B: sb}
	c.A.Run, c.B.Run = a, b // tally names a file a person allowed from its run's working directory
	if ha, hb := RunHome(a), RunHome(b); ha != "" && na(ha) == nb(hb) {
		c.Home = na(ha)
	}
	var rows []CmpRow
	for k := range keys {
		x, y := rowsA[k], rowsB[k]
		flag := k.class == ClassSecret || k.class == ClassNet && offList(k.target)
		row := CmpRow{Class: k.class, Label: classLabel(k.class), Target: k.target,
			A: x.cell(k.class, flag, storyA.muted(k)), B: y.cell(k.class, flag, storyB.muted(k))}
		row.Note = firstNonEmpty(x.noteOf(), y.noteOf())
		row.Hot = k.class == ClassSecret || k.class == ClassAsk || k.class == ClassNet && !publicDst(k.target)
		row.Differs = row.A.Tone != row.B.Tone && !(quiet(row.A.Tone) && quiet(row.B.Tone))
		row.Danger = danger(k, storyA, storyB)
		c.A.tally(k, x, flag)
		c.B.tally(k, y, flag)
		if !all && !row.Differs && quiet(row.A.Tone) && quiet(row.B.Tone) && k.class != ClassAsk {
			c.Routine++
			continue
		}
		if !all && !row.Danger && allBackground(k, x, y, storyA, storyB) {
			c.Folded++
			continue
		}
		rows = append(rows, row)
	}
	rows = mergeAttacker(rows, offList)
	slices.SortFunc(rows, func(p, q CmpRow) int {
		if d := rank(p) - rank(q); d != 0 {
			return d
		}
		if d := classRank(p) - classRank(q); d != 0 {
			return d
		}
		if d := q.A.Count + q.B.Count - p.A.Count - p.B.Count; d != 0 {
			return d
		}
		return cmp.Compare(p.Target, q.Target)
	})
	c.Rows = rows
	c.A.finish(offList, rowsA)
	c.B.finish(offList, rowsB)
	c.A.Verdict, c.B.Verdict = RunVerdict(a, siga), RunVerdict(b, sigb)
	c.Summary = summary(c)
	return c
}

// rank orders rows: the attack (Danger), one run only observed what the other refused (Stopped or Refused), other
// hot differences, other differences, hot rows alike in both runs, the rest.
func rank(r CmpRow) int {
	switch {
	case r.Danger:
		return -1
	case r.A.Tone == ToneBad && refusedTone(r.B.Tone) || refusedTone(r.A.Tone) && r.B.Tone == ToneBad:
		return 0
	case r.Hot && r.Differs:
		return 1
	case r.Differs:
		return 2
	case r.Hot:
		return 3
	}
	return 4
}

// classRank orders the classes within a rank: secrets and approvals, then destinations on this computer's network,
// then programs, then the destinations out on the internet.
func classRank(r CmpRow) int {
	switch {
	case r.Class == ClassSecret:
		return 0
	case r.Class == ClassAsk:
		return 1
	case r.Class == ClassNet && r.Hot:
		return 2
	case r.Class == ClassExec:
		return 3
	}
	return 4
}

func quiet(tone string) bool { return tone == "" || tone == ToneNeutral }

// refusedTone reports whether a cell's tone is a refusal's: Stopped (good) or Refused (muted).
func refusedTone(tone string) bool { return tone == ToneGood || tone == ToneMuted }

func classLabel(class string) string {
	switch class {
	case ClassSecret:
		return "Secret file"
	case ClassAsk:
		return "Approval"
	case ClassNet:
		return "Destination"
	}
	return "Program"
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// rootOf is the directory above a run's working directory: the one place a per-run copy of a setup differs (a
// demo's with/ and without/ trees), so paths under it merge across the two runs. Empty when it is too shallow to
// say anything.
func rootOf(r *Run) string {
	if r.Cwd == "" {
		return ""
	}
	if d := path.Dir(r.Cwd); strings.Count(d, "/") >= 2 {
		return d
	}
	return ""
}

// normer rewrites a path under this run's root to …/<rest> when the other run has another root.
func normer(root, other string) func(string) string {
	if root == "" || root == other {
		return func(p string) string { return p }
	}
	return func(p string) string {
		if strings.HasPrefix(p, root+"/") {
			return "…" + p[len(root):]
		}
		return p
	}
}

// background is a net line the table leaves out: name lookups, system sockets, netlink, and route probes
// (RouteProbe: UDP to port 65535 of a remote host, the connect musl's getaddrinfo makes to sort addresses).
func background(e *Event) bool {
	_, dst := splitNet(e.Target)
	switch {
	case e.SystemLookup, e.Rule == "net.resolver", e.Rule == "net.unspec", dst == "netlink", dst == "unspec":
		return true
	case strings.HasPrefix(dst, "unix:"):
		return !strings.Contains(dst, "docker") && !strings.Contains(dst, "agent")
	}
	return RouteProbe(e)
}

// publicDst reports whether dst is a routable address (or a name): not this computer, a private network, or a
// local-only address.
func publicDst(dst string) bool {
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		host = dst
	}
	if host == "localhost" {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}

// collect reads one run's sensitive lines into per-target tallies.
func collect(r *Run, norm func(string) string) (map[rowKey]*acc, CmpSide) {
	rows := map[rowKey]*acc{}
	var st CmpSide
	get := func(class, target string) *acc {
		k := rowKey{class, target}
		if rows[k] == nil {
			rows[k] = &acc{}
		}
		return rows[k]
	}
	type askInfo struct{ op, target string }
	asks, answers := map[string]askInfo{}, map[string]string{}
	var askOrder []string
	evs := r.AllEvents()
	for i := range evs {
		e := &evs[i]
		switch e.Kind {
		case "fs":
			for i, p := range strings.Split(e.Target, " → ") {
				if secretRule(e.Rule) || e.secretPart(i, p) {
					a := get(ClassSecret, norm(p))
					a.add(e.Verdict)
					if e.Verdict == "allow" && askedRule(e.Rule) {
						a.yes++
					}
					a.remember(p)
					break
				}
			}
		case "net":
			if background(e) {
				st.Background++
				continue
			}
			h, dst := splitNet(e.Target)
			a := get(ClassNet, dst)
			a.add(e.Verdict)
			if h != "" {
				a.host = h
			}
		case "exec":
			if f := strings.Fields(e.Target); len(f) > 0 {
				get(ClassExec, path.Base(f[0])).add(e.Verdict)
			}
		case "ask":
			if _, seen := asks[e.AskID]; !seen {
				askOrder = append(askOrder, e.AskID)
			}
			asks[e.AskID] = askInfo{firstNonEmpty(e.askOp, e.Op), firstNonEmpty(e.askTarget, "a held "+e.Op)}
		case "answer":
			var p struct {
				Approved *bool `json:"approved"`
			}
			_ = json.Unmarshal([]byte(e.Raw), &p)
			switch {
			case p.Approved == nil:
				answers[e.AskID] = "answered"
			case *p.Approved:
				answers[e.AskID] = "approved"
			default:
				answers[e.AskID] = "denied"
			}
		}
	}
	for _, id := range askOrder {
		in := asks[id]
		a := get(ClassAsk, norm(in.target))
		a.ask++
		a.op = in.op
		a.answer = firstNonEmpty(answers[id], "no answer")
		a.remember(in.target)
	}
	return rows, st
}

// remember keeps a real path behind a merged one (up to three).
func (a *acc) remember(p string) {
	if len(a.real) < 3 && !slices.Contains(a.real, p) {
		a.real = append(a.real, p)
	}
}

// noteOf is the row's extra context: the host of a destination, the operation of an approval.
func (a *acc) noteOf() string {
	if a == nil {
		return ""
	}
	return firstNonEmpty(a.host, a.op)
}

// cell is one run's cell for a row. flag marks a secret or an off-list destination, whose observed lines got through;
// muted says the row's refusals are not ones the run's verdict counts (storySets.muted), so they read Refused, not
// Stopped.
func (a *acc) cell(class string, flag, muted bool) CmpCell {
	if a == nil {
		return CmpCell{}
	}
	c := CmpCell{Seen: true, Count: a.obs + a.allow + a.ref + a.ask, Where: a.real}
	switch {
	case class == ClassAsk:
		c.Word, c.Tone, c.Detail = "Asked", ToneAsk, a.answer
		if a.ask > 1 {
			c.Detail += fmt.Sprintf(" ×%d", a.ask)
		}
		return c
	case a.obs > 0:
		c.Word, c.Tone = "Observed", ToneNeutral
		if flag {
			c.Word, c.Tone = "Got through", ToneBad
		}
	case a.ref > 0:
		c.Word, c.Tone = "Stopped", ToneGood
		if muted {
			c.Word, c.Tone = "Refused", ToneMuted
		}
	case a.ask > 0:
		c.Word, c.Tone = "Asked", ToneAsk
	default:
		c.Word, c.Tone = "Allowed", ToneNeutral
	}
	// The word names the first kind present; the detail is its count and then the other kinds.
	var parts []string
	first := true
	for _, p := range []struct {
		n    int
		word string
	}{{a.obs, "observed"}, {a.ref, "refused"}, {a.ask, "asked"}, {a.allow, "allowed"}} {
		switch {
		case p.n == 0:
		case first && p.n > 1:
			parts, first = append(parts, fmt.Sprintf("×%d", p.n)), false
		case first:
			first = false
		default:
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.word))
		}
	}
	c.Detail = strings.Join(parts, " · ")
	return c
}

// tally adds one row's counts to the side's totals.
func (s *CmpSide) tally(k rowKey, a *acc, flag bool) {
	if a == nil {
		return
	}
	switch k.class {
	case ClassSecret:
		switch {
		case a.obs+a.allow-a.yes > 0:
			s.SecretsOpened++
		case a.yes > 0:
			s.SecretsAllowed++
			if len(a.real) > 0 {
				s.AllowedNames = append(s.AllowedNames, s.nameOf(a.real[0]))
			}
		}
		if a.ref > 0 {
			s.SecretsRefused++
		}
	case ClassNet:
		if flag {
			s.OffList += a.obs + a.allow
		}
		s.OffListRefused += a.ref
	}
}

// finish names the side's first off-list destinations: those on this computer or its network first, then the
// busiest.
func (s *CmpSide) finish(offList func(string) bool, rows map[rowKey]*acc) {
	slices.Sort(s.AllowedNames) // tallied in map order
	type dest struct {
		dst string
		n   int
		hot bool
	}
	var ds []dest
	for k, a := range rows {
		if k.class == ClassNet && offList(k.target) && a.obs+a.allow > 0 {
			ds = append(ds, dest{k.target, a.obs + a.allow, !publicDst(k.target)})
		}
	}
	slices.SortFunc(ds, func(p, q dest) int {
		if p.hot != q.hot {
			if p.hot {
				return -1
			}
			return 1
		}
		if p.n != q.n {
			return q.n - p.n
		}
		return cmp.Compare(p.dst, q.dst)
	})
	for i, d := range ds {
		if i >= 2 {
			s.OffListMore = len(ds) - 2
			break
		}
		name := d.dst
		if d.n > 1 {
			name += fmt.Sprintf(" ×%d", d.n)
		}
		s.OffListTop = append(s.OffListTop, name)
	}
}

// askedRule reports whether rule is a contract entry that asks a person first (fs.ask_read, fs.ask): a read it allowed
// is one a person said yes to.
func askedRule(rule string) bool {
	return strings.HasPrefix(rule, "fs.ask_read[") || strings.HasPrefix(rule, "fs.ask[")
}

// nameOf is a path as the summary names it: from the run's working directory when under it (confidential/plan.md),
// else its file name.
func (s *CmpSide) nameOf(p string) string {
	if s.Run != nil && s.Run.Cwd != "" && strings.HasPrefix(p, s.Run.Cwd+"/") {
		return p[len(s.Run.Cwd)+1:]
	}
	return path.Base(p)
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
