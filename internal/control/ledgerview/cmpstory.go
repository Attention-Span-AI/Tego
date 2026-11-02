// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"strings"
)

// Compare tells the story first: the rows that are the attack (a secret read next to a send, an off-list destination
// next to a secret, in either run, as each run's Signal reads them) come before everything else; the destinations a
// run's Signal calls background (an agent's own retries and probes) fold behind "Show all" like the routine rows; and
// when each run sent to its own attacker address (the demo gives each side its own sink port, so no target can
// pair them) those rows merge into one "Where the secrets went" row, each run's cell naming its own address.

// MergedLabel is the label of the merged row of off-list destinations next to a secret.
const MergedLabel = "Where the secrets went"

// storySets is what one run's Signal says about the comparison's rows: the secret rows next to a send, the
// destinations next to a secret (off the contract), the destinations folded as background, and the destinations
// whose refusals the run's verdict counts as sends (stopped).
type storySets struct {
	secret, dest, bg, stopped map[string]bool
}

func storyOf(sig *RunSignal, norm func(string) string) storySets {
	st := storySets{secret: map[string]bool{}, dest: map[string]bool{}, bg: map[string]bool{}, stopped: map[string]bool{}}
	if sig == nil {
		return st
	}
	for _, s := range sig.Secrets {
		if s.NearSend {
			st.secret[norm(s.Path)] = true
		}
	}
	for i := range sig.Outbound {
		d := &sig.Outbound[i]
		switch {
		case d.Background:
			st.bg[d.Key] = true
		case d.NearSecret && !d.InContract:
			st.dest[d.Key] = true
		}
		// RunVerdict's own test, so a Stopped cell is one of the sends its count holds (a refusal is keyed by the
		// address it names, as a destination row is).
		if d.Refused > 0 && sendNearSecret(d) {
			st.stopped[d.Key] = true
		}
	}
	return st
}

// muted reports whether a row's refusals in this run are ones its verdict does not count, so that its cell reads
// Refused and not Stopped: a destination that is no send next to a secret (a connect no secret was near, a lookup, a
// destination the contract names). A secret file's refusals are the verdict's secret reads, and a program's keep
// Stopped: the verdict counts no program.
func (s storySets) muted(k rowKey) bool { return k.class == ClassNet && !s.stopped[k.target] }

// danger reports whether a row is part of the attack in either run.
func danger(k rowKey, sets ...storySets) bool {
	for _, s := range sets {
		if k.class == ClassSecret && s.secret[k.target] || k.class == ClassNet && s.dest[k.target] {
			return true
		}
	}
	return false
}

// allBackground reports whether a destination row is background in every run that saw it (and so is left out unless all).
func allBackground(k rowKey, x, y *acc, sa, sb storySets) bool {
	if k.class != ClassNet || x == nil && y == nil {
		return false
	}
	return (x == nil || sa.bg[k.target]) && (y == nil || sb.bg[k.target])
}

// mergeAttacker folds the off-list destination rows next to a secret into one row when each was seen by one run only
// and both runs have one: the same attacker reached at a different address in each run. It returns rows unchanged
// otherwise.
func mergeAttacker(rows []CmpRow, offList func(string) bool) []CmpRow {
	var idx []int
	inA, inB := false, false
	for i, r := range rows {
		if r.Class != ClassNet || !r.Danger || !offList(r.Target) {
			continue
		}
		if r.A.Seen == r.B.Seen {
			return rows // a destination both runs reached already pairs the two
		}
		inA, inB = inA || r.A.Seen, inB || r.B.Seen
		idx = append(idx, i)
	}
	if len(idx) < 2 || !inA || !inB {
		return rows
	}
	m := CmpRow{Class: ClassNet, Label: classLabel(ClassNet), Target: MergedLabel, Merged: true, Hot: true, Danger: true,
		Note: "off the list, next to a secret; each run's own address"}
	var as, bs []CmpCell
	var targets []string
	for _, i := range idx {
		r := rows[i]
		targets = append(targets, r.Target)
		if r.A.Seen {
			c := r.A
			c.Where = []string{r.Target}
			as = append(as, c)
		} else {
			c := r.B
			c.Where = []string{r.Target}
			bs = append(bs, c)
		}
	}
	m.A, m.B = joinCells(as), joinCells(bs)
	m.Differs = m.A.Tone != m.B.Tone
	m.Targets = targets
	out := []CmpRow{m}
	skip := map[int]bool{}
	for _, i := range idx {
		skip[i] = true
	}
	for i, r := range rows {
		if !skip[i] {
			out = append(out, r)
		}
	}
	return out
}

// joinCells is one cell for several rows of one run: the worst word and tone (Got through over the rest, Stopped over
// Refused, else the first's), the counts added, every address in Where.
func joinCells(cs []CmpCell) CmpCell {
	if len(cs) == 0 {
		return CmpCell{}
	}
	out := cs[0]
	out.Where = nil
	for i, c := range cs {
		if i > 0 {
			out.Count += c.Count
			if c.Tone == ToneBad && out.Tone != ToneBad || c.Tone == ToneGood && out.Tone == ToneMuted {
				out.Word, out.Tone = c.Word, c.Tone
			}
		}
		out.Where = append(out.Where, c.Where...)
	}
	if len(cs) > 1 {
		out.Detail = fmt.Sprintf("×%d", out.Count)
	}
	return out
}

// sideName is how the summary names one run: "Run A (watch-codex, watched)".
func sideName(s CmpSide, label string) string {
	mode := "enforced by Tego"
	if s.Run.Tier == "observe" {
		mode = "watched"
	}
	if s.Run.Agent != "" {
		return label + " (" + s.Run.Agent + ", " + mode + ")"
	}
	return label + " (" + mode + ")"
}

// did is the side's sentence: what it read and sent, then the verdict in the words and with the count its run page's
// banner and its Runs chip use: the secrets that left and where they went, or the attempts Tego refused. The refused
// count here is the verdict's, which leaves out the routine lookups and the refusals no secret was near; the table's
// Stopped cells of secret files and destinations are that count, and the connections it leaves out read Refused.
func (s CmpSide) did() string {
	// A file a person allowed (the contract asked first, the person said yes) is said as that, never as a secret
	// file read: the protected run read nothing it was not given.
	allowed := ""
	if s.SecretsAllowed > 0 {
		allowed = count(s.SecretsAllowed, "file a person allowed", "files a person allowed") + " (" + strings.Join(s.AllowedNames, ", ") + ")"
	}
	out := "read no secret file"
	switch {
	case s.SecretsOpened > 0 && allowed != "":
		out = "read " + count(s.SecretsOpened, "secret file", "secret files") + " and " + allowed + ","
	case s.SecretsOpened > 0:
		out = "read " + count(s.SecretsOpened, "secret file", "secret files")
	case allowed != "":
		out = "read " + allowed
	}
	conn := "made no off-list connection"
	if s.OffList > 0 {
		conn = "made " + count(s.OffList, "off-list connection", "off-list connections")
		if len(s.OffListTop) > 0 {
			conn += " (" + strings.Join(s.OffListTop, ", ")
			if s.OffListMore > 0 {
				conn += fmt.Sprintf(", and %d more", s.OffListMore)
			}
			conn += ")"
		}
	}
	out += " and " + conn
	switch v := s.Verdict; v.Kind {
	case VerdictLeak:
		out += "; " + count(len(v.Exposed), "secret", "secrets") + " left (" + strings.Join(v.Names(), ", ") + " sent to " + v.Dest() + ")"
	case VerdictProtected:
		out += "; Tego refused " + count(v.Stopped(), "attempt", "attempts") + " (" + v.RefusedWords() + ")"
	}
	return out
}

func summary(c *Comparison) string {
	return sideName(c.A, "Run A") + " " + c.A.did() + ". " + sideName(c.B, "Run B") + " " + c.B.did() + "."
}
