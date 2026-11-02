// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"
	"time"
)

func TestIsSecretPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/u/.ssh":                              true,
		"/home/u/.ssh/id_rsa":                       true,
		"/home/u/.ssh/id_rsa.pub":                   false,
		"/home/u/.aws/credentials":                  true,
		"/home/u/proj/.env":                         true,
		"/home/u/proj/.env.local":                   true,
		"/home/u/proj/.envrc":                       false,
		"/home/u/proj/confidential/plan.md":         true,
		"/home/u/.config/gcloud/creds.db":           true,
		"/home/u/.config/other":                     false,
		"/home/u/server.key":                        true,
		"/home/u/.codex/auth.json":                  true,
		"/etc/ssl/certs/Some_Root_CA.pem":           false,
		"/usr/lib/ssl/cert.pem":                     false,
		"/opt/python/certifi/cacert.pem":            false,
		"/home/u/proj/src/main.go":                  false,
		"/home/u/proj/docs/identity-and-secrets.md": false,
		"": false,
	} {
		if got := IsSecretPath(p); got != want {
			t.Errorf("IsSecretPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// compareFixture writes the demo's two runs: one only observed, one enforced. Their working directories sit in
// sibling trees (/d/without, /d/with), as the supply-chain demo's do.
func compareFixture(t *testing.T) (*Run, *Run) {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	const ra, rb = "r-aaaa-0001-watchx", "r-aaaa-0002-guardx"
	writeRun(t, root, ra,
		line(ra, "watch", 0, t0, "run_start", `"tier":"observe","cwd":"/d/without/proj","command":["codex"]`),
		line(ra, "watch", 1, t0.Add(time.Second), "fs", `"verdict":"observed","rule":"unmatched","op":"open","path":"/d/without/home/.ssh/id_rsa"`),
		line(ra, "watch", 2, t0.Add(2*time.Second), "fs", `"verdict":"observed","rule":"unmatched","op":"open","path":"/etc/ssl/certs/Root.pem"`),
		line(ra, "watch", 3, t0.Add(3*time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(ra, "watch", 4, t0.Add(4*time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(ra, "watch", 5, t0.Add(5*time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(ra, "watch", 6, t0.Add(6*time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"93.184.216.34:443"`),
		line(ra, "watch", 7, t0.Add(7*time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"udp","dst":"104.18.32.47:65535"`),
		line(ra, "watch", 8, t0.Add(8*time.Second), "net", `"verdict":"observed","rule":"net.resolver","proto":"udp","dst":"127.0.0.53:53"`),
		line(ra, "watch", 9, t0.Add(9*time.Second), "exec", `"verdict":"observed","rule":"unmatched","argv":["/usr/bin/git","status"]`),
		line(ra, "watch", 10, t0.Add(10*time.Second), "exec", `"verdict":"observed","rule":"unmatched","argv":["curl","-d","x"]`),
		line(ra, "watch", 11, t0.Add(11*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	writeRun(t, root, rb,
		line(rb, "guard", 0, t0, "run_start", `"tier":"landlock","cwd":"/d/with/proj","command":["codex"]`),
		line(rb, "guard", 1, t0.Add(time.Second), "fs", `"verdict":"refused","rule":"fs.deny_read[/d/with/home/.ssh/]","op":"open","path":"/d/with/home/.ssh"`),
		line(rb, "guard", 2, t0.Add(time.Second), "refused", `"rule":"fs.deny_read[/d/with/home/.ssh/]","reason":"read-denied","op":"open","target":"/d/with/home/.ssh"`),
		line(rb, "guard", 3, t0.Add(2*time.Second), "net", `"verdict":"allow","rule":"net[tcp://chatgpt.com:443]","proto":"tcp","dst":"93.184.216.34:443","host":"chatgpt.com"`),
		line(rb, "guard", 4, t0.Add(3*time.Second), "net", `"verdict":"refused","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(rb, "guard", 5, t0.Add(4*time.Second), "net", `"verdict":"refused","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(rb, "guard", 6, t0.Add(5*time.Second), "net", `"verdict":"refused","rule":"unmatched","proto":"udp","dst":"104.18.32.47:65535"`),
		line(rb, "guard", 7, t0.Add(6*time.Second), "exec", `"verdict":"allow","rule":"exec[git]","argv":["git","status"]`),
		line(rb, "guard", 8, t0.Add(7*time.Second), "exec", `"verdict":"refused","rule":"unmatched","argv":["curl","-d","x"]`),
		line(rb, "guard", 9, t0.Add(8*time.Second), "ask", `"ask_id":"q-1","hold":"open","op":"read","target":"/d/with/proj/confidential/plan.md","ask_rule":"fs.ask_read[./confidential/]"`),
		line(rb, "guard", 10, t0.Add(9*time.Second), "answer", `"ask_id":"q-1","by":"human","approved":true`),
		line(rb, "guard", 11, t0.Add(10*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return s.Find(ra), s.Find(rb)
}

func TestCompareObservedAgainstEnforced(t *testing.T) {
	a, b := compareFixture(t)
	c := Compare(a, b, false)

	// The attack first: the key read next to a send, then the attacker's address, observed in A and refused in B.
	if len(c.Rows) < 2 || c.Rows[0].Target != "…/home/.ssh/id_rsa" || c.Rows[1].Target != "127.0.0.1:8801" || !c.Rows[0].Danger || !c.Rows[1].Danger {
		t.Fatalf("first rows %+v, want the key and the destination observed in A and refused in B", c.Rows)
	}
	by := map[string]CmpRow{}
	for _, r := range c.Rows {
		by[r.Class+" "+r.Target] = r
	}
	// The ssh directory merges across the with/ and without/ trees: refused in B, and only the file was opened in A.
	ssh := by["secret …/home/.ssh"]
	if ssh.A.Seen || ssh.B.Word != "Stopped" || ssh.B.Tone != ToneGood {
		t.Errorf("ssh dir row %+v", ssh)
	}
	key := by["secret …/home/.ssh/id_rsa"]
	if key.A.Word != "Got through" || key.A.Tone != ToneBad || key.B.Seen {
		t.Errorf("ssh key row %+v", key)
	}
	// A destination on this computer, observed in A and refused in B. B's refused connects have no kind=refused line,
	// so B's verdict does not count them (the summary below), and the table agrees: Refused, muted, not Stopped.
	loop := by["net 127.0.0.1:8801"]
	if loop.A.Word != "Got through" || loop.A.Tone != ToneBad || loop.A.Detail != "×3" || loop.B.Word != "Refused" ||
		loop.B.Tone != ToneMuted || loop.B.Detail != "×2" || !loop.Differs {
		t.Errorf("loopback row %+v", loop)
	}
	// The destination B's contract allows is not off-list in A; neither is a public cert bundle a secret.
	if r, ok := by["net 93.184.216.34:443"]; ok {
		t.Errorf("an allowed destination is routine, got a row %+v", r)
	}
	if _, ok := by["secret /etc/ssl/certs/Root.pem"]; ok {
		t.Error("a certificate bundle is not a secret")
	}
	// Programs: curl refused in B is listed, and Stopped (the verdict counts no program); git allowed in both is
	// routine.
	if r := by["exec curl"]; r.A.Word != "Observed" || r.B.Word != "Stopped" || r.B.Tone != ToneGood {
		t.Errorf("curl row %+v", r)
	}
	if _, ok := by["exec git"]; ok || c.Routine != 2 {
		t.Errorf("routine rows %d (git, the allowed destination), git listed %v", c.Routine, ok)
	}
	// The approval.
	ap := by["ask …/proj/confidential/plan.md"]
	if ap.B.Word != "Asked" || ap.B.Detail != "approved" || ap.A.Seen || ap.Note != "read" {
		t.Errorf("approval row %+v", ap)
	}
	// Background: the 65535 probe and the resolver, per side.
	if c.A.Background != 2 || c.B.Background != 1 {
		t.Errorf("background %d and %d, want 2 and 1", c.A.Background, c.B.Background)
	}
	// The summary says what each run read and sent, then its verdict with the run's own count (RunVerdict): what left
	// A, and what Tego refused of B. B's refused connects here are action lines with no kind=refused line, which a
	// Signal does not count, so B's verdict counts its secret read only.
	if want := "Run A (watch, watched) read 1 secret file and made 3 off-list connections (127.0.0.1:8801 ×3); 1 secret left (id_rsa sent to 127.0.0.1:8801). " +
		"Run B (guard, enforced by Tego) read no secret file and made no off-list connection; Tego refused 1 attempt (1 secret read)."; c.Summary != want {
		t.Errorf("summary\n%q, want\n%q", c.Summary, want)
	}
	if c.Home != "…/home" {
		t.Errorf("home %q, want the merged …/home", c.Home)
	}
	if all := Compare(a, b, true); len(all.Rows) != len(c.Rows)+c.Routine || all.Routine != 0 {
		t.Errorf("all rows %d, routine %d; want %d", len(all.Rows), all.Routine, len(c.Rows)+c.Routine)
	}
}

// A destination's refusals read Stopped only when its run's verdict counts them (a send next to a secret): a refused
// connect no secret was near reads Refused, muted, so the table's Stopped cells add up to the count the sentence, the
// stat block and the Attempts stopped bar give. Both runs here are written as the supervisor writes them: each refused
// action is followed by its kind=refused mirror.
func TestCompareStoppedIsTheVerdictsCount(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	const ra, rb = "r-aaaa-0001-watchx", "r-aaaa-0002-guardx"
	writeRun(t, root, ra,
		line(ra, "watch", 0, t0, "run_start", `"tier":"observe","cwd":"/e/without/proj","command":["agent"]`),
		line(ra, "watch", 1, t0.Add(time.Second), "fs", `"verdict":"observed","rule":"unmatched","op":"open","path":"/e/without/home/.ssh/id_rsa"`),
		line(ra, "watch", 2, t0.Add(time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:9001"`),
		// A minute after the key: no secret is near this one.
		line(ra, "watch", 3, t0.Add(time.Minute), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"203.0.113.7:443"`),
		line(ra, "watch", 4, t0.Add(time.Minute+time.Second), "run_end", `"reason":"exit","exit_code":0`))
	refuse := func(seq int, ts time.Time, kind, action, mirror string) []string {
		return []string{line(rb, "guard", seq, ts, kind, action), line(rb, "guard", seq+1, ts, "refused", mirror)}
	}
	ls := []string{line(rb, "guard", 0, t0, "run_start", `"tier":"landlock","cwd":"/e/with/proj","command":["agent"]`)}
	ls = append(ls, refuse(1, t0.Add(time.Second), "fs",
		`"verdict":"refused","rule":"fs.deny_read[/e/with/home/.ssh/]","reason":"read-denied","op":"open","path":"/e/with/home/.ssh/id_rsa"`,
		`"rule":"fs.deny_read[/e/with/home/.ssh/]","reason":"read-denied","op":"open","target":"/e/with/home/.ssh/id_rsa"`)...)
	ls = append(ls, refuse(3, t0.Add(time.Second), "net",
		`"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:9001"`,
		`"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:9001"`)...)
	for i := range 2 {
		ls = append(ls, refuse(5+2*i, t0.Add(time.Minute), "net",
			`"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.7:443"`,
			`"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.7:443"`)...)
	}
	ls = append(ls, line(rb, "guard", 9, t0.Add(time.Minute+time.Second), "run_end", `"reason":"exit","exit_code":0`))
	writeRun(t, root, rb, ls...)
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	a, b := s.Find(ra), s.Find(rb)

	c := Compare(a, b, false)
	by := map[string]CmpRow{}
	for _, r := range c.Rows {
		by[r.Class+" "+r.Target] = r
	}
	// What the verdict counts keeps its words: the key B refused to read and the send next to it.
	if r := by["secret …/home/.ssh/id_rsa"]; r.A.Word != "Got through" || r.B.Word != "Stopped" || r.B.Tone != ToneGood {
		t.Errorf("key row %+v", r)
	}
	if r := by["net 127.0.0.1:9001"]; r.A.Word != "Got through" || r.B.Word != "Stopped" || r.B.Tone != ToneGood || !r.Danger {
		t.Errorf("sink row %+v", r)
	}
	// The connect no secret was near: refused, and still listed, but not Stopped.
	far, ok := by["net 203.0.113.7:443"]
	if !ok {
		t.Fatalf("the refused connect no secret was near is not listed (routine %d): %+v", c.Routine, c.Rows)
	}
	if far.A.Word != "Got through" || far.A.Tone != ToneBad || far.B.Word != "Refused" || far.B.Tone != ToneMuted ||
		far.B.Detail != "×2" || !far.Differs || far.Danger {
		t.Errorf("far row %+v, want Got through in A and a muted Refused ×2 in B", far)
	}
	// The table's Stopped cells add up to the verdict's count, the one the sentence gives.
	stopped := 0
	for _, r := range c.Rows {
		if r.B.Tone == ToneGood {
			stopped += r.B.Count
		}
	}
	if v := c.B.Verdict; v.Stopped() != 2 || stopped != v.Stopped() {
		t.Errorf("the table's Stopped cells count %d, the verdict %d (%+v); want 2 and 2", stopped, v.Stopped(), v)
	}
	if want := "Tego refused 2 attempts (1 secret read and 1 send to 127.0.0.1:9001)."; !strings.HasSuffix(c.Summary, want) {
		t.Errorf("summary %q, want it to end %q", c.Summary, want)
	}
	// Refused in both runs, a row is never routine, though neither cell is coloured.
	same := Compare(b, b, false)
	found := false
	for _, r := range same.Rows {
		if r.Target == "203.0.113.7:443" {
			found = true
			if r.A.Tone != ToneMuted || r.B.Tone != ToneMuted || r.Differs {
				t.Errorf("a run against itself: far row %+v", r)
			}
		}
	}
	if !found {
		t.Errorf("a refused connect refused in both runs is left out as routine: %+v", same.Rows)
	}
}

// One run's cells of the merged "Where the secrets went" row read as its worst: a send its verdict counts (Stopped)
// over one it does not (Refused), whichever comes first (the rows come in map order).
func TestJoinCellsStoppedOverRefused(t *testing.T) {
	refused := CmpCell{Seen: true, Word: "Refused", Tone: ToneMuted, Count: 1, Where: []string{"10.0.0.9:443"}}
	stopped := CmpCell{Seen: true, Word: "Stopped", Tone: ToneGood, Count: 2, Where: []string{"127.0.0.1:9002"}}
	for _, cs := range [][]CmpCell{{refused, stopped}, {stopped, refused}} {
		if c := joinCells(cs); c.Word != "Stopped" || c.Tone != ToneGood || c.Count != 3 || c.Detail != "×3" || len(c.Where) != 2 {
			t.Errorf("joinCells(%v) = %+v, want Stopped ×3 at both addresses", cs, c)
		}
	}
}

func TestCompareSameRunKeepsNothingHidden(t *testing.T) {
	a, _ := compareFixture(t)
	c := Compare(a, a, false)
	for _, r := range c.Rows {
		if r.Differs {
			t.Errorf("a run differs from itself on %+v", r)
		}
	}
}
