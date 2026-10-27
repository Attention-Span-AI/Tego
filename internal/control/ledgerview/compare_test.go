// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
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
	// A destination on this computer, observed in A and refused in B.
	loop := by["net 127.0.0.1:8801"]
	if loop.A.Word != "Got through" || loop.A.Tone != ToneBad || loop.A.Detail != "×3" || loop.B.Word != "Stopped" || loop.B.Detail != "×2" || !loop.Differs {
		t.Errorf("loopback row %+v", loop)
	}
	// The destination B's contract allows is not off-list in A; neither is a public cert bundle a secret.
	if r, ok := by["net 93.184.216.34:443"]; ok {
		t.Errorf("an allowed destination is routine, got a row %+v", r)
	}
	if _, ok := by["secret /etc/ssl/certs/Root.pem"]; ok {
		t.Error("a certificate bundle is not a secret")
	}
	// Programs: curl refused in B is listed, git allowed in both is routine.
	if r := by["exec curl"]; r.A.Word != "Observed" || r.B.Word != "Stopped" {
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

func TestCompareSameRunKeepsNothingHidden(t *testing.T) {
	a, _ := compareFixture(t)
	c := Compare(a, a, false)
	for _, r := range c.Rows {
		if r.Differs {
			t.Errorf("a run differs from itself on %+v", r)
		}
	}
}
