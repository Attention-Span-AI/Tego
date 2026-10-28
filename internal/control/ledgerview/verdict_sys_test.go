// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// sysRuns writes two runs shaped like what a real Codex or curl leaves under Tego (the UX lane's ledgers, 2026-10-27):
// each reads a secret, asks nscd for a name over its unix socket right after (the C library's getaddrinfo), reads a
// second secret and then connects to the attacker's sink at 127.0.0.1:48802. The nscd lookups sit closer to the
// secret reads than the sink does. W is tego watch (everything observed); E is enforced: both reads, the four nscd
// lookups and the send are refused.
func sysRuns(t *testing.T) (w, e *Run) {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	const wid, eid = "r-sysx-0001-watchx", "r-sysx-0002-enforc"
	seq := 0
	var ls []string
	add := func(run string, dt time.Duration, kind, extra string) {
		ls = append(ls, line(run, "codex", seq, t0.Add(dt), kind, extra))
		seq++
	}
	add(wid, 0, "run_start", `"tier":"observe","command":["codex"],"cwd":"/s/without/proj"`)
	add(wid, 10*time.Millisecond, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/s/without/home/.ssh/id_ed25519"`)
	add(wid, 11*time.Millisecond, "net", `"rule":"unmatched","verdict":"observed","dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	add(wid, 12*time.Millisecond, "net", `"rule":"unmatched","verdict":"observed","dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	add(wid, 13*time.Millisecond, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/s/without/home/.config/telemetry/token"`)
	for i := 0; i < 4; i++ {
		add(wid, 14*time.Millisecond, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/s/without/proj/README.md"`)
	}
	add(wid, 20*time.Millisecond, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:48802","proto":"tcp"`)
	add(wid, 30*time.Millisecond, "run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, wid, ls...)

	ls, seq = nil, 0
	refuse := func(dt time.Duration, kind, rule, reason, op, target, payload string) {
		add(eid, dt, kind, `"rule":"`+rule+`","verdict":"refused","reason":"`+reason+`",`+payload)
		add(eid, dt, "refused", `"rule":"`+rule+`","reason":"`+reason+`","op":"`+op+`","target":"`+target+`"`)
	}
	add(eid, time.Minute, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/s/with/proj"`)
	refuse(time.Minute+10*time.Millisecond, "fs", "fs.deny_read[/s/with/home/.ssh/]", "read-denied", "open", "/s/with/home/.ssh/id_ed25519",
		`"op":"open","path":"/s/with/home/.ssh/id_ed25519"`)
	for i := 0; i < 4; i++ {
		refuse(time.Minute+11*time.Millisecond, "net", "unmatched", "net-not-allowed", "net", "unix:/var/run/nscd/socket",
			`"dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	}
	refuse(time.Minute+13*time.Millisecond, "fs", "fs.deny_read[/s/with/home/.config/telemetry/]", "read-denied", "open", "/s/with/home/.config/telemetry/token",
		`"op":"open","path":"/s/with/home/.config/telemetry/token"`)
	refuse(time.Minute+20*time.Millisecond, "net", "unmatched", "net-not-allowed", "net", "127.0.0.1:48802",
		`"dst":"127.0.0.1:48802","proto":"tcp"`)
	add(eid, time.Minute+30*time.Millisecond, "run_end", `"reason":"exit","exit_code":1`)
	writeRun(t, root, eid, ls...)

	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return s.Find(wid), s.Find(eid)
}

func sysSensitive(r *Run) Sensitive {
	home := strings.TrimSuffix(r.Cwd, "/proj") + "/home"
	return Sensitive{Entries: []string{home + "/.ssh/", home + "/.config/telemetry/"}, Cwd: r.Cwd}
}

// A system lookup is never next to a secret, never a send and never where the secrets went (UX-F1), and Compare
// prints the count the banner and chip print (UX-F2).
func TestVerdictSystemLookupIsRoutine(t *testing.T) {
	w, e := sysRuns(t)
	sw, se := Signal(w, sysSensitive(w)), Signal(e, sysSensitive(e))

	for name, s := range map[string]*RunSignal{"watched": sw, "enforced": se} {
		for _, d := range s.Outbound {
			if IsSystemLookup(d.Key) && (d.NearSecret || !d.Background) {
				t.Errorf("%s: the nscd destination %+v is next to a secret or not routine", name, d)
			}
		}
		for _, g := range s.Groups {
			if g.SystemLookup && (g.NearSecret || !g.Background) {
				t.Errorf("%s: the nscd refusals %+v are next to a secret or not routine", name, g)
			}
		}
	}

	vw := RunVerdict(w, sw)
	if vw.Kind != VerdictLeak || !vw.Observe {
		t.Fatalf("watched verdict %+v, want a leak", vw)
	}
	if !slices.Equal(vw.Dests, []string{"127.0.0.1:48802"}) {
		t.Errorf("watched destinations %v, want the sink only, never the nscd socket", vw.Dests)
	}
	if !slices.Equal(vw.Names(), []string{"id_ed25519", "token"}) {
		t.Errorf("watched exposed %v, want id_ed25519 and token", vw.Exposed)
	}

	ve := RunVerdict(e, se)
	if ve.Kind != VerdictProtected {
		t.Fatalf("enforced verdict %+v, want protected", ve)
	}
	if ve.SecretReads != 2 || ve.Sends != 1 || ve.Stopped() != 3 || ve.Lookups != 4 {
		t.Errorf("enforced verdict %+v, want 2 secret reads, 1 send, 3 stopped and 4 lookups apart", ve)
	}
	if !slices.Equal(ve.Dests, []string{"127.0.0.1:48802"}) {
		t.Errorf("enforced destinations %v, want the sink only", ve.Dests)
	}
	if got, want := ve.RefusedWords(), "2 secret reads and 1 send to 127.0.0.1:48802"; got != want {
		t.Errorf("RefusedWords %q, want %q", got, want)
	}

	c := CompareSignals(w, e, sw, se, false)
	if got := c.B.Verdict.Stopped(); got != ve.Stopped() {
		t.Errorf("Compare counts %d refused for the enforced run, its verdict %d", got, ve.Stopped())
	}
	for _, want := range []string{
		"Run A (codex, watched) read 2 secret files and made 1 off-list connection (127.0.0.1:48802); 2 secrets left (id_ed25519, token sent to 127.0.0.1:48802).",
		"Run B (codex, enforced by Tego) read no secret file and made no off-list connection; Tego refused 3 attempts (2 secret reads and 1 send to 127.0.0.1:48802).",
	} {
		if !strings.Contains(c.Summary, want) {
			t.Errorf("summary\n%q\nlacks\n%q", c.Summary, want)
		}
	}
	if strings.Contains(c.Summary, "nscd") {
		t.Errorf("summary names the nscd socket: %q", c.Summary)
	}
}

func TestRefusedWordsSeveralDestinations(t *testing.T) {
	for _, c := range []struct {
		v    Verdict
		want string
	}{
		{Verdict{SecretReads: 1}, "1 secret read"},
		{Verdict{Sends: 3, Dests: []string{"10.0.0.9:443", "10.0.0.8:443"}}, "3 sends (to 10.0.0.9:443 and 1 more)"},
		{Verdict{SecretReads: 2, Sends: 1, Dests: []string{"127.0.0.1:1"}}, "2 secret reads and 1 send to 127.0.0.1:1"},
		{Verdict{}, ""},
	} {
		if got := c.v.RefusedWords(); got != c.want {
			t.Errorf("RefusedWords(%+v) = %q, want %q", c.v, got, c.want)
		}
	}
}

// A run that goes from live to lost leaves no new line: the cached Signal must still drop its "pending" ask (PF-F8).
func TestSignalCacheSeesLiveFlip(t *testing.T) {
	root, id := t.TempDir(), "r-sysx-0003-livefl"
	t0 := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	writeRun(t, root, id,
		line(id, "a", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/l"`),
		line(id, "a", 1, t0.Add(time.Second), "ask", `"ask_id":"q-1","ask_rule":"fs.ask[/l/held/]","hold":"open","op":"write","target":"/l/held/a"`))
	loaded, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	live := *loaded
	live.Live, live.Pending = true, []Ask{{AskID: "q-1"}}
	if s := Signal(&live, Sensitive{}); len(s.Approvals) != 1 || s.Approvals[0].State != "pending" || s.PendingN != 1 {
		t.Fatalf("live run approvals %+v, want one pending", s.Approvals)
	}
	lost := live
	lost.Live, lost.Pending = false, nil
	if s := Signal(&lost, Sensitive{}); len(s.Approvals) != 1 || s.Approvals[0].State != "lost" || s.PendingN != 0 {
		t.Errorf("lost run approvals %+v pending %d, want the ask lost and nothing pending", s.Approvals, s.PendingN)
	}
}
