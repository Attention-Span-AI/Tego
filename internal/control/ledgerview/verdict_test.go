// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// demoRuns writes the supply-chain demo's two runs as the QA lane recorded them (2026-10-26), in small: LEFT is tego
// watch (tier observe), robbed by a poisoned dependency that connects to its sink, reads the SSH key and the
// telemetry token and sends; it then reaches the project's own API and DNS. RIGHT is tego run under the filled
// contract, with its own sink port: the sends are refused, the key read is refused, and the token read asked a
// person, who said no. A third run is lost with an open ask.
func demoRuns(t *testing.T) (root string, left, right, lost *Run) {
	t.Helper()
	root = t.TempDir()
	t0 := time.Date(2026, 10, 27, 1, 43, 28, 0, time.UTC)
	const l, r, x = "r-aaaa-0001-leftxx", "r-aaaa-0002-rightx", "r-aaaa-0003-lostxx"
	seq := 0
	var ls []string
	add := func(run string, dt time.Duration, kind, extra string) {
		ls = append(ls, line(run, map[string]string{l: "watch-python3", r: "supply-chain", x: "loop"}[run], seq, t0.Add(dt), kind, extra))
		seq++
	}
	add(l, 0, "run_start", `"tier":"observe","command":["python3"],"cwd":"/d/without/proj","launcher_user":"alice"`)
	add(l, 0, "net", `"rule":"net.resolver","verdict":"observed","dst":"127.0.0.53:53","proto":"udp"`)
	for i := 0; i < 20; i++ {
		add(l, 10*time.Millisecond, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/usr/lib/python3/x.py"`)
	}
	add(l, 50*time.Millisecond, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:45805","proto":"tcp"`)
	add(l, 50*time.Millisecond, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:45805","proto":"tcp"`)
	add(l, 51*time.Millisecond, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/without/home/.ssh/id_rsa"`)
	add(l, 51*time.Millisecond, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/without/home/.config/telemetry/token"`)
	add(l, 52*time.Millisecond, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:45805","proto":"tcp"`)
	add(l, 53*time.Millisecond, "net", `"rule":"net.resolver","verdict":"observed","dst":"127.0.0.53:53","proto":"udp"`)
	for i := 0; i < 5; i++ {
		add(l, 60*time.Millisecond, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/without/proj/src/a.py"`)
	}
	add(l, 70*time.Millisecond, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:59465","proto":"tcp"`)
	add(l, 80*time.Millisecond, "run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, l, ls...)

	ls, seq = nil, 0
	add(r, time.Minute, "run_start", `"tier":"landlock","command":["python3"],"cwd":"/d/with/proj","launcher_user":"alice"`)
	add(r, time.Minute, "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","dst":"127.0.0.1:43437","proto":"tcp"`)
	add(r, time.Minute, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:43437"`)
	add(r, time.Minute, "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","dst":"127.0.0.1:43437","proto":"tcp"`)
	add(r, time.Minute, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:43437"`)
	add(r, time.Minute, "fs", `"rule":"fs.deny_read[/d/with/home/.ssh/]","verdict":"refused","reason":"read-denied","op":"open","path":"/d/with/home/.ssh/id_rsa"`)
	add(r, time.Minute, "refused", `"rule":"fs.deny_read[/d/with/home/.ssh/]","reason":"read-denied","op":"open","target":"/d/with/home/.ssh/id_rsa"`)
	add(r, time.Minute, "ask", `"ask_id":"q-1","ask_rule":"fs.ask_read[/d/with/home/.config/telemetry/]","hold":"open","op":"read","target":"/d/with/home/.config/telemetry/token"`)
	add(r, time.Minute+89*time.Second, "answer", `"ask_id":"q-1","approved":false,"by":"uid:1000 pid:42","after_s":89.0`)
	add(r, time.Minute+89*time.Second, "fs", `"rule":"fs.ask_read[/d/with/home/.config/telemetry/]","verdict":"refused","reason":"ask-denied","op":"open","path":"/d/with/home/.config/telemetry/token"`)
	add(r, time.Minute+89*time.Second, "refused", `"rule":"fs.ask_read[/d/with/home/.config/telemetry/]","reason":"ask-denied","op":"open","target":"/d/with/home/.config/telemetry/token"`)
	add(r, time.Minute+90*time.Second, "net", `"rule":"net[127.0.0.1:59465]","verdict":"allow","dst":"127.0.0.1:59465","host":"127.0.0.1","proto":"tcp"`)
	add(r, time.Minute+91*time.Second, "run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, r, ls...)

	ls, seq = nil, 0
	add(x, 2*time.Minute, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/d/loop"`)
	add(x, 2*time.Minute, "ask", `"ask_id":"q-9","ask_rule":"fs.ask[/d/loop/held/]","hold":"open","op":"write","target":"/d/loop/held/note.md"`)
	add(x, 2*time.Minute, "net", `"rule":"net[unix:/var/run/nscd/socket]","verdict":"allow","dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	writeRun(t, root, x, ls...)

	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, s.Find(l), s.Find(r), s.Find(x)
}

func TestVerdictObserveLeak(t *testing.T) {
	_, left, _, _ := demoRuns(t)
	s := Signal(left, Sensitive{Cwd: left.Cwd})
	v := RunVerdict(left, s)
	if v.Kind != VerdictLeak || !v.Observe {
		t.Fatalf("verdict %+v, want a leak on a watched run", v)
	}
	if !slices.Equal(v.Names(), []string{"id_rsa", "token"}) {
		t.Errorf("exposed %v, want id_rsa and token", v.Exposed)
	}
	// The sink is named first: its line is closest to the secret reads; the project's own API, contacted a few lines
	// later, may be listed after it but never before.
	if v.Dest() != "127.0.0.1:45805" {
		t.Errorf("destinations %v, want 127.0.0.1:45805 first", v.Dests)
	}
	// DNS is never next to a secret, and is never the destination named.
	for _, d := range s.Outbound {
		if ResolverDst(d.Key) && d.NearSecret {
			t.Errorf("the resolver %+v is marked next to a secret", d)
		}
	}
	if slices.Contains(v.Dests, "127.0.0.53:53") {
		t.Errorf("DNS named as a destination: %v", v.Dests)
	}
}

// TestMarkIsARead: on a run whose verdict names a secret path, the lines that read it carry the mark, and a line that
// cannot have read it does not: the timeline's "Secret read" chip says what the line did.
func TestMarkIsARead(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0021-markxx"
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	const key = "/w/home/.ssh/id_rsa"
	writeRun(t, root, id,
		line(id, "agent", 0, t0, "run_start", `"tier":"observe","command":["agent"],"cwd":"/w/proj"`),
		line(id, "agent", 1, t0.Add(time.Millisecond), "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":0,"errno":2,"path":"`+key+`"`),
		line(id, "agent", 2, t0.Add(2*time.Millisecond), "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":0,"path":"`+key+`"`),
		line(id, "agent", 3, t0.Add(3*time.Millisecond), "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":1,"path":"`+key+`"`),
		line(id, "agent", 4, t0.Add(4*time.Millisecond), "net", `"rule":"unmatched","verdict":"observed","dst":"198.51.100.7:443","proto":"tcp"`))
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	r := snap.Find(id)
	v := RunVerdict(r, Signal(r, Sensitive{Cwd: r.Cwd}))
	if v.Kind != VerdictLeak || !slices.Contains(v.Exposed, key) {
		t.Fatalf("verdict %+v, want a leak of the key", v)
	}
	want := map[uint64]string{1: "", 2: MarkSecret, 3: "", 4: MarkSent}
	evs := r.AllEvents()
	for i := range evs {
		if w, ok := want[evs[i].Seq]; ok {
			if got := v.Mark(&evs[i]); got != w {
				t.Errorf("line %d (%s): mark %q, want %q", evs[i].Seq, evs[i].Raw, got, w)
			}
		}
	}
}

// TestNeverAllowHoldsTheAddressBehindAName: a line that names its host keys the destination by the name, and learn
// writes the address, so what a contract made from the run must not allow is both, for every address the name reached.
func TestNeverAllowHoldsTheAddressBehindAName(t *testing.T) {
	root := t.TempDir()
	const id = "r-aaaa-0009-namedx"
	t0 := time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)
	seq := 0
	var ls []string
	add := func(kind, extra string) {
		ls = append(ls, line(id, "a", seq, t0.Add(time.Duration(seq)*time.Millisecond), kind, extra))
		seq++
	}
	add("run_start", `"tier":"landlock","command":["agent"],"cwd":"/d/proj"`)
	add("fs", `"rule":"unmatched","verdict":"allow","op":"open","flags":524288,"path":"/d/home/.ssh/id_rsa"`)
	const named = `"rule":"net.ask[tcp://evil.example:443]","verdict":"allow","proto":"tcp","host":"evil.example"`
	add("net", named+`,"dst":"203.0.113.9:443"`)
	add("net", `"rule":"unmatched","verdict":"allow","proto":"tcp","dst":"198.51.100.7:8443"`)
	add("net", named+`,"dst":"203.0.113.9:443"`)
	add("net", named+`,"dst":"203.0.113.10:443"`)
	add("run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	v := RunVerdict(r, Signal(r, Sensitive{Cwd: r.Cwd}))
	if v.Kind != VerdictLeak {
		t.Fatalf("verdict %+v", v)
	}
	want := []string{"evil.example:443", "203.0.113.9:443", "203.0.113.10:443", "198.51.100.7:8443"}
	if got := v.NeverAllow(); !slices.Equal(got, want) {
		t.Fatalf("NeverAllow %v, want %v", got, want)
	}
	if got := (Verdict{Kind: VerdictProtected, Dests: []string{"evil.example:443"}}).NeverAllow(); got != nil {
		t.Fatalf("a run that sent nothing has %v to withhold", got)
	}
}

func TestVerdictProtected(t *testing.T) {
	_, _, right, _ := demoRuns(t)
	s := Signal(right, Sensitive{Entries: []string{"/d/with/home/.ssh/", "/d/with/home/.config/telemetry/"}, Cwd: right.Cwd})
	v := RunVerdict(right, s)
	if v.Kind != VerdictProtected || v.Observe {
		t.Fatalf("verdict %+v, want protected", v)
	}
	if v.SecretReads != 2 || v.SecretFiles != 2 || v.Sends != 2 || v.Stopped() != 4 || v.Asked != 1 {
		t.Errorf("verdict %+v, want 2 secret reads over 2 files, 2 sends, 1 answered ask", v)
	}
	if !slices.Equal(v.Dests, []string{"127.0.0.1:43437"}) {
		t.Errorf("destinations %v, want the refused sink only", v.Dests)
	}
	// The Secrets chip counts secrets, not refusals (QU-4): two secrets kept, behind four refusals.
	if v.Protected() != 2 || len(v.Kept) != 2 {
		t.Errorf("kept %v, want the two secrets", v.Kept)
	}
	// The contract's own API, allowed right after the token read, is not next to a secret.
	for _, d := range s.Outbound {
		if d.Key == "127.0.0.1:59465" && (d.NearSecret || !d.InContract) {
			t.Errorf("the allowed API %+v is marked next to a secret", d)
		}
	}
}

func TestVerdictNoAttempt(t *testing.T) {
	root, _, _, lost := demoRuns(t)
	s := Signal(lost, Sensitive{Cwd: lost.Cwd})
	if v := RunVerdict(lost, s); v.Kind != VerdictQuiet || len(v.Dests) != 0 || v.Stopped() != 0 {
		t.Fatalf("verdict %+v, want no attack attempt", v)
	}
	// An fs.ask folder is a folder whose writes ask first, not a secret.
	if len(s.Secrets) != 0 {
		t.Errorf("secrets %+v, want none: held/ is an fs.ask write folder", s.Secrets)
	}
	// The run is lost (no run_end, not live): its open ask is never pending, anywhere.
	if len(s.Approvals) != 1 || s.Approvals[0].State != "lost" || s.PendingN != 0 {
		t.Errorf("approvals %+v pending %d, want one lost ask", s.Approvals, s.PendingN)
	}
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if p := snap.Pending(); len(p) != 0 {
		t.Errorf("snapshot pending %+v, want none from a lost run", p)
	}
	// A watched run that read a secret and sent nothing next to it is "watched", not a leak.
	w := &Run{Tier: "observe"}
	if v := RunVerdict(w, &RunSignal{Secrets: []SecretTouch{{Path: "/h/.ssh/id_rsa", Observed: 1}}}); v.Kind != VerdictWatched || len(v.Read) != 1 {
		t.Errorf("watched verdict %+v", v)
	}
}

func TestRunHome(t *testing.T) {
	_, left, right, lost := demoRuns(t)
	for _, c := range []struct {
		r    *Run
		want string
	}{{left, "/d/without/home"}, {right, "/d/with/home"}, {lost, ""}} {
		if got := RunHome(c.r); got != c.want {
			t.Errorf("RunHome(%s) = %q, want %q", c.r.ID, got, c.want)
		}
	}
	if got := RunHome(&Run{User: "alice", Cwd: "/home/alice/p"}); got != "/home/alice" {
		t.Errorf("fallback home %q", got)
	}
}

// Signal table rows: the classes the demo's background must fall into.
func TestSignalBackgroundClasses(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0004-bgxxxx"
	t0 := time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)
	ls := []string{line(id, "a", 0, t0, "run_start", `"tier":"landlock","cwd":"/w/proj"`)}
	for i, tgt := range []string{"127.0.0.53:53", "unix:/run/user/1000/bus", "unix:/run/user/1000/bus", "[::1]:53"} {
		ls = append(ls, line(id, "a", i+1, t0.Add(time.Duration(i)*time.Second), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"`+tgt+`"`))
	}
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	s := Signal(r, Sensitive{Cwd: r.Cwd})
	if s.Real != 0 || s.Background != 3 {
		t.Fatalf("groups real %d background %d, want 0 and 3: %+v", s.Real, s.Background, s.Groups)
	}
	for _, g := range s.Groups {
		want := "a DNS lookup"
		if g.Subject == "unix:/run/user/1000/bus" {
			want = "a system lookup socket"
		}
		if g.Why != want {
			t.Errorf("group %s background because %q, want %q", g.Subject, g.Why, want)
		}
	}
	if !IsSystemLookup("unix:/run/user/1000/bus") || IsSystemLookup("unix:/run/user/1000/bus2") || IsSystemLookup("/run/user/x/bus") {
		t.Error("IsSystemLookup and the session bus")
	}
	_ = os.Remove(filepath.Join(root, id, "events.jsonl"))
}

// TestWatchedReached: a send outside the verdict's window is no leak, and the verdict still says the run got somewhere:
// a send seconds after the read, one past 16 lines, and a host the run first contacted before it. A lookup, a unix
// socket and a destination the contract names are not counted, and a run that is not VerdictWatched has none.
func TestWatchedReached(t *testing.T) {
	const key = `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.ssh/id_rsa"`
	const noise = `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/proj/main.go"`
	send := func(dst string) [2]string {
		return [2]string{"net", `"rule":"unmatched","verdict":"observed","proto":"tcp","dst":"` + dst + `"`}
	}
	many := func(n int, x [2]string) [][2]string { return slices.Repeat([][2]string{x}, n) }
	for _, c := range []struct {
		name    string
		gap     time.Duration
		lines   [][2]string
		kind    string
		reached int
	}{
		{"a send 6 s after the read", 6 * time.Second, [][2]string{{"fs", key}, send("203.0.113.9:443")}, VerdictWatched, 1},
		{"a send 17 lines after the read", 10 * time.Millisecond,
			slices.Concat([][2]string{{"fs", key}}, many(NearSecretLines+1, [2]string{"fs", noise}), [][2]string{send("203.0.113.9:443")}), VerdictWatched, 1},
		{"a send to a host it contacted long before", time.Second,
			slices.Concat([][2]string{send("203.0.113.9:443")}, many(30, [2]string{"fs", noise}), [][2]string{{"fs", key}, send("203.0.113.9:443")}), VerdictLeak, 0},
		{"no send at all", time.Second, [][2]string{{"fs", key}}, VerdictWatched, 0},
		{"lookups and a unix socket", time.Minute, [][2]string{{"fs", key},
			{"net", `"rule":"net.resolver","verdict":"observed","proto":"udp","dst":"127.0.0.53:53"`},
			{"net", `"rule":"unmatched","verdict":"observed","dst":"unix:/run/nscd/socket"`},
			{"net", `"rule":"unmatched","verdict":"observed","dst":"unix:/tmp/agent.sock"`}}, VerdictWatched, 0},
		{"a contract's own destination", time.Minute, [][2]string{{"fs", key},
			{"net", `"rule":"net[api.example.com:443]","verdict":"allow","proto":"tcp","dst":"198.51.100.7:443"`}}, VerdictWatched, 0},
		{"a leak has no count of its own", time.Second, [][2]string{{"fs", key}, send("203.0.113.9:443")}, VerdictLeak, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, id := t.TempDir(), "r-aaaa-0054-reach0"
			t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
			ls := []string{line(id, "a", 0, t0, "run_start", `"tier":"observe","cwd":"/w/proj"`)}
			for i, x := range c.lines {
				ls = append(ls, line(id, "a", i+1, t0.Add(time.Duration(i+1)*c.gap), x[0], x[1]))
			}
			writeRun(t, root, id, ls...)
			r, err := LoadRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			if v := RunVerdict(r, Signal(r, Sensitive{Cwd: r.Cwd})); v.Kind != c.kind || v.Reached != c.reached {
				t.Errorf("verdict %+v, want %s with %d reached", v, c.kind, c.reached)
			}
		})
	}
}

// TestPort53IsNoLookupByItself: only the engine's word (rule net.resolver) or this machine makes port 53 a lookup. A
// server anyone runs there is a destination like any other, however often it is tried: a line to one, right after a
// key read, was Routine on every try, and on a watched run a real send there was no leak.
func TestPort53IsNoLookupByItself(t *testing.T) {
	const key = `"rule":"unmatched","verdict":"allow","op":"open","path":"/w/home/.ssh/id_rsa"`
	const watchedKey = `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.ssh/id_rsa"`
	refused := func(dst string) [][2]string {
		return [][2]string{{"net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"tcp","dst":"` + dst + `"`},
			refusedConnect("unmatched", dst)}
	}
	load := func(t *testing.T, tier string, lines ...[2]string) (*Run, *RunSignal) {
		t.Helper()
		root, id := t.TempDir(), "r-aaaa-0053-port53"
		t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
		ls := []string{line(id, "a", 0, t0, "run_start", `"tier":"`+tier+`","cwd":"/w/proj"`)}
		for i, x := range lines {
			ls = append(ls, line(id, "a", i+1, t0.Add(time.Duration(i+1)*time.Second/4), x[0], x[1]))
		}
		writeRun(t, root, id, ls...)
		r, err := LoadRun(root, id)
		if err != nil {
			t.Fatal(err)
		}
		return r, Signal(r, Sensitive{Cwd: r.Cwd})
	}
	t.Run("a refused send to another machine's port 53", func(t *testing.T) {
		lines := [][2]string{{"fs", key}}
		for range 20 {
			lines = append(lines, refused("203.0.113.9:53")...)
		}
		r, s := load(t, "landlock", lines...)
		if s.High != 1 || s.Background != 0 || len(s.Groups) != 1 {
			t.Fatalf("high %d, routine %d, groups %+v", s.High, s.Background, s.Groups)
		}
		if g := s.Groups[0]; !g.NearSecret || g.Severity != SevHigh || g.Count != 20 {
			t.Errorf("group %+v", g)
		}
		if v := RunVerdict(r, s); v.Kind != VerdictProtected || v.Sends != 20 || v.Dest() != "203.0.113.9:53" {
			t.Errorf("verdict %+v, want 20 sends to 203.0.113.9:53 stopped", v)
		}
	})
	t.Run("tried with no secret near, it stays High", func(t *testing.T) {
		var lines [][2]string
		for range 20 {
			lines = append(lines, refused("203.0.113.9:53")...)
		}
		if _, s := load(t, "landlock", lines...); s.High != 1 || s.Background != 0 {
			t.Errorf("high %d, routine %d, groups %+v", s.High, s.Background, s.Groups)
		}
	})
	t.Run("a watched send to another machine's port 53", func(t *testing.T) {
		r, s := load(t, "observe", [2]string{"fs", watchedKey},
			[2]string{"net", `"rule":"unmatched","verdict":"observed","proto":"tcp","dst":"203.0.113.9:53"`})
		if v := RunVerdict(r, s); v.Kind != VerdictLeak || v.Dest() != "203.0.113.9:53" {
			t.Errorf("verdict %+v, want a leak to 203.0.113.9:53", v)
		}
	})
	t.Run("a resolver the engine named, at any address", func(t *testing.T) {
		r, s := load(t, "observe", [2]string{"fs", watchedKey},
			[2]string{"net", `"rule":"net.resolver","verdict":"observed","proto":"udp","dst":"8.8.8.8:53"`})
		if v := RunVerdict(r, s); v.Kind != VerdictWatched || len(v.Dests) != 0 {
			t.Errorf("verdict %+v, want a watched run with no destination", v)
		}
		if len(s.Outbound) != 1 || !s.Outbound[0].Background || s.Outbound[0].NearSecret {
			t.Errorf("outbound %+v", s.Outbound)
		}
	})
	t.Run("a refused lookup on this machine", func(t *testing.T) {
		r, s := load(t, "landlock", append([][2]string{{"fs", key}}, refused("127.0.0.53:53")...)...)
		if s.Background != 1 || s.High != 0 || s.Groups[0].Why != "a DNS lookup" || s.Groups[0].NearSecret {
			t.Errorf("routine %d, high %d, groups %+v", s.Background, s.High, s.Groups)
		}
		if v := RunVerdict(r, s); v.Lookups != 1 || v.Stopped() != 0 {
			t.Errorf("verdict %+v, want one lookup and nothing stopped", v)
		}
	})
}

// Compare on the demo's two runs: the attack's rows lead, the two sinks read as one row, the cells say Got through and
// Stopped, and the summary agrees with the table.
func TestCompareDemoStory(t *testing.T) {
	_, left, right, _ := demoRuns(t)
	sl := Signal(left, Sensitive{Cwd: left.Cwd})
	sr := Signal(right, Sensitive{Entries: []string{"/d/with/home/.ssh/", "/d/with/home/.config/telemetry/"}, Cwd: right.Cwd})
	c := CompareSignals(left, right, sl, sr, false)
	if len(c.Rows) < 3 {
		t.Fatalf("rows %+v", c.Rows)
	}
	var merged *CmpRow
	for i, r := range c.Rows[:3] {
		if !r.Danger {
			t.Errorf("row %d %+v is not part of the attack", i, r)
		}
		if r.Merged {
			merged = &c.Rows[i]
		}
	}
	if merged == nil {
		t.Fatalf("no merged attacker row among the first three: %+v", c.Rows[:3])
	}
	if merged.A.Word != "Got through" || merged.A.Tone != ToneBad || !slices.Equal(merged.A.Where, []string{"127.0.0.1:45805"}) ||
		merged.B.Word != "Stopped" || merged.B.Tone != ToneGood || !slices.Equal(merged.B.Where, []string{"127.0.0.1:43437"}) {
		t.Errorf("merged row %+v", *merged)
	}
	for _, r := range c.Rows {
		if r.Target == "127.0.0.1:45805" || r.Target == "127.0.0.1:43437" {
			t.Errorf("a sink still has its own row: %+v", r)
		}
	}
	want := "Run A (watch-python3, watched) read 2 secret files and made 3 off-list connections (127.0.0.1:45805 ×3); 2 secrets left (id_rsa, token sent to 127.0.0.1:45805). " +
		"Run B (supply-chain, enforced by Tego) read no secret file and made no off-list connection; Tego refused 4 attempts (2 secret reads and 2 sends to 127.0.0.1:43437)."
	if c.Summary != want {
		t.Errorf("summary\n%q, want\n%q", c.Summary, want)
	}
}
