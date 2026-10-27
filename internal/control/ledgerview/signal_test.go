// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// repeatedConnects and repeatedTTY are how many refused connects to one host and refused /dev/tty opens enforcedRun has.
const repeatedConnects, repeatedTTY = 12, 11

// enforcedRun is the supply-chain demo's enforced run in small: Codex's own probes on port 65535 to a host it also
// reaches on 443, refused connects it retries, a /dev/tty the held reads cannot hold, and among them the three
// lines that matter: the SSH key refused and two sends to the attacker on 127.0.0.1:8802. The retries are repeated
// more than any noise rule could count, and stay real: only their place and operation decide (TestRepeatsKeepSeverity).
func enforcedRun(t *testing.T) *Run {
	t.Helper()
	root, id := t.TempDir(), "r-aaaa-0001-enforc"
	t0 := time.Date(2026, 10, 25, 23, 44, 0, 0, time.UTC)
	seq := 0
	var ls []string
	add := func(dt time.Duration, kind, extra string) {
		ls = append(ls, line(id, "supply-chain", seq, t0.Add(dt), kind, extra))
		seq++
	}
	add(0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/proj"`)
	add(time.Second, "net", `"rule":"net[tcp://chatgpt.com:443]","verdict":"allow","dst":"104.18.32.47:443","host":"chatgpt.com","proto":"tcp"`)
	add(time.Second, "net", `"rule":"net[127.0.0.1:8803]","verdict":"allow","dst":"127.0.0.1:8803","host":"127.0.0.1","proto":"tcp"`)
	for i := 0; i < 30; i++ { // probes to a host the run reaches: background, though fewer than K per port elsewhere
		add(2*time.Second, "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"104.18.32.47:65535"`)
		add(2*time.Second, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:65535"`)
	}
	for i := 0; i < repeatedConnects; i++ { // retries to a host never reached: a refused connect, however many
		add(3*time.Second, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"172.64.144.52:443"`)
	}
	for i := 0; i < repeatedTTY; i++ {
		add(4*time.Second, "refused", `"rule":"held-unsupported","reason":"fs-gate","op":"open","target":"/dev/tty"`)
	}
	add(5*time.Second, "refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/lsb_release"`)
	add(5*time.Second, "refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/bin/lsb_release"`)
	add(6*time.Second, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:9999"`)
	for i := 0; i < 40; i++ { // spacer: the attack comes much later and many lines on
		add(time.Minute, "net", `"rule":"net[tcp://chatgpt.com:443]","verdict":"allow","dst":"104.18.32.47:443","host":"chatgpt.com","proto":"tcp"`)
	}
	add(2*time.Minute, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:8802"`)
	add(2*time.Minute, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:8802"`)
	add(2*time.Minute, "fs", `"rule":"fs.deny_read[/w/home/.ssh/]","verdict":"refused","reason":"read-denied","op":"open","path":"/w/home/.ssh/id_rsa"`)
	add(2*time.Minute, "refused", `"rule":"fs.deny_read[/w/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`)
	add(3*time.Minute, "ask", `"ask_id":"q-1","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/w/proj/confidential/plan.md"`)
	add(3*time.Minute+41*time.Second, "answer", `"ask_id":"q-1","approved":true,"by":"uid:1000","after_s":41.5`)
	add(3*time.Minute+41*time.Second, "fs", `"rule":"fs.ask_read[./confidential/]","verdict":"allow","authority":"human","op":"open","path":"/w/proj/confidential/plan.md"`)
	add(4*time.Minute, "refused", `"rule":"live.block[exec:ls]","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/ls"`)
	add(5*time.Minute, "run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSignalEnforcedRunPutsTheKeyAndTheAttackerFirst(t *testing.T) {
	r := enforcedRun(t)
	s := Signal(r, Sensitive{Entries: []string{"/w/home/.ssh/", "./confidential/"}, Cwd: r.Cwd})

	if len(s.Secrets) != 2 || s.Secrets[0].Path != "/w/home/.ssh/id_rsa" || s.Secrets[0].Refused != 1 || s.Secrets[0].Rule == "" {
		t.Fatalf("secrets %+v, want the SSH key refused first", s.Secrets)
	}
	if p := s.Secrets[1]; p.Path != "/w/proj/confidential/plan.md" || p.Asked != 1 || p.Allowed != 1 {
		t.Fatalf("second secret %+v, want plan.md asked once and allowed once", p)
	}
	if d := s.Outbound[0]; d.Key != "127.0.0.1:8802" || d.Refused != 2 || !d.NearSecret || d.Background {
		t.Fatalf("first destination %+v, want 127.0.0.1:8802 refused twice, next to the secret", d)
	}
	// Loopback is never folded by "reached on another port": 9999 stays in front though 8803 was reached.
	var d9999, d8803 *Dest
	for i := range s.Outbound {
		switch s.Outbound[i].Key {
		case "127.0.0.1:9999":
			d9999 = &s.Outbound[i]
		case "127.0.0.1:8803":
			d8803 = &s.Outbound[i]
		}
	}
	if d9999 == nil || d9999.Background || d9999.NearSecret || d8803 == nil || !d8803.InContract {
		t.Fatalf("9999 %+v, 8803 %+v", d9999, d8803)
	}
	if s.BackgroundDests != 1 || s.BackgroundDestLines != 30 {
		t.Fatalf("background destinations %d (%d lines)", s.BackgroundDests, s.BackgroundDestLines)
	}

	// Never drop counts: every refused line is in exactly one group.
	sum := 0
	for _, g := range s.Groups {
		sum += g.Count
	}
	if sum != r.Refusals || s.RealLines+s.BackgroundLines != r.Refusals {
		t.Fatalf("groups hold %d lines (real %d + background %d), run has %d refusals", sum, s.RealLines, s.BackgroundLines, r.Refusals)
	}
	if want := 30 + repeatedTTY; s.BackgroundLines != want || s.Background != 2 {
		t.Fatalf("background %d groups, %d lines; want 2 and %d", s.Background, s.BackgroundLines, want)
	}
	why := map[string]string{}
	for _, g := range s.Groups {
		if g.Background {
			why[g.Subject] = g.Why
		}
	}
	if why["104.18.32.47:65535"] != "a route probe to port 65535" || why["/dev/tty"] != "a terminal or standard device" || why["172.64.144.52"] != "" {
		t.Fatalf("background reasons %v", why)
	}
	// The groups that matter come first: the secret, then the live block (a contract-named rule), then the send
	// next to the secret; background last.
	if g := s.Groups[0]; !g.Secret || g.Subject != "/w/home/.ssh/id_rsa" {
		t.Fatalf("first group %+v", g)
	}
	if g := s.Groups[1]; g.Rule != "live.block[exec:ls]" {
		t.Fatalf("second group %+v", g)
	}
	if g := s.Groups[2]; g.Subject != "127.0.0.1:8802" || g.Count != 2 || !g.NearSecret || len(g.Ports) != 1 || g.Ports[0] != "8802" {
		t.Fatalf("third group %+v", g)
	}
	if g := s.Groups[len(s.Groups)-1]; !g.Background {
		t.Fatalf("last group %+v is not background", g)
	}
	for _, g := range s.Groups {
		if g.Subject == "lsb_release" && (g.Count != 2 || len(g.Targets) != 2) {
			t.Fatalf("lsb_release group %+v, want both paths in one group of 2", g)
		}
	}

	if len(s.Approvals) != 1 || s.Approvals[0].State != "approved" || s.Approvals[0].By != "uid:1000" || s.Approvals[0].After != 41500*time.Millisecond || s.Approved != 1 {
		t.Fatalf("approvals %+v", s.Approvals)
	}
	if len(s.Blocks) != 1 || s.Blocks[0].Value != "exec:ls" || s.Blocks[0].N != 1 {
		t.Fatalf("blocks %+v", s.Blocks)
	}
	if len(s.Programs) != 2 || s.Programs[0].Program != "lsb_release" || s.Programs[0].N != 2 {
		t.Fatalf("programs %+v", s.Programs)
	}
	if h, tl := s.OutHead(1), s.OutTail(1); len(h) != 1 || len(h)+len(tl)+s.BackgroundDests != len(s.Outbound) {
		t.Fatalf("head %d tail %d background %d of %d", len(h), len(tl), s.BackgroundDests, len(s.Outbound))
	}
}

func TestSignalWatchRunShowsTheObservedKeyReadAndSend(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0002-watchx"
	t0 := time.Date(2026, 10, 25, 23, 40, 0, 0, time.UTC)
	ls := []string{line(id, "watch", 0, t0, "run_start", `"tier":"observe","command":["codex"],"cwd":"/w/proj"`)}
	for i := 1; i <= 50; i++ { // Codex reading its own auth.json and talking to its API, long before the attack
		ls = append(ls, line(id, "watch", i, t0.Add(time.Duration(i)*time.Millisecond), "net",
			`"rule":"unmatched","verdict":"observed","dst":"172.64.155.209:443","proto":"tcp"`))
	}
	ls = append(ls,
		line(id, "watch", 51, t0.Add(time.Second), "fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/codex-home/auth.json"`),
		line(id, "watch", 52, t0.Add(time.Minute), "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:8801","proto":"tcp"`),
		line(id, "watch", 53, t0.Add(time.Minute), "fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.ssh/id_rsa"`),
		line(id, "watch", 54, t0.Add(time.Minute), "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:8801","proto":"tcp"`),
		line(id, "watch", 55, t0.Add(time.Minute), "fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.config/telemetry/token"`),
		line(id, "watch", 56, t0.Add(2*time.Minute), "run_end", `"reason":"exit","exit_code":0`))
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	s := Signal(r, Sensitive{Cwd: r.Cwd})
	got := map[string]int{}
	for _, x := range s.Secrets {
		got[x.Path] = x.Observed
	}
	if got["/w/home/.ssh/id_rsa"] != 1 || got["/w/home/.config/telemetry/token"] != 1 || got["/w/codex-home/auth.json"] != 1 || len(got) != 3 {
		t.Fatalf("secrets %v", got)
	}
	if d := s.Outbound[0]; d.Key != "127.0.0.1:8801" || d.Observed != 2 || !d.NearSecret {
		t.Fatalf("first destination %+v, want 127.0.0.1:8801 observed twice, next to a secret", d)
	}
	if d := s.Outbound[1]; d.Key != "172.64.155.209:443" || d.NearSecret {
		t.Fatalf("second destination %+v, want the API, not near a secret", d)
	}
	if len(s.Groups) != 0 || s.BackgroundLines != 0 {
		t.Fatalf("groups %+v in a run with no refusal", s.Groups)
	}
}

// TestSensitiveUnder checks the run's own guarded entries, and the well-known places Highlights relies on;
// IsSecretPath (compare_test.go) is the one detector both Highlights and Compare use.
func TestSensitiveUnder(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/u/.ssh/id_ed25519":        true,
		"/home/u/.config/gh/token":       true,
		"/home/u/.config/token":          false,
		"/home/u/.git-credentials":       true,
		"/p/docs/ssh.md":                 false,
		fmt.Sprintf("/p/%s/x", ".gnupg"): true,
	} {
		if got := IsSecretPath(p); got != want {
			t.Errorf("IsSecretPath(%q) = %v, want %v", p, got, want)
		}
	}
	s := Sensitive{Entries: []string{"./confidential/", "/etc/secret", "~/.netrc", "/srv/*.key"}, Cwd: "/w/proj"}
	for p, want := range map[string]bool{
		"/w/proj/confidential":         true,
		"/w/proj/confidential/plan.md": true,
		"/w/proj/confidentialx":        false,
		"/etc/secret":                  true,
		"/etc/secretive":               false,
		"/srv/a.key":                   true,
	} {
		if _, got := s.under(p); got != want {
			t.Errorf("under(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestSignalRouteProbesFoldAndTheKeyNextToASendLeads is the demo's enforced run as the merged dashboard read it: a
// one-off connect to port 65535 of a host the run never reached is a route probe (background, not "that matters"),
// and of the secrets touched, the key read right before the send to the attacker leads, ahead of an earlier .ssh
// directory listing that no send followed.
func TestSignalRouteProbesFoldAndTheKeyNextToASendLeads(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0002-probes"
	t0 := time.Date(2026, 10, 25, 23, 44, 0, 0, time.UTC)
	seq := 0
	var ls []string
	add := func(dt time.Duration, kind, extra string) {
		ls = append(ls, line(id, "supply-chain", seq, t0.Add(dt), kind, extra))
		seq++
	}
	add(0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/proj"`)
	add(time.Second, "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"[2606:50c0:8000::154]:65535"`)
	add(time.Second, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"[2606:50c0:8000::154]:65535"`)
	add(time.Second, "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"127.0.0.1:65535"`)
	add(time.Second, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:65535"`)
	add(time.Second, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"[2606:50c0:8000::154]:443"`)
	add(20*time.Second, "refused", `"rule":"fs.deny_read[/w/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh"`)
	for i := 0; i < 20; i++ {
		add(time.Minute, "net", `"rule":"net[tcp://chatgpt.com:443]","verdict":"allow","dst":"104.18.32.47:443","host":"chatgpt.com","proto":"tcp"`)
	}
	add(2*time.Minute, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:8802"`)
	add(2*time.Minute, "refused", `"rule":"fs.deny_read[/w/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`)
	add(150*time.Second, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:8443"`)
	add(3*time.Minute, "run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	s := Signal(r, Sensitive{Entries: []string{"/w/home/.ssh/"}, Cwd: r.Cwd})
	why := map[string]string{}
	for _, g := range s.Groups {
		why[g.Subject] = g.Why
		if g.Subject == "127.0.0.1:65535" && g.Background {
			t.Errorf("a loopback port 65535 is a local service, never a route probe: %+v", g)
		}
	}
	if why["[2606:50c0:8000::154]:65535"] != "a route probe to port 65535" || why["[2606:50c0:8000::154]"] != "" ||
		why["104.18.32.47"] != "the run also reached this host" {
		t.Fatalf("background reasons %v", why)
	}
	if len(s.Secrets) != 2 || s.Secrets[0].Path != "/w/home/.ssh/id_rsa" || !s.Secrets[0].NearSend || s.Secrets[1].NearSend {
		t.Fatalf("secrets %+v, want the key next to the send first", s.Secrets)
	}
	if d := s.Outbound[0]; d.Key != "127.0.0.1:8802" {
		t.Fatalf("first destination %+v", d)
	}
	for _, d := range s.Outbound {
		if d.Key == "[2606:50c0:8000::154]:65535" && !d.Background || d.Key == "[2606:50c0:8000::154]:443" && d.Background {
			t.Fatalf("destination %+v: the probe folds, the real connect to the same host does not", d)
		}
	}
}

// TestSignalIsCachedPerRunAndLineCount: the same run asked twice is computed once; a run with one more line, or other
// secret entries, is computed again; and labelling a returned group does not change what the next caller gets.
func TestSignalIsCachedPerRunAndLineCount(t *testing.T) {
	r := enforcedRun(t)
	s := Sensitive{Entries: []string{"/w/home/.ssh/"}, Cwd: "/w/proj"}
	before := signalComputes.Load()
	a := Signal(r, s)
	if len(a.Groups) == 0 {
		t.Fatal("no groups")
	}
	a.Groups[0].Label = "changed by the web layer"
	b := Signal(r, s)
	if n := signalComputes.Load() - before; n != 1 {
		t.Errorf("computed %d times for two asks of the same run, want 1", n)
	}
	if b.Groups[0].Label != "" {
		t.Errorf("a label set on one result leaked into the cache: %q", b.Groups[0].Label)
	}
	if b.Real != a.Real || b.Background != a.Background || len(b.Secrets) != len(a.Secrets) {
		t.Errorf("cached result differs: %+v vs %+v", b, a)
	}
	longer := *r
	longer.Events = append(slices.Clone(r.Events), r.Events[len(r.Events)-1])
	longer.Events[len(longer.Events)-1].Seq++
	Signal(&longer, s)
	Signal(r, Sensitive{Cwd: "/w/proj"})
	if n := signalComputes.Load() - before; n != 3 {
		t.Errorf("computed %d times after a longer run and other entries, want 3", n)
	}
}

// TestRouteProbeIsAUDPConnect: a route probe is a UDP line to port 65535 of a remote host (musl's getaddrinfo
// connects a UDP socket there to sort the addresses it returns, and sends nothing). A TCP connect to the same port
// is a real attempt: the port alone named it a probe, so a beacon to an attacker's port 65535 folded as background.
// Highlights folds only the UDP one, Compare counts only the UDP one as background, and the Overview's recent
// refusals leave the UDP one out and keep the TCP one.
func TestRouteProbeIsAUDPConnect(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0003-udpprb"
	t0 := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	seq := 0
	var ls []string
	add := func(kind, extra string) {
		ls = append(ls, line(id, "codex", seq, t0.Add(time.Duration(seq)*time.Second), kind, extra))
		seq++
	}
	add("run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/proj"`)
	add("net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"104.18.32.47:65535"`)
	add("refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:65535"`)
	add("net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"tcp","dst":"198.51.100.9:65535"`)
	add("refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"198.51.100.9:65535"`)
	add("run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	bg := map[string]bool{}
	for _, g := range Signal(r, Sensitive{Cwd: r.Cwd}).Groups {
		bg[g.Subject] = g.Background
	}
	if !bg["104.18.32.47:65535"] || bg["198.51.100.9:65535"] {
		t.Fatalf("background %v: want the UDP probe folded and the TCP connect to port 65535 kept", bg)
	}
	var udp, tcp int
	for i := range r.Events {
		e := &r.Events[i]
		if e.Kind == "net" && background(e) {
			if e.Proto == "udp" {
				udp++
			} else {
				tcp++
			}
		}
	}
	if udp != 1 || tcp != 0 {
		t.Fatalf("compare background: udp %d tcp %d, want 1 and 0", udp, tcp)
	}
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	rows := s.Refusals(0)
	if len(rows) != 1 || rows[0].Target != "198.51.100.9:65535" {
		t.Fatalf("recent refusals %+v: want only the TCP connect, the route probe left out", rows)
	}
}
