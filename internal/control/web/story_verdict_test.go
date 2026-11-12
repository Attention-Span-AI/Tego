// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	sysWatchRun = "r-aaaaaaaa-0000000000031-syswat"
	sysGuardRun = "r-aaaaaaaa-0000000000032-sysgrd"
)

// sysFixture is the UX lane's two ledgers (2026-10-27), in small: a Codex-like agent reads the SSH key, asks nscd for
// a name over its unix socket right after (getaddrinfo), reads the telemetry token and sends to the sink at
// 127.0.0.1:48802. The watched run observes all of it; the enforced run is refused both reads, the four nscd lookups
// and the send, each refused action followed by the kind=refused line that mirrors it.
func sysFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	write := func(run, contract string, ls []string) {
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
		if contract != "" {
			if err := os.WriteFile(filepath.Join(root, run, "contract.yaml"), []byte(contract), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var ls []string
	seq := 0
	add := func(run string, ms int, kind, extra string) {
		ls = append(ls, line(run, "codex", seq, t0.Add(time.Duration(ms)*time.Millisecond), kind, extra))
		seq++
	}
	add(sysWatchRun, 0, "run_start", `"tier":"observe","command":["codex"],"cwd":"/s/without/proj"`)
	add(sysWatchRun, 10, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/s/without/home/.ssh/id_ed25519"`)
	add(sysWatchRun, 11, "net", `"rule":"unmatched","verdict":"observed","dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	add(sysWatchRun, 12, "net", `"rule":"unmatched","verdict":"observed","dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	add(sysWatchRun, 13, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/s/without/home/.config/telemetry/token"`)
	add(sysWatchRun, 20, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:48802","proto":"tcp"`)
	add(sysWatchRun, 30, "run_end", `"reason":"exit","exit_code":0`)
	write(sysWatchRun, "", ls)

	ls, seq = nil, 0
	refuse := func(ms int, kind, rule, reason, op, target, payload string) {
		add(sysGuardRun, ms, kind, `"rule":"`+rule+`","verdict":"refused","reason":"`+reason+`",`+payload)
		add(sysGuardRun, ms, "refused", `"rule":"`+rule+`","reason":"`+reason+`","op":"`+op+`","target":"`+target+`"`)
	}
	add(sysGuardRun, 60000, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/s/with/proj"`)
	refuse(60010, "fs", "fs.deny_read[/s/with/home/.ssh/]", "read-denied", "open", "/s/with/home/.ssh/id_ed25519",
		`"op":"open","path":"/s/with/home/.ssh/id_ed25519"`)
	for i := 0; i < 4; i++ {
		refuse(60011, "net", "unmatched", "net-not-allowed", "net", "unix:/var/run/nscd/socket", `"dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	}
	refuse(60013, "fs", "fs.deny_read[/s/with/home/.config/telemetry/]", "read-denied", "open", "/s/with/home/.config/telemetry/token",
		`"op":"open","path":"/s/with/home/.config/telemetry/token"`)
	refuse(60020, "net", "unmatched", "net-not-allowed", "net", "127.0.0.1:48802", `"dst":"127.0.0.1:48802","proto":"tcp"`)
	add(sysGuardRun, 60030, "run_end", `"reason":"exit","exit_code":1`)
	write(sysGuardRun, "fs:\n  deny_read:\n    - /s/with/home/.ssh/\n    - /s/with/home/.config/telemetry/\n", ls)
	return root
}

// The run page's banner and Compare's sentence give the enforced run one number of refusals (3: two secret reads and
// one send), never the nscd lookups (UX-F1, UX-F2); the chip on Overview and Runs counts the secrets kept (2), the
// same unit as the watched run's "2 exposed" (QU-4), with the refusals in its title. The watched run's secrets went
// to the sink, not to the nscd socket.
func TestStoryOneVerdictEverywhere(t *testing.T) {
	s := newServer(t, sysFixture(t))
	c := login(t, s)

	chip := regexp.MustCompile(`>(\d+) protected<`)
	for _, p := range []string{"/", "/runs"} {
		body := get(t, s, c, p)
		m := chip.FindStringSubmatch(body)
		if m == nil || m[1] != "2" {
			t.Errorf("%s: protected chip %v, want 2", p, m)
		}
		if !strings.Contains(body, ">2 exposed<") {
			t.Errorf("%s: the watched run has no 2 exposed chip", p)
		}
		if !strings.Contains(body, `title="2 secrets kept (id_ed25519, token); 2 secret reads and 1 send to 127.0.0.1:48802 refused"`) {
			t.Errorf("%s: the protected chip's title does not name each count with its destination", p)
		}
	}

	guard := get(t, s, c, "/runs/"+sysGuardRun)
	for _, want := range []string{
		"Protected: 2 secret reads and 1 send to 127.0.0.1:48802 refused",
		"4 routine lookups",
	} {
		if !strings.Contains(guard, want) {
			t.Errorf("enforced run page lacks %q", want)
		}
	}
	banner := guard[strings.Index(guard, `class="vt"`):]
	banner = banner[:strings.Index(banner, "</p>")]
	if strings.Contains(banner, "nscd") {
		t.Errorf("the enforced banner names the nscd socket: %s", banner)
	}

	watch := get(t, s, c, "/runs/"+sysWatchRun)
	if !strings.Contains(watch, "Secrets left: id_ed25519, token sent to 127.0.0.1:48802") {
		t.Error("the watched banner does not name the sink as where the secrets went")
	}
	if strings.Contains(watch, "sent to unix:") {
		t.Error("the watched banner names a unix socket as where the secrets went")
	}
	// Highlights never tags the nscd socket After a secret read.
	for name, body := range map[string]string{"watched": watch, "enforced": guard} {
		hl := body[strings.Index(body, `id="h-hl-o"`):strings.Index(body, `id="h-hl-a"`)]
		if i := strings.Index(hl, "nscd"); i >= 0 {
			if li := hl[i:]; strings.Contains(li[:strings.Index(li, "</li>")], "After a secret read") {
				t.Errorf("%s Highlights tag the nscd socket next to a secret", name)
			}
		}
	}

	cmp := get(t, s, c, "/compare?a="+sysWatchRun+"&b="+sysGuardRun)
	for _, want := range []string{
		"; 2 secrets left (id_ed25519, token sent to 127.0.0.1:48802)", "Tego refused 3 attempts (2 secret reads and 1 send to 127.0.0.1:48802).", "3 against secrets",
	} {
		if !strings.Contains(cmp, want) {
			t.Errorf("Compare lacks %q", want)
		}
	}

	ov := get(t, s, c, "/")
	for _, want := range []string{"Refused</span>", " routine</span>"} {
		if !strings.Contains(ov, want) {
			t.Errorf("Overview lacks %q", want)
		}
	}
	if strings.Contains(ov, "Stopped</span><span class=\"value\">") {
		t.Error("the Overview tile still says Stopped")
	}
}

// TestWatchedHighlightsCountNoSeverity: the Highlights counts are of blocked actions, so a watched run, which blocks
// nothing, has none: "0 High" over a key that got through would read as nothing serious. An enforced run keeps them.
func TestWatchedHighlightsCountNoSeverity(t *testing.T) {
	s := newServer(t, sysFixture(t))
	c := login(t, s)
	watched := get(t, s, c, "/runs/"+sysWatchRun)
	if strings.Contains(watched, `class="sev-counts"`) {
		t.Error("the watched run's Highlights count severities of nothing blocked")
	}
	if !strings.Contains(watched, "Got through") {
		t.Error("the watched run's Highlights lost what got through")
	}
	if !strings.Contains(get(t, s, c, "/runs/"+sysGuardRun), `class="sev-counts"`) {
		t.Error("the enforced run's Highlights lost their severity counts")
	}
}

func TestWhenNamesTheDay(t *testing.T) {
	loc := time.Local
	now := time.Date(2026, 10, 27, 9, 30, 0, 0, loc)
	for _, c := range []struct {
		t    time.Time
		want string
	}{
		{time.Date(2026, 10, 27, 1, 46, 19, 0, loc), "01:46:19"},
		{time.Date(2026, 10, 26, 21, 43, 28, 0, loc), "Yesterday 21:43"},
		{time.Date(2026, 10, 24, 21, 43, 28, 0, loc), "Oct 24 21:43"},
		{time.Date(2025, 12, 31, 23, 0, 0, 0, loc), "Dec 31 2025 23:00"},
		{time.Time{}, "—"},
	} {
		if got := when(c.t, now); got != c.want {
			t.Errorf("when(%v) = %q, want %q", c.t, got, c.want)
		}
	}
}
