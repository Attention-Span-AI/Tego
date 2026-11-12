// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// watchedStart is a run_start like tego watch's: tier observe, record full, the stage project as its folder.
func watchedStart() line {
	return line{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "observe", Capture: "off",
		Command: []string{"python3", "-m", "unittest", "-v"}, Cwd: "/stage/without/proj",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): true}}}
}

// TestSensitiveReadsOnlyWhatItCouldRead: the same test as tego learn's leak rule and the dashboard's verdict
// (secretpath.ReadOpen): a create, a failed open and an unlink of a secret-looking path are no read of it.
func TestSensitiveReadsOnlyWhatItCouldRead(t *testing.T) {
	obs := record.VerdictObserved
	fs := func(p record.FSPayload) line {
		return line{kind: record.KindFS, at: time.Second, verdict: obs, rule: "unmatched", payload: p}
	}
	rc := compute(t, []line{
		watchedStart(),
		fs(record.FSPayload{Op: record.FSOpen, Path: "/stage/a/made.key", Flags: 0o102, Created: true}),
		fs(record.FSPayload{Op: record.FSOpen, Path: "/stage/a/missing.key", Errno: 2}),
		fs(record.FSPayload{Op: record.FSOpen, Path: "/stage/a/write.key", Flags: 0o1}),
		fs(record.FSPayload{Op: record.FSUnlink, Path: "/stage/a/gone.key"}),
		fs(record.FSPayload{Op: record.FSOpen, Path: "/stage/a/real.key"}),
		end(2*time.Second, 0),
	}, Options{})
	if len(rc.SensitiveReads) != 1 || rc.SensitiveReads[0].Path != "/stage/a/real.key" {
		t.Errorf("sensitive reads %+v, want the one open that could read", rc.SensitiveReads)
	}
}

// TestStoryOfTheWatchedRun is the supply-chain demo's LEFT run: it read ~/.ssh/id_rsa and connected three
// times to the attacker, and tego watch refused nothing. The receipt must say both, and the JSON carries the keys.
func TestStoryOfTheWatchedRun(t *testing.T) {
	obs := record.VerdictObserved
	conn := line{kind: record.KindNet, at: 2 * time.Second, verdict: obs, rule: "unmatched",
		payload: record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9821"}}
	pyc := "/stage/without/proj/vendor/telemetry_helper/__pycache__/__init__.cpython-313.pyc"
	rc := compute(t, []line{
		watchedStart(),
		{kind: record.KindExec, at: time.Second, verdict: obs, rule: "exec[python3]",
			payload: record.ExecPayload{Path: "/usr/bin/python3", Argv: []string{"python3", "-m", "unittest"}, ExecID: "x"}},
		// the pyc cache: a fresh temp file, then renamed onto its name
		{kind: record.KindFS, at: time.Second, verdict: obs, rule: "unmatched",
			payload: record.FSPayload{Op: record.FSOpen, Path: pyc + ".126756766169344", Flags: 0o2000301}},
		{kind: record.KindFS, at: time.Second, verdict: obs, rule: "unmatched",
			payload: record.FSPayload{Op: record.FSRename, Path: pyc + ".126756766169344", Path2: pyc}},
		// Codex's shell and screen: no file written (PW-12, the rehearsal's "wrote 3 files")
		{kind: record.KindFS, at: time.Second, verdict: obs, rule: "unmatched",
			payload: record.FSPayload{Op: record.FSOpen, Path: "/dev/null", Flags: 0o1101}},
		{kind: record.KindFS, at: time.Second, verdict: obs, rule: "unmatched",
			payload: record.FSPayload{Op: record.FSOpen, Path: "/dev/tty", Flags: 0o2}},
		conn, conn,
		{kind: record.KindFS, at: 2 * time.Second, verdict: obs, rule: "unmatched",
			payload: record.FSPayload{Op: record.FSOpen, Path: "/stage/without/home/.ssh/id_rsa", Flags: 0o2000000}},
		// a public key and an ordinary source file are not secrets
		{kind: record.KindFS, at: 2 * time.Second, verdict: obs, rule: "unmatched",
			payload: record.FSPayload{Op: record.FSOpen, Path: "/stage/without/home/.ssh/id_rsa.pub"}},
		{kind: record.KindFS, at: 2 * time.Second, verdict: obs, rule: "unmatched",
			payload: record.FSPayload{Op: record.FSOpen, Path: "/stage/without/proj/src/app.py"}},
		conn,
		end(3*time.Second, 0),
	}, Options{Home: "/stage/without/home"})

	var text bytes.Buffer
	if err := rc.Text(&text); err != nil {
		t.Fatal(err)
	}
	out := text.String()
	for _, want := range []string{
		"\nConnections\n", "127.0.0.1:9821  3  recorded, not blocked",
		"\nPrograms run\n  1 program, started 1 time.\n", "/usr/bin/python3  1",
		"\nSensitive files read\n", "~/.ssh/id_rsa  1  recorded, not blocked",
		// the pyc temp write and rename fold into one write, shown relative to the run's folder
		"1 written, 0 created, 0 deleted, 0 renamed.", "Wrote vendor/telemetry_helper/__pycache__/__init__.cpython-313.pyc\n",
		"Nothing was refused.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "id_rsa.pub") || strings.Contains(out, "app.py") {
		t.Errorf("a public key or a source file is listed as sensitive:\n%s", out)
	}
	// The new sections come before the refusals, in the spec's order.
	iC, iP, iS, iR := strings.Index(out, "\nConnections\n"), strings.Index(out, "\nPrograms run\n"),
		strings.Index(out, "\nSensitive files read\n"), strings.Index(out, "\nRefused actions\n")
	if iC >= iP || iP >= iS || iS >= iR {
		t.Errorf("section order: connections %d, programs %d, sensitive %d, refused %d", iC, iP, iS, iR)
	}

	var js bytes.Buffer
	if err := rc.JSON(&js); err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(js.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"connections", "programs", "sensitive_reads"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("JSON lacks %q", k)
		}
	}
	var round Receipt
	if err := json.Unmarshal(js.Bytes(), &round); err != nil {
		t.Fatal(err)
	}
	if len(round.Connections) != 1 || round.Connections[0] != (Connection{Destination: "127.0.0.1:9821", Count: 3, Verdicts: Verdicts{Observed: 3}}) {
		t.Errorf("connections = %+v", round.Connections)
	}
	if len(round.SensitiveReads) != 1 || round.SensitiveReads[0].Path != "/stage/without/home/.ssh/id_rsa" {
		t.Errorf("sensitive_reads = %+v (JSON keeps full paths)", round.SensitiveReads)
	}
	if round.V != 1 {
		t.Errorf("receipt_v = %d, want 1", round.V)
	}
}

// TestStoryOfTheEnforcedRun is the demo's RIGHT run: the attacker connections refused (each a net line and its
// mirroring refused line: one try), the key read refused by fs.deny_read, the token read held and denied, one
// allowed connection, and the default deny named in words.
func TestStoryOfTheEnforcedRun(t *testing.T) {
	ref := record.VerdictRefused
	deny := "fs.deny_read[/stage/with/home/.ssh/]"
	ask := "fs.ask_read[/stage/with/home/.config/telemetry/]"
	refusedNet := []line{
		{kind: record.KindNet, at: time.Second, verdict: ref, rule: "unmatched", reason: record.ReasonNetNotAllowed,
			payload: record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9822"}},
		{kind: record.KindRefused, at: time.Second, rule: "unmatched", reason: record.ReasonNetNotAllowed,
			payload: record.RefusedPayload{Op: "net", Target: "127.0.0.1:9822", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"}},
	}
	lines := []line{{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "landlock", Capture: "off",
		Command: []string{"codex"}, Cwd: "/stage/with/proj",
		Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): false}}}}
	lines = append(lines, refusedNet...)
	lines = append(lines, refusedNet...)
	lines = append(lines,
		line{kind: record.KindFS, at: time.Second, verdict: ref, rule: deny, reason: record.ReasonReadDenied,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/stage/with/home/.ssh/id_rsa", Flags: 0o2000000}},
		line{kind: record.KindRefused, at: time.Second, rule: deny, reason: record.ReasonReadDenied,
			payload: record.RefusedPayload{Op: "open", Target: "/stage/with/home/.ssh/id_rsa", Reason: record.ReasonReadDenied, Rule: deny}},
		// a guarded file whose name is no secret: the rule makes it sensitive
		line{kind: record.KindFS, at: time.Second, verdict: ref, rule: ask, reason: record.ReasonAskDenied,
			payload: record.FSPayload{Op: record.FSOpen, Path: "/stage/with/home/.config/telemetry/session", Flags: 0o2000000}},
		line{kind: record.KindNet, at: 2 * time.Second, verdict: record.VerdictAllow, rule: "net[127.0.0.1:9823]",
			payload: record.NetPayload{Proto: "tcp", Dst: "127.0.0.1:9823", Host: "127.0.0.1"}},
		// a named host reads as its name and port
		line{kind: record.KindNet, at: 2 * time.Second, verdict: record.VerdictAllow, rule: "net[chatgpt.com:443]",
			payload: record.NetPayload{Proto: "tcp", Dst: "104.18.32.47:443", Host: "chatgpt.com"}},
		// an HTTP request line repeats a connection; not counted again
		line{kind: record.KindNet, at: 2 * time.Second, verdict: record.VerdictAllow, rule: "net[chatgpt.com:443]",
			payload: record.NetPayload{Op: "http_request", Proto: "http", Dst: "chatgpt.com:443", Host: "chatgpt.com"}},
		end(3*time.Second, 0),
	)
	rc := compute(t, lines, Options{Home: "/stage/with/home"})
	got := map[string]Verdicts{}
	for _, c := range rc.Connections {
		got[c.Destination] = c.Verdicts
	}
	if len(got) != 3 || got["127.0.0.1:9822"] != (Verdicts{Refused: 2}) || got["127.0.0.1:9823"] != (Verdicts{Allowed: 1}) ||
		got["chatgpt.com:443"] != (Verdicts{Allowed: 1}) {
		t.Errorf("connections = %+v", rc.Connections)
	}
	if rc.Connections[0].Destination != "127.0.0.1:9822" {
		t.Errorf("the most tried destination is not first: %+v", rc.Connections)
	}
	if len(rc.SensitiveReads) != 2 || rc.SensitiveReads[0].Verdicts != (Verdicts{Refused: 1}) ||
		rc.SensitiveReads[1].Path != "/stage/with/home/.config/telemetry/session" {
		t.Errorf("sensitive_reads = %+v", rc.SensitiveReads)
	}
	if rc.SensitiveReadsNote == "" {
		t.Error("a run that did not record allowed reads has no note saying so")
	}
	var text bytes.Buffer
	_ = rc.Text(&text)
	out := text.String()
	for _, want := range []string{"127.0.0.1:9822  2  refused", "chatgpt.com:443  1  allowed",
		"2  not allowed by any rule (net-not-allowed)", "connect 127.0.0.1:9822  not allowed by any rule (net-not-allowed)",
		"open ~/.ssh/id_rsa  fs.deny_read[~/.ssh/] (read-denied)"} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "unmatched") {
		t.Errorf("the text names the default deny by its ledger value:\n%s", out)
	}
	if rc.Refusals.Total != 4 {
		t.Errorf("refusals = %d, want 4 (two connections, two reads)", rc.Refusals.Total)
	}
}

// TestTempRenameFoldNeverHidesARealRename: only a temporary file the run created itself folds into a write; a rename
// of a file that was there before the run, or to a different name, is listed as a rename.
func TestTempRenameFoldNeverHidesARealRename(t *testing.T) {
	allow := record.VerdictAllow
	fsl := func(p record.FSPayload) line {
		return line{kind: record.KindFS, at: 1, verdict: allow, rule: "w", payload: p}
	}
	rc := compute(t, []line{
		start("off", true),
		// an existing file renamed to its name less a suffix: the agent's own rename, kept
		fsl(record.FSPayload{Op: record.FSRename, Path: "/p/report.txt.bak", Path2: "/p/report.txt"}),
		// a fresh temp file renamed to another name: kept
		fsl(record.FSPayload{Op: record.FSOpen, Path: "/p/a.tmp", Flags: 0o301}),
		fsl(record.FSPayload{Op: record.FSRename, Path: "/p/a.tmp", Path2: "/p/b"}),
		// a fresh temp file (created: true) renamed onto its name: folded
		fsl(record.FSPayload{Op: record.FSOpen, Path: "/p/c.json.x1", Flags: 0o1101, Created: true}),
		fsl(record.FSPayload{Op: record.FSRename, Path: "/p/c.json.x1", Path2: "/p/c.json"}),
		end(time.Second, 0),
	}, Options{})
	f := rc.Files
	if len(f.Renamed) != 2 || f.Renamed[0].From != "/p/report.txt.bak" || f.Renamed[1].From != "/p/a.tmp" {
		t.Errorf("renamed = %+v", f.Renamed)
	}
	if !equalStrs(f.Written, []string{"/p/a.tmp", "/p/c.json"}) || !equalStrs(f.Created, []string{}) {
		t.Errorf("written = %v, created = %v", f.Written, f.Created)
	}
}

func TestShortPathAndCutMiddle(t *testing.T) {
	rc := &Receipt{Cwd: "/w/proj", home: "/home/u"}
	for in, want := range map[string]string{
		"/w/proj/src/a.go":   "src/a.go",
		"/w/proj":            ".",
		"/w/proj-old/a":      "/w/proj-old/a",
		"/home/u/.ssh/id":    "~/.ssh/id",
		"/home/user2/x":      "/home/user2/x",
		"/etc/passwd":        "/etc/passwd",
		"127.0.0.1:443":      "127.0.0.1:443",
		"relative/not/moved": "relative/not/moved",
	} {
		if got := rc.shortPath(in); got != want {
			t.Errorf("shortPath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := rc.shortTarget("/w/proj/a -> /home/u/b"); got != "a -> ~/b" {
		t.Errorf("shortTarget = %q", got)
	}
	long := "/very/long/prefix/" + strings.Repeat("x", 80) + "/telemetry_helper.py"
	got := cutMiddle(long, 40)
	if len([]rune(got)) != 40 || !strings.HasSuffix(got, "telemetry_helper.py") || !strings.Contains(got, "…") {
		t.Errorf("cutMiddle = %q (%d runes)", got, len([]rune(got)))
	}
	if cutMiddle("short", 40) != "short" {
		t.Error("a short string was cut")
	}
}

// TestCoverageDoesNotRepeatSectionNotes: the tokens note is printed once, in its own section.
func TestCoverageDoesNotRepeatSectionNotes(t *testing.T) {
	rc := compute(t, []line{start("off", true), end(time.Second, 0)}, Options{})
	var text bytes.Buffer
	_ = rc.Text(&text)
	out := text.String()
	if n := strings.Count(out, "model traffic capture was off"); n != 1 {
		t.Errorf("the tokens note appears %d times, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "\nCoverage\n  Partial: the notes in the sections above") {
		t.Errorf("coverage with every gap already said lacks its pointer:\n%s", out)
	}
	if rc.Coverage.Complete || len(rc.Coverage.Gaps) == 0 {
		t.Errorf("the JSON coverage lost its gaps: %+v", rc.Coverage)
	}
}

// TestTopTenAndMore: the receipt names the ten most tried destinations and counts the rest.
func TestTopTenAndMore(t *testing.T) {
	lines := []line{start("off", true)}
	for i := range 13 {
		for range i + 1 {
			lines = append(lines, line{kind: record.KindNet, at: 1, verdict: record.VerdictAllow, rule: "n",
				payload: record.NetPayload{Proto: "tcp", Dst: "10.0.0." + string(rune('a'+i)) + ":80"}})
		}
	}
	lines = append(lines, end(time.Second, 0))
	rc := compute(t, lines, Options{})
	if len(rc.Connections) != MaxTop || rc.ConnectionsMore != 3 || rc.Connections[0].Count != 13 {
		t.Errorf("connections = %d listed, %d more, first %+v", len(rc.Connections), rc.ConnectionsMore, rc.Connections[0])
	}
	var text bytes.Buffer
	_ = rc.Text(&text)
	for _, want := range []string{"91 connections to 13 places; the 10 most used are below.\n", "and 3 more; tego events"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, text.String())
		}
	}
	if rc.ConnectionTries != 91 {
		t.Errorf("connection tries = %d, want 91 (every try, listed or not)", rc.ConnectionTries)
	}

	// Programs past the top ten: the count, and which are listed, in plain words.
	lines = []line{start("off", true)}
	for i := range 12 {
		lines = append(lines, line{kind: record.KindExec, at: 1, verdict: record.VerdictAllow, rule: "e",
			payload: record.ExecPayload{Path: "/usr/bin/p" + string(rune('a'+i)), ExecID: "x"}})
	}
	lines = append(lines, end(time.Second, 0))
	rc = compute(t, lines, Options{})
	text.Reset()
	_ = rc.Text(&text)
	if want := "\nPrograms run\n  12 programs; the 10 most started are below.\n"; !strings.Contains(text.String(), want) {
		t.Errorf("text lacks %q:\n%s", want, text.String())
	}
}

// TestPort53OfAnotherMachineIsAPlace: a line is a lookup when the engine named it one or it stays on this machine. A
// connect to port 53 of anyone else's server is a place the run connected to, as the dashboard's verdict reads it.
func TestPort53OfAnotherMachineIsAPlace(t *testing.T) {
	obs := record.VerdictObserved
	rc := compute(t, []line{watchedStart(),
		{kind: record.KindNet, at: time.Second, verdict: obs, rule: "net.resolver", payload: record.NetPayload{Proto: "udp", Dst: "8.8.8.8:53"}},
		{kind: record.KindNet, at: time.Second, verdict: obs, rule: "unmatched", payload: record.NetPayload{Proto: "udp", Dst: "127.0.0.53:53"}},
		{kind: record.KindNet, at: time.Second, verdict: obs, rule: "unmatched", payload: record.NetPayload{Proto: "tcp", Dst: "203.0.113.9:53"}},
		end(2*time.Second, 0)}, Options{})
	if len(rc.Connections) != 1 || rc.Connections[0].Destination != "203.0.113.9:53" || rc.ConnectionTries != 1 || rc.SystemLookups != 2 {
		t.Fatalf("connections = %+v, tries %d, lookups %d", rc.Connections, rc.ConnectionTries, rc.SystemLookups)
	}
}

// TestSystemLookupsAreNotPlaces: a real Codex under tego watch asks nscd for every name it resolves. Those connects,
// and a DNS resolver's, are routine system lookups (syslookup.Routine, the classifier the dashboard's verdict uses):
// counted apart in the dashboard's words, never a place, so the headline's total and top place are the network's.
func TestSystemLookupsAreNotPlaces(t *testing.T) {
	obs := record.VerdictObserved
	net := func(dst string) line {
		return line{kind: record.KindNet, at: time.Second, verdict: obs, rule: "unmatched", payload: record.NetPayload{Proto: "tcp", Dst: dst}}
	}
	lines := []line{watchedStart()}
	for range 5 {
		lines = append(lines, net("unix:/var/run/nscd/socket"))
	}
	lines = append(lines, net("127.0.0.53:53"))
	for range 3 {
		lines = append(lines, net("127.0.0.1:9821"))
	}
	lines = append(lines, end(2*time.Second, 0))
	rc := compute(t, lines, Options{})
	if len(rc.Connections) != 1 || rc.Connections[0].Destination != "127.0.0.1:9821" || rc.ConnectionTries != 3 || rc.SystemLookups != 6 {
		t.Fatalf("connections = %+v, tries %d, lookups %d", rc.Connections, rc.ConnectionTries, rc.SystemLookups)
	}
	var text bytes.Buffer
	_ = rc.Text(&text)
	for _, want := range []string{"\nConnections\n  3 connections to 1 place.\n", "127.0.0.1:9821  3  recorded, not blocked",
		"  Also 6 routine system lookups (the name and user lookups any program makes), not counted above.\n"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("receipt lacks %q:\n%s", want, text.String())
		}
	}
	if strings.Contains(text.String(), "nscd") {
		t.Errorf("the receipt names the nscd socket:\n%s", text.String())
	}

	// Only lookups: no connection, and the lookups still said.
	rc = compute(t, []line{watchedStart(), net("unix:/run/nscd/socket"), end(time.Second, 0)}, Options{})
	text.Reset()
	_ = rc.Text(&text)
	if want := "\nConnections\n  None, besides 1 routine system lookup (the name and user lookups any program makes).\n"; !strings.Contains(text.String(), want) {
		t.Errorf("receipt lacks %q:\n%s", want, text.String())
	}
}

// TestRoutineSocketsAreNotPlaces: glibc's getaddrinfo resets a probe socket with connect(AF_UNSPEC) and asks the
// kernel's netlink socket for its addresses. Their lines (dst unspec, rule net.unspec; dst family(16)) name no place:
// the first tego watch of a Python fetch on AlmaLinux 9.8 said "16 connections to 10 places (most: unspec)" and the
// Ubuntu 24.04 receipt listed "unspec  6  recorded, not blocked" and "family(16)  1  allowed" (guest kit/acc2). They
// are counted apart in RoutineSockets, as the dashboard folds them (syslookup.NoPlace), and an address, a unix socket
// and any other family are still places.
func TestRoutineSocketsAreNotPlaces(t *testing.T) {
	obs := record.VerdictObserved
	net := func(dst, rule string, verdict record.Verdict) line {
		return line{kind: record.KindNet, at: time.Second, verdict: verdict, rule: rule, payload: record.NetPayload{Proto: "udp", Dst: dst}}
	}
	lines := []line{watchedStart()}
	for range 6 {
		lines = append(lines, net("unspec", "net.unspec", obs))
	}
	lines = append(lines, net("family(16)", "route-query", record.VerdictAllow), net("unix:/run/nscd/socket", "unmatched", obs))
	for range 3 {
		lines = append(lines, net("151.101.0.223:443", "unmatched", obs))
	}
	lines = append(lines, net("unix:/tmp/agent.sock", "unmatched", obs), net("family(40)", "unmatched", obs), end(2*time.Second, 0))
	rc := compute(t, lines, Options{})
	got := map[string]int{}
	for _, c := range rc.Connections {
		got[c.Destination] = c.Count
	}
	want := map[string]int{"151.101.0.223:443": 3, "unix:/tmp/agent.sock": 1, "family(40)": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) || rc.ConnectionTries != 5 || rc.SystemLookups != 1 || rc.RoutineSockets != 7 {
		t.Fatalf("connections = %v, tries %d, lookups %d, routine sockets %d; want %v, 5, 1, 7", got, rc.ConnectionTries,
			rc.SystemLookups, rc.RoutineSockets, want)
	}
	var text bytes.Buffer
	_ = rc.Text(&text)
	for _, want := range []string{"\nConnections\n  5 connections to 3 places.\n",
		"  Also 1 routine system lookup (the name and user lookups any program makes), not counted above.\n",
		"  Also 7 routine socket calls that name no place (disconnects with AF_UNSPEC, the kernel's netlink socket), not counted above.\n"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("receipt lacks %q:\n%s", want, text.String())
		}
	}
	for _, bad := range []string{"unspec  ", "family(16)"} {
		if strings.Contains(text.String(), bad) {
			t.Errorf("the receipt lists %q as a place:\n%s", bad, text.String())
		}
	}
	var js bytes.Buffer
	if err := rc.JSON(&js); err != nil || !strings.Contains(js.String(), `"routine_sockets": 7`) {
		t.Errorf("JSON lacks routine_sockets 7 (%v):\n%s", err, js.String())
	}

	// Only routine sockets: no connection, and the count still said; a run with none writes no key.
	rc = compute(t, []line{watchedStart(), net("unspec", "net.unspec", obs), end(time.Second, 0)}, Options{})
	text.Reset()
	_ = rc.Text(&text)
	if want := "\nConnections\n  None, besides 1 routine socket call that names no place (disconnects with AF_UNSPEC, the kernel's netlink socket).\n"; !strings.Contains(text.String(), want) {
		t.Errorf("receipt lacks %q:\n%s", want, text.String())
	}
	rc = compute(t, []line{watchedStart(), net("unix:/run/nscd/socket", "unmatched", obs), net("family(16)", "route-query", record.VerdictAllow),
		end(time.Second, 0)}, Options{})
	text.Reset()
	_ = rc.Text(&text)
	if want := "\nConnections\n  None, besides 1 routine system lookup (the name and user lookups any program makes) and 1 routine " +
		"socket call that names no place (disconnects with AF_UNSPEC, the kernel's netlink socket).\n"; !strings.Contains(text.String(), want) {
		t.Errorf("receipt lacks %q:\n%s", want, text.String())
	}
	rc = compute(t, []line{watchedStart(), net("151.101.0.223:443", "unmatched", obs), end(time.Second, 0)}, Options{})
	js.Reset()
	if err := rc.JSON(&js); err != nil || strings.Contains(js.String(), "routine_sockets") {
		t.Errorf("a run with no routine socket writes the key (%v):\n%s", err, js.String())
	}
}

// TestARefusedCallThatNamesNoPlaceIsNoRoutineSocket: the supervisor refuses a sendto, sendmsg or sendmmsg whose
// address is AF_UNSPEC (R4: udp_sendmsg sends to the sockaddr_in behind the family word) and writes it dst unspec, rule
// unmatched, verdict refused, with no op; ADR 0128 refuses a netlink send that is no route query as a refused
// family(16) line. Neither is a routine disconnect: review 1 measured both printed as "routine socket calls that name
// no place (disconnects with AF_UNSPEC, ...)", and past the refused list's cap that was the only line naming the send.
// A refused one is a refusal: it counts in Refusals as before and, as the dashboard's verdict folds it, is no place
// and no routine socket call either. The allowed reset beside it is still counted.
func TestARefusedCallThatNamesNoPlaceIsNoRoutineSocket(t *testing.T) {
	refusedNet := func(proto, dst string) line {
		return line{kind: record.KindNet, at: time.Second, verdict: record.VerdictRefused, rule: "unmatched",
			reason: record.ReasonNetNotAllowed, payload: record.NetPayload{Proto: proto, Dst: dst}}
	}
	lines := []line{start("off", true)}
	for i := range 10 { // fill the refused list to its cap
		lines = append(lines, refusedNet("tcp", fmt.Sprintf("203.0.113.%d:443", i+1)))
	}
	lines = append(lines, refusedNet("udp", "unspec"), refusedNet("raw", "family(16)"),
		line{kind: record.KindNet, at: time.Second, verdict: record.VerdictAllow, rule: "net.unspec",
			payload: record.NetPayload{Proto: "udp", Dst: "unspec"}},
		end(2*time.Second, 0))
	rc := compute(t, lines, Options{})
	if rc.Refusals.Total != 12 {
		t.Errorf("refusals = %d, want 12: the refused send and the refused netlink line are refusals", rc.Refusals.Total)
	}
	if rc.RoutineSockets != 1 || rc.ConnectionTries != 10 || len(rc.Connections) != 10 {
		t.Errorf("routine sockets %d, tries %d, places %d; want 1 (the allowed reset only), 10, 10", rc.RoutineSockets,
			rc.ConnectionTries, len(rc.Connections))
	}
	for _, c := range rc.Connections {
		if c.Destination == "unspec" || c.Destination == "family(16)" {
			t.Errorf("%q is listed as a place", c.Destination)
		}
	}
	var text bytes.Buffer
	_ = rc.Text(&text)
	if want := "  Also 1 routine socket call that names no place (disconnects with AF_UNSPEC, the kernel's netlink socket), " +
		"not counted above.\n"; !strings.Contains(text.String(), want) {
		t.Errorf("receipt lacks %q:\n%s", want, text.String())
	}
	if !strings.Contains(text.String(), "  Tego refused 12 actions.\n") {
		t.Errorf("the receipt does not count the two refusals:\n%s", text.String())
	}
}

// TestNothingRefusedSaysWhatTheRunDoesNotRecord (b):a tier-landlock run with reason.reads off leaves no line for a read
// its deny_read refuses (ADR 0077), and its receipt said "Nothing was refused." with the note that reads went unrecorded
// in another section. Where run_start says refused reads leave no line (reason-off, no-supervisor), the refusals say so
// themselves; a run that records them, one that enforces nothing (tego watch) and a root tier's keep their words.
func TestNothingRefusedSaysWhatTheRunDoesNotRecord(t *testing.T) {
	const (
		nothing    = "  Nothing was refused.\n"
		unrecorded = "  No recorded action was refused; this run does not record refused reads (see Sensitive files read).\n"
		alsoNot    = "  This run does not record refused reads, so a read it refused is not counted (see Sensitive files read).\n"
	)
	startWith := func(rn *record.ReadsNotified) line {
		return line{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "landlock", Capture: "off",
			Command: []string{"sh", "agent.sh"}, Cwd: "/p", ReadsNotified: rn,
			Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): false}}}
	}
	refused := line{kind: record.KindRefused, at: time.Second, rule: "unmatched", reason: record.ReasonNetNotAllowed,
		payload: record.RefusedPayload{Op: "net", Target: "203.0.113.9:443", Reason: record.ReasonNetNotAllowed, Rule: "unmatched"}}
	for _, c := range []struct {
		name    string
		rn      *record.ReadsNotified
		refuse  bool
		want    string
		notWant string
	}{
		{"reason off", &record.ReadsNotified{Why: record.ReadsNotifiedWhyReasonOff}, false, unrecorded, nothing},
		{"no supervisor", &record.ReadsNotified{Why: record.ReadsNotifiedWhyNoSupervisor}, false, unrecorded, nothing},
		{"reason off, one refusal", &record.ReadsNotified{Why: record.ReadsNotifiedWhyReasonOff}, true, alsoNot, nothing},
		{"reason on", &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyReason}, false, nothing, unrecorded},
		{"watch", &record.ReadsNotified{Why: record.ReadsNotifiedWhyRecordsOnly}, false, nothing, unrecorded},
		{"root tier", &record.ReadsNotified{Why: record.ReadsNotifiedWhyKernel}, false, nothing, unrecorded},
		{"older record", nil, false, nothing, unrecorded},
		{"reason on, one refusal", &record.ReadsNotified{Notified: true, Why: record.ReadsNotifiedWhyReason}, true, "  Tego refused 1 action.\n", alsoNot},
	} {
		lines := []line{startWith(c.rn)}
		if c.refuse {
			lines = append(lines, refused)
		}
		rc := compute(t, append(lines, end(2*time.Second, 0)), Options{})
		var text bytes.Buffer
		_ = rc.Text(&text)
		if !strings.Contains(text.String(), c.want) || strings.Contains(text.String(), c.notWant) {
			t.Errorf("%s: the receipt lacks %q or says %q:\n%s", c.name, c.want, c.notWant, text.String())
		}
		if got, want := rc.RefusedReadsUnrecorded(), c.want == unrecorded || c.want == alsoNot; got != want {
			t.Errorf("%s: RefusedReadsUnrecorded() = %v, want %v", c.name, got, want)
		}
	}
}

// TestSensitiveReadsNoteSaysWhatTheRunKept: on the default tier 1 run a read Landlock refuses leaves no line, so the
// note must not say refused reads are listed; it may say so only where run_start says the supervisor was told of reads.
func TestSensitiveReadsNoteSaysWhatTheRunKept(t *testing.T) {
	const (
		refusedListed = "only refused reads are listed"
		neitherKept   = "allowed or refused"
		mayMiss       = "a refused read may be missing too"
	)
	notified := func(why string) *record.ReadsNotified { return &record.ReadsNotified{Notified: true, Why: why} }
	unseen := func(why string) *record.ReadsNotified { return &record.ReadsNotified{Why: why} }
	for _, tc := range []struct {
		name string
		rn   *record.ReadsNotified
		want string
	}{
		{"the default at tier landlock", unseen(record.ReadsNotifiedWhyReasonOff), neitherKept},
		{"a run that enforces nothing", unseen(record.ReadsNotifiedWhyRecordsOnly), neitherKept},
		{"no supervisor answered", unseen(record.ReadsNotifiedWhyNoSupervisor), neitherKept},
		{"reason.reads: on", notified(record.ReadsNotifiedWhyReason), refusedListed},
		{"an fs.read gate", notified(record.ReadsNotifiedWhyGate), refusedListed},
		{"an fs.ask_read entry", notified(record.ReadsNotifiedWhyAskRead), refusedListed},
		{"held reads", notified(record.ReadsNotifiedWhyHeld), refusedListed},
		{"a root tier's kernel record", unseen(record.ReadsNotifiedWhyKernel), mayMiss},
		{"a ledger older than reads_notified", nil, mayMiss},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := compute(t, []line{{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "landlock", Capture: "off",
				ReadsNotified: tc.rn,
				Capabilities:  map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): false}}},
				end(time.Second, 0)}, Options{})
			for _, claim := range []string{refusedListed, neitherKept, mayMiss} {
				if got := strings.Contains(rc.SensitiveReadsNote, claim); got != (claim == tc.want) {
					t.Errorf("note %q: holds %q is %v", rc.SensitiveReadsNote, claim, got)
				}
			}
			var text bytes.Buffer
			if err := rc.Text(&text); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text.String(), tc.want) {
				t.Errorf("the text lacks %q:\n%s", tc.want, text.String())
			}
		})
	}
}

// TestNoSensitiveReadOnlyWhereReadsWereRecorded: an empty list says "None" only on a run that recorded its reads. The
// default tier 1 run keeps no allowed read, so its empty list proves nothing, and neither does a ledger older than the
// capability line.
func TestNoSensitiveReadOnlyWhereReadsWereRecorded(t *testing.T) {
	const none, unknown = "None: no file that looks like a secret", "Not known: this run did not record every read"
	start := func(caps map[string]bool) []line {
		return []line{{kind: record.KindRunStart, payload: record.RunStartPayload{Tier: "landlock", Capture: "off", Capabilities: caps}},
			end(time.Second, 0)}
	}
	for _, tc := range []struct {
		name    string
		lines   []line
		unknown bool
	}{
		{"a run that recorded its reads", []line{watchedStart(), end(time.Second, 0)}, false},
		{"the default tier 1 run", start(map[string]bool{string(backend.CapRecordExecOpenNet): true,
			string(backend.CapRecordReads): false}), true},
		{"a ledger older than the capability line", start(nil), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := compute(t, tc.lines, Options{})
			if rc.SensitiveReadsUnknown != tc.unknown {
				t.Errorf("SensitiveReadsUnknown = %v, want %v", rc.SensitiveReadsUnknown, tc.unknown)
			}
			var text bytes.Buffer
			if err := rc.Text(&text); err != nil {
				t.Fatal(err)
			}
			out := text.String()
			if strings.Contains(out, none) == tc.unknown || strings.Contains(out, unknown) != tc.unknown {
				t.Errorf("unknown %v, the text says:\n%s", tc.unknown, out)
			}
		})
	}
}

// TestSensitiveReadsNoteStaysAwayWhenReadsAreKept: a run that records its reads has nothing to warn of.
func TestSensitiveReadsNoteStaysAwayWhenReadsAreKept(t *testing.T) {
	rc := compute(t, []line{watchedStart(), end(time.Second, 0)}, Options{})
	if rc.SensitiveReadsNote != "" {
		t.Errorf("note on a run that records reads: %q", rc.SensitiveReadsNote)
	}
}
