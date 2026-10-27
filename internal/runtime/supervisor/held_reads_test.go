// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// heldReadsFixture is a heldAskFixture as a run that holds its reads (ADR 0069) and has no gate: fs.write over the
// directory, its .env a deny_read the Landlock ruleset leaves unenforced, the built-in .env names over the directory.
func heldReadsFixture(t *testing.T, mode agent.RecordMode) (*heldAskFixture, string) {
	t.Helper()
	x := newHeldAskFixture(t)
	env := filepath.Join(x.dir, ".env")
	for p, body := range map[string]string{env: "TOKEN=real", filepath.Join(x.dir, ".env.example"): "TOKEN=",
		filepath.Join(x.dir, "node_modules", "x", ".env"): "DEP=1", filepath.Join(x.dir, "src", "a.txt"): "benign"} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rt := x.pol.Rules
	rt.Gate, rt.AskConfig, rt.Record = nil, nil, mode
	envRule := agent.FSRule{Path: env, Resolved: env, Kind: agent.FSDenyRead, BuiltIn: true, Unenforced: true}
	rt.FS = append(rt.FS, agent.FSRule{Path: x.dir, Resolved: x.dir, Kind: agent.FSWrite, Raw: x.dir, Access: agent.AccessWriteSet}, envRule)
	scopes := []agent.NameScope{{Canonical: x.dir, Spelling: x.dir}}
	rt.Reads = agent.HeldReads{Mode: agent.ReadsAuto, Nested: []agent.NestedRead{{Rule: envRule.RuleName(), Path: env}},
		Names: []agent.NameDenyRule{{Literal: ".env", Scopes: scopes, BuiltIn: true},
			{Literal: ".env.", Prefix: true, Except: []string{".env.example", ".env.sample", ".env.template", ".env.dist"}, Scopes: scopes, BuiltIn: true}}}
	if !rt.ReadsHeld() {
		t.Fatal("the fixture does not hold its reads")
	}
	return x, env
}

// TestHeldReadFloorsOnThePinnedObject holds ADR 0069 D3 to the object the deputy pinned, whatever the name copied:
// the nested .env by its path, through a symlink and through a /proc magic link; a case-folded .ENV and a .env.local
// no table row names, by the name rule; an O_RDWR open of it; the nested deny_read directory itself. The example file
// and a dependency directory's .env are delivered, and so is a benign file, with no line under record: summary.
func TestHeldReadFloorsOnThePinnedObject(t *testing.T) {
	x, env := heldReadsFixture(t, agent.RecordSummary)
	secrets := filepath.Join(x.dir, "secrets")
	if err := os.Mkdir(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.FS = append(x.pol.Rules.FS, agent.FSRule{Path: secrets, Resolved: secrets, Kind: agent.FSDenyRead, Raw: "secrets/", Unenforced: true})
	link := filepath.Join(x.dir, "innocent")
	if err := os.Symlink(env, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".ENV", ".env.local"} {
		if err := os.WriteFile(filepath.Join(x.dir, name), []byte("LATER=1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	held, err := os.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	magic := "/proc/" + strconv.Itoa(x.k.tid) + "/fd/" + strconv.Itoa(int(held.Fd()))
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	for _, tc := range []struct {
		name, path string
		flags      int
		rule       string // "" delivered
	}{
		{"the nested target", env, unix.O_RDONLY, "fs.deny_read[" + env + "]"},
		{"a symlink to it", link, unix.O_RDONLY, "fs.deny_read[" + env + "]"},
		{"a /proc magic link to it", magic, unix.O_RDONLY, "fs.deny_read[" + env + "]"},
		{"read-write", env, unix.O_RDWR, "fs.deny_read[" + env + "]"},
		{"case folded, made later", filepath.Join(x.dir, ".ENV"), unix.O_RDONLY, "fs.deny_read[" + x.dir + "/**/.env]"},
		{"a .env.local made later", filepath.Join(x.dir, ".env.local"), unix.O_RDONLY, "fs.deny_read[" + x.dir + "/**/.env.*]"},
		{"the nested directory itself", secrets, unix.O_RDONLY | unix.O_DIRECTORY, "fs.deny_read[secrets/]"},
		{"the example file", filepath.Join(x.dir, ".env.example"), unix.O_RDONLY, ""},
		{"a dependency directory's .env", filepath.Join(x.dir, "node_modules", "x", ".env"), unix.O_RDONLY, ""},
		{"a benign file", filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, ""},
	} {
		before, pins, delivered := len(sink.all()), x.dep.pins, len(x.k.heldDelivered)
		x.openAs(t, l, tc.path, tc.flags, 0)
		res, _ := x.f.lastResp()
		evs := sink.all()[before:]
		if x.dep.pins != pins+1 {
			t.Errorf("%s: not held (%d pins)", tc.name, x.dep.pins-pins)
			continue
		}
		if tc.rule == "" {
			if len(x.k.heldDelivered) != delivered+1 || len(evs) != 0 {
				t.Errorf("%s: delivered %d, lines %+v: want it delivered with no line under summary", tc.name, len(x.k.heldDelivered)-delivered, evs)
			}
			continue
		}
		if len(x.k.heldDelivered) != delivered || res.Error != -int32(unix.EACCES) {
			t.Errorf("%s: answer %+v, delivered %d: want EACCES", tc.name, res, len(x.k.heldDelivered)-delivered)
			continue
		}
		if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonReadDenied || evs[0].Rule != tc.rule {
			t.Errorf("%s: lines %+v, want one read-denied refusal by %s", tc.name, evs, tc.rule)
		}
	}
}

// TestHeldReadsLeaveWriteOnlyAndOPathOpens: an O_WRONLY open and an O_PATH open are not held reads (ADR 0069 D2): they
// go as before, the write entry's write-open continued for the kernel.
func TestHeldReadsLeaveWriteOnlyAndOPathOpens(t *testing.T) {
	x, env := heldReadsFixture(t, agent.RecordSummary)
	l, _, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	for _, flags := range []int{unix.O_WRONLY, unix.O_PATH} {
		x.openAs(t, l, env, flags, 0)
		if x.dep.pins != 0 {
			t.Fatalf("flags %#x: held (%d pins)", flags, x.dep.pins)
		}
		if res, _ := x.f.lastResp(); res.Error != 0 || res.Flags == 0 {
			t.Fatalf("flags %#x: answer %+v, want CONTINUE", flags, res)
		}
	}
}

// TestHeldReadsOPathLinesSayWhatHappened: an O_PATH open is not held (ADR 0069 D2) and no mechanism refuses it (the
// kernel runs no file_open hook for one, so neither Landlock nor the held floor sees it), so in a run that holds its
// reads under record: full its line under a deny_read says allow, by the entry, with the O_PATH marker: never
// "(unenforced: parent writable)" in a run whose capability line says the nested entry is enforced,
// and never refused for an open the kernel let through. Under summary or off such an open gets no line, a benign one
// included, as in an fs.ask_read run (D4: held reads change how a read is completed, never what the record keeps).
func TestHeldReadsOPathLinesSayWhatHappened(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordSummary, agent.RecordOff} {
		t.Run(string(mode), func(t *testing.T) {
			x, _ := heldReadsFixture(t, mode)
			secrets := filepath.Join(x.dir, "secrets")
			outside, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{secrets, outside} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			x.pol.Rules.FS = append(x.pol.Rules.FS,
				agent.FSRule{Path: secrets, Resolved: secrets, Kind: agent.FSDenyRead, Raw: "secrets/", Unenforced: true},
				agent.FSRule{Path: outside, Resolved: outside, Kind: agent.FSDenyRead, Raw: outside})
			l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
			src := filepath.Join(x.dir, "src")
			for _, tc := range []struct {
				path  string
				flags int
				rule  string
			}{
				{secrets, unix.O_PATH | unix.O_DIRECTORY, "fs.deny_read[secrets/]" + agent.OPathSuffix},
				{outside, unix.O_PATH | unix.O_DIRECTORY, "fs.deny_read[" + outside + "]" + agent.OPathSuffix},
				{filepath.Join(src, "a.txt"), unix.O_PATH, "fs.write[" + x.dir + "]"},
				{src, unix.O_PATH | unix.O_DIRECTORY, "fs.write[" + x.dir + "]"},
			} {
				before := len(sink.all())
				x.openAs(t, l, tc.path, tc.flags, 0)
				if res, _ := x.f.lastResp(); res.Error != 0 || res.Flags == 0 {
					t.Fatalf("%s: answer %+v, want CONTINUE", tc.path, res)
				}
				evs := sink.all()[before:]
				switch {
				case mode != agent.RecordFull && len(evs) != 0:
					t.Errorf("%s: %d lines under record: %s (first %s by %q), want none", tc.path, len(evs), mode, evs[0].Verdict, evs[0].Rule)
				case mode != agent.RecordFull:
				case len(evs) != 1:
					t.Errorf("%s: %d lines, want one allow by %q", tc.path, len(evs), tc.rule)
				case evs[0].Verdict != record.VerdictAllow || evs[0].Rule != tc.rule:
					t.Errorf("%s: %s by %q, want allow by %q", tc.path, evs[0].Verdict, evs[0].Rule, tc.rule)
				}
			}
			if x.dep.pins != 0 {
				t.Errorf("an O_PATH open was held (%d pins)", x.dep.pins)
			}
		})
	}
}

// TestHeldReadsOPathAtARootTier: at tier cgroup and bpflsm under fs.reads: held the filter notifies O_PATH opens too
// (ADR 0069 D2), and no mechanism of either tier sees one: the plane's only open hook is file_open, fanotify sends no
// permission event, and the kernel recorder's open hook is fexit/security_file_open, all of which do_dentry_open skips
// for O_PATH. So the open is continued, its line (record: full) is this loop's and says allow with the O_PATH marker
// beneath a deny_read, enforced or nested, never "refused"; with a kernel recorder reading, it is not
// handed over to a recorder that never records it, and a later record of the thread inherits no naming from it.
// Under summary it gets no line, at either tier, with or without a recorder.
func TestHeldReadsOPathAtARootTier(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		for _, mode := range []agent.RecordMode{agent.RecordFull, agent.RecordSummary} {
			for _, kernel := range []bool{false, true} {
				t.Run(string(tier)+"/"+string(mode)+"/kernel="+strconv.FormatBool(kernel), func(t *testing.T) {
					x, env := heldReadsFixture(t, mode)
					x.pol.Rules.Tier = tier
					x.pol.Rules.Reads.Mode = agent.ReadsHeld
					if !x.pol.Rules.ReadsHeld() {
						t.Fatal("the fixture does not hold its reads")
					}
					sink := &testSink{}
					opts := Options{kernel: x.k, openDeputy: x.dep}
					if kernel {
						opts.KernelFS = func() bool { return true }
					}
					l, err := New(testListener(), x.pol, sink, opts)
					if err != nil {
						t.Fatal(err)
					}
					for _, tc := range []struct {
						path  string
						flags int
						rule  string
					}{
						{x.denied, unix.O_PATH | unix.O_DIRECTORY, "fs.deny_read[" + x.denied + "]" + agent.OPathSuffix},
						{filepath.Join(x.denied, "key"), unix.O_PATH, "fs.deny_read[" + x.denied + "]" + agent.OPathSuffix},
						{env, unix.O_PATH, "fs.deny_read[" + env + "]" + agent.OPathSuffix},
						{filepath.Join(x.dir, "src", "a.txt"), unix.O_PATH, "fs.write[" + x.dir + "]"},
					} {
						before := len(sink.all())
						x.openAs(t, l, tc.path, tc.flags, 0)
						if res, _ := x.f.lastResp(); res.Error != 0 || res.Flags == 0 {
							t.Fatalf("%s: answer %+v, want CONTINUE", tc.path, res)
						}
						evs := sink.all()[before:]
						switch {
						case mode != agent.RecordFull && len(evs) != 0:
							t.Errorf("%s: %d lines under record: %s (first %s by %q), want none", tc.path, len(evs), mode, evs[0].Verdict, evs[0].Rule)
						case mode != agent.RecordFull:
						case len(evs) != 1:
							t.Errorf("%s: %d lines, want this loop's one allow by %q", tc.path, len(evs), tc.rule)
						case evs[0].Verdict != record.VerdictAllow || evs[0].Rule != tc.rule:
							t.Errorf("%s: %s by %q, want allow by %q", tc.path, evs[0].Verdict, evs[0].Rule, tc.rule)
						}
						if naming, ok := l.ContinuedFS(x.k.tid, record.FSOpen, filepath.Base(tc.path), "", monotonicNS()+1); ok {
							t.Errorf("%s: handed to the kernel recorder as %+v, which never records an O_PATH open", tc.path, naming)
						}
					}
					if x.dep.pins != 0 {
						t.Errorf("an O_PATH open was held (%d pins)", x.dep.pins)
					}
				})
			}
		}
	}
}

// TestHeldReadsRaceIsDecidedOnThePin: a sibling that rewrites the pathname between this loop's copy of ./a.txt and the
// deputy's lookup makes the deputy reach the .env: the floor refuses on what was pinned, never on the copied name.
func TestHeldReadsRaceIsDecidedOnThePin(t *testing.T) {
	x, env := heldReadsFixture(t, agent.RecordFull)
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.dep.swapTo = env
	x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
	res, _ := x.f.lastResp()
	evs := sink.all()
	if len(x.k.heldDelivered) != 0 || res.Error != -int32(unix.EACCES) {
		t.Fatalf("answer %+v, delivered %q: the pinned .env is refused", res, x.k.heldDelivered)
	}
	if len(evs) != 1 || evs[0].Rule != "fs.deny_read["+env+"]" {
		t.Fatalf("lines %+v", evs)
	}
	if p := decodeHeldLine(t, evs[0]); p.Path != env {
		t.Fatalf("line %s names the copied name, want the pinned %s", evs[0].Payload, env)
	}
	// Under record: full an allowed held read keeps its line.
	x.dep.swapTo = ""
	before := len(sink.all())
	x.openAs(t, l, filepath.Join(x.dir, "src", "a.txt"), unix.O_RDONLY, 0)
	if evs := sink.all()[before:]; len(evs) != 1 || evs[0].Verdict != record.VerdictAllow || len(x.k.heldDelivered) != 1 {
		t.Fatalf("lines %+v, delivered %q: under record: full the allowed read has its line", evs, x.k.heldDelivered)
	}
}

// TestHeldReadsRefuseTegosOwnState is ADR 0069 D3 (d): a held read in tego's own state is refused, but not beneath the
// run's own runtime directory, which the run is given to read (its reason file).
func TestHeldReadsRefuseTegosOwnState(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordSummary)
	own := filepath.Join(x.dir, "own")
	mine, other := filepath.Join(own, "run-mine"), filepath.Join(own, "run-other")
	for _, d := range []string{mine, other} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "last-refusal.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	x.pol.Rules.FS = x.pol.Rules.FS[:len(x.pol.Rules.FS)-2] // no write entry over the directory: own state stands alone
	x.pol.Rules.Reads.Mode = agent.ReadsHeld
	var sink *testSink
	l, s, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	sink = s
	l.runtimeDir = mine
	x.openAs(t, l, filepath.Join(mine, "last-refusal.json"), unix.O_RDONLY, 0)
	if len(x.k.heldDelivered) != 1 {
		t.Fatalf("the run's own reason file was not delivered: %+v", sink.all())
	}
	x.openAs(t, l, filepath.Join(other, "last-refusal.json"), unix.O_RDONLY, 0)
	evs := sink.all()
	if len(x.k.heldDelivered) != 1 || len(evs) != 1 || evs[0].Rule != "fs.deny_read["+own+"]" || evs[0].Reason != record.ReasonReadDenied {
		t.Fatalf("another run's file: delivered %d, lines %+v", len(x.k.heldDelivered), evs)
	}
}

// replaceByRename writes body to a sibling of p and renames it over p, as an editor, a package manager or the
// ledger's own reason file write replaces a file: the inode p named loses its last link and p names a new one.
func replaceByRename(t *testing.T, p, body string) {
	t.Helper()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Error(err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Error(err)
	}
}

// TestHeldReadOfAFileReplacedAfterThePinIsRepinned is a held read racing a rename over its file (ADR 0069 D2,
// ADR 0041 D4's one re-pin): the deputy pinned the old file, whose last link is gone when this loop reads the pin. The
// kernel's own open, made now, opens the file the name names now, so the open is pinned again, checked and scored on
// the new file, and delivered. It was refused gate.unreadable, with a gate's fields in a run with no gate: the run's
// read of its reason file while the ledger rewrote it failed 2 times in 60.
func TestHeldReadOfAFileReplacedAfterThePinIsRepinned(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordSummary)
	a := filepath.Join(x.dir, "src", "a.txt")
	once := false
	x.dep.afterPin = func() {
		if !once {
			once = true
			replaceByRename(t, a, "replaced")
		}
	}
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.openAs(t, l, a, unix.O_RDONLY, 0)
	res, _ := x.f.lastResp()
	if res.Error != 0 || len(x.k.heldDelivered) != 1 || x.k.heldDelivered[0] != "replaced" {
		t.Fatalf("answer %+v, delivered %q, lines %+v: want the file the name names now", res, x.k.heldDelivered, sink.all())
	}
	if x.dep.pins != 2 || len(sink.all()) != 0 {
		t.Fatalf("%d pins, lines %+v: want one re-pin and no line under record: summary", x.dep.pins, sink.all())
	}
}

// TestHeldReadWhoseNameKeepsBeingReplacedIsRefused is the bound on that re-pin: a sibling that replaces the file after
// every pin gets one re-pin, and the second answer stands. A held read's floor needs the pinned object's name, so the
// open is refused; no gate scored it, so the refusal is held-unsupported with no gate fields and authority rule, never
// a gate's gate.unreadable.
func TestHeldReadWhoseNameKeepsBeingReplacedIsRefused(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordSummary)
	a := filepath.Join(x.dir, "src", "a.txt")
	n := 0
	x.dep.afterPin = func() {
		n++
		replaceByRename(t, a, "replaced "+strconv.Itoa(n))
	}
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	x.openAs(t, l, a, unix.O_RDONLY, 0)
	res, _ := x.f.lastResp()
	evs := sink.all()
	if res.Error != -int32(unix.EACCES) || len(x.k.heldDelivered) != 0 || x.dep.pins != 2 {
		t.Fatalf("answer %+v, delivered %q, %d pins: want EACCES after one re-pin", res, x.k.heldDelivered, x.dep.pins)
	}
	if len(evs) != 1 || evs[0].Rule != ruleHeldUnsupported || evs[0].Authority != record.AuthorityRule {
		t.Fatalf("lines %+v: want one held-unsupported refusal, authority rule", evs)
	}
	if p := decodeHeldLine(t, evs[0]); p.GateFacts != "" || p.Path != a {
		t.Fatalf("line %s: want no gate fields, the copied name", evs[0].Payload)
	}
}
