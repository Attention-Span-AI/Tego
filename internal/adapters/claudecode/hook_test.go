// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

var update = flag.Bool("update", false, "rewrite testdata/golden")

// TestEachEventGolden is acceptance (1): over every documented payload, SessionStart prints the run's facts and
// counts the session; the four delivery events claim the refusals no hook has shown (the cursor becomes their
// highest seq) and print them once, and print nothing the second time. The goldens are testdata/golden/<payload>.
func TestEachEventGolden(t *testing.T) {
	names := make([]string, 0, len(payloadNames))
	for n := range payloadNames {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		event := payloadNames[name]
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.refusals(t, 3)
			p := payload(t, name)
			r := f.hook(t, p)
			if r.code != 0 || r.stderr != "" {
				t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
			}
			if quietPayloads[name] {
				golden(t, name, r.stdout)
				if r.stdout != "" || f.state(t) != (State{}) {
					t.Errorf("stdout %q, state %+v; want nothing and no claim", r.stdout, f.state(t))
				}
				return
			}
			ctx := context(t, r.stdout, event)
			golden(t, name, strings.ReplaceAll(r.stdout, f.reasonFile, "$REASON"))
			s := f.state(t)
			if event == EventSessionStart {
				if ctx != reason.HookInstructions(f.reasonFile) {
					t.Errorf("SessionStart context:\n%s\nwant reason.HookInstructions", ctx)
				}
				if s != (State{V: StateVersion, Run: testRun, Sessions: 1}) {
					t.Errorf("state after SessionStart: %+v", s)
				}
				if again := f.hook(t, p); context(t, again.stdout, event) != ctx || f.state(t).Sessions != 2 {
					t.Errorf("a second SessionStart: %q, sessions %d", again.stdout, f.state(t).Sessions)
				}
				return
			}
			if want := (State{V: StateVersion, Run: testRun, Cursor: refusalAt(2).Seq, Deliveries: 1, RefusalsDelivered: 3}); s != want {
				t.Errorf("state %+v, want %+v", s, want)
			}
			if again := f.hook(t, p); again != (result{}) {
				t.Errorf("nothing new, yet the hook answered %+v", again)
			}
			if f.state(t) != s {
				t.Errorf("nothing new changed the state: %+v", f.state(t))
			}
		})
	}
}

// golden compares got with testdata/golden/<name>.golden (-update rewrites it).
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s:\n%s\nwant\n%s", path, got, want)
	}
}

// TestNoRefusalYet: before the run's first refusal there is no reason file; the delivery events print nothing and
// leave no state, and SessionStart still states the run's facts.
func TestNoRefusalYet(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"post-tool-use-bash", "post-tool-use-failure-bash", "post-tool-batch", "stop"} {
		if r := f.hook(t, payload(t, name)); r != (result{}) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if s := f.state(t); s != (State{}) {
		t.Errorf("state %+v, want none", s)
	}
	r := f.hook(t, payload(t, "session-start"))
	if context(t, r.stdout, EventSessionStart) != reason.HookInstructions(f.reasonFile) || r.code != 0 {
		t.Errorf("SessionStart: %+v", r)
	}
}

// TestNewRefusalsOnly: refusals after a delivery are the only ones the next event prints.
func TestNewRefusalsOnly(t *testing.T) {
	f := newFixture(t)
	f.refusals(t, 2)
	f.hook(t, payload(t, "post-tool-use-bash"))
	f.refusals(t, 5)
	ctx := context(t, f.hook(t, payload(t, "post-tool-batch")).stdout, EventPostToolBatch)
	want := reason.Render([]reason.Entry{entry(t, 2), entry(t, 3), entry(t, 4)}, 0)
	if ctx != want {
		t.Errorf("context:\n%s\nwant\n%s", ctx, want)
	}
	if s := f.state(t); s.Cursor != refusalAt(4).Seq || s.RefusalsDelivered != 5 || s.Deliveries != 2 {
		t.Errorf("state %+v", s)
	}
}

// entry is the i-th refusal as a reason file lists it.
func entry(t *testing.T, i uint64) reason.Entry {
	t.Helper()
	f, err := reason.Decode(strings.NewReader(string(encodeRefusals(t, i+1, nil))))
	if err != nil {
		t.Fatal(err)
	}
	return f.Recent[len(f.Recent)-1]
}

// TestCursorOlderThanTheRing is acceptance (3): a cursor older than the ring's oldest entry gets every listed
// refusal and the count of those the file no longer lists.
func TestCursorOlderThanTheRing(t *testing.T) {
	f := newFixture(t)
	f.refusals(t, 5)
	f.hook(t, payload(t, "post-tool-use-bash"))
	f.refusals(t, 50) // refusals 6..50; the ring lists 19..50, so 13 (6..18) are not listed
	ctx := context(t, f.hook(t, payload(t, "stop")).stdout, EventStop)
	if !strings.HasPrefix(ctx, "Tego, this run's access control, refused 45 actions:\n") {
		t.Errorf("header: %q", ctx)
	}
	if !strings.HasSuffix(ctx, "\n13 more not listed.\n") {
		t.Errorf("not-listed count: %q", ctx)
	}
	for i := uint64(18); i < 50; i++ {
		if !strings.Contains(ctx, refusalAt(i).Payload.Target) {
			t.Errorf("refusal %d (%s) not listed", i, refusalAt(i).Payload.Target)
		}
	}
	if strings.Contains(ctx, refusalAt(17).Payload.Target) {
		t.Errorf("refusal 17 listed though the ring no longer holds it")
	}
}

// TestStopNeverLoops is acceptance (4): a Stop with new refusals keeps the turn going once; the Stop that follows,
// stop_hook_active, prints nothing, so the agent stops (with new refusals too: TestStopHookActiveClaimsNothing).
func TestStopNeverLoops(t *testing.T) {
	for _, mode := range []string{ModeJSON, ModeStderr} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.refusals(t, 2)
			if r := f.hook(t, payload(t, "stop"), "--mode", mode); r.stdout == "" && r.stderr == "" {
				t.Fatalf("the first Stop told nothing: %+v", r)
			}
			if r := f.hook(t, payload(t, "stop-repeat"), "--mode", mode); r != (result{}) {
				t.Errorf("a repeated Stop with nothing new: %+v", r)
			}
		})
	}
}

// TestStopHookActiveClaimsNothing: a Stop that Claude Code runs because a Stop hook already kept the turn going
// (stop_hook_active) prints nothing and claims nothing, even with new refusals, so the turn goes on at most once per
// end of turn (REASON-CHANNEL §3) however long the run keeps refusing; those refusals stay for the next PostToolUse
// or the next turn's first Stop. Before, every such Stop kept the turn going, and a background process the contract
// kept refusing, with a model that checked by a tool call each time (which resets Claude Code's continuation cap),
// gave a turn that never ended.
func TestStopHookActiveClaimsNothing(t *testing.T) {
	for _, mode := range []string{ModeJSON, ModeStderr} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.refusals(t, 1)
			if r := f.hook(t, payload(t, "stop"), "--mode", mode); r.stdout == "" && r.stderr == "" {
				t.Fatalf("the first Stop told nothing: %+v", r)
			}
			before := f.state(t)
			for round := 2; round <= 5; round++ {
				f.refusals(t, uint64(round))
				if r := f.hook(t, payload(t, "stop-repeat"), "--mode", mode); r != (result{}) {
					t.Fatalf("round %d: a Stop with stop_hook_active kept the turn going: %+v", round, r)
				}
				if s := f.state(t); s != before {
					t.Fatalf("round %d: a Stop with stop_hook_active claimed: %+v, was %+v", round, s, before)
				}
			}
			want := reason.Render([]reason.Entry{entry(t, 1), entry(t, 2), entry(t, 3), entry(t, 4)}, 0)
			r := f.hook(t, payload(t, "post-tool-use-bash"), "--mode", mode)
			got := r.stderr
			if mode == ModeJSON {
				got = context(t, r.stdout, EventPostToolUse)
			}
			if got != want {
				t.Errorf("the next PostToolUse told %q, want the refusals left unclaimed, %q", got, want)
			}
		})
	}
}

// TestStderrMode is acceptance (5): in --mode stderr, PostToolUse, PostToolUseFailure and Stop exit 2 with the text
// on stderr; PostToolBatch and SessionStart print nothing, exit 0 and claim nothing, since exit 2 there would end the
// agent's loop or reach only the user.
func TestStderrMode(t *testing.T) {
	for name, event := range payloadNames {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.refusals(t, 3)
			r := f.hook(t, payload(t, name), "--mode", ModeStderr)
			switch {
			case event == EventSessionStart, event == EventPostToolBatch, quietPayloads[name]:
				if r != (result{}) {
					t.Errorf("%+v, want nothing", r)
				}
				if s := f.state(t); s != (State{}) {
					t.Errorf("state %+v, want none", s)
				}
			default:
				want := reason.Render([]reason.Entry{entry(t, 0), entry(t, 1), entry(t, 2)}, 0)
				if r.code != 2 || r.stdout != "" || r.stderr != want {
					t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and %q", r.code, r.stdout, r.stderr, want)
				}
			}
		})
	}
}

// TestFailOpen is acceptance (6): each thing the hook cannot use gives exit 0, nothing on stdout and one line on
// stderr; json mode never exits 2.
func TestFailOpen(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *fixture) (stdin []byte, args []string)
	}{
		{"unreadable reason file", func(t *testing.T, f *fixture) ([]byte, []string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a file of mode 0")
			}
			f.refusals(t, 1)
			if err := os.Chmod(f.reasonFile, 0); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"reason file not v1", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.publish(t, []byte(`{"op":"write","target":"/x","reason":"write-outside-contract","rule":"fs.write"}`))
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"reason file a FIFO", func(t *testing.T, f *fixture) ([]byte, []string) {
			if err := unix.Mkfifo(f.reasonFile, 0o600); err != nil {
				t.Fatal(err)
			}
			return payload(t, "stop"), nil
		}},
		{"reason file a link", func(t *testing.T, f *fixture) ([]byte, []string) {
			real := filepath.Join(f.xdg, "elsewhere.json")
			if err := os.WriteFile(real, encodeRefusals(t, 1, nil), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, f.reasonFile); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"reason file of another run", func(t *testing.T, f *fixture) ([]byte, []string) {
			b, err := reason.Encode("r-other", 1, []reason.Refusal{refusalAt(0)})
			if err != nil {
				t.Fatal(err)
			}
			f.publish(t, b)
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"malformed stdin", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return []byte(`{"hook_event_name": "PostToolUse", `), nil
		}},
		{"stdin not an object", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return []byte(`["PostToolUse"]`), nil
		}},
		{"stdin with no event", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return []byte(`{"session_id": "abc123"}`), nil
		}},
		{"stdin over its bound", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return []byte(`{"hook_event_name":"PostToolUse","tool_response":"` + strings.Repeat("a", MaxInputBytes) + `"}`), nil
		}},
		{"an event the hook does not answer", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`), nil
		}},
		{"lock timeout", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			fd, err := unix.Open(filepath.Join(f.dir, StateDirName), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(fd) })
			if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"state file a link", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			if err := os.Symlink(filepath.Join(f.xdg, "planted"), filepath.Join(f.dir, StateDirName, StateFileName)); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"temporary state file a link", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			if err := os.Symlink(filepath.Join(f.xdg, "planted"), filepath.Join(f.dir, StateDirName, stateTmpName)); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"state file over its bound", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			big := `{"v":1,"run":"` + testRun + `","pad":"` + strings.Repeat("x", MaxStateBytes) + `"}`
			if err := os.WriteFile(filepath.Join(f.dir, StateDirName, StateFileName), []byte(big), 0o600); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"state file garbage", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			if err := os.WriteFile(filepath.Join(f.dir, StateDirName, StateFileName), []byte("{]"), 0o600); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"state file of another run", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			if err := os.WriteFile(filepath.Join(f.dir, StateDirName, StateFileName), []byte(`{"v":1,"run":"r-other"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"no hook-state", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			if err := os.Remove(filepath.Join(f.dir, StateDirName)); err != nil {
				t.Fatal(err)
			}
			return payload(t, "session-start"), nil
		}},
		{"hook-state a link", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			other := filepath.Join(f.xdg, "other-state")
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.dir, StateDirName)); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, filepath.Join(f.dir, StateDirName)); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), nil
		}},
		{"--reason outside the convention", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			other := filepath.Join(f.xdg, "elsewhere", testRun)
			if err := os.MkdirAll(filepath.Join(other, StateDirName), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(other, reason.FileName), encodeRefusals(t, 1, nil), 0o600); err != nil {
				t.Fatal(err)
			}
			return payload(t, "post-tool-use-bash"), []string{"--reason", filepath.Join(other, reason.FileName)}
		}},
		{"--reason empty", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return payload(t, "post-tool-use-bash"), []string{"--reason", ""}
		}},
		{"an unknown flag", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return payload(t, "post-tool-use-bash"), []string{"--print-settings"}
		}},
		{"an unknown mode", func(t *testing.T, f *fixture) ([]byte, []string) {
			f.refusals(t, 1)
			return payload(t, "post-tool-use-bash"), []string{"--mode", "block"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			stdin, args := tc.setup(t, f)
			r := f.hookWithin(t, 50*time.Millisecond, stdin, args...) // the lock case waits this long, not LockBudget
			if r.code != 0 || r.stdout != "" || strings.Count(r.stderr, "\n") != 1 || !strings.HasSuffix(r.stderr, "\n") {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 0, nothing on stdout and one stderr line", r.code, r.stdout, r.stderr)
			}
			if !strings.HasPrefix(r.stderr, "tego hook claude-code: ") {
				t.Errorf("stderr %q does not name the hook", r.stderr)
			}
		})
	}
	t.Run("another harness", func(t *testing.T) {
		var o, e strings.Builder
		code := run(strings.NewReader(""), &o, &e, []string{"codex"}, func(string) string { return "" }, 1000, LockBudget)
		if code != 0 || o.Len() != 0 || strings.Count(e.String(), "\n") != 1 {
			t.Errorf("exit %d, stdout %q, stderr %q", code, o.String(), e.String())
		}
	})
}

// TestJSONModeNeverExitsTwo: whatever the event and the state of the run, json mode exits 0.
func TestJSONModeNeverExitsTwo(t *testing.T) {
	f := newFixture(t)
	for i := uint64(1); i <= 3; i++ {
		f.refusals(t, i)
		for name := range payloadNames {
			if r := f.hook(t, payload(t, name)); r.code != 0 {
				t.Errorf("%s after %d refusals: exit %d", name, i, r.code)
			}
		}
	}
}

// TestOutputBound is acceptance (8): what the hook prints is at most 4000 characters, the context of a full ring of
// the longest targets the reason file holds and the facts of a run whose name is as long as a path element can be.
func TestOutputBound(t *testing.T) {
	f := newFixture(t)
	f.publish(t, encodeRefusals(t, 40, func(r *reason.Refusal) {
		r.Payload.Target = "/home/user/" + strings.Repeat("é", reason.MaxFieldBytes) + r.Payload.Target
	}))
	for _, mode := range []string{ModeJSON, ModeStderr} {
		// Each mode starts from a state that has shown nothing.
		if err := os.WriteFile(filepath.Join(f.dir, StateDirName, StateFileName), []byte(`{"v":1,"run":"`+testRun+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		r := f.hook(t, payload(t, "post-tool-use-write"), "--mode", mode)
		text := r.stderr
		if mode == ModeJSON {
			text = context(t, r.stdout, EventPostToolUse)
		}
		if n := utf8.RuneCountInString(text); n > MaxContextChars || n == 0 {
			t.Errorf("%s: %d characters, want 1..%d", mode, n, MaxContextChars)
		}
	}
	long := strings.Repeat("r", 255)
	xdg := t.TempDir()
	dir := filepath.Join(xdg, runtimeDirName, long)
	if err := os.MkdirAll(filepath.Join(dir, StateDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	g := &fixture{xdg: xdg, dir: dir, reasonFile: filepath.Join(dir, reason.FileName)}
	if n := utf8.RuneCountInString(context(t, g.hook(t, payload(t, "session-start")).stdout, EventSessionStart)); n > MaxContextChars {
		t.Errorf("SessionStart: %d characters", n)
	}
}

// TestOutsideAnyRun is acceptance (9)'s no-op: with no --reason and no TEGO_REASON the hook says nothing at all and
// opens no file of its own (the process's start-up reads are TestHookMakesOnlyItsDocumentedSyscalls's), whatever
// stdin holds, so installing it by hand outside tego is safe.
func TestOutsideAnyRun(t *testing.T) {
	none := func(string) string { return "" }
	stdins := [][]byte{nil, []byte("{]"), payload(t, "post-tool-use-bash"), payload(t, "session-start"), payload(t, "stop")}
	for _, mode := range []string{ModeJSON, ModeStderr} {
		for _, in := range stdins {
			var o, e strings.Builder
			if code := run(strings.NewReader(string(in)), &o, &e, []string{Harness, "--mode", mode}, none, 1000, LockBudget); code != 0 || o.Len() != 0 || e.Len() != 0 {
				t.Errorf("%s over %q: exit %d, stdout %q, stderr %q", mode, in, code, o.String(), e.String())
			}
		}
	}
}

// TestNamesMatchTheEngines: the adapter may not import the packages these names live in, so a test holds them equal.
func TestNamesMatchTheEngines(t *testing.T) {
	if envReason != identity.EnvReason {
		t.Errorf("envReason %q, identity.EnvReason %q", envReason, identity.EnvReason)
	}
	if envClaudeSettings != identity.EnvClaudeSettings {
		t.Errorf("envClaudeSettings %q, identity.EnvClaudeSettings %q", envClaudeSettings, identity.EnvClaudeSettings)
	}
	if runtimeDirName != agent.RuntimeDirName {
		t.Errorf("runtimeDirName %q, agent.RuntimeDirName %q", runtimeDirName, agent.RuntimeDirName)
	}
}
