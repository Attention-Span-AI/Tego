// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// An empty --settings value is refused, not read as "no settings": a launcher that passes --settings "$EMPTY" must
// not get a run with no hooks, which a check for "no reminder reached the model" would pass for the wrong reason.
func TestAnEmptySettingsValueIsRefused(t *testing.T) {
	m := newFakeModel(t, nil)
	env := []string{"ANTHROPIC_BASE_URL=" + m.srv.URL}
	good := filepath.Join(t.TempDir(), "a.json")
	if err := os.WriteFile(good, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"separate value": {"--settings", ""},
		"equals form":    {"--settings="},
		"blanks":         {"--settings", "  "},
		"last one wins":  {"--settings", good, "--settings", ""},
	} {
		var out, errb bytes.Buffer
		if code := run(args, env, &out, &errb); code != 1 || len(m.reqs) != 0 || !strings.Contains(errb.String(), "needs a file path") {
			t.Errorf("%s: exit %d, %d requests, stderr %q", name, code, len(m.reqs), errb.String())
		}
	}
}

// The class of the empty --settings bug: no other value flag takes an empty value as "not given" either.
func TestAnEmptyValueForAnyValueFlagIsRefused(t *testing.T) {
	m := newFakeModel(t, nil)
	env := []string{"ANTHROPIC_BASE_URL=" + m.srv.URL}
	for _, f := range []string{"--script", "--result", "--cwd", "--session-id", "--model", "--spill-dir"} {
		for _, args := range [][]string{{f, ""}, {f + "="}} {
			var out, errb bytes.Buffer
			if code := run(args, env, &out, &errb); code != 2 || len(m.reqs) != 0 || !strings.Contains(errb.String(), "needs a non-empty value") {
				t.Errorf("%q: exit %d, %d requests, stderr %q", args, code, len(m.reqs), errb.String())
			}
		}
	}
}

// continue:false from a PostToolUse hook stops Claude "processing entirely": the calls of the turn that have not run
// yet do not run, and PostToolBatch does not fire.
func TestContinueFalseFromPostToolUseStopsLaterSequentialCalls(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write", "Write"}})
	r := fc(t, m, `{"turns":[{"calls":[{"write":"a.txt","content":"A"},{"write":"b.txt","content":"B"}]}]}`,
		settingsJSON(t, map[string]string{EvPostToolUse: "json-stop", EvPostToolBatch: "context"}))
	if r.code != 0 || r.sum.Ended != "stopped_by_hook" || len(m.reqs) != 1 {
		t.Fatalf("code %d ended %q requests %d stderr %s", r.code, r.sum.Ended, len(m.reqs), r.stderr)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "a.txt")); err != nil {
		t.Errorf("the first call did not run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "b.txt")); err == nil {
		t.Error("the second call ran after a hook said continue:false")
	}
	for _, h := range r.sum.Hooks {
		if h.Event == EvPostToolBatch {
			t.Error("PostToolBatch fired after continue:false")
		}
	}
	calls := r.sum.Turns[0].Calls
	if len(calls) != 2 || !calls[0].OK || calls[0].Skipped || !calls[1].Skipped || calls[1].OK {
		t.Errorf("summary calls %+v", calls)
	}
}

// A parallel turn's calls are all running when one hook stops the loop, so they all ran; PostToolBatch still does not.
func TestContinueFalseInAParallelTurnStillSkipsPostToolBatch(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write", "Write"}})
	r := fc(t, m, `{"turns":[{"parallel":true,"calls":[{"write":"a.txt","content":"A"},{"write":"b.txt","content":"B"}]}]}`,
		settingsJSON(t, map[string]string{EvPostToolUse: "json-stop", EvPostToolBatch: "context"}))
	if r.sum.Ended != "stopped_by_hook" || len(m.reqs) != 1 {
		t.Fatalf("ended %q requests %d", r.sum.Ended, len(m.reqs))
	}
	for _, h := range r.sum.Hooks {
		if h.Event == EvPostToolBatch {
			t.Error("PostToolBatch fired after continue:false")
		}
	}
}

// SessionStart's continue:false ends the session before the first model request: no request, no tool call.
func TestContinueFalseFromSessionStartEndsBeforeTheFirstRequest(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write"}})
	r := fc(t, m, `{"turns":[{"calls":[{"write":"a.txt","content":"A"}]}]}`,
		settingsJSON(t, map[string]string{EvSessionStart: "json-stop", EvPostToolUse: "context", EvStop: "exit2-always"}))
	if r.code != 0 || r.sum.Ended != "stopped_by_hook" || len(m.reqs) != 0 || len(r.sum.Requests) != 0 {
		t.Fatalf("code %d ended %q requests %d/%d stderr %s", r.code, r.sum.Ended, len(m.reqs), len(r.sum.Requests), r.stderr)
	}
	// report.py check --result reads this shape for a run stopped before its first request: an empty list, not null
	if b, _ := json.Marshal(r.sum); !strings.Contains(string(b), `"requests":[]`) || !strings.Contains(string(b), `"ended":"stopped_by_hook"`) {
		t.Errorf("summary %s", b)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "a.txt")); err == nil {
		t.Error("a tool call ran after SessionStart said continue:false")
	}
	if !strings.Contains(r.stderr, "hook stopped the session: stand-in hook: json stop") {
		t.Errorf("stderr %q", r.stderr)
	}
	for _, h := range r.sum.Hooks {
		if h.Event != EvSessionStart {
			t.Errorf("%s ran after the session was stopped", h.Event)
		}
	}
}

// A model that asks for more tool calls than the script has turns is a disagreement, recorded on that request so
// report.py check --result fails without a shape file.
func TestAModelThatAsksForMoreTurnsThanTheScriptHasDisagrees(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write"}, {"Bash"}})
	r := fc(t, m, `{"turns":[{"calls":[{"write":"a.txt","content":"A"}]}]}`, "")
	if len(r.sum.Requests) != 2 {
		t.Fatalf("%d requests", len(r.sum.Requests))
	}
	if a := r.sum.Requests[1].Agrees; a == nil || *a {
		t.Errorf("request 1 agrees_with_script %v, want false", a)
	}
	if a := r.sum.Requests[0].Agrees; a == nil || !*a {
		t.Errorf("request 0 agrees_with_script %v, want true", a)
	}
}

// A file that is a FIFO when it is opened is refused without blocking, however it got there: the file is opened
// without blocking and judged from the descriptor, so a file swapped for a FIFO after a stat cannot hang a run.
func TestReadRegularRefusesAFifoWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readRegular(fifo, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errNotRegular) {
			t.Errorf("error %v, want errNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readRegular blocked on a FIFO")
	}
}

func TestReadRegularCapsWhatItReads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readRegular(p, 5); err != nil || string(b) != "12345" {
		t.Errorf("at the limit: %q %v", b, err)
	}
	if _, err := readRegular(p, 4); !errors.Is(err, errTooBig) {
		t.Errorf("over the limit: %v", err)
	}
	if _, err := readRegular("/dev/zero", 1<<20); !errors.Is(err, errNotRegular) {
		t.Errorf("/dev/zero: %v", err)
	}
}

// The Read tool does not read a FIFO (it would block the turn) or a device (it would never end), and caps a file.
func TestReadToolRefusesWhatIsNotAnOrdinaryFileOrTooBig(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxCapture+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ path, want string }{
		"fifo":      {fifo, "not a regular file"},
		"/dev/zero": {"/dev/zero", "not a regular file"},
		"directory": {dir, "EISDIR: illegal operation on a directory, read"},
		"too big":   {big, "exceeds the"},
	} {
		done := make(chan toolRun, 1)
		go func() { done <- Call{Read: tc.path}.Execute(dir, os.Environ()) }()
		select {
		case r := <-done:
			if !strings.Contains(r.Err, tc.want) {
				t.Errorf("%s: error %q, want %q", name, r.Err, tc.want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the Read tool blocked", name)
		}
	}
}

// The script file gets the same care as the settings file: a FIFO or a device is refused, not read.
func TestAScriptThatIsNotAnOrdinaryFileExitsOne(t *testing.T) {
	m := newFakeModel(t, nil)
	env := []string{"ANTHROPIC_BASE_URL=" + m.srv.URL}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, "/dev/zero"} {
		done := make(chan int, 1)
		var out, errb bytes.Buffer
		go func() { done <- run([]string{"--script", p}, env, &out, &errb) }()
		select {
		case code := <-done:
			if code != 1 || !strings.Contains(errb.String(), "not a regular file") || len(m.reqs) != 0 {
				t.Errorf("%s: exit %d stderr %q", p, code, errb.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: run blocked on the script file", p)
		}
	}
}

// The reply to a Stop continuation is past the script's last turn too: a model that answers it with a tool call is a
// disagreement, recorded on that request, not a silent end_turn that report.py check --result passes.
func TestAModelThatAnswersAStopContinuationWithAToolCallDisagrees(t *testing.T) {
	t.Setenv("FAKECLAUDE_HOOK_LOG", filepath.Join(t.TempDir(), "hooks.log"))
	m := newFakeModel(t, [][]string{nil, {"Bash"}})
	r := fc(t, m, `{"turns":[]}`, settingsJSON(t, map[string]string{EvStop: "exit2-once"}))
	if r.code != 0 || r.sum.Ended != "end_turn" || len(r.sum.Requests) != 2 {
		t.Fatalf("code %d ended %q requests %d", r.code, r.sum.Ended, len(r.sum.Requests))
	}
	if len(r.sum.Requests[1].ToolUses) != 1 {
		t.Fatalf("the continuation's reply was not a tool call: %+v", r.sum.Requests[1])
	}
	if a := r.sum.Requests[1].Agrees; a == nil || *a {
		t.Errorf("request 1 agrees_with_script %v, want false", a)
	}
	if a := r.sum.Requests[0].Agrees; a != nil {
		t.Errorf("request 0 agrees_with_script %v, want unset (it asked for nothing)", *a)
	}
}

// A name that becomes a FIFO at the moment of the open, whatever was true of it earlier, does not hang readRegular:
// the open is non-blocking and the verdict comes from the descriptor. A pre-check by name followed by a blocking open
// (the shape this replaced) hangs here, as does an open without O_NONBLOCK, so the test holds the descriptor-based
// design and not only the end state.
func TestReadRegularSurvivesANameSwappedForAFifoAtTheOpen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "name")
	if err := os.WriteFile(p, []byte("regular"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := openFile
	t.Cleanup(func() { openFile = orig })
	var flagsSeen int
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		flagsSeen = flag
		if err := os.Remove(name); err != nil {
			return nil, err
		}
		if err := syscall.Mkfifo(name, 0o600); err != nil {
			return nil, err
		}
		return orig(name, flag, perm)
	}
	type res struct {
		data []byte
		err  error
	}
	done := make(chan res, 1)
	go func() {
		d, err := readRegular(p, 1<<20)
		done <- res{d, err}
	}()
	select {
	case r := <-done:
		if !errors.Is(r.err, errNotRegular) {
			t.Errorf("readRegular = %q, %v; want errNotRegular", r.data, r.err)
		}
	case <-time.After(5 * time.Second):
		// release a blocked open so the goroutine ends
		if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		t.Fatal("readRegular blocked when the name became a FIFO at the open")
	}
	if flagsSeen&syscall.O_NONBLOCK == 0 {
		t.Errorf("open flags %#x lack O_NONBLOCK", flagsSeen)
	}
}
