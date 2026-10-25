// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// A recorded request, as the model stub would see it.
type seen struct {
	Messages []struct {
		Role    string
		Content []map[string]any
	}
}

// fakeModel is an in-process model stub: it answers request n with n-th entry of tools (the tool names of a tool_use
// block each) and then with a text, and keeps every request body.
type fakeModel struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []seen
	tool [][]string
	// failFrom, when above zero, makes the model answer HTTP 500 from its failFrom-th request on (1-based).
	failFrom int
}

func newFakeModel(t *testing.T, tools [][]string) *fakeModel {
	m := &fakeModel{tool: tools}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var s seen
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		m.mu.Lock()
		m.reqs = append(m.reqs, s)
		n := len(m.reqs)
		m.mu.Unlock()
		if m.failFrom > 0 && n >= m.failFrom {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		turn := 0
		for _, msg := range s.Messages {
			if msg.Role == "assistant" {
				turn++
			}
		}
		content := []map[string]any{{"type": "text", "text": fmt.Sprintf("final text %d", turn)}}
		stop := "end_turn"
		if turn < len(m.tool) && m.tool[turn] != nil { // a nil entry is a plain text answer
			content, stop = nil, "tool_use"
			for i, n := range m.tool[turn] {
				content = append(content, map[string]any{"type": "tool_use", "id": fmt.Sprintf("toolu_m_%d_%d", turn, i), "name": n, "input": map[string]any{}})
			}
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "message", "role": "assistant", "content": content, "stop_reason": stop})
	}))
	t.Cleanup(m.srv.Close)
	return m
}

type fcResult struct {
	code           int
	stdout, stderr string
	sum            Summary
	model          *fakeModel
	dir            string
}

// fc runs fakeclaude in this process against the model, in a fresh working directory, with the script and the
// settings given as text.
func fc(t *testing.T, m *fakeModel, script, settings string, extra ...string) fcResult {
	t.Helper()
	return fcWith(t, m, script, settings, []string{"CLAUDE_CODE_SIMPLE="}, extra...)
}

func fcWith(t *testing.T, m *fakeModel, script, settings string, more []string, extra ...string) fcResult {
	t.Helper()
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "script.json")
	if err := os.WriteFile(scriptPath, []byte(strings.ReplaceAll(script, "@DIR@", dir)), 0o644); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(dir, "result.json")
	args := append([]string{"--script", scriptPath, "--result", result, "--cwd", work, "--spill-dir", filepath.Join(dir, "spill")}, extra...)
	if settings != "" {
		args = append(args, "--settings", settings)
	}
	env := append(append(os.Environ(), "ANTHROPIC_BASE_URL="+m.srv.URL, "ANTHROPIC_API_KEY=dummy"), more...)
	var out, errb bytes.Buffer
	r := fcResult{model: m, dir: work}
	r.code = run(args, env, &out, &errb)
	r.stdout, r.stderr = out.String(), errb.String()
	b, err := os.ReadFile(result)
	if err != nil {
		t.Fatalf("no result file: %v (stderr %s)", err, r.stderr)
	}
	if err := json.Unmarshal(b, &r.sum); err != nil {
		t.Fatal(err)
	}
	return r
}

// tail is the blocks of request n's messages after its last assistant message: the user message and the system
// message of notes after it, when there is one.
func (r fcResult) tail(n int) []map[string]any {
	msgs := r.model.reqs[n].Messages
	i := len(msgs)
	for i > 0 && msgs[i-1].Role != "assistant" {
		i--
	}
	var out []map[string]any
	for _, m := range msgs[i:] {
		for _, b := range m.Content {
			b["role"] = m.Role
			out = append(out, b)
		}
	}
	return out
}

// userText is every text of request n's tail, a system message's split into its notes.
func (r fcResult) userText(n int) []string {
	var out []string
	for _, b := range r.tail(n) {
		if b["type"] != "text" {
			continue
		}
		if t := b["text"].(string); b["role"] == "system" {
			out = append(out, strings.Split(t, noteSep)...)
		} else {
			out = append(out, t)
		}
	}
	return out
}

func (r fcResult) results(n int) []map[string]any {
	var out []map[string]any
	for _, b := range r.tail(n) {
		if b["type"] == "tool_result" {
			out = append(out, b)
		}
	}
	return out
}

func countContaining(ss []string, sub string) int {
	n := 0
	for _, s := range ss {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

const twoTurnScript = `{"prompt":"hello","turns":[
 {"calls":[{"write":"a.txt","content":"A"}]},
 {"calls":[{"read":"a.txt"},{"run":["sh","-c","exit 4"]}]}]}`

// A reminder from a PostToolUseFailure hook is labelled with that event, not with PostToolUse: the model, and a test
// reading the stub's log, can tell which hook spoke.
func TestAFailedCallsReminderIsLabelledPostToolUseFailure(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write", "Bash"}})
	r := fc(t, m, `{"turns":[{"calls":[{"write":"a.txt","content":"A"},{"run":["sh","-c","exit 4"]}]}]}`,
		settingsJSON(t, map[string]string{EvPostToolUse: "context", EvPostToolUseFailure: "context"}))
	if r.code != 0 {
		t.Fatalf("code %d stderr %s", r.code, r.stderr)
	}
	txt := r.userText(1)
	if countContaining(txt, "PostToolUseFailure:Bash hook additional context") != 1 ||
		countContaining(txt, "PostToolUse:Write hook additional context") != 1 ||
		countContaining(txt, "PostToolUse:Bash") != 0 {
		t.Errorf("request 1 text: %q", txt)
	}
}

func TestLoopSendsResultsAndReminders(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write"}, {"Read", "Bash"}})
	r := fc(t, m, twoTurnScript, settingsJSON(t, map[string]string{
		EvSessionStart: "context", EvPostToolUse: "context", EvPostToolUseFailure: "context", EvPostToolBatch: "context"}))
	if r.code != 0 || r.sum.Ended != "end_turn" || r.stdout != "final text 2\n" {
		t.Fatalf("code %d ended %q stdout %q stderr %s", r.code, r.sum.Ended, r.stdout, r.stderr)
	}
	if len(m.reqs) != 3 {
		t.Fatalf("%d requests", len(m.reqs))
	}
	// request 0: the prompt and SessionStart's context, once
	first := r.userText(0)
	if first[0] != "hello" || countContaining(first, FixedContext+" (SessionStart)") != 1 || !strings.HasPrefix(first[1], "SessionStart hook additional context: ") ||
		r.tail(0)[1]["role"] != "system" {
		t.Errorf("request 0: %q", first)
	}
	// request 1: the Write's result, PostToolUse's and PostToolBatch's reminders
	if res := r.results(1); len(res) != 1 || res[0]["tool_use_id"] != "toolu_m_0_0" || res[0]["is_error"] != nil {
		t.Errorf("request 1 results: %v", res)
	}
	t1 := r.userText(1)
	if countContaining(t1, "(PostToolUse)") != 1 || countContaining(t1, "(PostToolBatch)") != 1 || countContaining(t1, "SessionStart") != 0 {
		t.Errorf("request 1 text: %q", t1)
	}
	// request 2: a Read that worked and a Bash that failed: PostToolUse once, PostToolUseFailure once, ids and error flag
	res := r.results(2)
	if len(res) != 2 || res[0]["tool_use_id"] != "toolu_m_1_0" || res[1]["tool_use_id"] != "toolu_m_1_1" || res[1]["is_error"] != true ||
		!strings.HasPrefix(res[1]["content"].(string), "Exit code 4") {
		t.Errorf("request 2 results: %v", res)
	}
	t2 := r.userText(2)
	if countContaining(t2, "(PostToolUse)") != 1 || countContaining(t2, "(PostToolUseFailure)") != 1 || countContaining(t2, "(PostToolBatch)") != 1 {
		t.Errorf("request 2 text: %q", t2)
	}
	// the history is consistent: each user turn (and the system message of its notes) answers the assistant turn
	// before it, as the real binary sends it
	var roles []string
	for _, msg := range m.reqs[2].Messages {
		roles = append(roles, msg.Role)
	}
	if strings.Join(roles, " ") != "user system assistant user system assistant user system" {
		t.Errorf("history roles: %q", roles)
	}
	for _, rr := range r.sum.Requests {
		if rr.Status != 200 {
			t.Errorf("request %d status %d", rr.N, rr.Status)
		}
	}
	if len(r.sum.Turns) != 2 || r.sum.Turns[1].Calls[1].OK || !r.sum.Turns[1].Calls[0].OK || r.sum.Requests[0].Agrees == nil || !*r.sum.Requests[0].Agrees {
		t.Errorf("summary %+v", r.sum.Turns)
	}
	// the Write really happened
	if b, _ := os.ReadFile(filepath.Join(r.dir, "a.txt")); string(b) != "A" {
		t.Errorf("a.txt %q", b)
	}
}

// A bare session runs no hook at all, --settings' included (claude --help 2.1.310 "skip hooks"; RESULTS.md R2):
// no note, no exit-2 feedback, no hook in the summary, and the call still runs.
func TestBareRunsNoHook(t *testing.T) {
	settings := settingsJSON(t, map[string]string{EvSessionStart: "context", EvPostToolUse: "exit2", EvPostToolBatch: "context"})
	for name, extra := range map[string][]string{"flag": {"--bare"}, "env": nil} {
		m := newFakeModel(t, [][]string{{"Write"}})
		script := `{"turns":[{"calls":[{"write":"a.txt","content":"A"}]}]}`
		var r fcResult
		if name == "env" {
			r = fcWith(t, m, script, settings, []string{"CLAUDE_CODE_SIMPLE=1"})
		} else {
			r = fc(t, m, script, settings, extra...)
		}
		all := append(r.userText(0), r.userText(1)...)
		if countContaining(all, "hook additional context") != 0 || countContaining(all, FixedContext) != 0 || countContaining(all, "exit 2 reason") != 0 {
			t.Errorf("%s: a hook's text reached the model: %q", name, all)
		}
		if !r.sum.Bare || len(r.sum.Hooks) != 0 || len(r.results(1)) != 1 {
			t.Errorf("%s: summary bare %v hooks %v, results %v", name, r.sum.Bare, r.sum.Hooks, r.results(1))
		}
		if b, _ := os.ReadFile(filepath.Join(r.dir, "a.txt")); string(b) != "A" {
			t.Errorf("%s: a.txt %q", name, b)
		}
	}
}

func TestParallelCallsRunAtOnceAndHooksRunPerCall(t *testing.T) {
	log := filepath.Join(t.TempDir(), "hooks.log")
	t.Setenv("FAKECLAUDE_HOOK_LOG", log)
	m := newFakeModel(t, [][]string{{"Write", "Write", "Bash"}})
	r := fc(t, m, `{"turns":[{"parallel":true,"calls":[
	  {"write":"one.txt","content":"1"},{"write":"two.txt","content":"2"},{"bash":"sleep 0.2; echo done"}]}]}`,
		settingsJSON(t, map[string]string{EvPostToolUse: "context", EvPostToolBatch: "context"}))
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	res := r.results(1)
	if len(res) != 3 || res[0]["tool_use_id"] != "toolu_m_0_0" || res[2]["tool_use_id"] != "toolu_m_0_2" {
		t.Errorf("results out of call order: %v", res)
	}
	// three PostToolUse payloads and one PostToolBatch carrying all three calls, in call order
	var post, batch int
	data, _ := os.ReadFile(log)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var p struct {
			Event string `json:"hook_event_name"`
			Calls []struct {
				ID string `json:"tool_use_id"`
			} `json:"tool_calls"`
		}
		if err := json.Unmarshal([]byte(line), &p); err != nil {
			t.Fatal(err)
		}
		switch p.Event {
		case EvPostToolUse:
			post++
		case EvPostToolBatch:
			batch++
			if len(p.Calls) != 3 || p.Calls[0].ID != "toolu_m_0_0" || p.Calls[2].ID != "toolu_m_0_2" {
				t.Errorf("batch calls: %+v", p.Calls)
			}
		}
	}
	if post != 3 || batch != 1 {
		t.Errorf("PostToolUse %d PostToolBatch %d", post, batch)
	}
	if got := countContaining(r.userText(1), "(PostToolUse)"); got != 3 {
		t.Errorf("%d PostToolUse reminders", got)
	}
}

// The calls of a parallel turn run at the same time: each of two calls waits for a file only the other creates, which
// can succeed only when both are running at once. The same two calls in a sequential turn cannot meet, so the first
// one times out waiting.
func TestParallelCallsOverlapAndSequentialCallsDoNot(t *testing.T) {
	meet := func(mine, theirs string) string {
		return fmt.Sprintf(`{"bash":"touch %s; for i in $(seq 40); do [ -e %s ] && exit 0; sleep 0.05; done; echo never met; exit 1"}`, mine, theirs)
	}
	calls := meet("a", "b") + "," + meet("b", "a")
	for _, tc := range []struct {
		parallel bool
		wantErrs int
	}{{true, 0}, {false, 1}} {
		m := newFakeModel(t, [][]string{{"Bash", "Bash"}})
		r := fc(t, m, fmt.Sprintf(`{"turns":[{"parallel":%v,"calls":[%s]}]}`, tc.parallel, calls), "")
		if r.code != 0 {
			t.Fatalf("parallel %v: %d %s", tc.parallel, r.code, r.stderr)
		}
		errs := 0
		for _, res := range r.results(1) {
			if res["is_error"] == true {
				errs++
			}
		}
		if errs != tc.wantErrs {
			t.Errorf("parallel %v: %d calls failed to meet, want %d (%v)", tc.parallel, errs, tc.wantErrs, r.results(1))
		}
	}
}

func TestPostToolBatchExitTwoEndsTheLoop(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write"}, {"Write"}})
	r := fc(t, m, `{"turns":[{"calls":[{"write":"a","content":"1"}]},{"calls":[{"write":"b","content":"2"}]}]}`,
		settingsJSON(t, map[string]string{EvPostToolBatch: "exit2", EvStop: "exit2-always"}))
	if r.code != 0 || r.sum.Ended != "stopped_by_hook" || len(m.reqs) != 1 {
		t.Errorf("code %d ended %q requests %d", r.code, r.sum.Ended, len(m.reqs))
	}
	if _, err := os.Stat(filepath.Join(r.dir, "b")); err == nil {
		t.Error("the second turn ran after the loop was stopped")
	}
	for _, h := range r.sum.Hooks {
		if h.Event == EvStop {
			t.Error("Stop ran after PostToolBatch stopped the loop")
		}
	}
}

func TestStopExitTwoContinuesOnceThenStopHookActive(t *testing.T) {
	log := filepath.Join(t.TempDir(), "hooks.log")
	t.Setenv("FAKECLAUDE_HOOK_LOG", log)
	m := newFakeModel(t, nil)
	r := fc(t, m, `{"turns":[]}`, settingsJSON(t, map[string]string{EvStop: "exit2-once"}))
	if r.code != 0 || r.sum.StopContinuations != 1 || r.sum.Ended != "end_turn" || len(m.reqs) != 2 {
		t.Fatalf("code %d continuations %d ended %q requests %d", r.code, r.sum.StopContinuations, r.sum.Ended, len(m.reqs))
	}
	if countContaining(r.userText(1), "keep going") != 1 {
		t.Errorf("the continuation did not carry the stderr: %q", r.userText(1))
	}
	data, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"stop_hook_active":false`) || !strings.Contains(lines[1], `"stop_hook_active":true`) ||
		!strings.Contains(lines[0], `"last_assistant_message":"final text 0"`) || !strings.Contains(lines[1], `"last_assistant_message":"final text 1"`) {
		t.Errorf("Stop payloads:\n%s", data)
	}
}

// A model request that fails after the Stop hook asked for a continuation is as much a failed run as one that fails
// in a tool turn: exit 1, the error in the summary, and the run is not reported as ended.
func TestAFailedModelRequestInTheStopPhaseExitsOne(t *testing.T) {
	m := newFakeModel(t, nil)
	m.failFrom = 2
	r := fc(t, m, `{"turns":[]}`, settingsJSON(t, map[string]string{EvStop: "exit2-always"}))
	if r.code != 1 || r.sum.Ended != "request_failed" || !strings.Contains(r.sum.Error, "HTTP 500") || !strings.Contains(r.stderr, "HTTP 500") {
		t.Errorf("code %d ended %q error %q stderr %s", r.code, r.sum.Ended, r.sum.Error, r.stderr)
	}
	if len(m.reqs) != 2 {
		t.Errorf("%d requests", len(m.reqs))
	}
}

func TestStopThatNeverSatisfiesEndsAtTheCap(t *testing.T) {
	for name, tc := range map[string]struct {
		env  []string
		want int
	}{
		"default":          {nil, 8},
		"raised":           {[]string{"CLAUDE_CODE_STOP_HOOK_BLOCK_CAP=11"}, 11},
		"lowered":          {[]string{"CLAUDE_CODE_STOP_HOOK_BLOCK_CAP=2"}, 2},
		"not a number":     {[]string{"CLAUDE_CODE_STOP_HOOK_BLOCK_CAP=lots"}, 8},
		"zero or negative": {[]string{"CLAUDE_CODE_STOP_HOOK_BLOCK_CAP=0"}, 8},
	} {
		m := newFakeModel(t, nil)
		r := fcWith(t, m, `{"turns":[]}`, settingsJSON(t, map[string]string{EvStop: "exit2-always"}), append([]string{"CLAUDE_CODE_SIMPLE="}, tc.env...))
		if r.sum.Ended != "stop_hook_cap" || r.sum.StopContinuations != tc.want || len(m.reqs) != 1+tc.want {
			t.Errorf("%s: ended %q continuations %d requests %d, want %d continuations", name, r.sum.Ended, r.sum.StopContinuations, len(m.reqs), tc.want)
		}
	}
}

func TestAHookThatTimesOutOrFailsDoesNotBlock(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write"}})
	settings := `{"hooks":{"PostToolUse":[{"hooks":[
	  {"type":"command","command":"` + os.Args[0] + `","args":["__hook__","sleep"],"timeout":0.3},
	  {"type":"command","command":"` + os.Args[0] + `","args":["__hook__","exit1"]},
	  {"type":"command","command":"` + os.Args[0] + `","args":["__hook__","context"]}]}]}}`
	r := fc(t, m, `{"turns":[{"calls":[{"write":"a","content":"1"}]}]}`, settings)
	if r.code != 0 || len(m.reqs) != 2 {
		t.Fatalf("code %d requests %d", r.code, len(m.reqs))
	}
	if countContaining(r.userText(1), "(PostToolUse)") != 1 || countContaining(r.userText(1), "exit 1") != 0 {
		t.Errorf("model text: %q", r.userText(1))
	}
	if !strings.Contains(r.stderr, "timed out") || !strings.Contains(r.stderr, "non-blocking status code: 1") {
		t.Errorf("user lines: %s", r.stderr)
	}
}

func TestContextOverTheCapReachesTheModelAsAPathAndPreview(t *testing.T) {
	m := newFakeModel(t, [][]string{{"Write"}})
	r := fc(t, m, `{"turns":[{"calls":[{"write":"a","content":"1"}]}]}`, settingsJSON(t, map[string]string{EvPostToolUse: "big"}))
	got := strings.Join(r.userText(1), "\n")
	if !strings.Contains(got, "Output too large (12000 characters)") || !strings.Contains(got, strings.Repeat("x", contextPreview)) || strings.Contains(got, strings.Repeat("x", contextPreview+1)) {
		t.Errorf("%.300q", got)
	}
}

func TestRefusesAModelThatIsNotLocal(t *testing.T) {
	for _, base := range []string{"", "https://api.anthropic.com", "http://10.1.2.3:80", "ftp://127.0.0.1", "http://[::1"} {
		var out, errb bytes.Buffer
		if code := run(nil, []string{"ANTHROPIC_BASE_URL=" + base}, &out, &errb); code != 2 {
			t.Errorf("%q: exit %d, stderr %s", base, code, errb.String())
		}
	}
	for _, base := range []string{"http://127.0.0.1:1", "https://localhost:1", "http://[::1]:1"} {
		if _, err := newClient(base, "", "m"); err != nil {
			t.Errorf("%q: %v", base, err)
		}
	}
}

func TestAFailedModelRequestIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", 500) }))
	defer srv.Close()
	var out, errb bytes.Buffer
	if code := run(nil, []string{"ANTHROPIC_BASE_URL=" + srv.URL}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "HTTP 500") {
		t.Errorf("exit %d: %s", code, errb.String())
	}
}

// A loopback stub that answers with a redirect must not move the request (body and x-api-key) to another host: the
// loopback check is on the base URL only, so the client itself refuses every redirect.
func TestARedirectIsAFailedRequestAndIsNeverFollowed(t *testing.T) {
	var far atomic.Int32
	farSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { far.Add(1) }))
	defer farSrv.Close()
	for _, code := range []int{http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, farSrv.URL+"/v1/messages", code)
		}))
		var out, errb bytes.Buffer
		got := run(nil, []string{"ANTHROPIC_BASE_URL=" + srv.URL, "ANTHROPIC_API_KEY=probe-key"}, &out, &errb)
		srv.Close()
		if got != 1 || !strings.Contains(errb.String(), fmt.Sprintf("HTTP %d", code)) {
			t.Errorf("%d: exit %d: %s", code, got, errb.String())
		}
	}
	if n := far.Load(); n != 0 {
		t.Errorf("%d requests reached the redirect target", n)
	}
}

func TestUnreadableScriptOrSettingsExitsOne(t *testing.T) {
	m := newFakeModel(t, nil)
	env := []string{"ANTHROPIC_BASE_URL=" + m.srv.URL}
	for _, args := range [][]string{{"--script", "/nonexistent"}, {"--settings", "/nonexistent"}, {"--settings", t.TempDir()}} {
		var out, errb bytes.Buffer
		if code := run(args, env, &out, &errb); code != 1 || len(m.reqs) != 0 {
			t.Errorf("%q: exit %d, %d requests", args, code, len(m.reqs))
		}
	}
}
