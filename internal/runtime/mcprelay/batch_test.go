// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/mcptools"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The rule of C203 (ADR 0126 §4, amended 2026-11-21): a JSON-RPC batch is decided member by member, a refused member is
// answered with an error of its own and recorded, and no member rides on another's decision.

func batchOf(members ...string) string { return "[" + strings.Join(members, ",") + "]" }

func ping(id int) string {
	return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"ping"}`
}

func notification(method string) string {
	return `{"jsonrpc":"2.0","method":"` + method + `"}`
}

// callNotification is a tools/call with no id: it expects no answer, and the server would run it all the same.
func callNotification(tool string) string {
	return `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
}

// members are the messages of a JSON array, or the one message of a JSON object, as raw JSON.
func members(t *testing.T, b []byte) []json.RawMessage {
	t.Helper()
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) > 0 && b[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(b, &arr); err != nil {
			t.Fatalf("not a JSON array: %q: %v", b, err)
		}
		return arr
	}
	if !json.Valid(b) {
		t.Fatalf("not JSON: %q", b)
	}
	return []json.RawMessage{b}
}

// idsOf are the ids of the members of b, as raw JSON in order.
func idsOf(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	for _, m := range members(t, b) {
		var e struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(m, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, string(e.ID))
	}
	return out
}

// toolsOf are the tools the tools/call members of b name, in order.
func toolsOf(t *testing.T, b []byte) []string {
	t.Helper()
	var out []string
	for _, m := range members(t, b) {
		var e struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.Unmarshal(m, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e.Method+":"+e.Params.Name)
	}
	return out
}

// answered is what the client gets for a refused member: its error code, the rule and the reason the relay names.
func answered(t *testing.T, m json.RawMessage) (id, rule, reason, message string, code int) {
	t.Helper()
	var e struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Tego struct {
					Rule   string `json:"rule"`
					Reason string `json:"reason"`
				} `json:"tego"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(m, &e); err != nil {
		t.Fatal(err)
	}
	return string(e.ID), e.Error.Data.Tego.Rule, e.Error.Data.Tego.Reason, e.Error.Message, e.Error.Code
}

// frames reads n frames from the relay: the arrays it sent the client and the messages it sent the server, in order.
func (sh *shim) frames(n int) (toClient, toServer [][]byte) {
	sh.t.Helper()
	for range n {
		f := sh.read()
		switch {
		case f.ToClient != nil:
			toClient = append(toClient, f.ToClient)
		case f.ToServer != nil:
			toServer = append(toServer, f.ToServer)
		default:
			sh.t.Fatalf("an empty frame %+v", f)
		}
	}
	return toClient, toServer
}

// quiet fails if the relay sends anything within a short wait: it sends the line after the one it just answered, so a
// frame the relay owed would come first.
func (sh *shim) nextIsServerPing(id int) {
	sh.t.Helper()
	sh.client(ping(id))
	f := sh.read()
	if f.ToServer == nil || !strings.Contains(string(f.ToServer), `"id":`+strconv.Itoa(id)) {
		sh.t.Fatalf("the next frame was %+v, want the ping %d for the server: the relay sent something else first", f, id)
	}
}

// linesOf are the mcp lines of the sink as "verdict tool rule".
func linesOf(t *testing.T, sk *sink) []string {
	t.Helper()
	var out []string
	for _, e := range sk.of(record.KindMCP) {
		var p record.MCPPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		out = append(out, string(e.Verdict)+" "+p.Tool+" "+e.Rule)
	}
	return out
}

func TestBatchMembersAreDecidedOnTheirOwn(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "read_file"), toolCall(2, "delete_file"), ping(3)))
	toClient, toServer := sh.frames(2)
	if len(toClient) != 1 || len(toServer) != 1 {
		t.Fatalf("to the client %q, to the server %q: want one each", toClient, toServer)
	}
	// The denied member is answered by its own error, naming its own rule.
	ms := members(t, toClient[0])
	if len(ms) != 1 {
		t.Fatalf("answers %s", toClient[0])
	}
	if id, rule, reason, msg, code := answered(t, ms[0]); id != "2" || rule != "mcp[files].tools.deny[delete_file]" ||
		reason != mcptool.ReasonDenied || code != mcptool.RefusalCode || !strings.Contains(msg, "delete_file") {
		t.Fatalf("answer %s", ms[0])
	}
	// The others went on, as a batch, without the denied one.
	if got := idsOf(t, toServer[0]); strings.Join(got, ",") != "1,3" {
		t.Fatalf("the server got members %v of %s, want 1 and 3", got, toServer[0])
	}
	if strings.Contains(string(toServer[0]), "delete_file") {
		t.Fatalf("the denied call reached the server: %s", toServer[0])
	}
	if got := strings.Join(linesOf(t, sk), "; "); got != "allow read_file mcp[files]; refused delete_file mcp[files].tools.deny[delete_file]" {
		t.Fatalf("record lines: %s", got)
	}
}

func TestBatchOfOnlyAllowedMembersPassesAsItCame(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "read_file"), notification("notifications/initialized"), ping(2)))
	_, toServer := sh.frames(1)
	if got := toolsOf(t, toServer[0]); strings.Join(got, ",") != "tools/call:read_file,notifications/initialized:,ping:" {
		t.Fatalf("the server got %s", toServer[0])
	}
}

func TestBatchAskedMemberIsAskedAndGoesOnAlone(t *testing.T) {
	for _, c := range []struct {
		name     string
		approve  bool
		reason   string
		toServer int
	}{
		{"approved", true, "", 2},
		{"denied by the person", false, "ask-denied", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, sk, _ := start(t, nil, filesServer())
			var asked []ask.Request
			var mu sync.Mutex
			s.ConfigureMCPAsk(func(_ context.Context, r ask.Request) (ask.Decision, error) {
				mu.Lock()
				asked = append(asked, r)
				mu.Unlock()
				if c.approve {
					return ask.Decision{Approved: true}, nil
				}
				return ask.Decision{Reason: ask.ReasonDenied}, nil
			})
			sh, _ := dial(t, s, "files", filesCmd)
			sh.client(batchOf(toolCall(1, "read_file"), toolCall(2, "write_file")))
			// The allowed member goes at once, as the batch of the one; the asked one follows by itself, or is answered.
			toClient, toServer := sh.frames(2)
			if len(toServer) != c.toServer {
				t.Fatalf("to the server %q, to the client %q", toServer, toClient)
			}
			if got := toolsOf(t, toServer[0]); strings.Join(got, ",") != "tools/call:read_file" {
				t.Fatalf("first to the server: %s", toServer[0])
			}
			if c.approve {
				if got := toolsOf(t, toServer[1]); strings.Join(got, ",") != "tools/call:write_file" || strings.HasPrefix(string(toServer[1]), "[") {
					t.Fatalf("the approved call goes alone, as it came: %s", toServer[1])
				}
			} else if _, rule, reason, _, _ := answered(t, members(t, toClient[0])[0]); reason != c.reason || rule != "mcp[files].tools.ask[write_file]" {
				t.Fatalf("answer %s", toClient[0])
			}
			mu.Lock()
			defer mu.Unlock()
			if len(asked) != 1 || asked[0].Target != "files write_file" {
				t.Fatalf("asked %+v: one card, for the asked member only", asked)
			}
			if got := len(sk.of(record.KindMCP)); got != 2 {
				t.Fatalf("record lines %d, want one for each member", got)
			}
		})
	}
}

func TestBatchAskedMemberIsRefusedWhenNobodyCanBeAsked(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer()) // no broker configured
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "read_file"), toolCall(2, "write_file")))
	toClient, toServer := sh.frames(2)
	if len(toServer) != 1 || len(toClient) != 1 {
		t.Fatalf("to the server %q, to the client %q", toServer, toClient)
	}
	if _, _, reason, _, _ := answered(t, members(t, toClient[0])[0]); reason != "ask-unavailable" {
		t.Fatalf("answer %s", toClient[0])
	}
	if got := linesOf(t, sk); len(got) != 2 {
		t.Fatalf("record lines %v", got)
	}
}

func TestBatchRepeatedIDsAreRefusedTogether(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	// Two answers under id 1 could not be told apart: the denied call's error could be read as the allowed one's result,
	// or the reverse. Both are refused, and id 2 goes on. The ids 1 and "1" are different ids.
	sh.client(batchOf(toolCall(1, "read_file"), toolCall(1, "delete_file"), toolCall(2, "read_file"),
		`{"jsonrpc":"2.0","id":"1","method":"ping"}`))
	toClient, toServer := sh.frames(2)
	ms := members(t, toClient[0])
	if len(ms) != 2 {
		t.Fatalf("answers %s", toClient[0])
	}
	for _, m := range ms {
		if id, rule, _, msg, _ := answered(t, m); id != "1" || rule != "mcp[files].relay" || !strings.Contains(msg, "same id") {
			t.Fatalf("answer %s", m)
		}
	}
	if got := idsOf(t, toServer[0]); strings.Join(got, ",") != `2,"1"` {
		t.Fatalf("the server got members %v: %s", got, toServer[0])
	}
	want := "refused read_file mcp[files].relay; refused delete_file mcp[files].relay; allow read_file mcp[files]"
	if got := strings.Join(linesOf(t, sk), "; "); got != want {
		t.Fatalf("record lines: %s", got)
	}
}

func TestBatchNotificationsAreDecidedToo(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	// A denied call with no id has no one to answer, and it is recorded all the same. The other notification passes.
	sh.client(batchOf(toolCall(1, "read_file"), callNotification("delete_file"), notification("notifications/initialized"),
		toolCall(2, "delete_file")))
	toClient, toServer := sh.frames(2)
	if ids := idsOf(t, toClient[0]); len(ids) != 1 || ids[0] != "2" {
		t.Fatalf("answers %s: only the member with an id is answered", toClient[0])
	}
	if got := toolsOf(t, toServer[0]); strings.Join(got, ",") != "tools/call:read_file,notifications/initialized:" {
		t.Fatalf("the server got %s", toServer[0])
	}
	// The tool of a call with no id is not one the shared reader names (derive/mcp reads requests), so the relay refuses it
	// by its own rule, as it refuses any call it cannot name.
	want := "allow read_file mcp[files]; refused  mcp[files].relay; refused delete_file mcp[files].tools.deny[delete_file]"
	if got := strings.Join(linesOf(t, sk), "; "); got != want {
		t.Fatalf("record lines: %s", got)
	}
}

func TestBatchOfOnlyRefusedNotificationsSendsNothingAndIsRecorded(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(callNotification("delete_file")))
	sh.nextIsServerPing(9) // nothing was sent for the batch: the first frame is for the line after it
	if got := strings.Join(linesOf(t, sk), "; "); got != "refused  mcp[files].relay" {
		t.Fatalf("record lines: %s", got)
	}
}

func TestBatchOverTheBoundIsRefusedWholeAndRecordedOnce(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	var ms []string
	for i := range MaxBatch + 1 {
		ms = append(ms, toolCall(i+1, "delete_file"))
	}
	sh.client(batchOf(ms...))
	f := sh.read()
	if f.ToServer != nil {
		t.Fatalf("an oversized batch reached the server: %s", f.ToServer)
	}
	id, _, _, msg, code := answered(t, f.ToClient)
	if id != "null" || code != -32600 || !strings.Contains(msg, strconv.Itoa(MaxBatch)) {
		t.Fatalf("answer %s", f.ToClient)
	}
	sh.nextIsServerPing(900)
	if n := len(sk.of(record.KindMCP)); n != 1 {
		t.Fatalf("record lines %d: one line for the refused batch, not one for each of its members", n)
	}
	// A batch of exactly the bound is read, and each of its members is decided.
	ms = ms[:MaxBatch]
	for i := range ms {
		ms[i] = ping(1000 + i)
	}
	sh.client(batchOf(ms...))
	if _, toServer := sh.frames(1); len(members(t, toServer[0])) != MaxBatch {
		t.Fatal("a batch of the bound was not passed whole")
	}
}

func TestBatchWithAMemberThatIsNotAMessageIsRefusedWhole(t *testing.T) {
	s, sk, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "read_file"), `7`, toolCall(2, "delete_file")))
	f := sh.read()
	if f.ToServer != nil || !strings.Contains(string(f.ToClient), "-32700") {
		t.Fatalf("frame %+v", f)
	}
	if n := len(sk.of(record.KindMCP)); n != 1 {
		t.Fatalf("record lines %d", n)
	}
}

func TestBatchMemberWithNoReadableToolIsRefusedAlone(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "read_file"),
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{}}}`))
	toClient, toServer := sh.frames(2)
	if id, rule, _, _, _ := answered(t, members(t, toClient[0])[0]); id != "2" || rule != "mcp[files].relay" {
		t.Fatalf("answer %s", toClient[0])
	}
	if got := idsOf(t, toServer[0]); strings.Join(got, ",") != "1" {
		t.Fatalf("the server got %s", toServer[0])
	}
}

// TestBatchSwitchLandingWhileAMemberIsHeldAppliesToTheNextCall: a Deny put in force while one member waits for a person
// stops that member (it is decided again), and the batch's other members were already decided and went on.
func TestBatchSwitchLandingWhileAMemberIsHeldAppliesToTheHeldMember(t *testing.T) {
	s, sk, dir := start(t, nil, filesServer())
	s.ConfigureMCPAsk(denyDuringHold(t, dir, "files", "write_file"))
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(batchOf(toolCall(1, "write_file"), toolCall(2, "read_file")))
	toClient, toServer := sh.frames(2)
	if got := toolsOf(t, toServer[0]); strings.Join(got, ",") != "tools/call:read_file" {
		t.Fatalf("the server got %s", toServer[0])
	}
	if id, rule, _, _, _ := answered(t, members(t, toClient[0])[0]); id != "1" || rule != "mcp[files].live[write_file]" {
		t.Fatalf("answer %s", toClient[0])
	}
	if got := len(sk.of(record.KindMCP)); got != 2 {
		t.Fatalf("record lines %d", got)
	}
}

// ---- over HTTP

// recorder is an upstream MCP server that answers each message with a result of its own and keeps what it was sent.
type recorder struct {
	mu     sync.Mutex
	bodies []string
	// answer, when set, is the whole response (content type and body) for a request body.
	answer func(body string) (contentType string, status int, out string)
}

func (r *recorder) handler(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.bodies = append(r.bodies, string(b))
	r.mu.Unlock()
	ct, status, out := "application/json", 200, ""
	if r.answer != nil {
		ct, status, out = r.answer(string(b))
	} else {
		var ids []string
		for _, m := range membersOf(b) {
			var e struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(m, &e)
			if len(e.ID) > 0 {
				ids = append(ids, `{"jsonrpc":"2.0","id":`+string(e.ID)+`,"result":{"content":[]}}`)
			}
		}
		if len(ids) == 1 && !strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
			out = ids[0]
		} else {
			out = "[" + strings.Join(ids, ",") + "]"
		}
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, out)
}

func membersOf(b []byte) []json.RawMessage {
	t := strings.TrimSpace(string(b))
	if strings.HasPrefix(t, "[") {
		var arr []json.RawMessage
		_ = json.Unmarshal([]byte(t), &arr)
		return arr
	}
	return []json.RawMessage{json.RawMessage(t)}
}

func (r *recorder) sent() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

// httpRelayFor is a started service of an Adjustable run with one http server, its peer admission and holder stubbed.
func httpRelayFor(t *testing.T, rec *recorder, rules mcptool.Rules) (*Service, *sink, string, string) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(rec.handler))
	t.Cleanup(up.Close)
	s, sk, dir := start(t, nil, Server{Name: "web", URL: up.URL + "/mcp", Rules: rules})
	s.https[0].admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	s.https[0].holderPID = os.Getpid
	return s, sk, dir, s.httpURLs()["web"]
}

func postJSON(t *testing.T, url, body string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func webRules() mcptool.Rules {
	return mcptool.Rules{Deny: []string{"delete_file"}, Ask: []string{"write_file"}}
}

func TestHTTPBatchMembersAreDecidedOnTheirOwn(t *testing.T) {
	rec := &recorder{}
	_, sk, _, relay := httpRelayFor(t, rec, webRules())
	code, body, _ := postJSON(t, relay, batchOf(toolCall(1, "read_file"), toolCall(2, "delete_file"), ping(3)))
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	// The server was sent the members that passed, and the client gets the server's answers and the refusal in one array.
	sent := rec.sent()
	if len(sent) != 1 || strings.Contains(sent[0], "delete_file") || strings.Join(idsOf(t, []byte(sent[0])), ",") != "1,3" {
		t.Fatalf("the server was sent %q", sent)
	}
	got := map[string]string{}
	for _, m := range members(t, []byte(body)) {
		var e struct {
			ID    json.RawMessage `json:"id"`
			Error *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(m, &e)
		if e.Error != nil {
			got[string(e.ID)] = "error " + strconv.Itoa(e.Error.Code)
		} else {
			got[string(e.ID)] = "result"
		}
	}
	if got["1"] != "result" || got["3"] != "result" || got["2"] != "error -32001" || len(got) != 3 {
		t.Fatalf("the client got %s", body)
	}
	if want := "allow read_file mcp[web]; refused delete_file mcp[web].tools.deny[delete_file]"; strings.Join(linesOf(t, sk), "; ") != want {
		t.Fatalf("record lines: %v", linesOf(t, sk))
	}
}

func TestHTTPBatchOfOnlyRefusedMembersNeverReachesTheServer(t *testing.T) {
	rec := &recorder{}
	_, sk, _, relay := httpRelayFor(t, rec, webRules())
	code, body, _ := postJSON(t, relay, batchOf(toolCall(1, "delete_file"), toolCall(2, "delete_file")))
	if code != 200 || len(members(t, []byte(body))) != 2 || len(rec.sent()) != 0 {
		t.Fatalf("status %d, body %s, the server was sent %q", code, body, rec.sent())
	}
	// A batch of refused notifications has no answer to give: 202, nothing sent, both recorded.
	code, body, _ = postJSON(t, relay, batchOf(callNotification("delete_file"), callNotification("delete_file")))
	if code != http.StatusAccepted || strings.TrimSpace(body) != "" || len(rec.sent()) != 0 {
		t.Fatalf("status %d, body %q, the server was sent %q", code, body, rec.sent())
	}
	if n := len(sk.of(record.KindMCP)); n != 4 {
		t.Fatalf("record lines %d, want one for each refused member", n)
	}
}

func TestHTTPBatchRepeatedIDsNotificationsAndTheBound(t *testing.T) {
	rec := &recorder{}
	_, sk, _, relay := httpRelayFor(t, rec, webRules())
	code, body, _ := postJSON(t, relay, batchOf(toolCall(1, "read_file"), toolCall(1, "delete_file"), callNotification("delete_file"),
		toolCall(2, "read_file")))
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if sent := rec.sent(); len(sent) != 1 || strings.Join(idsOf(t, []byte(sent[0])), ",") != "2" {
		t.Fatalf("the server was sent %q, want id 2 only", sent)
	}
	var errs int
	for _, m := range members(t, []byte(body)) {
		if id, _, _, _, code := answered(t, m); code == mcptool.RefusalCode {
			errs++
			if id != "1" {
				t.Fatalf("an error for id %s: %s", id, body)
			}
		}
	}
	if errs != 2 {
		t.Fatalf("the client got %d errors, want one for each member that has id 1 (the notification has none): %s", errs, body)
	}
	if n := len(sk.of(record.KindMCP)); n != 4 {
		t.Fatalf("record lines %d, want 4", n)
	}
	var ms []string
	for i := range MaxBatch + 1 {
		ms = append(ms, ping(i+1))
	}
	before := len(rec.sent())
	code, body, _ = postJSON(t, relay, batchOf(ms...))
	if id, _, _, _, ec := answered(t, []byte(body)); code != 200 || ec != -32600 || id != "null" || len(rec.sent()) != before {
		t.Fatalf("status %d, body %s, the server got %d more", code, body, len(rec.sent())-before)
	}
}

func TestHTTPBatchAskedMembersAreAskedTogether(t *testing.T) {
	for _, approve := range []bool{true, false} {
		t.Run("approve="+strconv.FormatBool(approve), func(t *testing.T) {
			rec := &recorder{}
			s, sk, _, relay := httpRelayFor(t, rec, webRules())
			var mu sync.Mutex
			var asked []string
			s.ConfigureMCPAsk(func(_ context.Context, r ask.Request) (ask.Decision, error) {
				mu.Lock()
				asked = append(asked, r.Target)
				mu.Unlock()
				if approve {
					return ask.Decision{Approved: true}, nil
				}
				return ask.Decision{Reason: ask.ReasonDenied}, nil
			})
			code, body, _ := postJSON(t, relay, batchOf(toolCall(1, "write_file"), toolCall(2, "read_file"), toolCall(3, "write_file")))
			if code != 200 {
				t.Fatalf("status %d: %s", code, body)
			}
			mu.Lock()
			n := len(asked)
			mu.Unlock()
			if n != 2 {
				t.Fatalf("asked %d times, want once for each asked member", n)
			}
			wantSent := "2"
			if approve {
				wantSent = "1,2,3"
			}
			if sent := rec.sent(); len(sent) != 1 || strings.Join(idsOf(t, []byte(sent[0])), ",") != wantSent {
				t.Fatalf("the server was sent %q, want ids %s", sent, wantSent)
			}
			if got := len(sk.of(record.KindMCP)); got != 3 {
				t.Fatalf("record lines %d", got)
			}
			errs := 0
			for _, m := range members(t, []byte(body)) {
				if _, _, reason, _, c := answered(t, m); c == mcptool.RefusalCode && reason == "ask-denied" {
					errs++
				}
			}
			if want := map[bool]int{true: 0, false: 2}[approve]; errs != want {
				t.Fatalf("%d refusals in %s, want %d", errs, body, want)
			}
		})
	}
}

func TestHTTPBatchAnswerAsAnEventStreamCarriesTheRefusals(t *testing.T) {
	rec := &recorder{answer: func(body string) (string, int, string) {
		return "text/event-stream", 200, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	}}
	_, _, _, relay := httpRelayFor(t, rec, webRules())
	code, body, header := postJSON(t, relay, batchOf(toolCall(1, "read_file"), toolCall(2, "delete_file")))
	if code != 200 || !strings.HasPrefix(header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status %d, type %q: %s", code, header.Get("Content-Type"), body)
	}
	if !strings.Contains(body, `"id":2`) || !strings.Contains(body, "-32001") || !strings.Contains(body, `"id":1,"result"`) {
		t.Fatalf("the stream: %s", body)
	}
}

func TestHTTPBatchWithOnlyNotificationsPassedStillAnswersTheRefusals(t *testing.T) {
	rec := &recorder{answer: func(string) (string, int, string) { return "", http.StatusAccepted, "" }}
	_, _, _, relay := httpRelayFor(t, rec, webRules())
	code, body, header := postJSON(t, relay, batchOf(notification("notifications/initialized"), toolCall(2, "delete_file")))
	if code != 200 || !strings.HasPrefix(header.Get("Content-Type"), "application/json") || !strings.Contains(body, "-32001") {
		t.Fatalf("status %d, type %q, body %s: the refusal had nowhere to go", code, header.Get("Content-Type"), body)
	}
}

func TestHTTPBatchAnswerThatIsNotJSONIsNotPassedOn(t *testing.T) {
	rec := &recorder{answer: func(string) (string, int, string) { return "application/json", 200, "not json" }}
	_, sk, _, relay := httpRelayFor(t, rec, webRules())
	code, body, _ := postJSON(t, relay, batchOf(toolCall(1, "read_file"), toolCall(2, "delete_file")))
	if code != http.StatusBadGateway || strings.Contains(body, "not json") {
		t.Fatalf("status %d: %s", code, body)
	}
	// The refusal is on the record whether or not the answer could be given; so is the answer that was not passed on.
	if n := len(sk.of(record.KindMCP)); n != 3 {
		t.Fatalf("record lines %d, want 3", n)
	}
}

// TestHTTPBatchMidBatchSwitch: a switch that lands while members are asked applies to the held member, as for a call.
func TestHTTPBatchMidBatchSwitch(t *testing.T) {
	rec := &recorder{}
	s, _, dir, relay := httpRelayFor(t, rec, webRules())
	s.ConfigureMCPAsk(func(ctx context.Context, _ ask.Request) (ask.Decision, error) {
		if _, err := mcptools.Update(ctx, dir, "r-test", func(o *mcptools.Overlay) (bool, error) {
			return o.Set("web", "write_file", mcptools.Deny, "uid:1 pid:2 cli", time.Now())
		}); err != nil {
			t.Error(err)
		}
		return ask.Decision{Approved: true}, nil
	})
	_, body, _ := postJSON(t, relay, batchOf(toolCall(1, "write_file"), toolCall(2, "read_file")))
	if sent := rec.sent(); len(sent) != 1 || strings.Join(idsOf(t, []byte(sent[0])), ",") != "2" {
		t.Fatalf("the server was sent %q", sent)
	}
	if !strings.Contains(body, "mcp[web].live[write_file]") {
		t.Fatalf("the held member's answer: %s", body)
	}
}

// TestHTTPBatchAnswerThatIsAnErrorPassesAsItCame: a server's own failure of the whole POST (a 401, a 500) carries nothing
// the batch held, so the refusals are not added to it.
func TestHTTPBatchAnswerThatIsAnErrorPassesAsItCame(t *testing.T) {
	rec := &recorder{answer: func(string) (string, int, string) {
		return "application/json", http.StatusUnauthorized, `{"error":"unauthorized"}`
	}}
	_, sk, _, relay := httpRelayFor(t, rec, webRules())
	code, body, _ := postJSON(t, relay, batchOf(toolCall(1, "read_file"), toolCall(2, "delete_file")))
	if code != http.StatusUnauthorized || body != `{"error":"unauthorized"}` {
		t.Fatalf("status %d: %s", code, body)
	}
	if n := len(sk.of(record.KindMCP)); n != 2 {
		t.Fatalf("record lines %d: the refusal is recorded though its answer had nowhere to go", n)
	}
}

// TestHTTPBatchOfAMillionMembersIsRefusedAtTheBound: the members are counted as they are read, and the answer is the bound's,
// not an unreadable body's, whatever the members are.
func TestHTTPBatchOfAMillionMembersIsRefusedAtTheBound(t *testing.T) {
	rec := &recorder{}
	_, _, _, relay := httpRelayFor(t, rec, webRules())
	body := "[" + strings.Repeat("1,", 1<<20) + "1]"
	code, out, _ := postJSON(t, relay, body)
	if _, _, _, _, ec := answered(t, []byte(out)); code != 200 || ec != -32600 || len(rec.sent()) != 0 {
		t.Fatalf("status %d: %s", code, out)
	}
}
