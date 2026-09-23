// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testTS = time.Date(2026, 9, 22, 10, 4, 5, 123456789, time.UTC)

const (
	testRun   = "r-3f9c2a1b-0kq4v1l2m3n4p-a1b2c3"
	testAgent = "retriever"
)

// base returns a valid non-action event of kind k with the given payload object.
func base(k Kind, payload string) *Event {
	e := &Event{
		V: Version, TS: testTS, MonoNS: 1_000_000_000, Run: testRun, Agent: testAgent,
		PID: 4242, TID: 4243, Cgroup: 12345, Kind: k, Source: SourceSupervisor,
	}
	if payload != "" {
		e.Payload = json.RawMessage(payload)
	}
	return e
}

// action returns a valid action event of kind k.
func action(k Kind, payload string) *Event {
	e := base(k, payload)
	e.Source = SourceLandlock
	e.Rule = "fs.write[0]"
	e.Verdict = VerdictAllow
	e.Authority = AuthorityRule
	e.Attr = AttributedByTime("t1", 3)
	return e
}

// perKind returns one valid event per v1 kind, with a payload built from the kind's payload struct.
func perKind(t *testing.T) map[Kind]*Event {
	t.Helper()
	set := func(e *Event, v any) *Event {
		if err := e.SetPayload(v); err != nil {
			t.Fatalf("SetPayload(%T): %v", v, err)
		}
		return e
	}
	return map[Kind]*Event{
		KindRunStart: set(base(KindRunStart, ""), RunStartPayload{
			LauncherPID: 4242, LauncherStartNS: 77, TegoVersion: "0.1.0", Commit: "abc1234", Tier: "landlock",
			Capture: "forwarder", Kernel: "6.17.0", ContractHash: strings.Repeat("ab", 32),
			Parsers: map[string]string{"anthropic": "1"}, StopGrace: "10s", Command: []string{"python3", "agent.py"},
			Cwd: "/home/u/proj", Limits: &Limits{Tokens: ptr[int64](200000), CostUSD: ptr(5.0)},
		}),
		KindRunEnd: set(base(KindRunEnd, ""), RunEndPayload{Reason: RunEndExit, ExitCode: 0,
			Supervisor: Supervisor{Notifications: 12, HeldMS: 3}}),
		KindExec: set(action(KindExec, ""), ExecPayload{Path: "/usr/bin/rg", Argv: []string{"rg", "-n", "x"},
			ExecID: testRun + "/4242/77"}),
		KindFS:  set(action(KindFS, ""), FSPayload{Op: FSOpen, Path: "/home/u/proj/out/a.txt", Flags: 0x241}),
		KindNet: set(action(KindNet, ""), NetPayload{Proto: "tcp", Dst: "127.0.0.1:41337", Host: "api.anthropic.com"}),
		KindMCP: set(action(KindMCP, ""), MCPPayload{Name: "fs", Transport: "stdio", Tool: "read_file"}),
		KindSSLRequest: set(base(KindSSLRequest, ""), SSLRequestPayload{Endpoint: "anthropic", Method: "POST",
			Path: "/v1/messages", Host: "api.anthropic.com", Size: 1024, TraceID: strings.Repeat("0a", 16)}),
		KindSSLResponse: set(base(KindSSLResponse, ""), SSLResponsePayload{RequestSeq: new(uint64(3)), Status: 200,
			Model: "claude-sonnet-4-5", Usage: &Usage{Input: 10, Output: 20}, LatencyMS: 900, ParserVersion: "anthropic/1"}),
		KindDecision: set(base(KindDecision, ""), DecisionPayload{Step: 1, ToolUseID: "toolu_01", Tool: "bash",
			InputHash: strings.Repeat("cd", 32)}),
		KindAsk:    set(base(KindAsk, ""), AskPayload{AskID: "ask-1", Hold: "exec"}),
		KindAnswer: set(base(KindAnswer, ""), AnswerPayload{AskID: "ask-1", By: "human", AfterS: 2.5}),
		// reason and rule are lifted from the payload into the shared common slots.
		KindRefused: set(base(KindRefused, ""), RefusedPayload{Op: "open", Target: "/etc/shadow",
			Reason: ReasonReadDenied, Rule: "fs.deny_read[0]"}),
		KindGap:      set(base(KindGap, ""), GapPayload{What: GapCapture, Why: "no-openssl", Binary: "/usr/bin/gh"}),
		KindBoundary: set(base(KindBoundary, ""), BoundaryPayload{ContextBytes: 10, DockerfileSHA256: "x", Tags: []string{"a"}}),
		KindLimit: func() *Event {
			e := set(base(KindLimit, ""), LimitPayload{Which: LimitTokens, Value: 200001, Ceiling: 200000})
			e.Reason = ReasonLimitTokens
			return e
		}(),
	}
}

func mustLine(t *testing.T, e *Event) []byte {
	t.Helper()
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatalf("MarshalLine: %v", err)
	}
	return line
}

func TestMarshalLineCanonicalOrder(t *testing.T) {
	e := action(KindFS, `{"path":"/x","op":"open","flags":577}`)
	e.Reason = ReasonWriteOutsideContract
	line := mustLine(t, e)
	want := `{"v":1,"seq":0,"id":"` + e.ID + `","prev":"","ts":"2026-09-22T10:04:05.123456789Z","mono_ns":1000000000,` +
		`"run":"` + testRun + `","agent":"retriever","pid":4242,"tid":4243,"cgroup":12345,"kind":"fs","source":"landlock",` +
		`"rule":"fs.write[0]","verdict":"allow","authority":"rule","reason":"write-outside-contract",` +
		`"attribution":{"thread":"t1","step":3,"confidence":"likely","method":"time"},"flags":577,"op":"open","path":"/x"}`
	if string(line) != want {
		t.Fatalf("canonical line mismatch\n got %s\nwant %s", line, want)
	}
	if !IsID(e.ID) {
		t.Fatalf("id %q is not 64 hex", e.ID)
	}
}

func TestMarshalLineOmitsZeroOptionalFields(t *testing.T) {
	line := mustLine(t, base(KindGap, `{"what":"record","why":"ring-buffer","count":3}`))
	for _, k := range []string{`"rule"`, `"verdict"`, `"authority"`, `"reason"`, `"attribution"`} {
		if bytes.Contains(line, []byte(k)) {
			t.Errorf("zero-value %s must be dropped: %s", k, line)
		}
	}
	for _, k := range []string{`"pid":4242`, `"tid":4243`, `"cgroup":12345`} {
		if !bytes.Contains(line, []byte(k)) {
			t.Errorf("always-present %s missing: %s", k, line)
		}
	}
}

// Also pins record-ledger.md R3, E25: a payload is spliced sorted after attribution; a payload field named
// like a common field is ErrPayloadFieldCollision.
func TestMarshalLinePayloadRules(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr error
		want    string // payload part of the line, after "source":"supervisor",
	}{
		{"sorted and compacted", `{ "z" : 1 , "a" : { "y": [1, 2] } }`, nil, `,"a":{"y":[1,2]},"z":1}`},
		{"empty object", `{}`, nil, `}`},
		{"whitespace only", `   `, nil, `}`},
		{"collision seq", `{"seq":9}`, ErrPayloadFieldCollision, ""},
		{"collision id", `{"id":"x"}`, ErrPayloadFieldCollision, ""},
		{"collision attribution", `{"attribution":{}}`, ErrPayloadFieldCollision, ""},
		{"shared reason wrong type", `{"reason":1}`, ErrInvalidEvent, ""},
		{"shared reason on gap", `{"reason":"oom","what":"record","why":"x"}`, ErrInvalidEvent, ""},
		{"duplicate key", `{"a":1,"a":2}`, ErrInvalidEvent, ""},
		{"array payload", `[1]`, ErrInvalidEvent, ""},
		{"trailing data", `{"a":1} x`, ErrInvalidEvent, ""},
		{"invalid utf8 in value", "{\"p\":\"a\xffb\"}", nil, `,"p":"a` + "�" + `b"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := base(KindGap, tc.payload)
			line, err := e.MarshalLine()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				if line != nil || e.ID != "" {
					t.Fatalf("on error no bytes and no id: %q %q", line, e.ID)
				}
				return
			}
			if !bytes.HasSuffix(line, []byte(`"source":"supervisor"`+tc.want)) {
				t.Fatalf("payload tail = %s, want suffix %s", line, tc.want)
			}
		})
	}
}

func TestSharedFields(t *testing.T) {
	// run_end: reason lives in the payload struct and is written once, in the common slot.
	e := base(KindRunEnd, `{"reason":"limit","supervisor":{"notifications":1,"held_ms":0}}`)
	line := mustLine(t, e)
	if e.Reason != "limit" || bytes.Count(line, []byte(`"reason"`)) != 1 {
		t.Fatalf("reason not lifted once: %s", line)
	}
	if !bytes.Contains(line, []byte(`"source":"supervisor","reason":"limit","supervisor":`)) {
		t.Fatalf("reason must sit in its canonical slot: %s", line)
	}
	got, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	var p RunEndPayload
	if err := got.DecodePayload(&p); err != nil || p.Reason != "limit" || got.Reason != "limit" {
		t.Fatalf("mirrored reason: payload %+v event %q err %v", p, got.Reason, err)
	}
	// refused: rule and reason from the payload; a conflicting value on the event is a collision.
	r := base(KindRefused, `{"op":"open","reason":"read-denied","rule":"fs.deny_read[0]","target":"/etc/shadow"}`)
	line = mustLine(t, r)
	if r.Rule != "fs.deny_read[0]" || r.Reason != ReasonReadDenied {
		t.Fatalf("lifted rule %q reason %q", r.Rule, r.Reason)
	}
	if !bytes.Contains(line, []byte(`"source":"supervisor","rule":"fs.deny_read[0]","reason":"read-denied","op":"open","target":"/etc/shadow"}`)) {
		t.Fatalf("refused line: %s", line)
	}
	r = base(KindRefused, `{"op":"open","reason":"read-denied","rule":"fs.deny_read[0]","target":"/etc/shadow"}`)
	r.Rule = "other"
	if _, err := r.MarshalLine(); !errors.Is(err, ErrPayloadFieldCollision) {
		t.Fatalf("conflicting rule: %v", err)
	}
	r.Rule = "fs.deny_read[0]"
	if _, err := r.MarshalLine(); err != nil {
		t.Fatalf("equal rule on both is fine: %v", err)
	}
}

func TestMarshalLineSanitizesStrings(t *testing.T) {
	e := action(KindExec, "")
	e.Rule = "bad\xffrule\"q\\\n <&>"
	line := mustLine(t, e)
	if !json.Valid(line) {
		t.Fatalf("line is not valid JSON: %s", line)
	}
	got, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	if want := "bad�rule\"q\\\n <&>"; got.Rule != want {
		t.Fatalf("rule = %q, want %q", got.Rule, want)
	}
	if !bytes.Contains(line, []byte(`\u202`+`8<&>"`)) {
		t.Fatalf("U+2028 escaped as six characters, HTML not escaped: %s", line)
	}
}

func TestMarshalLinePatchEqualsReserialize(t *testing.T) {
	// R2 says "serialize one more time"; MarshalLine patches the id in place. Prove the two are identical.
	for k, e := range perKind(t) {
		line := mustLine(t, e)
		fields, _, err := payloadFields(e.Payload)
		if err != nil {
			t.Fatal(err)
		}
		again, off := e.canonical(fields)
		copy(again[off:off+IDLen], e.ID)
		if !bytes.Equal(line, again) {
			t.Errorf("%s: patched line differs from a second serialization", k)
		}
		if _, err := VerifyLine(line); err != nil {
			t.Errorf("%s: VerifyLine: %v", k, err)
		}
	}
}

func TestRoundTripPerKind(t *testing.T) {
	for k, e := range perKind(t) {
		t.Run(string(k), func(t *testing.T) {
			line := mustLine(t, e)
			got, err := Decode(line)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("Validate(decoded): %v", err)
			}
			if got.ID != e.ID || got.Seq != e.Seq || got.Kind != e.Kind || !got.TS.Equal(e.TS) ||
				got.MonoNS != e.MonoNS || got.Run != e.Run || got.Agent != e.Agent || got.PID != e.PID ||
				got.TID != e.TID || got.Cgroup != e.Cgroup || got.Source != e.Source || got.Rule != e.Rule ||
				got.Verdict != e.Verdict || got.Authority != e.Authority || got.Reason != e.Reason {
				t.Fatalf("common fields differ:\n got %+v\nwant %+v", got, e)
			}
			if (got.Attr == nil) != (e.Attr == nil) || (got.Attr != nil && *got.Attr != *e.Attr) {
				t.Fatalf("attribution differs: %+v vs %+v", got.Attr, e.Attr)
			}
			// I9: re-encoding the decoded event reproduces the stored bytes exactly.
			again := mustLine(t, got)
			if !bytes.Equal(again, line) {
				t.Fatalf("re-encode differs\n got %s\nwant %s", again, line)
			}
		})
	}
}

func TestDecodeToleratesUnknownFields(t *testing.T) {
	line := mustLine(t, base(KindGap, `{"what":"record","why":"x"}`))
	// A newer v1 writer added an optional common field; this reader keeps it as payload and reproduces the line.
	withNew := bytes.Replace(line, []byte(`,"what":`), []byte(`,"host":"h1","what":`), 1)
	got, err := Decode(withNew)
	if err != nil {
		t.Fatalf("Decode with unknown key: %v", err)
	}
	var p struct {
		What string `json:"what"`
		Host string `json:"host"`
	}
	if err := got.DecodePayload(&p); err != nil || p.What != "record" || p.Host != "h1" {
		t.Fatalf("payload = %+v, %v", p, err)
	}
	if string(got.Payload) != `{"host":"h1","what":"record","why":"x"}` {
		t.Fatalf("payload bytes = %s", got.Payload)
	}
}

func TestDecodeErrors(t *testing.T) {
	good := string(mustLine(t, base(KindGap, `{"what":"record","why":"x"}`)))
	tests := []struct {
		name string
		line string
		want error
	}{
		{"version 2", strings.Replace(good, `{"v":1,`, `{"v":2,`, 1), ErrUnsupportedVersion},
		{"version string", strings.Replace(good, `{"v":1,`, `{"v":"1",`, 1), ErrUnsupportedVersion},
		{"missing v", strings.Replace(good, `{"v":1,`, `{`, 1), ErrUnsupportedVersion},
		{"missing run", strings.Replace(good, `"run":"`+testRun+`",`, ``, 1), ErrMalformedLine},
		{"wrong type", strings.Replace(good, `"pid":4242`, `"pid":"4242"`, 1), ErrMalformedLine},
		{"torn", good[:len(good)/2], ErrMalformedLine},
		{"empty", "", ErrMalformedLine},
		{"array", "[]", ErrMalformedLine},
		{"trailing", good + "{}", ErrMalformedLine},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(tc.line))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := Decode([]byte(good + "\n")); err != nil {
		t.Fatalf("a terminated line must decode: %v", err)
	}
}

func TestVerifyLineTamper(t *testing.T) {
	line := mustLine(t, base(KindGap, `{"what":"record","why":"x"}`))
	if id, err := VerifyLine(append(line, '\n')); err != nil || !IsID(id) {
		t.Fatalf("VerifyLine(good) = %q, %v", id, err)
	}
	tampered := bytes.Replace(line, []byte(`"why":"x"`), []byte(`"why":"y"`), 1)
	if _, err := VerifyLine(tampered); !errors.Is(err, ErrIDMismatch) {
		t.Fatalf("one-byte tamper: err = %v, want ErrIDMismatch", err)
	}
	if _, err := VerifyLine([]byte(`{"seq":0,"v":1}`)); !errors.Is(err, ErrMalformedLine) {
		t.Fatalf("non-canonical: err = %v", err)
	}
	if _, err := VerifyLine(line[:40]); !errors.Is(err, ErrMalformedLine) {
		t.Fatalf("truncated id: err = %v", err)
	}
	if _, err := VerifyLine([]byte(`{"v":1,"seq":x,"id":"`)); !errors.Is(err, ErrMalformedLine) {
		t.Fatalf("no seq digits: err = %v", err)
	}
}

func TestChain(t *testing.T) {
	var lines [][]byte
	prev := ""
	for i := 0; i < 3; i++ {
		e := base(KindGap, `{"what":"record","why":"x"}`)
		e.Seq, e.Prev = uint64(i), prev
		line := mustLine(t, e)
		lines = append(lines, line)
		prev = e.ID
	}
	var c Chain
	for _, l := range lines {
		if _, err := c.Add(l); err != nil {
			t.Fatal(err)
		}
	}
	if c.Len() != 3 || c.Head() != prev {
		t.Fatalf("Len %d Head %q", c.Len(), c.Head())
	}
	// A gap in seq and a wrong prev are both ErrCorruptChain; a tampered byte is ErrIDMismatch.
	e := base(KindGap, `{"what":"record","why":"x"}`)
	e.Seq, e.Prev = 4, prev
	if _, err := c.Add(mustLine(t, e)); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("seq gap: %v", err)
	}
	e.Seq, e.Prev = 3, strings.Repeat("ef", 32)
	if _, err := c.Add(mustLine(t, e)); !errors.Is(err, ErrCorruptChain) {
		t.Fatalf("wrong prev: %v", err)
	}
	e.Seq, e.Prev = 3, prev
	line := mustLine(t, e)
	line[len(line)-2] ^= 1
	if _, err := c.Add(line); !errors.Is(err, ErrIDMismatch) {
		t.Fatalf("tamper: %v", err)
	}
	if c.Len() != 3 {
		t.Fatalf("a failed Add must not advance the chain: %d", c.Len())
	}
}

// TestValidateRules also pins record-ledger.md R8, the presence half: attribution is required of an action
// event and refused on any other kind.
func TestValidateRules(t *testing.T) {
	tests := []struct {
		name string
		mut  func(e *Event)
		ok   bool
	}{
		{"valid action", func(e *Event) {}, true},
		{"bad version", func(e *Event) { e.V = 2 }, false},
		{"unknown kind", func(e *Event) { e.Kind = "weird" }, false},
		{"unknown source", func(e *Event) { e.Source = "cloud" }, false},
		{"empty run", func(e *Event) { e.Run = "" }, false},
		{"bad agent", func(e *Event) { e.Agent = "Bad_Agent" }, false},
		{"zero ts", func(e *Event) { e.TS = time.Time{} }, false},
		{"seq0 with prev", func(e *Event) { e.Prev = strings.Repeat("a", 64) }, false},
		{"seq1 without prev", func(e *Event) { e.Seq = 1 }, false},
		{"seq1 with prev", func(e *Event) { e.Seq = 1; e.Prev = strings.Repeat("a", 64) }, true},
		{"action without rule", func(e *Event) { e.Rule = "" }, false},
		{"action bad verdict", func(e *Event) { e.Verdict = "maybe" }, false},
		{"action bad authority", func(e *Event) { e.Authority = "" }, false},
		{"action without attribution", func(e *Event) { e.Attr = nil }, false},
		{"action bad confidence", func(e *Event) { e.Attr = &Attribution{Confidence: "sure", Method: MethodNone} }, false},
		{"action unattributed", func(e *Event) { e.Attr = Unattributed() }, true},
		{"action with reason", func(e *Event) { e.Verdict = VerdictRefused; e.Reason = ReasonWriteOutsideContract }, true},
		{"action bad reason", func(e *Event) { e.Reason = "because" }, false},
		{"non-action with rule", func(e *Event) { *e = *base(KindGap, ""); e.Rule = "x" }, false},
		{"non-action with attribution", func(e *Event) { *e = *base(KindGap, ""); e.Attr = Unattributed() }, false},
		{"gap with reason", func(e *Event) { *e = *base(KindGap, ""); e.Reason = ReasonOOM }, false},
		{"refused with rule and reason", func(e *Event) { *e = *base(KindRefused, ""); e.Rule = "r"; e.Reason = ReasonOOM }, true},
		{"refused without rule", func(e *Event) { *e = *base(KindRefused, ""); e.Reason = ReasonOOM }, false},
		{"refused without reason", func(e *Event) { *e = *base(KindRefused, ""); e.Rule = "r" }, false},
		{"limit with reason", func(e *Event) { *e = *base(KindLimit, ""); e.Reason = ReasonLimitCost }, true},
		{"limit without reason", func(e *Event) { *e = *base(KindLimit, "") }, true},
		{"limit bad reason", func(e *Event) { *e = *base(KindLimit, ""); e.Reason = ReasonOOM }, false},
		{"run_end reason exit", func(e *Event) { *e = *base(KindRunEnd, ""); e.Reason = "exit" }, true},
		{"run_end without reason", func(e *Event) { *e = *base(KindRunEnd, "") }, false},
		{"run_end refusal code", func(e *Event) { *e = *base(KindRunEnd, ""); e.Reason = ReasonReadDenied }, false},
		{"bad id shape", func(e *Event) { e.ID = "abc" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := action(KindFS, "")
			tc.mut(e)
			err := e.Validate()
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("err = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

func TestSetPayloadRejectsNonObject(t *testing.T) {
	e := base(KindGap, "")
	if err := e.SetPayload([]int{1}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("err = %v", err)
	}
	if err := e.SetPayload(make(chan int)); err == nil {
		t.Fatal("unmarshalable value must error")
	}
	var p GapPayload
	if err := base(KindGap, "").DecodePayload(&p); err != nil {
		t.Fatalf("empty payload decodes to zero value: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	for _, e := range map[Kind]*Event{KindGap: base(KindGap, `{"what":"record","why":"x"}`)} {
		line, _ := e.MarshalLine()
		f.Add(line)
	}
	f.Add([]byte(`{"v":1`))
	f.Add([]byte(`{"v":1,"seq":0,"id":"x"}`))
	f.Add([]byte("\xff\xfe"))
	f.Fuzz(func(t *testing.T, line []byte) {
		e, err := Decode(line)
		if err != nil {
			if e != nil {
				t.Fatal("error with non-nil event")
			}
			return
		}
		// Whatever decodes must re-encode when valid, and re-decode to the same bytes.
		if err := e.Validate(); err != nil {
			return
		}
		again, err := e.MarshalLine()
		if err != nil {
			t.Fatalf("MarshalLine after Decode: %v", err)
		}
		if _, err := Decode(again); err != nil {
			t.Fatalf("Decode(MarshalLine): %v", err)
		}
		_, _ = VerifyLine(line)
	})
}

func BenchmarkMarshalLine(b *testing.B) {
	e := action(KindFS, `{"op":"open","path":"/home/u/proj/out/report.md","flags":577}`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := e.MarshalLine(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	e := action(KindFS, `{"op":"open","path":"/home/u/proj/out/report.md","flags":577}`)
	line, _ := e.MarshalLine()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(line); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyLine(b *testing.B) {
	e := action(KindFS, `{"op":"open","path":"/home/u/proj/out/report.md","flags":577}`)
	line, _ := e.MarshalLine()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyLine(line); err != nil {
			b.Fatal(err)
		}
	}
}
