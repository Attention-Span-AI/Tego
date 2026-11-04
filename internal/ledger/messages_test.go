// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// conversation builds the request bodies one agent sends over a conversation of turns turns: a fixed system
// prompt and tool list, and a messages array that grows by an assistant turn and a tool result each time.
// The last message carries a cache_control marker that moves to the new last message on the next request,
// as prompt-caching clients do, so the tail of the array is not byte-identical between requests. sep is the
// separator between JSON tokens: "" is Go's compact encoding, " " is Python's json.dumps default.
func conversation(t *testing.T, turns int, sep string) [][]byte {
	t.Helper()
	system := strings.Repeat("You are a careful coding agent. ", 256) // 8 KiB
	tools := `[{"name":"bash","input_schema":{"type":"object"}}` + strings.Repeat(`,{"name":"t","description":"`+strings.Repeat("d", 900)+`"}`, 20) + `]`
	var msgs []string
	var bodies [][]byte
	for i := range turns {
		msgs = append(msgs, fmt.Sprintf(`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_%04d","content":%q}]}`,
			i, strings.Repeat(fmt.Sprintf("line %d of the output\n", i), 90)))
		last := len(msgs) - 1
		withMarker := make([]string, len(msgs))
		copy(withMarker, msgs)
		withMarker[last] = strings.TrimSuffix(msgs[last], "}") + `,"cache_control":{"type":"ephemeral"}}`
		body := `{"model":"claude-opus-5","max_tokens":8192,"system":` + mustQuote(system) +
			`,"tools":` + tools + `,"messages":[` + strings.Join(withMarker, ","+sep) + `],"stream":true}`
		if sep != "" {
			body = strings.ReplaceAll(body, `","`, `", "`)
		}
		if !json.Valid([]byte(body)) {
			t.Fatalf("turn %d: the test built invalid JSON", i)
		}
		bodies = append(bodies, []byte(body))
		msgs = append(msgs, fmt.Sprintf(`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_%04d","name":"bash","input":{"command":%q}}]}`,
			i+1, strings.Repeat("rg -n TODO ", 120)))
	}
	return bodies
}

func mustQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// blobsBytes is how much the run directory's blobs/ holds.
func blobsBytes(t *testing.T, dir string) int64 {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, BlobsDir))
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		n += fi.Size()
	}
	return n
}

// A growing conversation is stored once (P0-DESIGN §2.10, R11). Every
// request re-sends the whole history, so storing each body whole puts the conversation on disk once per
// request, O(n²) in its length. Stored as splices, a turn is on disk once its group has closed, whichever
// requests carried it, and a few times before that while it is in the last group; the system prompt and tools
// are on disk once for the run, and every request body reads back byte for byte.
func TestAGrowingConversationIsStoredOnce(t *testing.T) {
	for _, sep := range []string{"", " "} {
		t.Run(fmt.Sprintf("separator %q", sep), func(t *testing.T) {
			w, dir := startedWriter(t)
			pipeline := w.RedactStage(w.SplitBlobsStage(w.Append))
			bodies := conversation(t, 60, sep)
			var sent int64
			for _, body := range bodies {
				sent += int64(len(body))
				if err := pipeline(sslRequest(nil, map[string]any{"body": string(body), "size": len(body)})); err != nil {
					t.Fatal(err)
				}
			}
			last := int64(len(bodies[len(bodies)-1]))
			stored := blobsBytes(t, dir)
			t.Logf("stored %d bytes; last request %d; all requests %d", stored, last, sent)
			// The last request is the whole conversation; a store that keeps each turn once holds about
			// that much, plus a chain link per group and one frame per request. The moving cache_control
			// marker changes the last element of every request, and the last group, a few KiB, is stored
			// again with each request until it closes: 2.4 to 2.7 times the last body here, where storing
			// whole bodies needs about 33. Those are apparent sizes for this fixture's 1.4 to 2.1 KB
			// turns; the re-stored last group weighs more against shorter turns, roughly 1 + G/(2t) for
			// groups of G bytes and turns of t bytes, and every file is at least a block on disk (R11).
			if stored > 3*last {
				t.Errorf("blobs/ holds %d bytes for a conversation whose last request is %d bytes (all %d "+
					"requests sent %d): the history is being stored again with every request", stored, last,
					len(bodies), sent)
			}

			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			i := 0
			for e, err := range r.Iter() {
				if err != nil {
					t.Fatal(err)
				}
				if e.Kind != record.KindSSLRequest {
					continue
				}
				var p record.SSLRequestPayload
				if err := e.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if !IsSHA(p.Frame) || !IsSHA(p.Messages) {
					t.Fatalf("request %d: frame %q, messages %q: the body was not stored message by message", i, p.Frame, p.Messages)
				}
				sum := sha256.Sum256(bodies[i])
				if p.BodySHA256 != hex.EncodeToString(sum[:]) {
					t.Errorf("request %d: body_sha256 = %s, want the sha256 of the whole body", i, p.BodySHA256)
				}
				// blob names the file holding the body whole (v1), and a spliced body has none: a
				// reader that follows blob must find nothing to follow, not a missing file.
				if p.Blob != "" {
					t.Errorf("request %d: blob = %s for a body no file holds whole", i, p.Blob)
				}
				got, err := r.Body(e)
				if err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
				if string(got) != string(bodies[i]) {
					t.Fatalf("request %d: the rebuilt body differs from the one sent", i)
				}
				i++
			}
			if i != len(bodies) {
				t.Fatalf("read %d requests, wrote %d", i, len(bodies))
			}
		})
	}
}

// Two requests whose histories begin the same way share the chain up to the last group
// before they part, so here, where the shorter's one element is over the threshold and so a group of its own,
// the messages field of the shorter is a link in the longer's chain (the prefix E28 threads on).
func TestASharedHistorySharesItsChain(t *testing.T) {
	w, dir := startedWriter(t)
	pipeline := w.SplitBlobsStage(w.Append)
	big := strings.Repeat("x", BlobThreshold)
	short := `{"model":"m","messages":[{"role":"user","content":"` + big + `"}]}`
	long := `{"model":"m","messages":[{"role":"user","content":"` + big + `"},{"role":"assistant","content":"ok"}]}`
	for _, b := range []string{short, long} {
		if err := pipeline(sslRequest(nil, map[string]any{"body": b, "size": len(b)})); err != nil {
			t.Fatal(err)
		}
	}
	events := readAll(t, dir)
	var a, b record.SSLRequestPayload
	if err := events[1].DecodePayload(&a); err != nil {
		t.Fatal(err)
	}
	if err := events[2].DecodePayload(&b); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, BlobsDir, b.Messages))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"splice":"`+a.Messages+`"`) {
		t.Errorf("the longer request's chain %s does not continue the shorter's %s", raw, a.Messages)
	}
}

// The forms a ledger written before message dedup holds, and the bodies this stage still
// stores whole, all read back through the same call (VERSIONING §2: a reader for every shape shipped).
func TestBodyReadsEveryStoredForm(t *testing.T) {
	w, dir := startedWriter(t)
	pipeline := w.SplitBlobsStage(w.Append)
	notJSON := strings.Repeat("not json ", 1000)
	noMessages := `{"model":"m","input":"` + strings.Repeat("y", BlobThreshold) + `"}`
	inline := `{"model":"m","messages":[]}`
	cases := []string{notJSON, noMessages, inline}
	for _, b := range cases {
		if err := pipeline(sslRequest(nil, map[string]any{"body": b, "size": len(b)})); err != nil {
			t.Fatal(err)
		}
	}
	// An ssl_request exactly as a pre-dedup writer left it: the body whole under its sha256.
	old := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("z", BlobThreshold) + `"}]}`
	sha, err := w.Blob([]byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(sslRequest(nil, map[string]any{"blob": sha, "size": len(old)})); err != nil {
		t.Fatal(err)
	}
	cases = append(cases, old)
	// summary mode: no body at all.
	if err := w.Append(sslRequest(nil, nil)); err != nil {
		t.Fatal(err)
	}

	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	events := readAll(t, dir)[1:]
	for i, want := range cases {
		var p record.SSLRequestPayload
		if err := events[i].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Frame != "" {
			t.Errorf("case %d: a body with no messages to share was stored as a splice", i)
		}
		got, err := r.Body(events[i])
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if string(got) != want {
			t.Errorf("case %d: read back %d bytes, want the %d written", i, len(got), len(want))
		}
	}
	if _, err := r.Body(events[len(cases)]); !errors.Is(err, ErrNoBody) {
		t.Errorf("summary-mode request: err = %v, want ErrNoBody", err)
	}
}

// A splice is read as data a later hand may have edited (E16), so a reader
// refuses what this package never writes — a splice that contains itself, a frame that rebuilds bytes
// other than the ones the event hashed — instead of looping or returning them.
func TestBodyRefusesASpliceThatDoesNotRebuildTheBody(t *testing.T) {
	w, dir := startedWriter(t)
	body := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("q", BlobThreshold) + `"}]}`
	if err := w.SplitBlobsStage(w.Append)(sslRequest(nil, map[string]any{"body": body, "size": len(body)})); err != nil {
		t.Fatal(err)
	}
	ev := readAll(t, dir)[1]
	var p record.SSLRequestPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	t.Run("a frame whose bytes are not the body", func(t *testing.T) {
		wrong := *ev
		var m map[string]any
		_ = json.Unmarshal(ev.Payload, &m)
		m["body_sha256"] = strings.Repeat("0", 64)
		wrong.Payload = mustJSON(t, m)
		if _, err := r.Body(&wrong); !errors.Is(err, ErrCorruptBlob) {
			t.Errorf("err = %v, want ErrCorruptBlob", err)
		}
	})
	t.Run("a splice that contains itself", func(t *testing.T) {
		// A name chosen before its content, so the file cannot hash to it: exactly the edit E16 says a
		// reader does not detect by hashing, and the one a loop would come from.
		loop := strings.Repeat("ab", 32)
		content := `{"v":1,"parts":[{"text":"["},{"splice":"` + loop + `"}]}`
		if err := os.WriteFile(filepath.Join(dir, BlobsDir, loop), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		looped := *ev
		var m map[string]any
		_ = json.Unmarshal(ev.Payload, &m)
		m["frame"] = loop
		looped.Payload = mustJSON(t, m)
		if _, err := r.Body(&looped); !errors.Is(err, ErrCorruptBlob) {
			t.Errorf("err = %v, want ErrCorruptBlob", err)
		}
	})
	t.Run("a missing link", func(t *testing.T) {
		if err := os.Remove(filepath.Join(dir, BlobsDir, p.Messages)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Body(ev); !errors.Is(err, ErrCorruptBlob) {
			t.Errorf("err = %v, want ErrCorruptBlob", err)
		}
	})
}

// The fields a splice adds are refused like blob itself when the payload already
// holds them, so no recorded value is overwritten without a trace.
func TestSplitRequestRefusesToOverwriteItsFields(t *testing.T) {
	w, _ := startedWriter(t)
	body := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("q", BlobThreshold) + `"}]}`
	for _, field := range []string{"body_sha256", "frame", "messages"} {
		e := sslRequest(nil, map[string]any{"body": body, field: "already here"})
		before := string(e.Payload)
		if err := w.splitBlobs(e); err == nil || !strings.Contains(err.Error(), "overwrite") {
			t.Errorf("%s: err = %v, want the overwrite refused", field, err)
		}
		if string(e.Payload) != before {
			t.Errorf("%s: the payload changed on the refused path", field)
		}
	}
}

// FuzzShapeOf: the scanner that finds a request's messages reads bytes an agent chose, so it must not panic
// on any valid JSON, and every span it reports must be a JSON value of its own.
func FuzzShapeOf(f *testing.F) {
	for _, s := range []string{
		`{"messages":[1]}`, `{"messages":[{"a":"]"},"\"}"]}`, ` { "x" : [ ] , "messages" : [ [ ] , { } ] } `,
		`{"messages":"no"}`, `{"messages":[1],"messages":[2]}`, `[]`, `{}`, `{"messages":[1]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		sh, ok := shapeOf(body)
		if !ok {
			return
		}
		for _, sp := range append(append([]span{sh.messages}, sh.elements...), sh.large...) {
			if sp.start < 0 || sp.end > len(body) || sp.start >= sp.end || !json.Valid(body[sp.start:sp.end]) {
				t.Fatalf("span %v of %q is not a JSON value", sp, body)
			}
		}
	})
}

// blobFiles is how many files the run directory's blobs/ holds.
func blobFiles(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, BlobsDir))
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// storeRequest runs one request body through the blob stage and reads it back, failing unless it was
// spliced and rebuilds byte for byte.
func storeRequest(t *testing.T, w *Writer, dir string, body string) record.SSLRequestPayload {
	t.Helper()
	if err := w.SplitBlobsStage(w.Append)(sslRequest(nil, map[string]any{"body": body, "size": len(body)})); err != nil {
		t.Fatal(err)
	}
	events := readAll(t, dir)
	ev := events[len(events)-1]
	var p record.SSLRequestPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if !IsSHA(p.Frame) {
		t.Fatalf("a %d-byte body was not spliced", len(body))
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := r.Body(ev)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("the rebuilt body differs from the %d bytes stored", len(body))
	}
	return p
}

// The files one request body adds are bounded by its size, whatever its elements (R15).
// The agent writes the request body, and the event is recorded whether or not the upstream accepts it, so
// the agent chooses how many elements a body has. One file per element made a 100 KB body of 50k elements
// into 50,001 files, 204 MB of 4 KiB blocks and a second of the pipeline's time; grouping small elements
// keeps a body of n bytes at 4n/BlobThreshold + 3 files at most, the worst case being elements over the
// threshold each after a tiny one, each costing its own blob, its link, the tiny one's group and its link.
//
// Also pins record-ledger.md R15: the files a request body adds are bounded by its size.
func TestTheFilesOneBodyAddsAreBounded(t *testing.T) {
	distinct := func(i, n int) string { return fmt.Sprintf("%0*d", n, i) }
	var ones, tiny, alternating []string
	for range 50000 {
		ones = append(ones, `"aaaaaaaaaaaaaaa"`) // the smallest element a body is split by (minElementBytes)
	}
	for i := range 20000 {
		tiny = append(tiny, `"`+distinct(i, 16)+`"`)
	}
	for i := range 40 {
		alternating = append(alternating, fmt.Sprint(i), `"`+distinct(i, BlobThreshold)+`"`)
	}
	for _, tc := range []struct {
		name     string
		elements []string
	}{
		{"fifty thousand identical small strings", ones},
		{"twenty thousand distinct strings", tiny},
		{"a tiny element before each large one", alternating},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, dir := startedWriter(t)
			body := `{"model":"m","messages":[` + strings.Join(tc.elements, ",") + `]}`
			before := blobFiles(t, dir)
			storeRequest(t, w, dir, body)
			added := blobFiles(t, dir) - before
			bound := 4*len(body)/BlobThreshold + 3
			t.Logf("%d elements, %d bytes: %d files, bound %d", len(tc.elements), len(body), added, bound)
			if added > bound {
				t.Errorf("a %d-byte body of %d elements added %d files, want at most %d (4n/%d + 3)",
					len(body), len(tc.elements), added, bound, BlobThreshold)
			}
		})
	}
}

// window builds the requests of a client that keeps its last size messages and drops the oldest, so every
// request's history begins with a different message: 1.5 KB messages, one new per request.
func window(requests, size int) []string {
	var msgs, bodies []string
	for i := range requests + size - 1 {
		msgs = append(msgs, fmt.Sprintf(`{"role":"user","content":%q}`, strings.Repeat(fmt.Sprintf("turn %04d. ", i), 140)))
		if len(msgs) >= size {
			bodies = append(bodies, `{"model":"m","messages":[`+strings.Join(msgs[len(msgs)-size:], ",")+`]}`)
		}
	}
	return bodies
}

// A message is stored by hash, not once per distinct history prefix (R11). A client
// that trims its history at the front sends every message in twenty requests, each at a different position.
// When each message was stored inside the chain of the prefix before it, a 20-message window over 100
// requests stored 3.90 MB, more than the 3.06 MB storing each body whole would have: every message twenty
// times. Stored in groups whose ends the messages decide, a message is stored again only in the groups the
// window's two moving ends form around it, while it is in the last group, which grows until it closes, and
// once the front of the window has cut into its group. Here that is about five and a half times the
// distinct messages' bytes, a third of what storing whole bodies costs; the test holds it under eight times
// and under half. Those are apparent sizes of 1.5 KB messages. On disk the trimmed front costs more: a link
// file for every group on every request, each at least a block, so in 4 KiB blocks this window takes about
// 22% more than whole bodies would (R11).
func TestATrimmedHistoryIsStoredByMessageNotByPrefix(t *testing.T) {
	w, dir := startedWriter(t)
	bodies := window(100, 20)
	var sent int
	for _, b := range bodies {
		sent += len(b)
		storeRequest(t, w, dir, b)
	}
	stored := blobsBytes(t, dir)
	distinct := 119 * len(fmt.Sprintf(`{"role":"user","content":%q}`, strings.Repeat("turn 0000. ", 140)))
	t.Logf("sent %d bytes in %d requests; %d distinct message bytes; stored %d bytes in %d files",
		sent, len(bodies), distinct, stored, blobFiles(t, dir))
	if stored > int64(sent)/2 || stored > 8*int64(distinct) {
		t.Errorf("stored %d bytes for %d sent and %d distinct: a trimmed history is being stored once per "+
			"prefix", stored, sent, distinct)
	}

	t.Run("an edit early in a long history", func(t *testing.T) {
		w, dir := startedWriter(t)
		long := window(1, 200)[0]
		storeRequest(t, w, dir, long)
		before := blobsBytes(t, dir)
		edited := strings.Replace(long, "turn 0001. ", "turn 000I. ", 1)
		storeRequest(t, w, dir, edited)
		added := blobsBytes(t, dir) - before
		// The groups around the edit are new, and every link after it, since a link names the one
		// before: a few groups of at most maxGroup bytes, and a link of about 150 bytes a group.
		t.Logf("a %d-byte history edited at its second message added %d bytes", len(long), added)
		if added > int64(len(long))/10 {
			t.Errorf("an edit at the second of 200 messages stored %d bytes again of a %d-byte history",
				added, len(long))
		}
	})
}

// The conversation arrays of the other providers' request shapes are stored the same
// way — OpenAI's Responses input[], which Codex sends, and Gemini's contents[] — and a body naming two of
// them, whose conversation is a parser's choice, is stored whole.
func TestEveryConversationShapeIsSpliced(t *testing.T) {
	msg := func(i int) string {
		return fmt.Sprintf(`{"role":"user","content":%q}`, strings.Repeat(fmt.Sprintf("item %d ", i), 600))
	}
	for _, key := range []string{"messages", "input", "contents"} {
		t.Run(key, func(t *testing.T) {
			w, dir := startedWriter(t)
			first := `{"model":"m","` + key + `":[` + msg(1) + `,` + msg(2) + `]}`
			second := `{"model":"m","` + key + `":[` + msg(1) + `,` + msg(2) + `,` + msg(3) + `]}`
			storeRequest(t, w, dir, first)
			before := blobsBytes(t, dir)
			storeRequest(t, w, dir, second)
			if added := blobsBytes(t, dir) - before; added > int64(len(msg(3)))+1024 {
				t.Errorf("the second request added %d bytes for one new %d-byte item", added, len(msg(3)))
			}
		})
	}
	t.Run("two conversation members", func(t *testing.T) {
		w, dir := startedWriter(t)
		body := `{"model":"m","input":[` + msg(1) + `],"messages":[` + msg(2) + `]}`
		if err := w.SplitBlobsStage(w.Append)(sslRequest(nil, map[string]any{"body": body, "size": len(body)})); err != nil {
			t.Fatal(err)
		}
		var p record.SSLRequestPayload
		if err := readAll(t, dir)[1].DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Frame != "" || !IsSHA(p.Blob) {
			t.Errorf("frame %q, blob %q: a body with two conversations was not stored whole", p.Frame, p.Blob)
		}
	})
}

// Expanding a splice is bounded in work as well as in bytes. The blobs directory is data
// anyone with the run's uid may have edited (E16), and a splice may name another any number of times: three
// levels of splices each naming the next 500 times, every file of them small enough to pass the reader's
// size check, are 125 million reads, however few bytes they rebuild. And a splice padded with JSON
// whitespace to the most one read allowed, naming one empty blob, cost two part visits and a read of twice
// the body: a fan-out of those spent the whole visit budget reading and parsing size x 2*size bytes — 12.6 GB
// and 15 s for a 64 KiB body. The reader bounds the files it opens and the splice bytes it reads, all reads
// together, by what the writer stores a body of the recorded size in, and refuses a splice with no parts,
// which the writer never makes.
func TestBodyRefusesASpliceThatCostsMoreThanItsBody(t *testing.T) {
	w, dir := startedWriter(t)
	put := func(parts []splicePart) string {
		t.Helper()
		sha, err := w.putSplice(splice{Parts: parts})
		if err != nil {
			t.Fatal(err)
		}
		return sha
	}
	fanout := func(n int, part splicePart) string {
		parts := make([]splicePart, n)
		for i := range parts {
			parts[i] = part
		}
		return put(parts)
	}
	// deep is levels of splices above leaf, each naming the one below 500 times.
	deep := func(levels int, leaf string) string {
		for range levels {
			leaf = fanout(500, splicePart{Splice: leaf})
		}
		return leaf
	}
	nothing, err := w.Blob(nil)
	if err != nil {
		t.Fatal(err)
	}
	const body = `{"messages":[1]}`
	sum := sha256.Sum256([]byte(body))
	for _, tc := range []struct {
		name  string
		frame string
	}{
		{"a fan-out of empty splices", deep(3, put(nil))},
		{"a fan-out of empty blobs", deep(2, fanout(500, splicePart{Blob: nothing}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			reads := &countingBlobs{BlobRepository: r.blobs, stopAt: 100000}
			r.blobs = reads
			ev := sslRequest(nil, map[string]any{"frame": tc.frame, "body_sha256": hex.EncodeToString(sum[:]), "size": len(body)})
			if _, err := r.Body(ev); !errors.Is(err, ErrCorruptBlob) {
				t.Errorf("err = %v, want ErrCorruptBlob", err)
			}
			if bound := int(spliceOpens(int64(len(body)))); reads.gets > bound {
				t.Errorf("rebuilding a %d-byte body read %d blobs, want at most %d: the work was the "+
					"splice's to choose", len(body), reads.gets, bound)
			}
		})
	}
	t.Run("a fan-out of splices padded to the most one read allows", func(t *testing.T) {
		const size = 64 << 10
		big := `{"messages":[` + strings.Repeat("1,", size/2-8) + `1]}`
		bigSum := sha256.Sum256([]byte(big))
		// The padded leaf: one part naming an empty blob, then whitespace up to the per-read limit the
		// reader used to allow every splice read, 2*size + 64 KiB.
		leaf := []byte(`{"v":1,"parts":[{"blob":"` + nothing + `"}]}`)
		leaf = append(leaf, bytes.Repeat([]byte(" "), 2*size+1<<16-len(leaf))...)
		padded, err := w.Blob(leaf)
		if err != nil {
			t.Fatal(err)
		}
		frame := deep(2, fanout(500, splicePart{Splice: padded}))
		r, err := OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		// A walk the reader did not bound is cut off at 64 times the body, so the unbounded reader
		// fails this test in well under a second rather than reading gigabytes first.
		reads := &countingBlobs{BlobRepository: r.blobs, stopAt: 1 << 30, stopBytes: 64 * size}
		r.blobs = reads
		ev := sslRequest(nil, map[string]any{"frame": frame, "body_sha256": hex.EncodeToString(bigSum[:]), "size": size})
		if _, err := r.Body(ev); !errors.Is(err, ErrCorruptBlob) {
			t.Errorf("err = %v, want ErrCorruptBlob", err)
		}
		if bound := spliceBytes(size) + size + spliceOpens(size); reads.bytes > bound {
			t.Errorf("rebuilding a %d-byte body read %d bytes of blobs in %d files, want at most %d: "+
				"the work must be linear in the body", size, reads.bytes, reads.gets, bound)
		}
		t.Logf("read %d bytes in %d files for a %d-byte body", reads.bytes, reads.gets, size)
	})
	t.Run("the writer's own worst cases stay inside the budgets", func(t *testing.T) {
		var alternating []string
		for i := range 40 {
			alternating = append(alternating, fmt.Sprint(i), `"`+fmt.Sprintf("%0*d", BlobThreshold, i)+`"`)
		}
		// Members under BlobThreshold stay in the frame as text, and quotes and backslashes are what JSON
		// escaping doubles: the frame's text at its largest beside the body.
		var members []string
		for i := range 30 {
			members = append(members, fmt.Sprintf(`"m%d":"%s"`, i, strings.Repeat(`\"\\`, 1000)))
		}
		quoted := `{` + strings.Join(members, ",\t") + `,"messages":[` + strings.Join(alternating, ", ") + `]}`
		for _, b := range append([]string{quoted}, func() []string {
			var out []string
			for _, c := range conversation(t, 30, " ") {
				out = append(out, string(c))
			}
			return out
		}()...) {
			w, dir := startedWriter(t)
			p := storeRequest(t, w, dir, b)
			r, err := OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			reads := &countingBlobs{BlobRepository: r.blobs, stopAt: 1 << 30, stopBytes: 1 << 40}
			r.blobs = reads
			ev := sslRequest(nil, map[string]any{"frame": p.Frame, "body_sha256": p.BodySHA256, "size": len(b)})
			if got, err := r.Body(ev); err != nil || string(got) != b {
				t.Fatalf("a %d-byte body the writer stored: %v", len(b), err)
			}
			n := int64(len(b))
			if int64(reads.gets) > spliceOpens(n) || reads.bytes > spliceBytes(n)+n {
				t.Errorf("a %d-byte body opened %d files and read %d bytes, budgets %d and %d", n, reads.gets,
					reads.bytes, spliceOpens(n), spliceBytes(n)+n)
			}
			_ = r.Close()
		}
	})
	t.Run("a splice with no parts, beside the body's own bytes", func(t *testing.T) {
		r, err := OpenReader(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		frame := put([]splicePart{{Splice: put(nil)}, {Text: body}})
		ev := sslRequest(nil, map[string]any{"frame": frame, "body_sha256": hex.EncodeToString(sum[:]), "size": len(body)})
		if got, err := r.Body(ev); !errors.Is(err, ErrCorruptBlob) {
			t.Errorf("Body = %q, %v; want ErrCorruptBlob for a splice the writer never makes", got, err)
		}
	})
}

// countingBlobs counts the blobs a reader opens and the bytes it reads from them, and fails every open past
// stopAt, and every read once stopBytes have been read, so that a walk the reader does not bound ends
// anyway, with counts that say so.
type countingBlobs struct {
	BlobRepository
	gets, stopAt     int
	bytes, stopBytes int64
}

func (c *countingBlobs) Get(sha string) (io.ReadCloser, error) {
	if c.gets++; c.gets > c.stopAt {
		return nil, os.ErrNotExist
	}
	rc, err := c.BlobRepository.Get(sha)
	if err != nil {
		return nil, err
	}
	return &countingReader{ReadCloser: rc, c: c}, nil
}

type countingReader struct {
	io.ReadCloser
	c *countingBlobs
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.c.stopBytes > 0 && r.c.bytes >= r.c.stopBytes {
		return 0, errors.New("countingBlobs: read budget of the test spent")
	}
	n, err := r.ReadCloser.Read(p)
	r.c.bytes += int64(n)
	return n, err
}

// FuzzSpliceRoundTrip: whatever body the agent sends, a body stored as a splice reads back byte for byte and
// adds no more files than R15's bound, and a body that is not spliced is left to the whole-body path.
func FuzzSpliceRoundTrip(f *testing.F) {
	for _, s := range []string{
		`{"messages":[1]}`, ` { "input" : [ "a" , { "b" : [ ] } ] , "x" : 1 } `, `{"contents":[[],{},"",0,null,true]}`,
		`{"messages":[` + strings.Repeat(`"`+strings.Repeat("m", 700)+`",`, 30) + `1]}`,
		`{"system":"` + strings.Repeat("s", 5000) + `","messages":[{"role":"user","content":" \"\\"}]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(checkSpliceRoundTrip)
}

// TestSpliceRoundTripClosesDescriptors checks the fuzz callback's lifetime, including its early return for
// the crash corpus's non-spliced body. TempDir removes files, but does not close a Writer's descriptors.
func TestSpliceRoundTripClosesDescriptors(t *testing.T) {
	for _, body := range []string{"0", `{"messages":["a message long enough to splice"]}`} {
		before := openFDs(t)
		t.Run(body, func(t *testing.T) { checkSpliceRoundTrip(t, []byte(body)) })
		// As in TestWriterLeaksNoDescriptor, an earlier test may close a descriptor while this runs.
		if after := openFDs(t); after > before {
			t.Errorf("%q: open descriptors before %d, after %d", body, before, after)
		}
	}
}

func checkSpliceRoundTrip(t *testing.T, body []byte) {
	t.Helper()
	w, dir := startedWriter(t)
	// Each fuzz input owns a Writer, even when splitRequest declines the body. The callback needs no
	// run_end or durability barrier, but must release the Writer before TempDir removes its files.
	defer func() {
		if err := w.Abandon(); err != nil {
			t.Error(err)
		}
	}()
	before := blobFiles(t, dir)
	stored, ok, err := w.splitRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		return
	}
	if added, bound := blobFiles(t, dir)-before, 4*len(body)/BlobThreshold+3; added > bound {
		t.Fatalf("a %d-byte body added %d files, bound %d", len(body), added, bound)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ev := sslRequest(nil, map[string]any{"frame": stored.frame, "body_sha256": stored.whole, "size": len(body)})
	got, err := r.Body(ev)
	if err != nil {
		t.Fatalf("%q: %v", body, err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("rebuilt %q, stored %q", got, body)
	}
}
