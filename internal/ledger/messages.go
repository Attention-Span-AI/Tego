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
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Message dedup (R11, docs/P0-DESIGN.md §2.10 "messages[] items stored once by hash").
//
// A model request re-sends the whole conversation every turn, so storing each request body as one blob
// stores turn k of an n-turn conversation n-k times: O(n²) in the conversation's length. Instead a request
// body whose top level is an object holding one conversation array — messages[], input[] or contents[] —
// is stored as a splice: a small JSON blob that lists the body's bytes in order as literal text, raw blobs,
// and other splices.
//
// The array's elements are stored by their own hash, not by where they sit. An element over BlobThreshold
// is a raw blob of its own. Smaller ones are grouped, a run of consecutive elements stored as the one raw
// blob of their bytes, and where a group ends is decided by the elements themselves (groupsOf): a group
// closes once it holds BlobThreshold bytes, at an element whose hash says so. A history trimmed at the
// front, or edited early, therefore typically falls back into the same groups a few elements past the
// change, and a group is stored once per run whichever request, and whichever position, it came in. A
// small element is stored again only inside a group whose other elements differ. Grouping is also what
// bounds the files one body can create, which an agent chooses the shape of: a group is at least
// BlobThreshold bytes unless an element over it or the array's end closed it, so a body of n bytes adds at
// most 4n/BlobThreshold + 3 files, however many elements it has (R15).
//
// The groups are joined by a chain, one splice per group naming the splice of the groups before it, so a
// request whose history is an earlier request's plus new turns reuses that request's chain up to its last
// group and adds links only for the groups after it, where a flat list of groups would be rewritten, and
// grow, with every request. The system prompt and the tool list, repeated verbatim on every request,
// become raw blobs of their own and are stored once.
//
// The splice reproduces the body byte for byte, separators and whitespace included. blob keeps its v1
// meaning, the file that holds the body whole, so a spliced body has none: body_sha256 carries the whole
// body's sha256 instead, frame names the splice that rebuilds it, and messages names the chain's last link.
// Reader.Body rebuilds the body and checks it against body_sha256.

// ErrNoBody is returned by Reader.Body for an event that carries no body: record: summary, a body capture
// left off, or a kind that has none.
var ErrNoBody = errors.New("ledger: the event carries no body")

// ErrCorruptBlob is returned by Reader.Body when the blobs a body is stored as do not rebuild it: a splice
// that does not parse, names a blob that is missing, loops, takes more work than the body it rebuilds could
// need, or rebuilds bytes whose sha256 is not the one the event recorded, and a whole body's blob that holds
// more bytes than the event's size, or than 1 GiB whatever the size.
var ErrCorruptBlob = errors.New("ledger: blobs do not rebuild the body")

// spliceVersion is the one splice format this package writes and reads.
const spliceVersion = 1

// conversationKeys are the top-level members that hold a request's conversation: Anthropic's and the OpenAI
// chat API's messages, the OpenAI Responses API's input (which Codex sends), Gemini's contents.
var conversationKeys = [][]byte{[]byte(`"messages"`), []byte(`"input"`), []byte(`"contents"`)}

// maxGroup closes a group of small elements whatever their hashes say, so that no hash sequence, chosen or
// unlucky, makes one group of the whole conversation, which would be stored again with every request.
const maxGroup = 4 * BlobThreshold

// splice is the stored form of a body split into parts: the body is the parts' bytes, in order.
type splice struct {
	V     int          `json:"v"`
	Parts []splicePart `json:"parts"`
}

// splicePart is one run of a body's bytes: literal text, a raw blob, or another splice's expansion. Exactly
// one field is set.
type splicePart struct {
	Text   string `json:"text,omitempty"`
	Blob   string `json:"blob,omitempty"`
	Splice string `json:"splice,omitempty"`
}

// span is a byte range [start, end) of a body.
type span struct{ start, end int }

// requestShape is where a request body's conversation and large members sit.
type requestShape struct {
	// messages is the value of the one top-level conversation member, and elements its array's elements.
	messages span
	elements []span
	// large are the other top-level members' values over BlobThreshold, in body order.
	large []span
}

// shapeOf finds the parts of a request body this package stores apart. ok is false for anything that is not
// a single JSON object with exactly one top-level conversation member (conversationKeys) holding a non-empty
// array: such a body is stored whole, as before. A body that is not valid UTF-8 is stored whole too, since
// a splice holds its literal text as JSON strings, and those carry only valid UTF-8 back unchanged.
func shapeOf(body []byte) (requestShape, bool) {
	var sh requestShape
	if !utf8.Valid(body) || !json.Valid(body) {
		return sh, false
	}
	i := skipWS(body, 0)
	if i >= len(body) || body[i] != '{' {
		return sh, false
	}
	i++
	found := false
	for {
		i = skipWS(body, i)
		if body[i] == '}' {
			break
		}
		if body[i] == ',' {
			i = skipWS(body, i+1)
		}
		keyStart := i
		i = skipString(body, i)
		key := body[keyStart:i]
		i = skipWS(body, i) + 1 // the ':'
		i = skipWS(body, i)
		valStart := i
		i = skipValue(body, i)
		val := span{valStart, i}
		switch {
		case isConversationKey(key):
			if found {
				// Two conversation members, or one key twice: which of them a parser reads is its
				// choice, not this package's.
				return sh, false
			}
			found = true
			sh.messages = val
			sh.elements = arrayElements(body, val)
		case val.end-val.start > BlobThreshold:
			sh.large = append(sh.large, val)
		}
	}
	return sh, found && len(sh.elements) > 0
}

// isConversationKey reports whether a raw JSON key, quotes included, names a conversation member. A key
// spelled with escapes is not one: a provider reads its own member names, which it writes plainly.
func isConversationKey(key []byte) bool {
	for _, k := range conversationKeys {
		if bytes.Equal(key, k) {
			return true
		}
	}
	return false
}

// minElementBytes is the least an element of a conversation array averages, separator included, for the
// array to be split. A real message is well above it (an empty chat message is 28 bytes); an array of
// numbers or empty objects is not, and one span and one hash per element of it cost the recorder's single
// pipeline goroutine about ten times what storing the body whole does.
const minElementBytes = 16

// arrayElements returns the element spans of the array value at v, or nil when v is not an array or holds
// more elements than minElementBytes allows (the body is then stored whole).
func arrayElements(body []byte, v span) []span {
	if body[v.start] != '[' {
		return nil
	}
	limit := (v.end-v.start)/minElementBytes + 1
	var out []span
	i := skipWS(body, v.start+1)
	for body[i] != ']' {
		if body[i] == ',' {
			i = skipWS(body, i+1)
		}
		start := i
		i = skipValue(body, i)
		out = append(out, span{start, i})
		if len(out) > limit {
			return nil
		}
		i = skipWS(body, i)
	}
	return out
}

// skipWS returns the index of the first byte at or after i that is not JSON whitespace.
func skipWS(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// skipString returns the index just past the JSON string starting at i. The body has been validated, so
// the string is terminated.
func skipString(b []byte, i int) int {
	for i++; i < len(b); i++ {
		switch b[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return i
}

// skipValue returns the index just past the JSON value starting at i, in a validated body.
func skipValue(b []byte, i int) int {
	switch b[i] {
	case '"':
		return skipString(b, i)
	case '{', '[':
		depth := 0
		for ; i < len(b); i++ {
			switch b[i] {
			case '"':
				i = skipString(b, i) - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		return i
	default:
		for ; i < len(b); i++ {
			switch b[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return i
			}
		}
		return i
	}
}

// groupsOf splits a conversation's elements into the runs stored as one blob each. An element over
// BlobThreshold is a run of its own, so it is stored once by its own hash wherever it sits. Smaller
// elements run together until the run holds BlobThreshold bytes and an element whose hash says to close
// it (cutAfter) ends it, or until it reaches maxGroup. Every decision depends only on the run's own elements
// and the one after it, so two arrays that share a run boundary make the same runs from there on: a history that
// only grows at the end keeps every run but its last, and one trimmed or edited earlier falls back into
// the same runs soon after the change, typically within a run or two.
func groupsOf(body []byte, elements []span) []span {
	var (
		out []span
		cur = span{-1, -1}
	)
	flush := func() {
		if cur.start >= 0 {
			out = append(out, cur)
			cur = span{-1, -1}
		}
	}
	for _, el := range elements {
		if el.end-el.start > BlobThreshold {
			flush()
			out = append(out, el)
			continue
		}
		if cur.start < 0 {
			cur.start = el.start
		}
		cur.end = el.end
		if n := cur.end - cur.start; n >= maxGroup || (n >= BlobThreshold && cutAfter(body[el.start:el.end])) {
			flush()
		}
	}
	flush()
	return out
}

// cutAfter is the content-defined half of groupsOf's rule: about one element in two closes a run that is
// already BlobThreshold bytes long. The bit has to depend on every byte of the element. A cheap hash's low
// bit need not: FNV-1a's is the parity of the element's odd bytes, the same for every message of one
// template whose varying digits each appear an even number of times, which left every run to maxGroup and
// no run shared between a history and itself trimmed by one message. A sender who picks elements to steer
// the bit gets runs between BlobThreshold and maxGroup bytes, which is what the file bound is stated for.
func cutAfter(el []byte) bool {
	return sha256.Sum256(el)[0]&1 == 0
}

// storedRequest is what splitRequest wrote for one body.
type storedRequest struct {
	whole    string // sha256 of the whole body; no file is named by it
	frame    string // the splice that rebuilds it
	messages string // the last link of its conversation chain
}

// splitRequest stores a request body as a splice when it has the shape shapeOf looks for. ok is false, and
// nothing is written, when it does not. An error part way leaves the blobs already written, which nothing
// names; the caller drops the event, as it does for any split that fails.
func (w *Writer) splitRequest(body []byte) (storedRequest, bool, error) {
	sh, ok := shapeOf(body)
	if !ok {
		return storedRequest{}, false, nil
	}
	// The chain: link k is link k-1, the separator before group k, and group k's blob. The first link
	// starts with the array's own '[' and the whitespace after it. A group's blob holds its elements and
	// the separators between them, so it names the same bytes wherever the group sits.
	chain := ""
	prevEnd := sh.messages.start
	for _, g := range groupsOf(body, sh.elements) {
		var s splice
		if chain != "" {
			s.Parts = append(s.Parts, splicePart{Splice: chain})
		}
		s.Parts = appendText(s.Parts, body[prevEnd:g.start])
		sha, err := w.Blob(body[g.start:g.end])
		if err != nil {
			return storedRequest{}, false, err
		}
		s.Parts = append(s.Parts, splicePart{Blob: sha})
		if chain, err = w.putSplice(s); err != nil {
			return storedRequest{}, false, err
		}
		prevEnd = g.end
	}
	// The frame: everything around the chain, with the large members stored apart. Members before and
	// after the conversation are both walked in body order, so the frame's parts are too.
	var frame splice
	at := 0
	emitLarge := func(upTo int) error {
		for _, l := range sh.large {
			if l.start < at || l.end > upTo {
				continue
			}
			frame.Parts = appendText(frame.Parts, body[at:l.start])
			sha, err := w.Blob(body[l.start:l.end])
			if err != nil {
				return err
			}
			frame.Parts = append(frame.Parts, splicePart{Blob: sha})
			at = l.end
		}
		return nil
	}
	if err := emitLarge(sh.messages.start); err != nil {
		return storedRequest{}, false, err
	}
	frame.Parts = appendText(frame.Parts, body[at:sh.messages.start])
	frame.Parts = append(frame.Parts, splicePart{Splice: chain})
	at = prevEnd
	if err := emitLarge(len(body)); err != nil {
		return storedRequest{}, false, err
	}
	frame.Parts = appendText(frame.Parts, body[at:])
	frameSHA, err := w.putSplice(frame)
	if err != nil {
		return storedRequest{}, false, err
	}
	sum := sha256.Sum256(body)
	return storedRequest{whole: hex.EncodeToString(sum[:]), frame: frameSHA, messages: chain}, true, nil
}

// appendText adds literal text to parts, joining it to a text part already at the end. Empty text adds
// nothing, so no part is ever empty.
func appendText(parts []splicePart, b []byte) []splicePart {
	if len(b) == 0 {
		return parts
	}
	if n := len(parts); n > 0 && parts[n-1].Blob == "" && parts[n-1].Splice == "" {
		parts[n-1].Text += string(b)
		return parts
	}
	return append(parts, splicePart{Text: string(b)})
}

// putSplice stores one splice. Encoding the struct is deterministic, which content addressing needs: the
// same parts are the same bytes and so the same blob.
func (w *Writer) putSplice(s splice) (string, error) {
	s.V = spliceVersion
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", fmt.Errorf("ledger: splice: %w", err)
	}
	return w.Blob(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// maxSpliceBody bounds what Reader.Body reads for any event, a splice's rebuild and a whole body's blob alike:
// a splice names other blobs, and a directory edited after the fact (E16: blobs are not re-verified on read)
// could make that expansion, or a blob file, as large as it likes. It is the whole bound for an event that
// gives no size, which every ssl_response is, since its payload has no size field, and the ceiling on one that
// does, whose size may be a number the agent chose (R11).
const maxSpliceBody = 1 << 30

// bodyLimit is the most Reader.Body rebuilds or reads for an event that records size: the size where it is
// below maxSpliceBody, and maxSpliceBody otherwise, so a size is a tighter bound than the ceiling, never a
// looser one. The forwarder records the length the client declared when it exceeds the bytes read, and
// net/http accepts any Content-Length up to 2^63-1, so an agent can put nearly any size on an honest event.
// Taken as it was, a size of 2^63-1 wrapped the blob read's limit+1 negative and returned an empty body with
// no error, and a size near it wrapped expand's byte budget negative and refused an honest splice. No writer
// stores more of a body than its capture cap, 8 MiB for the forwarder and 64 MiB for the uprobe path, far
// under the ceiling, so holding the size to it refuses nothing a writer made (R11).
func bodyLimit(size int64) int64 {
	if size > 0 && size < maxSpliceBody {
		return size
	}
	return maxSpliceBody
}

// Body returns the body an ssl_request or ssl_response carries, whichever way it was stored: inline under
// "body", as the splice "frame" names, whose rebuilt bytes must hash to "body_sha256", or as the one file
// "blob" names. ErrNoBody when the event has none; ErrCorruptBlob when the blobs do not rebuild what the
// event says the body was, which for a blob is a file longer than bodyLimit allows for the event's size.
func (r *Reader) Body(e *record.Event) ([]byte, error) {
	var p struct {
		Body       *string `json:"body"`
		Blob       string  `json:"blob"`
		BodySHA256 string  `json:"body_sha256"`
		Frame      string  `json:"frame"`
		Size       int64   `json:"size"`
	}
	if len(e.Payload) == 0 {
		return nil, ErrNoBody
	}
	if err := json.Unmarshal(e.Payload, &p); err != nil {
		return nil, fmt.Errorf("ledger: body: %w", err)
	}
	limit := bodyLimit(p.Size)
	switch {
	case p.Body != nil:
		return []byte(*p.Body), nil
	case p.Frame != "":
		if !IsSHA(p.BodySHA256) {
			return nil, fmt.Errorf("%w: frame %s without the body's sha256", ErrCorruptBlob, p.Frame)
		}
		out, err := r.expand(p.Frame, limit)
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(out); hex.EncodeToString(sum[:]) != p.BodySHA256 {
			return nil, fmt.Errorf("%w: frame %s rebuilds %d bytes that do not hash to %s",
				ErrCorruptBlob, p.Frame, len(out), p.BodySHA256)
		}
		return out, nil
	case p.Blob != "":
		// The file is data anyone with the run's uid may have replaced (E16), so it is read only to limit and
		// one byte more, the byte that finds it longer: read whole, a file of any size had a reader allocate
		// all of it for a body the event says is small. No writer stores more under blob than the size it
		// records (the uprobe path records the bytes it stores, the forwarder the bytes it read or the length
		// the client declared, whichever is larger), so a longer file is not the body. The bound is only as
		// tight as that size, and the declared length is the agent's, so a sized event is held to at most
		// maxSpliceBody like an event with no size, every ssl_response (R11).
		rc, err := r.Blob(p.Blob)
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(io.LimitReader(rc, limit+1))
		if err != nil {
			return nil, fmt.Errorf("ledger: read blob %s: %w", p.Blob, err)
		}
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("%w: blob %s holds more than %d bytes, the most this event's body can be",
				ErrCorruptBlob, p.Blob, limit)
		}
		// The bytes are in memory and the blob's name is their sha256, so a file edited to the same length
		// is refused here as a frame body is, though the chain covers only the name.
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != p.Blob {
			return nil, fmt.Errorf("%w: blob %s holds %d bytes that do not hash to its name", ErrCorruptBlob, p.Blob, len(b))
		}
		return b, nil
	}
	return nil, ErrNoBody
}

// expand rebuilds a splice's bytes. It walks the parts with an explicit stack rather than by recursion,
// since a chain is as deep as the conversation is long, and it refuses what this package never writes: a
// splice with no parts, a splice that names itself on its own path, an expansion past limit, and a walk
// that costs more than a body of limit bytes can. The blobs directory is data anyone with the run's uid may
// have edited (E16), so the bytes alone do not bound the work: a splice may name another any number of
// times, and one naming a second a thousand times that names an empty third a thousand times is a million
// file reads that rebuild nothing, while a splice padded with whitespace to the size of the body is read
// and parsed in full each time it is named. Three budgets make the work linear in limit:
//
//   - files opened, splices and blobs together, at most spliceOpens(limit): what the writer makes for a
//     body of n bytes is a frame, a link and a blob per group and a blob per large member, and every group
//     but a short one before an element over BlobThreshold holds BlobThreshold bytes of the body (R15);
//   - bytes of splice files read, all of them together, at most spliceBytes(limit): a splice holds its text
//     as JSON strings, which escaping makes at most twice the text they carry, and a link or a blob part
//     costs a few hundred bytes of JSON per group;
//   - parts visited, at most 2*limit: every text part the writer makes rebuilds at least one byte.
func (r *Reader) expand(root string, limit int64) ([]byte, error) {
	type frame struct {
		sha   string
		parts []splicePart
	}
	var (
		out       []byte
		stack     []frame
		onPath    = map[string]bool{}
		visited   int64
		opens     int64
		readBytes int64
		maxOpens  = spliceOpens(limit)
		maxBytes  = spliceBytes(limit)
		budget    = 2 * limit
	)
	open := func(sha string) error {
		if opens++; opens > maxOpens {
			return fmt.Errorf("%w: splice %s names more files than a body of %d bytes is stored in",
				ErrCorruptBlob, root, limit)
		}
		return nil
	}
	push := func(sha string) error {
		if !IsSHA(sha) {
			return fmt.Errorf("%w: splice name %q", ErrCorruptBlob, sha)
		}
		if onPath[sha] {
			return fmt.Errorf("%w: splice %s contains itself", ErrCorruptBlob, sha)
		}
		if err := open(sha); err != nil {
			return err
		}
		b, err := r.readBlob(sha, maxBytes-readBytes)
		if err != nil {
			return err
		}
		readBytes += int64(len(b))
		var s splice
		if err := json.Unmarshal(b, &s); err != nil || s.V != spliceVersion {
			return fmt.Errorf("%w: splice %s does not parse", ErrCorruptBlob, sha)
		}
		if len(s.Parts) == 0 {
			return fmt.Errorf("%w: splice %s has no parts", ErrCorruptBlob, sha)
		}
		onPath[sha] = true
		stack = append(stack, frame{sha: sha, parts: s.Parts})
		return nil
	}
	if err := push(root); err != nil {
		return nil, err
	}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		if len(top.parts) == 0 {
			delete(onPath, top.sha)
			stack = stack[:len(stack)-1]
			continue
		}
		if visited++; visited > budget {
			return nil, fmt.Errorf("%w: splice %s has more parts than a body of %d bytes can",
				ErrCorruptBlob, root, limit)
		}
		part := top.parts[0]
		top.parts = top.parts[1:]
		switch {
		case part.Splice != "" && part.Blob == "" && part.Text == "":
			if err := push(part.Splice); err != nil {
				return nil, err
			}
			continue
		case part.Blob != "" && part.Splice == "" && part.Text == "":
			if err := open(part.Blob); err != nil {
				return nil, err
			}
			b, err := r.readBlob(part.Blob, limit-int64(len(out)))
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		case part.Text != "" && part.Blob == "" && part.Splice == "":
			out = append(out, part.Text...)
		default:
			return nil, fmt.Errorf("%w: a part of splice %s is not exactly one of text, blob and splice",
				ErrCorruptBlob, top.sha)
		}
		if int64(len(out)) > limit {
			return nil, fmt.Errorf("%w: splice %s rebuilds more than the %d bytes the event recorded",
				ErrCorruptBlob, root, limit)
		}
	}
	return out, nil
}

// spliceOpens bounds the files expand opens for a body of limit bytes. The writer stores such a body in
// at most 4*limit/BlobThreshold + 3 files (R15) and a top-level member over BlobThreshold adds one more
// per BlobThreshold bytes; a chain shared with earlier requests is opened again, never more often than its
// groups occur in this body. The slack keeps a body that is exactly at a boundary on the right side.
func spliceOpens(limit int64) int64 { return 5*limit/BlobThreshold + 8 }

// spliceBytes bounds the bytes of splice files expand reads for a body of limit bytes, all of them
// together: twice the body for its text escaped as JSON strings, and a few hundred bytes of JSON for each
// part that names a file (a link names the one before it and its group's blob), which the file bound
// above caps at a fraction of the body.
func spliceBytes(limit int64) int64 { return 3*limit + 256*spliceOpens(limit) + 1<<16 }

// readBlob reads one blob whole, refusing one larger than limit.
func (r *Reader) readBlob(sha string, limit int64) ([]byte, error) {
	rc, err := r.Blob(sha)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorruptBlob, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("ledger: read blob %s: %w", sha, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: blob %s holds more than the %d bytes a body of the recorded size leaves for it",
			ErrCorruptBlob, sha, limit)
	}
	return b, nil
}
