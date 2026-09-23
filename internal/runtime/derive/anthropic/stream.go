// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/attention-span-ai/tego/internal/runtime/derive/sse"
)

// ParseStreamEvent decodes one `data:` payload. name is the event field of the SSE frame, which the
// payload's own "type" overrides when both are present; a payload with neither is a schema error.
func ParseStreamEvent(name string, data []byte) (*StreamEvent, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%w: empty stream event %q", ErrSchema, name)
	}
	if name == EventError && !bytes.Contains(data, scanError) {
		if err := uniqueAccounting(data, eventAccounting); err != nil {
			return nil, fmt.Errorf("%w: stream event %q: %w", ErrSchema, name, err)
		}
	}
	// Names are read as written (keys.go): a type or usage in another spelling of its key is not the event's
	// (R29).
	var ev StreamEvent
	if err := unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("%w: stream event %q: %w", ErrSchema, name, err)
	}
	if ev.Type == "" {
		ev.Type = name
	}
	if ev.Type == "" {
		return nil, fmt.Errorf("%w: stream event without a type", ErrSchema)
	}
	return &ev, nil
}

// ParseStream assembles a whole server-sent event stream into the response it describes, returning the
// events it read alongside it so a caller can see the sequence the assembly came from (R29).
//
// It accepts the raw wire stream (`event:`/`data:` lines, comments and blank separators) and the legacy
// collected form, one `data:` payload per line. Current capture explicitly selects wire framing through
// Message.WireSSE so a JSON-looking unknown SSE field cannot be mistaken for a collected payload. A stream
// that never started, or that failed after message_start (a mid-stream close, a body a cap cut short, an
// error event) is a schema error. After message_start the response it returns alongside the error holds what
// the stream had already reported, its usage above all (R29); unknown event and delta types are ignored.
//
// An error event before message_start is an error answer, not a failure: no message began and nothing was
// spent, so it returns a Response with ErrorAnswer set and no error (R29). A failure after
// message_start does not end the scan: the frames after it are still read for a message_delta's usage, and
// only for that, because the output count the budgets need is on the wire whether or not a tool_use input
// before it assembled (fine-grained tool streaming allows one that is not valid JSON; R29).
func ParseStream(body []byte) (*Response, []StreamEvent, error) {
	return parseStream(body, true, false)
}

// parseStreamResponse is ParseStream for a caller that wants the response alone: it keeps no event and no
// content text, which decisions() never reads, so a body of text deltas costs a small multiple of its size
// and not ten times it (TestParseStreamAllocationBoundedByBody).
func parseStreamResponse(body []byte, wireSSE bool) (*Response, error) {
	resp, _, err := parseStream(body, false, wireSSE)
	return resp, err
}

// parseStream is the assembly; full keeps the events and the text of every block, as ParseStream returns them.
func parseStream(body []byte, full, wireSSE bool) (*Response, []StreamEvent, error) {
	a := newAssembler()
	var accounting StreamUsageScanner
	a.lean = !full
	var (
		events []StreamEvent
		failed error // the first failure; after it frames are read for usage alone
	)
	// Frames are parsed as the scan finds them, never collected first: the body is agent-shaped on the uprobe
	// path, and a slice of every frame (with events sized to match) cost hundreds of bytes per short line.
	err := scanSSE(body, wireSSE, func(f frame) error {
		accounting.event([]byte(f.name), f.data)
		if failed != nil {
			// Only a frame that can be a message_delta is decoded: the rest of a failed body is agent-shaped
			// on the uprobe path, and decoding every short line of it cost an error value each. A JSON
			// escape can spell its routing type, as the usage scanner also accepts.
			if f.name != EventMessageDelta && !bytes.Contains(f.data, scanMessageDelta) && !bytes.Contains(f.data, scanEscape) {
				return nil
			}
			if ev, err := ParseStreamEvent(f.name, f.data); err == nil {
				a.usageOnly(ev)
			}
			return nil
		}
		ev, err := ParseStreamEvent(f.name, f.data)
		if err != nil {
			failed = err
			return nil
		}
		if full {
			events = append(events, *ev)
		}
		if err := a.apply(ev); err != nil {
			if errors.Is(err, errErrorAnswer) {
				return err
			}
			failed = err
		}
		return nil
	})
	if errors.Is(err, errErrorAnswer) {
		return &Response{Stream: true, Type: EventError, ErrorAnswer: true}, events, nil
	}
	if accounting.Incomplete() {
		a.resp.incompleteUsage = true
		if failed == nil {
			failed = fmt.Errorf("%w: stream accounting is incomplete", ErrSchema)
		}
	}
	if failed != nil {
		err = failed // the first failure is the one to report, not one the usage-only scan met later
	}
	if err != nil {
		return a.partial(), events, err
	}
	resp, err := a.finish()
	if err != nil {
		return a.partial(), events, err
	}
	return resp, events, nil
}

// partial is what a stream that failed after message_start still said for certain: its model, id, stop
// reason and the usage message_start and any message_delta reported. The budgets need that usage whether or
// not the stream then parsed to the end; nil when the stream never started.
func (a *assembler) partial() *Response {
	if !a.started {
		if a.startUsage {
			return &Response{Stream: true, Model: a.resp.Model, Usage: a.resp.Usage, FinalUsage: a.resp.FinalUsage, incompleteUsage: a.resp.incompleteUsage}
		}
		return nil
	}
	return &Response{Stream: true, ID: a.resp.ID, Model: a.resp.Model, Role: a.resp.Role, Type: a.resp.Type,
		StopReason: a.resp.StopReason, Usage: a.resp.Usage, FinalUsage: a.resp.FinalUsage, incompleteUsage: a.resp.incompleteUsage}
}

// frame is one SSE frame: the event name and the concatenated data payload.
type frame struct {
	name string
	data []byte
}

// scanSSE splits an event stream into frames and hands each to yield, stopping at yield's first error.
// Comments (`:` lines), `retry:` and `id:` directives and blank separators never reach a parser (R16, edge
// case #19). It walks the body in place, one line at a time.
func scanSSE(body []byte, wireSSE bool, yield func(frame) error) error {
	var (
		name     string
		data     []byte
		haveData bool
	)
	flush := func() error {
		f, dispatch := frame{name: name, data: data}, haveData
		name, data, haveData = "", nil, false
		if !dispatch {
			return nil
		}
		return yield(f)
	}
	for rest := sse.WithoutBOM(body); len(rest) > 0; {
		var line []byte
		line, rest, _ = sse.CutLine(rest)
		switch {
		case len(line) == 0:
			if err := flush(); err != nil {
				return err
			}
		case line[0] == ':':
			// A comment, including a proxy heartbeat.
		case line[0] == '{' && !wireSSE:
			// Collected form: one JSON payload per line, without event framing.
			if err := flush(); err != nil {
				return err
			}
			if err := yield(frame{data: line}); err != nil {
				return err
			}
		default:
			field, value := sse.SplitField(line)
			switch string(field) {
			case "event":
				name = string(value)
			case "data":
				if haveData {
					data = append(data, '\n')
				}
				data = append(data, value...)
				haveData = true
			default:
				// id, retry and unrecognized fields do not contribute provider data.
			}
		}
	}
	return flush()
}

// blockState is one content block being built across its start, deltas and stop.
type blockState struct {
	typ     string
	id      string
	name    string
	text    []byte
	partial []byte          // input_json_delta fragments, exactly as they arrived (R31)
	input   json.RawMessage // the opening block's input, used when no fragment arrived
	closed  bool
}

// assembler folds the event sequence into one Response.
type assembler struct {
	resp    Response
	blocks  map[int]*blockState
	order   []int
	started bool
	stopped bool
	// startUsage: a message_start that failed to assemble still reported usage, folded into resp (the
	// StreamUsageScanner reads it the same way, from the fields it needs alone).
	startUsage bool
	// lean: only what a decision reads is kept, the input of tool_use blocks; the text and thinking of a block
	// are not decoded or accumulated.
	lean bool
}

func newAssembler() *assembler {
	return &assembler{blocks: make(map[int]*blockState), resp: Response{Stream: true}}
}

func (a *assembler) apply(ev *StreamEvent) error {
	switch ev.Type {
	case EventMessageStart:
		return a.messageStart(ev)
	case EventContentBlockStart:
		return a.blockStart(ev)
	case EventContentBlockDelta:
		return a.blockDelta(ev)
	case EventContentBlockStop:
		return a.blockStop(ev)
	case EventMessageDelta:
		return a.messageDelta(ev)
	case EventMessageStop:
		a.stopped = true
		return nil
	case EventPing:
		return nil
	case EventError:
		if !a.started {
			return errErrorAnswer
		}
		return fmt.Errorf("%w: stream carried an error event: %s", ErrSchema, string(ev.Error))
	default:
		// The Messages API adds event types over time and asks clients to ignore the ones they do not know.
		// Refusing one voided the whole stream, its usage with it, so the token and cost budgets counted a
		// valid response as nothing.
		return nil
	}
}

// errErrorAnswer stops a stream whose first event is an error: the answer is the error, and nothing after
// it is read.
var errErrorAnswer = errors.New("anthropic: stream is an error answer")

// usageOnly reads one frame after the stream failed: a message_delta's usage is kept, and nothing else. The
// failure (a tool_use input that did not assemble, a malformed frame) says nothing about the count the
// upstream reported after it; stopping there charged a whole stream max_tokens.
func (a *assembler) usageOnly(ev *StreamEvent) {
	if (a.started || a.startUsage) && ev.Type == EventMessageDelta && foldUsage(&a.resp.Usage, ev.Usage) && ev.Usage.hasOutput {
		a.resp.FinalUsage = true
	}
}

func (a *assembler) messageStart(ev *StreamEvent) error {
	if a.started {
		return fmt.Errorf("%w: a second message_start", ErrSchema)
	}
	var msg Response
	if err := unmarshal(ev.Message, &msg); err != nil {
		a.startUsageOnly(ev)
		return fmt.Errorf("%w: message_start.message: %w", ErrSchema, err)
	}
	if msg.ID == "" && msg.Model == "" {
		a.startUsageOnly(ev)
		return fmt.Errorf("%w: message_start without an id or a model", ErrSchema)
	}
	if err := msg.Usage.validate(); err != nil {
		return err
	}
	a.started = true
	a.resp.ID, a.resp.Model, a.resp.Role, a.resp.Type = msg.ID, msg.Model, msg.Role, msg.Type
	a.resp.StopReason = msg.StopReason
	a.resp.Usage.merge(msg.Usage)
	return nil
}

// startUsageOnly keeps the usage and model of a message_start whose message did not assemble (a field of
// another type, no id or model): they are on the wire whatever else in the message is wrong, and the budgets
// need them (R29). Only the two fields are decoded, as the StreamUsageScanner decodes them.
func (a *assembler) startUsageOnly(ev *StreamEvent) {
	var m struct {
		Model string `json:"model"`
		Usage *Usage `json:"usage"`
	}
	if unmarshal(ev.Message, &m) != nil || !foldUsage(&a.resp.Usage, m.Usage) {
		return
	}
	a.startUsage = true
	if m.Model != "" {
		a.resp.Model = m.Model
	}
}

func (a *assembler) blockStart(ev *StreamEvent) error {
	if !a.started {
		return fmt.Errorf("%w: content_block_start before message_start", ErrSchema)
	}
	if _, dup := a.blocks[ev.Index]; dup {
		return fmt.Errorf("%w: content_block_start reopened index %d", ErrSchema, ev.Index)
	}
	var b ContentBlock
	if err := unmarshal(ev.ContentBlock, &b); err != nil {
		return fmt.Errorf("%w: content_block_start[%d]: %w", ErrSchema, ev.Index, err)
	}
	if b.Type == "" {
		return fmt.Errorf("%w: content_block_start[%d] without a type", ErrSchema, ev.Index)
	}
	bs := &blockState{typ: b.Type, id: b.ID, name: b.Name, input: b.Input}
	if !a.lean {
		bs.text = []byte(b.Text)
	}
	a.blocks[ev.Index] = bs
	a.order = append(a.order, ev.Index)
	return nil
}

func (a *assembler) blockDelta(ev *StreamEvent) error {
	b, ok := a.blocks[ev.Index]
	if !ok {
		return fmt.Errorf("%w: content_block_delta for unopened index %d", ErrSchema, ev.Index)
	}
	if b.closed {
		return fmt.Errorf("%w: content_block_delta after stop on index %d", ErrSchema, ev.Index)
	}
	if a.lean {
		var d struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
		}
		if err := unmarshal(ev.Delta, &d); err != nil {
			return fmt.Errorf("%w: content_block_delta[%d]: %w", ErrSchema, ev.Index, err)
		}
		if d.Type == DeltaInputJSON {
			b.partial = append(b.partial, d.PartialJSON...)
		}
		return nil
	}
	var d struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		Thinking    string `json:"thinking"`
	}
	if err := unmarshal(ev.Delta, &d); err != nil {
		return fmt.Errorf("%w: content_block_delta[%d]: %w", ErrSchema, ev.Index, err)
	}
	switch d.Type {
	case DeltaText:
		b.text = append(b.text, d.Text...)
	case DeltaInputJSON:
		b.partial = append(b.partial, d.PartialJSON...)
	case DeltaThinking, DeltaSignature:
		// Thinking blocks carry no decision and no body the ledger keeps separately.
	default:
		// A delta type this parser does not know (citations_delta, and whatever follows it) adds nothing
		// to a decision; ignoring it keeps the stream, and its usage, instead of voiding both.
	}
	return nil
}

func (a *assembler) blockStop(ev *StreamEvent) error {
	b, ok := a.blocks[ev.Index]
	if !ok {
		return fmt.Errorf("%w: content_block_stop for unopened index %d", ErrSchema, ev.Index)
	}
	return a.close(ev.Index, b)
}

// close finalises one block: a tool_use's accumulated fragments are parsed exactly once, here (R29),
// and kept as the bytes that arrived so input_hash is a hash of the wire (R31).
func (a *assembler) close(index int, b *blockState) error {
	if b.closed {
		return nil
	}
	b.closed = true
	if b.typ != BlockToolUse {
		return nil
	}
	if len(b.partial) > 0 {
		b.input = json.RawMessage(b.partial)
	}
	if len(b.input) == 0 {
		b.input = json.RawMessage("{}")
	}
	if !json.Valid(b.input) {
		return fmt.Errorf("%w: tool_use input on index %d is not valid JSON", ErrSchema, index)
	}
	return nil
}

func (a *assembler) messageDelta(ev *StreamEvent) error {
	if !a.started {
		return fmt.Errorf("%w: message_delta before message_start", ErrSchema)
	}
	// The usage is folded first: it is on the wire whether or not the delta member decodes, and the
	// StreamUsageScanner reads it either way.
	if ev.Usage != nil {
		if err := ev.Usage.validate(); err != nil {
			return err
		}
		a.resp.Usage.merge(*ev.Usage)
		a.resp.FinalUsage = a.resp.FinalUsage || ev.Usage.hasOutput
	}
	if len(ev.Delta) > 0 {
		var d struct {
			StopReason string `json:"stop_reason"`
		}
		if err := unmarshal(ev.Delta, &d); err != nil {
			return fmt.Errorf("%w: message_delta.delta: %w", ErrSchema, err)
		}
		if d.StopReason != "" {
			a.resp.StopReason = d.StopReason
		}
	}
	return nil
}

// finish returns the assembled response, rejecting a stream that never started or never ended (R29: a
// mid-stream close and a body a cap cut short are both structural, and the closed why set's nearest
// value for them is schema).
func (a *assembler) finish() (*Response, error) {
	if !a.started {
		return nil, fmt.Errorf("%w: event stream without a message_start", ErrSchema)
	}
	if !a.stopped {
		return nil, fmt.Errorf("%w: event stream ended without a message_stop", ErrSchema)
	}
	sort.Ints(a.order)
	for _, i := range a.order {
		if err := a.close(i, a.blocks[i]); err != nil {
			return nil, err
		}
	}
	a.resp.Content = make([]ContentBlock, 0, len(a.order))
	for _, i := range a.order {
		b := a.blocks[i]
		a.resp.Content = append(a.resp.Content, ContentBlock{
			Type: b.typ, Text: string(b.text), ID: b.id, Name: b.name, Input: b.input,
		})
	}
	return &a.resp, nil
}
