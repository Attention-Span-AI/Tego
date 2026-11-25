// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"encoding/json"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive/mcp"
	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// helloWait bounds the hello a connection must open with.
const helloWait = 5 * time.Second

// maxInflight bounds the requests one connection has waiting for their answers. A request past it is refused with an error
// of its own, as is one whose id is already waiting (an answer under a repeated id is one no client could tell apart).
const maxInflight = 1024

// stdioConn is one admitted shim: one stdio server's session.
type stdioConn struct {
	s      *Service
	c      net.Conn
	fw     *FrameWriter
	server string
	pid    int // the shim's

	mu       sync.Mutex
	inflight map[string]struct{} // the client's requests awaiting their answers, by id (idKey)
	once     sync.Once
}

func (c *stdioConn) close() { c.once.Do(func() { _ = c.c.Close() }) }

// serveStdio admits one control connection and relays its lines until it ends.
func (s *Service) serveStdio(nc net.Conn) {
	fr := NewFrameReader(nc, maxFrame)
	_ = nc.SetReadDeadline(time.Now().Add(helloWait))
	hello, err := fr.Read()
	_ = nc.SetReadDeadline(time.Time{})
	fw := NewFrameWriter(nc)
	if err != nil {
		_ = nc.Close()
		return
	}
	refuse := func(why string) {
		s.opts.Logger.Warn("mcp relay: refused a shim", "server", hello.Server, "why", why)
		_ = fw.Write(Frame{Error: why})
		_ = nc.Close()
	}
	s.mu.Lock()
	run := s.run
	s.mu.Unlock()
	shim, err := s.opts.admit(nc, hello.PID, run.CgroupID)
	if err != nil {
		refuse(err.Error())
		return
	}
	pid := shim.pid
	sv, ok := s.servers[hello.Server]
	switch {
	case hello.V != ProtocolVersion:
		refuse("unknown relay protocol version")
		return
	case !ok:
		refuse("server " + hello.Server + " is not behind this run's relay (no tools: in its contract entry)")
		return
	case sv.BusinessRules:
		refuse(ErrBusinessUnavailable.Error())
		return
	case len(sv.Command) == 0:
		refuse("server " + hello.Server + " is an HTTP server; its relay is a URL, not a command")
		return
	case !slices.Equal(hello.Argv, sv.Command):
		refuse("the command after -- is not server " + hello.Server + "'s declared command")
		return
	}
	c := &stdioConn{s: s, c: nc, fw: fw, server: hello.Server, pid: pid, inflight: map[string]struct{}{}}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = nc.Close()
		return
	}
	if _, exists := s.pending[pid]; exists {
		s.mu.Unlock()
		refuse("this shim already has a pending start")
		return
	}
	s.pending[pid] = pendingStart{server: hello.Server, shim: shim}
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		s.clearPending(shim)
		c.close()
	}()
	if err := fw.Write(Frame{OK: true}); err != nil {
		return
	}
	bound := false
	for {
		f, err := fr.Read()
		if err != nil {
			return
		}
		switch {
		case f.Stage != nil:
			if bound || !s.prepareStage(shim, *f.Stage) {
				_ = fw.Write(Frame{Error: "server stage could not be prepared"})
				return
			}
			if err := fw.Write(Frame{OK: true}); err != nil {
				return
			}
		case f.Child != 0:
			if bound || !s.bindChild(shim, f.Child) {
				_ = fw.Write(Frame{Error: "server child could not be pinned"})
				return
			}
			bound = true
			if err := fw.Write(Frame{OK: true}); err != nil {
				return
			}
		case f.Started != 0:
			// The shim waited for the stage's close-on-exec control socket: the server exec has passed the gate.
			s.clearPending(shim)
		case f.C != nil:
			c.clientLine(f.C)
		case f.S != nil:
			c.serverLine(f.S)
		case f.Oversize != "":
			if f.Oversize == "c" {
				// The refusal is the record's line of it (refuseUnreadable); the log says how big it was.
				s.opts.Logger.Warn("mcp relay: dropped a client line over the size bound", "server", c.server, "size", f.Size, "limit", MaxLine)
				c.refuseUnreadable()
			} else {
				// A server's answer the client never gets: the record says which server, how big and what the limit was.
				s.emitOversize(record.GapMCPResponseOversize, c.server, f.Size, MaxLine)
			}
		case f.Exit != nil:
			return
		}
	}
}

// unreadableAnswer is the JSON-RPC parse error a client gets for a message the relay could not read.
var unreadableAnswer = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Tego's MCP relay could not read this message, so it was not passed to the server"}}`)

// envelope is the part of a JSON-RPC message the relay routes by.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method *string         `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// call is one client message as the relay reads it.
type call struct {
	raw    json.RawMessage // the message in its wire form, as it is passed on
	id     json.RawMessage
	method string
	tool   string // a tools/call's tool, "" when unreadable
	isCall bool   // a tools/call request
}

// readStatus is how readBatch took a client line or POST body.
type readStatus int

const (
	readOK readStatus = iota
	// readUnreadable is a body that is not JSON-RPC at all, or a batch with a member that is not a message.
	readUnreadable
	// readTooMany is a batch of more than MaxBatch messages.
	readTooMany
)

// readBatch reads a client line or POST body in its wire form: one message or a batch. Only the wire form is read,
// which is UTF-8: json.Valid takes a bad byte, and "delete_file\xff" would pass a deny list as a name no one denied.
// A batch of more than MaxBatch members is refused unread (readTooMany): each member would be a line of the record and
// an answer, and the bound is on what one body can make the relay write.
func readBatch(line []byte) (calls []call, batch bool, st readStatus) {
	t := bytes.TrimSpace(line)
	if len(t) == 0 || !json.Valid(t) {
		return nil, false, readUnreadable
	}
	var raws []json.RawMessage
	if t[0] == '[' {
		// The members are read one at a time and counted as they come, so a body of a million of them is refused at the
		// bound without being held (json.Valid has read it once already, and found it whole).
		dec := json.NewDecoder(bytes.NewReader(t))
		if _, err := dec.Token(); err != nil {
			return nil, true, readUnreadable
		}
		for dec.More() {
			var r json.RawMessage
			if dec.Decode(&r) != nil {
				return nil, true, readUnreadable
			}
			if raws = append(raws, r); len(raws) > MaxBatch {
				return nil, true, readTooMany
			}
		}
		if len(raws) == 0 {
			return nil, true, readUnreadable
		}
		batch = true
	} else {
		raws = []json.RawMessage{t}
	}
	for _, r := range raws {
		var e envelope
		if json.Unmarshal(r, &e) != nil || ambiguousKeys(r) {
			return nil, batch, readUnreadable
		}
		c := call{raw: r, id: e.ID}
		if e.Method != nil {
			c.method = *e.Method
		}
		if c.method == "tools/call" {
			c.isCall = true
			// The tool is the one every server's parser reads (derive/mcp): a call it cannot name is refused.
			if items, bad := mcp.Read(r); bad == 0 && len(items) == 1 && items[0].Kind == mcp.KindToolCall {
				c.tool = items[0].Tool
			}
		}
		calls = append(calls, c)
	}
	return calls, batch, readOK
}

// clientLine decides one client line: what goes to the server, what the client is answered with, what waits. Past the
// first statement the line is its wire form: raw is what the agent sent, and neither it nor any part of it is forwarded.
func (c *stdioConn) clientLine(raw []byte) {
	if c.refuseBusinessLegacy() {
		return
	}
	line, ok := wireLine(raw)
	var (
		calls []call
		batch bool
		st    = readUnreadable
	)
	if ok {
		calls, batch, st = readBatch(line)
	}
	switch st {
	case readTooMany:
		c.refuseTooMany()
		return
	case readUnreadable:
		c.refuseUnreadable()
		return
	case readOK:
	}
	if !batch {
		cl := calls[0]
		if why := c.begin(cl); why != "" {
			c.refuseBusy(cl, why)
			return
		}
		if !cl.isCall {
			_ = c.fw.Write(Frame{ToServer: line})
			return
		}
		c.decideCall(cl, line)
		return
	}
	c.clientBatch(calls)
}

// clientBatch decides a batch member by member (ADR 0126 §4, amended 2026-11-21): each tools/call on its own rule, and no
// member rides on another's decision. What is allowed goes to the server as a batch of its own members; each refused
// member that has an id is answered with an error of its own, in one array, at once; a member the rules ask about is
// held like a single call, on its own goroutine, and goes on alone when a person approves it. The asked members are held
// only after the allowed ones have been written, so an approval never reaches the server before them. Every refused member
// is a line of the record, whether or not it has an id to answer.
func (c *stdioConn) clientBatch(calls []call) {
	var pass, answers []json.RawMessage
	var held []batchItem
	for _, it := range c.s.planBatch(c.server, calls) {
		cl := it.cl
		if it.kind != itemRefuse {
			if why := c.begin(cl); why != "" {
				it = refused(c.server, cl, why)
			}
		}
		switch it.kind {
		case itemPass:
			if cl.isCall {
				c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, it.res.Rule, record.VerdictAllow, record.AuthorityRule, "")
			}
			pass = append(pass, cl.raw)
		case itemAsk:
			held = append(held, it)
		case itemRefuse:
			c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, it.rule, record.VerdictRefused, record.AuthorityRule, it.reason)
			if len(cl.id) > 0 {
				answers = append(answers, it.answer(c.server))
			}
		}
	}
	if len(answers) > 0 {
		_ = c.fw.Write(Frame{ToClient: joinJSON(answers)})
	}
	if len(pass) > 0 {
		_ = c.fw.Write(Frame{ToServer: joinJSON(pass)})
	}
	// Held only now: an approval that comes back at once must not reach the server before the batch's allowed members.
	for _, it := range held {
		c.holdAsk(it.cl, it.res, it.cl.raw)
	}
}

// begin remembers a request's id until its answer comes, so no two requests wait under one id (a call's answer would take
// a list's entry, and no client could tell two answers apart). It returns "" when the request may go on and else the
// reason it may not: the id is waiting already, or the connection has maxInflight waiting. A message with no id, or that is
// not a request, is not remembered.
func (c *stdioConn) begin(cl call) string {
	if cl.method == "" || len(cl.id) == 0 {
		return ""
	}
	k := idKey(cl.id)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, waiting := c.inflight[k]; waiting {
		return "a request with this id is still waiting for its answer"
	}
	if len(c.inflight) >= maxInflight {
		return "too many requests are waiting for their answers, so this one was not passed on"
	}
	c.inflight[k] = struct{}{}
	return ""
}

// end forgets a request's id: its answer came, or the relay answered it itself.
func (c *stdioConn) end(id json.RawMessage) {
	if len(id) == 0 {
		return
	}
	c.mu.Lock()
	delete(c.inflight, idKey(id))
	c.mu.Unlock()
}

// refuseBusy answers a request the connection cannot take now (begin): not passed on, answered with an error of its own, and
// a line of the record.
func (c *stdioConn) refuseBusy(cl call, why string) {
	it := refused(c.server, cl, why)
	c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, it.rule, record.VerdictRefused, record.AuthorityRule, it.reason)
	_ = c.fw.Write(Frame{ToClient: it.answer(c.server)})
}

// refuseUnreadable answers a client line the relay cannot read and records the refusal: it may have been a call, and the
// relay passes nothing it cannot read. A server would answer a parse error, so the client gets one, with no id to name.
func (c *stdioConn) refuseUnreadable() {
	c.s.emitCall(c.pid, c.server, TransportStdio, "", "mcp["+c.server+"].relay", record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
	_ = c.fw.Write(Frame{ToClient: unreadableAnswer})
}

// refuseTooMany answers a batch of more than MaxBatch members, none of which was read or passed: one line of the record,
// and one error with no id, as a batch the server cannot take as a whole is answered (JSON-RPC 2.0 §6).
func (c *stdioConn) refuseTooMany() {
	c.s.emitCall(c.pid, c.server, TransportStdio, "", "mcp["+c.server+"].relay", record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
	_ = c.fw.Write(Frame{ToClient: tooManyAnswer})
}

// decideCall decides one tools/call; an ask waits on its own goroutine, so only it waits. An approval answers the
// question that was asked, and a Deny put in force while it waited is a later rule: the call is decided again, and only
// a Deny stops it, since an Ask would ask the same person the same thing (ADR 0126 §4).
func (c *stdioConn) decideCall(cl call, line []byte) {
	if c.refuseBusinessLegacy() {
		return
	}
	if cl.tool == "" {
		rule := "mcp[" + c.server + "].relay"
		c.s.emitCall(c.pid, c.server, TransportStdio, "", rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
		c.answer(cl, mcptool.Refusal(cl.id, c.server, "", rule, mcptool.ReasonDenied))
		return
	}
	res := c.s.decide(c.server, cl.tool)
	switch res.Decision {
	case mcptool.Allow:
		c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityRule, "")
		_ = c.fw.Write(Frame{ToServer: line})
	case mcptool.Ask:
		c.holdAsk(cl, res, line)
	default:
		c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
		c.answer(cl, mcptool.Refusal(cl.id, c.server, cl.tool, res.Rule, mcptool.ReasonDenied))
	}
}

// answer sends the client the relay's own answer to cl, which the server will not give, and frees cl's id. A notification
// (a call with no id) has no one to be answered: its refusal is the record's line alone, as JSON-RPC answers none.
func (c *stdioConn) answer(cl call, refusal []byte) {
	c.end(cl.id)
	if len(cl.id) > 0 {
		_ = c.fw.Write(Frame{ToClient: refusal})
	}
}

// holdAsk holds one call the rules ask about, on its own goroutine, and sends line (the call alone, whether it came as a
// single message or as a member of a batch) when a person approves it.
func (c *stdioConn) holdAsk(cl call, res mcptool.Result, line []byte) {
	c.s.wg.Add(1)
	go func() {
		defer c.s.wg.Done()
		ok, reason := c.s.askPerson(c.s.ctx, c.server, cl.tool, res.Rule, c.pid)
		if ok {
			if now := c.s.decide(c.server, cl.tool); now.Decision == mcptool.Deny {
				c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, now.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
				c.answer(cl, mcptool.Refusal(cl.id, c.server, cl.tool, now.Rule, mcptool.ReasonDenied))
				return
			}
			c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityHuman, "")
			_ = c.fw.Write(Frame{ToServer: line})
			return
		}
		c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityHuman, reason)
		c.answer(cl, mcptool.Refusal(cl.id, c.server, cl.tool, res.Rule, reason))
	}()
}

// serverLine passes one server line to the client, filtering every tools/list result in it and freeing the ids it answers.
func (c *stdioConn) serverLine(line []byte) {
	if c.s.servers[c.server].BusinessRules {
		return
	}
	c.answered(line)
	_ = c.fw.Write(Frame{ToClient: c.s.filterResponse(c.server, line)})
}

// answered frees the ids of the requests a server line answers: a message with an id and no method, or each such member of
// a batch of them. A message that has a method is the server's own request, whose id is the server's.
func (c *stdioConn) answered(line []byte) {
	c.mu.Lock()
	idle := len(c.inflight) == 0
	c.mu.Unlock()
	t := bytes.TrimSpace(line)
	if idle || len(t) == 0 || (t[0] != '{' && t[0] != '[') {
		return
	}
	var raws []json.RawMessage
	if t[0] == '[' {
		if json.Unmarshal(t, &raws) != nil {
			return
		}
	} else {
		raws = []json.RawMessage{t}
	}
	for _, r := range raws {
		var e envelope
		if json.Unmarshal(r, &e) == nil && e.Method == nil && len(e.ID) > 0 {
			c.end(e.ID)
		}
	}
}

// filterResponse is a server message with every tools/list result in it filtered (denied tools hidden): the message, or
// each member of a batch of them, that has a result with a tools array. It goes by the answer's shape, not by its id: a
// server may spell an id another way (1 for 1.0), answer a list under an id the client no longer waits on, or answer
// before its request was read here, and none of that may show a tool the rules deny. Any other message is returned as it
// came. A server answers a batch of requests with a batch, so the members are read too.
func (s *Service) filterResponse(server string, msg []byte) []byte {
	t := bytes.TrimSpace(msg)
	if len(t) == 0 {
		return msg
	}
	if t[0] == '[' {
		var arr []json.RawMessage
		if json.Unmarshal(t, &arr) != nil {
			return msg
		}
		changed := false
		for i := range arr {
			if out := s.filterResponse(server, arr[i]); !bytes.Equal(out, arr[i]) {
				arr[i], changed = out, true
			}
		}
		if !changed {
			return msg
		}
		b, err := json.Marshal(arr)
		if err != nil {
			return msg
		}
		return b
	}
	if t[0] != '{' {
		return msg
	}
	var e envelope
	if json.Unmarshal(t, &e) != nil || e.Method != nil || len(e.Result) == 0 || !bytes.Contains(e.Result, []byte(`"tools"`)) {
		return msg
	}
	out, names, ok := mcptool.FilterToolsList(e.Result, s.denied(server))
	if !ok {
		s.opts.Logger.Warn("mcp relay: a result with a tools member could not be read as a tools/list; passed as it came", "server", server)
		return msg
	}
	s.noteSeen(server, names)
	if bytes.Equal(out, e.Result) {
		return msg
	}
	var whole map[string]json.RawMessage
	if json.Unmarshal(t, &whole) != nil {
		return msg
	}
	whole["result"] = out
	b, err := json.Marshal(whole)
	if err != nil {
		return msg
	}
	return b
}
