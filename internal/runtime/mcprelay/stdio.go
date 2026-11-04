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

// maxListIDs bounds the tools/list requests one connection has in flight.
const maxListIDs = 64

// stdioConn is one admitted shim: one stdio server's session.
type stdioConn struct {
	s      *Service
	c      net.Conn
	fw     *FrameWriter
	server string
	pid    int // the shim's

	mu    sync.Mutex
	lists map[string]bool // ids of the client's tools/list requests awaiting their result
	once  sync.Once
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
	case len(sv.Command) == 0:
		refuse("server " + hello.Server + " is an HTTP server; its relay is a URL, not a command")
		return
	case !slices.Equal(hello.Argv, sv.Command):
		refuse("the command after -- is not server " + hello.Server + "'s declared command")
		return
	}
	c := &stdioConn{s: s, c: nc, fw: fw, server: hello.Server, pid: pid, lists: map[string]bool{}}
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
			s.opts.Logger.Warn("mcp relay: dropped a line over the size bound", "server", c.server, "from", f.Oversize)
			if f.Oversize == "c" {
				c.refuseUnreadable()
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
	id     json.RawMessage
	method string
	tool   string // a tools/call's tool, "" when unreadable
	isCall bool   // a tools/call request
}

// readCalls reads a client line or POST body in its wire form (wireLine, wireForm): one message or a batch. ok is false
// for one that is not JSON-RPC at all. Only the wire form is read, which is UTF-8: json.Valid takes a bad byte, and
// "delete_file\xff" would pass a deny list as a name no one denied.
func readCalls(line []byte) (calls []call, batch, ok bool) {
	t := bytes.TrimSpace(line)
	if len(t) == 0 || !json.Valid(t) {
		return nil, false, false
	}
	var raws []json.RawMessage
	if t[0] == '[' {
		if json.Unmarshal(t, &raws) != nil || len(raws) == 0 {
			return nil, true, false
		}
		batch = true
	} else {
		raws = []json.RawMessage{t}
	}
	for _, r := range raws {
		var e envelope
		if json.Unmarshal(r, &e) != nil || ambiguousKeys(r) {
			return nil, batch, false
		}
		c := call{id: e.ID}
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
	return calls, batch, true
}

// clientLine decides one client line: what goes to the server, what the client is answered with, what waits. Past the
// first statement the line is its wire form: raw is what the agent sent, and neither it nor any part of it is forwarded.
func (c *stdioConn) clientLine(raw []byte) {
	line, ok := wireLine(raw)
	var (
		calls []call
		batch bool
	)
	if ok {
		calls, batch, ok = readCalls(line)
	}
	if !ok {
		c.refuseUnreadable()
		return
	}
	for _, cl := range calls {
		if cl.method == "tools/list" && len(cl.id) > 0 {
			c.mu.Lock()
			if len(c.lists) < maxListIDs {
				c.lists[string(cl.id)] = true
			}
			c.mu.Unlock()
		}
	}
	if !batch {
		cl := calls[0]
		if !cl.isCall {
			_ = c.fw.Write(Frame{ToServer: line})
			return
		}
		c.decideCall(cl, line)
		return
	}
	// A batch: every tools/call in it must be allowed now, or every member is answered with an error (ADR 0126 §4).
	type decided struct {
		cl  call
		res mcptool.Result
	}
	var ds []decided
	refuse := false
	for _, cl := range calls {
		if !cl.isCall {
			continue
		}
		res := mcptool.Result{Decision: mcptool.Deny, Rule: "mcp[" + c.server + "].relay"}
		if cl.tool != "" {
			res = c.s.decide(c.server, cl.tool)
		}
		ds = append(ds, decided{cl, res})
		if res.Decision != mcptool.Allow {
			refuse = true
		}
	}
	if !refuse {
		for _, d := range ds {
			c.s.emitCall(c.pid, c.server, TransportStdio, d.cl.tool, d.res.Rule, record.VerdictAllow, record.AuthorityRule, "")
		}
		_ = c.fw.Write(Frame{ToServer: line})
		return
	}
	var out []json.RawMessage
	for _, cl := range calls {
		res := mcptool.Result{Decision: mcptool.Deny, Rule: "mcp[" + c.server + "].relay"}
		reason := mcptool.ReasonDenied
		for _, d := range ds {
			if bytes.Equal(d.cl.id, cl.id) && d.cl.tool == cl.tool {
				res = d.res
			}
		}
		if res.Decision == mcptool.Ask {
			reason = "ask-unavailable" // a batch is never held: its calls would wait on one another
		}
		if cl.isCall {
			c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityRule, reason)
		}
		if len(cl.id) > 0 {
			out = append(out, mcptool.Refusal(cl.id, c.server, cl.tool, res.Rule, reason))
		}
	}
	if len(out) > 0 {
		b, _ := json.Marshal(out)
		_ = c.fw.Write(Frame{ToClient: b})
	}
}

// refuseUnreadable answers a client line the relay cannot read and records the refusal: it may have been a call, and the
// relay passes nothing it cannot read. A server would answer a parse error, so the client gets one, with no id to name.
func (c *stdioConn) refuseUnreadable() {
	c.s.emitCall(c.pid, c.server, TransportStdio, "", "mcp["+c.server+"].relay", record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
	_ = c.fw.Write(Frame{ToClient: unreadableAnswer})
}

// decideCall decides one tools/call; an ask waits on its own goroutine, so only it waits. An approval answers the
// question that was asked, and a Deny put in force while it waited is a later rule: the call is decided again, and only
// a Deny stops it, since an Ask would ask the same person the same thing (ADR 0126 §4).
func (c *stdioConn) decideCall(cl call, line []byte) {
	if cl.tool == "" {
		rule := "mcp[" + c.server + "].relay"
		c.s.emitCall(c.pid, c.server, TransportStdio, "", rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
		_ = c.fw.Write(Frame{ToClient: mcptool.Refusal(cl.id, c.server, "", rule, mcptool.ReasonDenied)})
		return
	}
	res := c.s.decide(c.server, cl.tool)
	switch res.Decision {
	case mcptool.Allow:
		c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityRule, "")
		_ = c.fw.Write(Frame{ToServer: line})
	case mcptool.Ask:
		c.s.wg.Add(1)
		go func() {
			defer c.s.wg.Done()
			ok, reason := c.s.askPerson(c.s.ctx, c.server, cl.tool, res.Rule, c.pid)
			if ok {
				if now := c.s.decide(c.server, cl.tool); now.Decision == mcptool.Deny {
					c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, now.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
					_ = c.fw.Write(Frame{ToClient: mcptool.Refusal(cl.id, c.server, cl.tool, now.Rule, mcptool.ReasonDenied)})
					return
				}
				c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictAllow, record.AuthorityHuman, "")
				_ = c.fw.Write(Frame{ToServer: line})
				return
			}
			c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityHuman, reason)
			_ = c.fw.Write(Frame{ToClient: mcptool.Refusal(cl.id, c.server, cl.tool, res.Rule, reason)})
		}()
	default:
		c.s.emitCall(c.pid, c.server, TransportStdio, cl.tool, res.Rule, record.VerdictRefused, record.AuthorityRule, mcptool.ReasonDenied)
		_ = c.fw.Write(Frame{ToClient: mcptool.Refusal(cl.id, c.server, cl.tool, res.Rule, mcptool.ReasonDenied)})
	}
}

// serverLine passes one server line to the client, filtering the result of a tools/list the client asked.
func (c *stdioConn) serverLine(line []byte) {
	_ = c.fw.Write(Frame{ToClient: c.s.filterResponse(c.server, line, c.takeList)})
}

// takeList reports whether id is a tools/list request of this connection's client, and forgets it.
func (c *stdioConn) takeList(id json.RawMessage) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lists[string(id)] {
		delete(c.lists, string(id))
		return true
	}
	return false
}

// filterResponse is a server message with a tools/list result filtered (denied tools hidden), when it answers a
// tools/list (isList) and has a result; any other message is returned as it came.
func (s *Service) filterResponse(server string, msg []byte, isList func(json.RawMessage) bool) []byte {
	t := bytes.TrimSpace(msg)
	if len(t) == 0 || t[0] != '{' {
		return msg
	}
	var e envelope
	if json.Unmarshal(t, &e) != nil || e.Method != nil || len(e.ID) == 0 || len(e.Result) == 0 || !isList(e.ID) {
		return msg
	}
	out, names, ok := mcptool.FilterToolsList(e.Result, s.denied(server))
	if !ok {
		s.opts.Logger.Warn("mcp relay: a tools/list result could not be read; passed as it came", "server", server)
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
