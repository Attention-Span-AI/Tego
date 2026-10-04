// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

const (
	maxPacket     = askproto.MaxPacket
	maxClients    = 32
	clientTimeout = askproto.Timeout
)

// The wire frames are pkg/spec/askproto's, the one definition the broker and its clients share.
type (
	command  = askproto.Command
	response = askproto.Response
)

// server is the run's ask socket. conns is every client connection, true once its command was taken: close leaves
// those open to reply, so an answer that ends the run (the held operation refused, the agent exiting, the broker
// closed) is still told to the person who gave it, never EOF.
type server struct {
	b         *Broker
	dir       *os.File
	listener  *net.UnixListener
	socket    os.FileInfo
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	conns     map[*net.UnixConn]bool
	wg        sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newServer(runDir string, b *Broker) (*server, error) {
	// Open the final directory without following a symlink, the same lookup the client dials by.
	dir, path, err := askclient.OpenSocketDir(runDir)
	if err != nil {
		return nil, fmt.Errorf("%w: open run directory: %v", ErrUnavailable, err)
	}
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("%w: listen: %v", ErrUnavailable, err)
	}
	l.SetUnlinkOnClose(false)
	cleanup := func() { _ = l.Close(); _ = os.Remove(path); _ = dir.Close() }
	// Credential generation must be enabled before a client can queue its
	// first packet; enabling it only on the accepted socket is too late.
	raw, err := l.SyscallConn()
	if err != nil {
		cleanup()
		return nil, err
	}
	var passErr error
	if err = raw.Control(func(fd uintptr) { passErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || passErr != nil {
		cleanup()
		return nil, errors.Join(err, passErr)
	}
	if err = os.Chmod(path, 0600); err != nil {
		cleanup()
		return nil, err
	}
	if os.Geteuid() == 0 {
		if err = os.Chown(path, int(b.opts.UID), -1); err != nil {
			cleanup()
			return nil, err
		}
	}
	st, err := os.Lstat(path)
	if err != nil {
		cleanup()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &server{b: b, dir: dir, listener: l, socket: st, ctx: ctx, cancel: cancel, conns: make(map[*net.UnixConn]bool), done: make(chan struct{})}
	s.wg.Add(1)
	go s.accept()
	go func() { s.wg.Wait(); close(s.done) }()
	return s, nil
}

func (s *server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.listener.AcceptUnix()
		if err != nil {
			s.b.shutdown()
			return
		}
		s.mu.Lock()
		if s.closed || len(s.conns) >= maxClients {
			s.mu.Unlock()
			_ = c.Close()
			continue
		}
		s.conns[c] = false
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handle(c)
	}
}

// identify is who connected to c, as peer.Identify reads and proves it (ADR 0100 (3)): the SO_PEERCRED pid and uid
// and that pid's cgroup and cgroup namespace, read while the connecting process is shown alive. It also returns the
// process's start time, which tells it from a later process under its pid. A variable only so a test can stand in
// for the packet's reading and show the broker judges that reading, not the connect's (export_test.go).
var identify = identifyPeer

func identifyPeer(c *net.UnixConn) (Peer, uint64, error) {
	p, err := peer.Identify(c)
	if err != nil {
		return Peer{}, 0, err
	}
	return Peer{PID: p.PID, UID: uint32(p.UID), Cgroup: p.Cgroup, CgroupNS: p.CgroupNS}, p.StartBootNS, nil
}

func passCred(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var controlErr error
	err = raw.Control(func(fd uintptr) { controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) })
	if err != nil {
		return err
	}
	return controlErr
}

// Credentials are kernel supplied; connection-time credentials alone cannot
// authenticate an inherited or passed connected client socket's later writer.
// The received rights are returned for the caller to close or take; on an
// error every one is closed already.
func packetPeer(oob []byte, flags int) (Peer, []int, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		closeRights(oobRights(oob))
		return Peer{}, nil, ErrProtocol
	}
	var writer Peer
	var rights []int
	credentials := 0
	bad := flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_RIGHTS:
			fds, e := unix.ParseUnixRights(&m)
			rights = append(rights, fds...)
			if e != nil {
				bad = true
			}
		case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_CREDENTIALS:
			cred, e := unix.ParseUnixCredentials(&m)
			if e != nil {
				bad = true
				continue
			}
			credentials++
			writer = Peer{PID: int(cred.Pid), UID: cred.Uid}
		default:
			bad = true
		}
	}
	if bad || credentials != 1 || writer.PID <= 0 {
		closeRights(rights)
		return Peer{}, nil, ErrProtocol
	}
	return writer, rights, nil
}

// oobRights is every descriptor an unparseable control buffer may still have delivered, best effort.
func oobRights(oob []byte) []int {
	var out []int
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	for _, m := range msgs {
		if fds, e := unix.ParseUnixRights(&m); e == nil {
			out = append(out, fds...)
		}
	}
	return out
}

func closeRights(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

// decodeCommand reads a client's packet strictly (askproto.DecodeCommand).
func decodeCommand(data []byte) (command, error) { return askproto.DecodeCommand(data) }

func (s *server) handle(c *net.UnixConn) {
	defer s.wg.Done()
	defer func() { _ = c.Close(); s.mu.Lock(); delete(s.conns, c); s.mu.Unlock() }()
	_ = c.SetDeadline(time.Now().Add(clientTimeout))
	connectionPeer, started, err := identify(c)
	if err != nil || s.b.authorize(connectionPeer) != nil {
		s.reply(c, response{Error: ErrUnauthorized.Error(), Code: askproto.CodeUnauthorized})
		return
	}
	if err = passCred(c); err != nil {
		s.reply(c, response{Error: ErrUnavailable.Error(), Code: askproto.CodeUnavailable})
		return
	}
	peerFD, err := unix.PidfdOpen(connectionPeer.PID, 0)
	if err != nil {
		s.reply(c, response{Error: ErrUnauthorized.Error(), Code: askproto.CodeUnauthorized})
		return
	}
	defer func() { _ = unix.Close(peerFD) }()
	if !pidfdAlive(peerFD) {
		return
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return
	}
	challenge := hex.EncodeToString(nonce[:])
	s.reply(c, response{Ready: challenge})
	buf := make([]byte, maxPacket)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(256*4))
	n, on, flags, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return
	}
	writer, rights, err := packetPeer(oob[:on], flags)
	if err != nil {
		s.reply(c, response{Error: ErrProtocol.Error(), Code: askproto.CodeProtocol})
		return
	}
	if writer.PID != connectionPeer.PID || !pidfdAlive(peerFD) {
		closeRights(rights)
		s.reply(c, response{Error: ErrUnauthorized.Error(), Code: askproto.CodeUnauthorized})
		return
	}
	// The writer's cgroup is read again now that its packet is in: a process can move between cgroups after its
	// connect, and the connect's reading is not the writer's. The same process, by its start time, or nothing.
	now, nowStarted, err := identify(c)
	if err != nil || now.PID != writer.PID || nowStarted != started {
		closeRights(rights)
		s.reply(c, response{Error: ErrUnauthorized.Error(), Code: askproto.CodeUnauthorized})
		return
	}
	writer.Cgroup, writer.CgroupNS = now.Cgroup, now.CgroupNS
	if err = s.b.authorize(writer); err != nil {
		closeRights(rights)
		s.reply(c, response{Error: ErrUnauthorized.Error(), Code: askproto.CodeUnauthorized})
		return
	}
	cmd, err := decodeCommand(buf[:n])
	if err != nil || cmd.Nonce != challenge || !pidfdAlive(peerFD) || (cmd.Alternate != nil) != (len(rights) == 1) || len(rights) > 1 {
		// An alternate is the one descriptor its answer passes; any other packet passes none.
		closeRights(rights)
		s.reply(c, response{Error: ErrProtocol.Error(), Code: askproto.CodeProtocol})
		return
	}
	var alternate *AlternateFile
	if cmd.Alternate != nil {
		alternate, err = newAlternateFile(rights[0])
		if err != nil {
			s.reply(c, response{Error: fmt.Sprintf("%s: %s is not a regular file", ErrBadAlternate, *cmd.Alternate), Code: askproto.CodeBadAlternate})
			return
		}
		alternate.Named = *cmd.Alternate
		defer func() { _ = alternate.Close() }()
	}
	// Taken under the lock close holds while it closes the connections not yet taken: a command is acted on only on
	// a connection close leaves open for its reply.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.conns[c] = true
	s.mu.Unlock()
	r := response{}
	switch cmd.Action {
	case askproto.ActionList:
		pending := s.b.list()
		sort.Slice(pending, func(i, j int) bool { return pending[i].AskID < pending[j].AskID })
		for _, p := range pending {
			r.Pending = append(r.Pending, p.wire())
		}
	case askproto.ActionDetail:
		var req Request
		req, err = s.b.detail(cmd.AskID)
		if err == nil {
			w := req.wire()
			r.Request = &w
		}
	case askproto.ActionAnswer:
		ctx, cancel := context.WithTimeout(s.ctx, clientTimeout)
		defer cancel()
		var decision Decision
		decision, err = s.b.answer(ctx, cmd.AskID, *cmd.Approve, cmd.Remember != nil && *cmd.Remember, alternate, writer)
		if err == nil {
			w := decision.wire()
			r.Decision = &w
		}
	}
	if err != nil {
		r.Error = err.Error()
		r.Code = askproto.Code(err)
	}
	s.reply(c, r)
}

func (s *server) reply(c *net.UnixConn, r response) {
	data, err := json.Marshal(r)
	if err != nil || len(data) > askproto.MaxResponse {
		data = []byte(askproto.ResponseTooLarge)
	}
	_, _ = c.Write(data)
}

// pidfdAlive reports whether the process fd refers to has not exited. poll(2) with a zero timeout fails EINTR when a
// signal is pending (the Go runtime's own SIGURG, often), which is no exit: it is asked again.
func pidfdAlive(fd int) bool {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 0)
		if err == unix.EINTR {
			continue
		}
		return err == nil && n == 0 && fds[0].Revents == 0
	}
}

func (s *server) close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		_ = s.listener.Close()
		// A connection whose command was taken replies first: its work ends with s.ctx and its write by the
		// connection's deadline, and its handler closes it; one still waiting for a command is closed now.
		for c, taken := range s.conns {
			if !taken {
				_ = c.Close()
			}
		}
		s.mu.Unlock()
		select {
		case <-s.done:
		case <-time.After(clientTimeout):
			s.closeErr = errors.New("ask: socket workers did not stop")
		}
		path := fmt.Sprintf("/proc/self/fd/%d/%s", s.dir.Fd(), SocketName)
		if st, err := os.Lstat(path); err == nil && os.SameFile(st, s.socket) {
			s.closeErr = errors.Join(s.closeErr, os.Remove(path))
		}
		s.closeErr = errors.Join(s.closeErr, s.dir.Close())
	})
	return s.closeErr
}

// The client calls are internal/askclient's, here in the broker's own types.

// ListFor lists held requests. expectedPID must come from a verified live launcher pidfd and
// run lock, retained until the request finishes.
func ListFor(ctx context.Context, dir string, expectedPID int) ([]Summary, error) {
	pending, e := askclient.List(ctx, dir, expectedPID)
	var out []Summary
	for _, p := range pending {
		out = append(out, summaryOf(p))
	}
	return out, e
}

// DetailFor is one held request, its target whole.
func DetailFor(ctx context.Context, dir string, expectedPID int, id string) (Request, error) {
	r, e := askclient.Detail(ctx, dir, expectedPID, id)
	if e != nil {
		return Request{}, e
	}
	return requestOf(r), nil
}

// AnswerFor answers one held request. With always, the answer also stands for the rest of the run, for the
// same operation, rule and exact target (ErrNotRememberable, ErrStandingFull or ErrStandingBusy leave the request
// pending, so the caller can answer it once instead).
func AnswerFor(ctx context.Context, dir string, expectedPID int, id string, approve, always bool) (Decision, error) {
	d, e := askclient.Answer(ctx, dir, expectedPID, id, approve, always)
	if e != nil {
		return Decision{}, e
	}
	return decisionOf(d), nil
}

// AlternateFor answers one held file open with an alternate: alt, a file the caller opened when the person named it
// (OpenAlternateFile), is passed to the broker as a descriptor, and the supervisor reopens that descriptor, as the
// agent, in place of the target and delivers it (ADR 0057). The caller keeps alt and closes it. With always the
// alternate also stands for every later request for the same operation, rule and exact target in this run,
// delivering the same file, checked anew each time. ErrNoAlternate, ErrBadAlternate and the "always" errors leave
// the request pending.
func AlternateFor(ctx context.Context, dir string, expectedPID int, id string, alt *AlternateFile, always bool) (Decision, error) {
	if alt == nil {
		return Decision{}, ErrProtocol
	}
	d, e := askclient.Alternate(ctx, dir, expectedPID, id, alt.Named, alt, always)
	if e != nil {
		return Decision{}, e
	}
	return decisionOf(d), nil
}

// wire is r as the socket carries it: every field but Alternates, which never leaves the run.
func (r Request) wire() askproto.Request {
	return askproto.Request{Score: r.Score, GateRule: r.GateRule, AskID: r.AskID, Op: r.Op, Target: r.Target, Target2: r.Target2, Rule: r.Rule,
		Hold: r.Hold, PID: r.PID, TID: r.TID}
}

// requestOf is a request as the socket carried it.
func requestOf(w askproto.Request) Request {
	return Request{Score: w.Score, GateRule: w.GateRule, AskID: w.AskID, Op: w.Op, Target: w.Target, Target2: w.Target2, Rule: w.Rule,
		Hold: w.Hold, PID: w.PID, TID: w.TID}
}

func (s Summary) wire() askproto.Summary {
	return askproto.Summary{Request: s.Request.wire(), TargetTruncated: s.TargetTruncated, RuleTruncated: s.RuleTruncated}
}

func summaryOf(w askproto.Summary) Summary {
	return Summary{Request: requestOf(w.Request), TargetTruncated: w.TargetTruncated, RuleTruncated: w.RuleTruncated}
}

// wire is d as the socket carries it: every field but File, the descriptor, which never leaves the run.
func (d Decision) wire() askproto.Decision {
	return askproto.Decision{AskID: d.AskID, Approved: d.Approved, By: d.By, Reason: d.Reason, AfterS: d.AfterS, Always: d.Always,
		Alternate: d.Alternate, AlternateDev: d.AlternateDev, AlternateIno: d.AlternateIno}
}

func decisionOf(w askproto.Decision) Decision {
	return Decision{AskID: w.AskID, Approved: w.Approved, By: w.By, Reason: w.Reason, AfterS: w.AfterS, Always: w.Always,
		Alternate: w.Alternate, AlternateDev: w.AlternateDev, AlternateIno: w.AlternateIno}
}
