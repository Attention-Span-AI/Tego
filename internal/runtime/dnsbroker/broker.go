// SPDX-License-Identifier: Apache-2.0

// Package dnsbroker provides an opt-in DNS transport for cooperating clients.
// It enforces query policy and authenticates the governed sender. It forwards
// upstream DNSSEC data but does not perform DNSSEC validation or prevent a
// trusted allowed domain from using permitted query names as a data channel.
package dnsbroker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

const SocketName = "dns.sock"
const maxClients = 32

// replyGrace is how long past a request's deadline its connection stays writable, for the one reply packet
// the deadline produced: a SOCK_SEQPACKET write to a client with room in its queue does not block.
const replyGrace = 250 * time.Millisecond

var (
	ErrProtocol     = errors.New("dns broker: invalid or unsupported DNS packet")
	ErrUnauthorized = errors.New("dns broker: unauthorized sender")
	ErrUnavailable  = errors.New("dns broker: unavailable")
)

// Options configures bounded upstream transport, query policy and governed-peer authentication.
// Authorize must verify that this actual PID belongs to the governed run (and
// its permitted descendants). It must be bounded; a matching UID alone is not
// sufficient. Optional Emit records query names/types and verdicts, never bodies.
// Allowed decisions are emitted before dispatch. Completion metadata is emitted
// afterward; a failed completion write withholds the reply but cannot undo an
// upstream query already sent. Emit must be bounded and must not call Close
// synchronously on this broker.
type Options struct {
	// RelayPID permits only this broker process to connect a governed socket
	// through the supervisor. Zero disables the exception; no external PID is accepted.
	RelayPID           int
	UID                uint32
	Policy             *dnspolicy.Policy
	Upstreams          []netip.AddrPort
	MaxParallel, Cache int
	Timeout            time.Duration
	Authorize          func(Peer) error
	Emit               func(Event) error
}

const (
	PhaseDecision   = "decision"
	PhaseCompletion = "completion"
)

// Event distinguishes query admission from subsequent response availability.
type Event struct {
	Phase           string
	Peer            Peer
	Name, Rule      string
	Type            uint16
	Allowed, Cached bool
	Error           string
}
type cacheEntry struct {
	raw             []byte
	fields          []ttlField
	stored, expires time.Time
}
type syscallConnection interface {
	SyscallConn() (syscall.RawConn, error)
}
type Broker struct {
	opts       Options
	dir        *os.File
	path       string
	socket     os.FileInfo
	listener   *net.UnixListener
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	conns      map[*net.UnixConn]struct{}
	cache      map[string]cacheEntry
	slots      chan struct{}
	wg         sync.WaitGroup
	once       sync.Once
	closeErr   error
	done       chan struct{}
	acceptErr  error
	relayPIDFD int
}

func New(runDir string, opts Options) (*Broker, error) {
	absolute, err := filepath.Abs(runDir)
	if err != nil {
		return nil, err
	}
	runDir = absolute
	if opts.RelayPID != 0 && opts.RelayPID != os.Getpid() {
		return nil, fmt.Errorf("%w: relay must be the broker launcher", ErrUnauthorized)
	}
	if opts.Authorize == nil || opts.Policy == nil || len(opts.Upstreams) == 0 || len(opts.Upstreams) > 8 {
		return nil, fmt.Errorf("%w: policy, governed-peer authorization and numeric upstreams are required", ErrUnavailable)
	}
	if opts.MaxParallel == 0 {
		opts.MaxParallel = 8
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.MaxParallel < 1 || opts.MaxParallel > 16 || opts.Cache < 0 || opts.Cache > 512 || opts.Timeout < 10*time.Millisecond || opts.Timeout > 5*time.Second {
		return nil, fmt.Errorf("%w: invalid bounds", ErrUnavailable)
	}
	opts.Upstreams = append([]netip.AddrPort(nil), opts.Upstreams...)
	for _, a := range opts.Upstreams {
		if !a.IsValid() || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
			return nil, fmt.Errorf("%w: invalid upstream", ErrUnavailable)
		}
	}
	dir, path, err := openSocketDir(runDir)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	cleanup := func() { _ = l.Close(); _ = os.Remove(path); _ = dir.Close() }
	if err = setPassCred(l); err != nil {
		cleanup()
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		cleanup()
		return nil, err
	}
	if os.Geteuid() == 0 {
		if err = os.Chown(path, int(opts.UID), -1); err != nil {
			cleanup()
			return nil, err
		}
	}
	st, err := os.Lstat(path)
	if err != nil {
		cleanup()
		return nil, err
	}
	relayPIDFD := -1
	if opts.RelayPID != 0 {
		relayPIDFD, err = unix.PidfdOpen(opts.RelayPID, 0)
		if err != nil {
			cleanup()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{relayPIDFD: relayPIDFD, opts: opts, dir: dir, path: path, socket: st, listener: l, ctx: ctx, cancel: cancel, conns: map[*net.UnixConn]struct{}{}, cache: map[string]cacheEntry{}, slots: make(chan struct{}, opts.MaxParallel), done: make(chan struct{})}
	b.wg.Add(1)
	go b.accept()
	return b, nil
}

func openSocketDir(dirName string) (*os.File, string, error) {
	// A cooperating governed client needs only a stable pathname handle, not
	// directory-read authority over the private run's ledger contents.
	fd, err := unix.Open(dirName, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	dir := os.NewFile(uintptr(fd), dirName)
	return dir, fmt.Sprintf("/proc/self/fd/%d/%s", fd, SocketName), nil
}

// Available means the owned accept loop remains live; nil and closed brokers
// cannot advertise a cooperating DNS capability.
func (b *Broker) Available() bool {
	if b == nil {
		return false
	}
	select {
	case <-b.done:
		return false
	default:
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.closed
}

func (b *Broker) Endpoint() string { return filepath.Join(b.dir.Name(), SocketName) }

// Run monitors the owned listener until cancellation. Unexpected listener loss
// is a startup/runtime failure, rather than an active broker capability.
func (b *Broker) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return b.Close()
	case <-b.done:
		b.mu.Lock()
		err, closed := b.acceptErr, b.closed
		b.mu.Unlock()
		if closed {
			return nil
		}
		return fmt.Errorf("%w: listener: %w", ErrUnavailable, err)
	}
}

func (b *Broker) accept() {
	defer b.wg.Done()
	defer close(b.done)
	for {
		c, err := b.listener.AcceptUnix()
		if err != nil {
			b.mu.Lock()
			b.acceptErr = err
			b.mu.Unlock()
			return
		}
		b.mu.Lock()
		if b.closed || len(b.conns) >= maxClients {
			b.mu.Unlock()
			_ = c.Close()
			continue
		}
		b.conns[c] = struct{}{}
		b.wg.Add(1)
		b.mu.Unlock()
		go b.handle(c)
	}
}

func (b *Broker) authorized(p Peer) error {
	if p.UID != b.opts.UID || p.PID <= 0 {
		return ErrUnauthorized
	}
	return b.opts.Authorize(p)
}

func (b *Broker) handle(c *net.UnixConn) {
	defer b.wg.Done()
	defer func() { _ = c.Close(); b.mu.Lock(); delete(b.conns, c); b.mu.Unlock() }()
	// One deadline from the handler's start bounds the read and the upstream exchange; the connection keeps
	// replyGrace past it so the reply that deadline produces (an answer, or SERVFAIL when it ran out) can
	// still be written. The exchange used to get a fresh Timeout of its own after the decision was recorded,
	// so a late answer was recorded as completed and then failed the connection's earlier write deadline.
	deadline := time.Now().Add(b.opts.Timeout)
	_ = c.SetDeadline(deadline.Add(replyGrace))
	peer, err := socketPeer(c)
	if err != nil {
		return
	}
	relayed := false
	if b.authorized(peer) != nil {
		// The production Unix relay connects as the task's effective UID but
		// retains the launcher's TGID. Only our pinned launcher may do this. RelayPID 0 disables it rather
		// than match a peer whose pid reads 0, one outside this PID namespace.
		if b.opts.RelayPID <= 0 || peer.PID != b.opts.RelayPID || peer.UID != b.opts.UID || !pidfdAlive(b.relayPIDFD) {
			return
		}
		relayed = true
	}
	pidfd, err := unix.PidfdOpen(peer.PID, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(pidfd) }()
	if !pidfdAlive(pidfd) || setPassCred(c) != nil {
		return
	}
	raw := make([]byte, MaxPacket)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(256*4))
	n, on, flags, _, err := c.ReadMsgUnix(raw, oob)
	if err != nil {
		return
	}
	sender, err := packetPeer(oob[:on], flags)
	if err != nil || !pidfdAlive(pidfd) || !relayed && sender != peer {
		return
	}
	senderPIDFD := pidfd
	if relayed && sender != peer {
		senderPIDFD, err = unix.PidfdOpen(sender.PID, 0)
		if err != nil {
			return
		}
		defer func() { _ = unix.Close(senderPIDFD) }()
	}
	// SCM credentials authenticate the actual writer. A relay connector is
	// never authority for a packet from an outside or differently owned task.
	if !pidfdAlive(senderPIDFD) || b.authorized(sender) != nil || !pidfdAlive(senderPIDFD) {
		return
	}
	raw = raw[:n]
	q, err := queryMessage(raw)
	if err != nil {
		return
	}
	name := q.Questions[0].Name.String()
	typ := uint16(q.Questions[0].Type)
	rule, allow := b.opts.Policy.Match(name, typ)
	event := Event{Phase: PhaseDecision, Peer: sender, Name: name, Type: typ, Rule: rule, Allowed: allow}
	if !allow {
		if b.emit(event) == nil {
			_, _ = c.Write(errorReply(q, dnsmessage.RCodeRefused))
		}
		return
	}
	if b.emit(event) != nil {
		return // no upstream work before the admission decision is durable
	}
	event.Phase = PhaseCompletion
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		event.Error = "parallel limit"
		if b.emit(event) == nil {
			_, _ = c.Write(errorReply(q, dnsmessage.RCodeServerFailure))
		}
		return
	}
	ctx, cancel := context.WithDeadline(b.ctx, deadline)
	defer cancel()
	response, cached, err := b.exchange(ctx, raw, q)
	event.Cached = cached
	if err != nil {
		event.Error = "upstream unavailable"
		response = errorReply(q, dnsmessage.RCodeServerFailure)
	}
	if b.emit(event) != nil {
		return
	}
	// Only the broker's own cancellation withholds the reply; the request running out of time is the
	// SERVFAIL above, which the client gets rather than EOF.
	if b.ctx.Err() != nil || !pidfdAlive(pidfd) || !pidfdAlive(senderPIDFD) {
		return
	}
	_, _ = c.Write(response)
}

func (b *Broker) emit(e Event) error {
	if b.opts.Emit == nil {
		return nil
	}
	return b.opts.Emit(e)
}

func (b *Broker) exchange(ctx context.Context, raw []byte, q dnsmessage.Message) ([]byte, bool, error) {
	key := string(raw[2:])
	now := time.Now()
	if b.opts.Cache > 0 {
		b.mu.Lock()
		entry, ok := b.cache[key]
		if ok && !now.Before(entry.expires) {
			delete(b.cache, key)
			ok = false
		}
		b.mu.Unlock()
		if ok {
			out := bytes.Clone(entry.raw)
			age := uint32((now.Sub(entry.stored) + time.Second - 1) / time.Second)
			for _, f := range entry.fields {
				ttl := uint32(0)
				if f.value > age {
					ttl = f.value - age
				}
				binary.BigEndian.PutUint32(out[f.offset:f.offset+4], ttl)
			}
			binary.BigEndian.PutUint16(out, q.ID)
			return out, true, nil
		}
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, false, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	request := bytes.Clone(raw)
	copy(request, idBytes[:])
	var last error
	for i, server := range b.opts.Upstreams {
		// Reserve a fair portion of the bounded overall deadline for each
		// configured resolver, so a silent first resolver cannot consume
		// the entire budget and prevent fallback to a healthy resolver.
		attempt := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			attempt, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(b.opts.Upstreams)-i))
		}
		out, m, fields, err := upstream(attempt, server, request, id, q.Questions[0])
		cancel()
		if err != nil {
			last = err
			continue
		}
		binary.BigEndian.PutUint16(out, q.ID)
		if b.opts.Cache > 0 && m.RCode == dnsmessage.RCodeSuccess && !m.Truncated && len(m.Answers) > 0 && len(fields) > 0 {
			ttl := uint32(300)
			for _, f := range fields {
				if f.value < ttl {
					ttl = f.value
				}
			}
			if ttl > 0 {
				stored := time.Now()
				b.mu.Lock()
				if len(b.cache) >= b.opts.Cache {
					for k, e := range b.cache {
						if !stored.Before(e.expires) {
							delete(b.cache, k)
						}
					}
				}
				if len(b.cache) < b.opts.Cache {
					b.cache[key] = cacheEntry{bytes.Clone(out), fields, stored, stored.Add(time.Duration(ttl) * time.Second)}
				}
				b.mu.Unlock()
			}
		}
		return out, false, nil
	}
	return nil, false, last
}

func upstream(ctx context.Context, server netip.AddrPort, request []byte, id uint16, q dnsmessage.Question) ([]byte, dnsmessage.Message, []ttlField, error) {
	var empty dnsmessage.Message
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", server.String())
	if err != nil {
		return nil, empty, nil, err
	}
	defer func() { _ = conn.Close() }()
	if at, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(at)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err = conn.Write(request); err != nil {
		return nil, empty, nil, err
	}
	for i := 0; i < 32; i++ {
		raw := make([]byte, MaxPacket+1)
		n, e := conn.Read(raw)
		if e != nil {
			return nil, empty, nil, e
		}
		raw = raw[:n]
		m, fields, e := responseMessage(raw, id, q)
		if e != nil {
			continue
		}
		if m.Truncated {
			return upstreamTCP(ctx, server, request, id, q)
		}
		return raw, m, fields, nil
	}
	return nil, empty, nil, ErrProtocol
}

func upstreamTCP(ctx context.Context, server netip.AddrPort, request []byte, id uint16, q dnsmessage.Question) ([]byte, dnsmessage.Message, []ttlField, error) {
	var empty dnsmessage.Message
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, empty, nil, err
	}
	defer func() { _ = conn.Close() }()
	if at, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(at)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	framed := make([]byte, 2, len(request)+2)
	binary.BigEndian.PutUint16(framed, uint16(len(request)))
	framed = append(framed, request...)
	if _, err = io.Copy(conn, bytes.NewReader(framed)); err != nil {
		return nil, empty, nil, err
	}
	var length [2]byte
	if _, err = io.ReadFull(conn, length[:]); err != nil {
		return nil, empty, nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 12 || n > MaxPacket {
		return nil, empty, nil, ErrProtocol
	}
	raw := make([]byte, n)
	if _, err = io.ReadFull(conn, raw); err != nil {
		return nil, empty, nil, err
	}
	m, fields, err := responseMessage(raw, id, q)
	if err == nil && m.Truncated {
		err = ErrProtocol
	}
	return raw, m, fields, err
}

func (b *Broker) Close() error {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.cancel()
		err := b.listener.Close()
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		for c := range b.conns {
			_ = c.Close()
		}
		b.mu.Unlock()
		b.wg.Wait()
		st, e := os.Lstat(b.path)
		if e == nil && os.SameFile(st, b.socket) {
			e = os.Remove(b.path)
		}
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
		var relayErr error
		if b.relayPIDFD >= 0 {
			relayErr = unix.Close(b.relayPIDFD)
		}
		b.closeErr = errors.Join(err, e, b.dir.Close(), relayErr)
	})
	return b.closeErr
}
