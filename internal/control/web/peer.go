// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
)

// The peer-uid check (F21). The URL token can sit in a browser's argv for its lifetime (a link pasted
// into `google-chrome <link>`; --open passes a one-time code instead, opencode.go), and /proc/<pid>/cmdline is
// world-readable on a box without hidepid, so the token alone does not keep another local
// user out: anyone who reads it could approve, stop, live-block and rewrite the serving user's contracts. Every
// request therefore has to come from a socket the serving user owns. The kernel prints each TCP socket's owner
// in /proc/net/tcp and /proc/net/tcp6 (proc(5)); the client's socket is the row whose local address is the
// request's RemoteAddr and whose remote address is the listener's address. Anything else (no such row, an
// unreadable table, an address the server cannot name) refuses: the check fails closed.

// peerTables are the tables a loopback connection can appear in: an AF_INET client in the first, an AF_INET6 one
// (v4-mapped, since the dashboard listens on 127.0.0.1 only) in the second.
var peerTables = [...]string{"/proc/net/tcp", "/proc/net/tcp6"}

// tcpUIDField is the index of the uid column in a /proc/net/tcp row, counting the leading "sl:" as column 0: sl,
// local_address, rem_address, st, tx_queue:rx_queue, tr:tm->when, retrnsmt, uid (net/ipv4/tcp_ipv4.c
// get_tcp4_sock).
const tcpUIDField = 7

// maxPeerTable bounds one table read; a box with this many sockets is refused rather than read without limit.
const maxPeerTable = 32 << 20

// errPeer marks every refusal of the peer check.
var errPeer = errors.New("the connection's owner could not be shown to be you")

// peerCheck answers whether a request's client socket belongs to the serving user.
type peerCheck struct {
	// read returns one table's contents: os.ReadFile, or a fake table in tests.
	read func(name string) ([]byte, error)
	// euid is the serving user, the only uid let in.
	euid int
}

// procPeer is the real check: the kernel's tables, against this process's effective uid.
func procPeer() peerCheck {
	return peerCheck{read: os.ReadFile, euid: os.Geteuid()}
}

// owns returns nil when the request's client socket is owned by p.euid, and an errPeer error saying why not
// otherwise.
func (p peerCheck) owns(r *http.Request) error {
	client, server, err := connEnds(r)
	if err != nil {
		return fmt.Errorf("%w: %w", errPeer, err)
	}
	for _, name := range peerTables {
		data, err := p.read(name)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && name != peerTables[0] {
				continue // a kernel built without IPv6 has no tcp6 table
			}
			return fmt.Errorf("%w: read %s: %w", errPeer, name, err)
		}
		if len(data) > maxPeerTable {
			return fmt.Errorf("%w: %s is larger than %d bytes", errPeer, name, maxPeerTable)
		}
		uid, found, err := findUID(data, client, server)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", errPeer, name, err)
		}
		if !found {
			continue
		}
		if uid != p.euid {
			return fmt.Errorf("%w: the connection from %s belongs to uid %d, and this dashboard serves uid %d",
				errPeer, client, uid, p.euid)
		}
		return nil
	}
	return fmt.Errorf("%w: no socket %s -> %s in the kernel's tcp tables", errPeer, client, server)
}

// Once per connection. A socket's owner is set when it is made and never changes, so every request on one
// keep-alive connection has the first one's answer; reading the tcp tables (a few MiB on a busy host) for each
// static file, region fetch and status poll bought nothing. Serve gives each connection a connPeer (ConnContext);
// only a pass is kept, so a refusal (another uid, or a table that could not be read just then) is asked again on
// the connection's next request. A request without a connPeer (a handler served some other way) is checked itself.

// connPeerKey is the context key of a connection's connPeer.
type connPeerKey struct{}

// connPeer is one connection's peer check: passed once it has been passed.
type connPeer struct {
	mu     sync.Mutex
	passed bool
}

// withConnPeer is Serve's ConnContext: a fresh, unchecked connPeer for each accepted connection.
func withConnPeer(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connPeerKey{}, &connPeer{})
}

// peerOnce is s.peer(r) asked once per connection: nil without a look when an earlier request on r's connection
// passed.
func (s *Server) peerOnce(r *http.Request) error {
	cp, ok := r.Context().Value(connPeerKey{}).(*connPeer)
	if !ok {
		return s.peer(r)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.passed {
		return nil
	}
	err := s.peer(r)
	cp.passed = err == nil
	return err
}

// connEnds is a request's connection: the client's address and port and the server's own, unmapped.
func connEnds(r *http.Request) (client, server netip.AddrPort, err error) {
	client, err = netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return client, server, fmt.Errorf("client address %q: %w", r.RemoteAddr, err)
	}
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok || la == nil {
		return client, server, errors.New("the server's own address is unknown")
	}
	server, err = netip.ParseAddrPort(la.String())
	if err != nil {
		return client, server, fmt.Errorf("server address %q: %w", la.String(), err)
	}
	return unmap(client), unmap(server), nil
}

// findUID scans one table for the client's side of the connection (local = client, remote = server; the server's
// accepted socket is the same pair reversed, so the order matters) and returns its uid.
func findUID(data []byte, client, server netip.AddrPort) (int, bool, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4<<10), 64<<10)
	sc.Scan() // the column header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) <= tcpUIDField {
			continue
		}
		local, ok := parseTCPAddr(fields[1])
		if !ok || local != client {
			continue
		}
		remote, ok := parseTCPAddr(fields[2])
		if !ok || remote != server {
			continue
		}
		uid, err := strconv.Atoi(fields[tcpUIDField])
		if err != nil || uid < 0 {
			return 0, false, fmt.Errorf("uid %q", fields[tcpUIDField])
		}
		return uid, true, nil
	}
	if err := sc.Err(); err != nil {
		return 0, false, err
	}
	return 0, false, nil
}

// parseTCPAddr reads one "address:port" cell of a /proc/net/tcp row, unmapping a v4-mapped v6 address.
//
// The kernel prints the address with %08X straight off the in-memory __be32 (four of them for v6), so on a
// little-endian host each group of eight hex digits reads back as a little-endian u32 whose bytes are the address
// in network order: 0100007F is 127.0.0.1. Tego releases amd64 and arm64, both little-endian; on a big-endian host
// no row would match and every request would be refused, the safe direction. The port is printed big-endian.
// (internal/runtime/capture/forwarder parses the same cells; the dashboard may not import the runtime.)
func parseTCPAddr(cell string) (netip.AddrPort, bool) {
	host, portText, ok := strings.Cut(cell, ":")
	if !ok || (len(host) != 8 && len(host) != 32) {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw := make([]byte, 0, len(host)/2)
	for i := 0; i < len(host); i += 8 {
		word, err := strconv.ParseUint(host[i:i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		raw = append(raw, byte(word), byte(word>>8), byte(word>>16), byte(word>>24))
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.AddrPort{}, false
	}
	return unmap(netip.AddrPortFrom(addr, uint16(port))), true
}

func unmap(ap netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) }

// notYours is the 403 page for a request the peer check refused: why, and what to do instead.
func (s *Server) notYours(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprintf(w, "tego-control serve: this dashboard serves only the user who started it.\n%v.\n"+
		"Open it as that user, or start your own: tego-control serve.\n", err)
}
