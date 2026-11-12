// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"net/netip"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/thishost"
)

// FileID is a file's identity, st_dev and st_ino as stat(2) reports them.
type FileID struct{ Dev, Ino uint64 }

// Resolved is what the launcher learned about an overlay's entries beyond their text: the addresses each blocked
// host resolves to, and the identity of each blocked absolute program path (stat(2), symlinks followed). A Set
// matches a block by its text alone where these are missing.
type Resolved struct {
	Addrs map[string][]netip.Addr
	Files map[string]FileID
	// Boot maps a block's limit, by DeadlineKey of its key and instant (an until or a from), to its BOOTTIME pin: the
	// launcher pins each the first time it sees it (Clock.Pin). A limit with no pin is judged on the wall clock alone.
	Boot map[string]time.Duration
}

// Set is an overlay compiled for matching at decision time. It is immutable; the launcher builds a new one for
// every change and the supervisor reads the newest through one atomic load. A nil *Set blocks nothing.
type Set struct {
	exec []execBlock
	net  []netBlock
	unix []netBlock
	// fs is every path, read and write block, in the overlay's order, each with the access classes it refuses.
	fs []fsBlock
	// serial is the overlay's, for the launcher's own bookkeeping.
	serial uint64
	// timed is a Set holding a block with an until or a from: only then does a match read the clock.
	timed bool
}

// window is when a block refuses: from its from (zero: now) until its until (zero: no end), each judged on both clocks
// with its pin (ADR 0125 decision 4).
type window struct {
	until, from             time.Time
	untilPin, fromPin       time.Duration
	untilPinned, fromPinned bool
}

// active reports whether a block in window w refuses at c: its until has not Ended (a narrowing ends only when both
// clocks passed it) and its from has Begun (a refusal comes back as soon as either clock reaches it).
func (w window) active(c Clock) bool {
	if !w.until.IsZero() && Ended(w.until, w.untilPin, w.untilPinned, c) {
		return false
	}
	return w.from.IsZero() || Begun(w.from, w.fromPin, w.fromPinned, c)
}

type execBlock struct {
	e Entry
	w window
	// dir is a value ending in "/": every program beneath it.
	dir bool
	// base is a bare program name.
	base bool
	id   FileID
	idOK bool
	// grant is a block that matches by link (MatchLink): it refuses what the running contract grants under the
	// exec.allow entry at its value (Grant), and only where the contract holds no such entry the whole file.
	grant bool
}

type fsBlock struct {
	e   Entry
	w   window
	acc Access
	// path is what the block matches: the entry's value, or (alias) its Real, the path the value led to when the
	// block was written. Both refuse under the entry's own rule.
	path  string
	alias bool
}

type netBlock struct {
	e Entry
	w window
	// host is a DNS name (lower case), addr an address; port 0 is every port.
	host  string
	addr  netip.Addr
	addrs []netip.Addr
	port  uint16
	// loopback is a host RFC 6761 reserves for loopback, which needs no lookup to name this host.
	loopback bool
	// sock is a unix socket path or an @abstract name.
	sock string
}

// Compile is the Set of o's blocks with what the launcher resolved for them. A nil or empty overlay is nil.
func Compile(o *Overlay, res Resolved) *Set {
	if o == nil {
		return nil
	}
	return CompileEntries(o.Blocks, o.Serial, res)
}

// CompileEntries is the Set of entries, an overlay's blocks and an Adjustable run's fence refusals, compiled at the
// overlay's serial with what the launcher resolved for them. No entries is nil.
func CompileEntries(entries []Entry, serial uint64, res Resolved) *Set {
	if len(entries) == 0 {
		return nil
	}
	s := &Set{serial: serial}
	for _, e := range entries {
		w := window{until: e.Until, from: e.From}
		if !e.Until.IsZero() {
			w.untilPin, w.untilPinned = res.Boot[DeadlineKey(e.Key(), e.Until)]
			s.timed = true
		}
		if !e.From.IsZero() {
			w.fromPin, w.fromPinned = res.Boot[DeadlineKey(e.Key(), e.From)]
			s.timed = true
		}
		switch e.Kind {
		case KindExec:
			b := execBlock{e: e, w: w, dir: strings.HasSuffix(e.Value, "/"), base: !strings.HasPrefix(e.Value, "/")}
			b.id, b.idOK = res.Files[e.Value]
			b.grant = e.Match == MatchLink && !b.dir && !b.base
			s.exec = append(s.exec, b)
		case KindNet:
			b := netBlock{e: e, w: w}
			switch {
			case strings.HasPrefix(e.Value, "/"), strings.HasPrefix(e.Value, "@"):
				b.sock = e.Value
				s.unix = append(s.unix, b)
				continue
			}
			b.host, b.addr, b.port = splitDest(e.Value)
			if b.host != "" {
				b.addrs = res.Addrs[b.host]
				b.loopback = thishost.Name(b.host)
			}
			s.net = append(s.net, b)
		case KindPath, KindRead, KindWrite:
			s.fs = append(s.fs, fsBlock{e: e, w: w, acc: e.Kind.Access(), path: e.Value})
			if e.Real != "" && e.Real != e.Value {
				// The block was written through a link (Entry.Real): the supervisor sees the real path, so both
				// spellings refuse, under one rule.
				s.fs = append(s.fs, fsBlock{e: e, w: w, acc: e.Kind.Access(), path: e.Real, alias: true})
			}
		}
	}
	return s
}

// splitDest reads a normalized inet destination: an address, an address and port, a host, or a host and port.
func splitDest(v string) (host string, addr netip.Addr, port uint16) {
	if a, err := netip.ParseAddr(v); err == nil {
		return "", a, 0
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return "", ap.Addr(), ap.Port()
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		if n, err := strconv.Atoi(v[i+1:]); err == nil {
			return v[:i], netip.Addr{}, uint16(n)
		}
	}
	return v, netip.Addr{}, 0
}

// now is the clock a match judges limits on: read once per call, and only when s holds a limit.
func (s *Set) now() Clock {
	if !s.timed {
		return Clock{}
	}
	return readClock()
}

// on reports whether a block in window w refuses at c, the reading now gave.
func (s *Set) on(w window, c Clock) bool { return !s.timed || w.active(c) }

// Serial is the serial of the overlay s was compiled from.
func (s *Set) Serial() uint64 {
	if s == nil {
		return 0
	}
	return s.serial
}

// Fenced is how many of s's entries are fence refusals (Entry.Fence), refusing now or not; 0 for a nil Set. The
// launcher checks the first Set of an Adjustable run with it: a run starts only with every fence refusal in force.
func (s *Set) Fenced() int {
	if s == nil {
		return 0
	}
	n := 0
	count := func(e Entry) {
		if e.Fence {
			n++
		}
	}
	for _, b := range s.exec {
		count(b.e)
	}
	for _, b := range s.net {
		count(b.e)
	}
	for _, b := range s.unix {
		count(b.e)
	}
	for _, b := range s.fs {
		if !b.alias {
			count(b.e)
		}
	}
	return n
}

// The Has* methods are structural: they report that s holds such a block, refusing now or not (one that ended, or one
// still dormant), so the supervisor keeps notifying what a block may refuse later.

// HasExec reports whether s blocks any program.
func (s *Set) HasExec() bool { return s != nil && len(s.exec) > 0 }

// HasNet reports whether s blocks any destination, inet or unix.
func (s *Set) HasNet() bool { return s != nil && (len(s.net) > 0 || len(s.unix) > 0) }

// HasPath reports whether s blocks any path for any access: a path, read or write block.
func (s *Set) HasPath() bool { return s != nil && len(s.fs) > 0 }

// HasAccess reports whether s blocks any path for an access of acc: a read block for AccessRead, a write block for
// AccessWrite, a path block for either.
func (s *Set) HasAccess(acc Access) bool {
	if s == nil {
		return false
	}
	for _, b := range s.fs {
		if b.acc&acc != 0 {
			return true
		}
	}
	return false
}

// Hosts are the host names s blocks, which the launcher resolves.
func (s *Set) Hosts() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, b := range s.net {
		if b.host != "" {
			out = append(out, b.host)
		}
	}
	return out
}

// Grant is what the running contract says of one exec, for a block that matches by link (MatchLink). Asked of such a
// block's value, it reports whether the contract holds a program entry at that path (held) and, if so, whether that
// entry grants this exec (grants): by the exec's spelling, or by the file and the path the value resolved to when the
// run started, which the supervisor fixed then and grants it by for the whole run (execGranted). A nil Grant holds no
// entry.
type Grant func(value string) (held, grants bool)

// MatchExec is the block that names an exec, if one does. names are what the supervisor knows the image by: the
// name its line gives it, the pathname as spelled, the image's own path as its descriptor reads; id is the image's
// identity when idOK. An absolute block matches a name equal to it, or the image whose identity its path had when the
// launcher stat'ed it; a directory block, a name beneath it; a bare name, a name whose last element it is.
//
// A block that matches by link (MatchLink, the rules editor's block for an exec.allow entry removed) is asked of g
// instead: it refuses exactly the execs the running contract grants under the entry at its value, by any name, and
// leaves every other exec to the contract, which grants or refuses it under its own entries as the next run's
// contract would. That holds however the value's links were moved after the run started, since the grant is the one
// the run fixed then. Where g holds no entry at the value (g nil, or a contract with no such entry), the block
// matches as an absolute block does, the whole file, fail closed.
func (s *Set) MatchExec(names []string, id FileID, idOK bool, g Grant) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	c := s.now()
	for _, b := range s.exec {
		if !s.on(b.w, c) {
			continue
		}
		if b.grant && g != nil {
			if held, grants := g(b.e.Value); held {
				if grants {
					return b.e, true
				}
				continue
			}
		}
		if idOK && b.idOK && b.id == id {
			return b.e, true
		}
		for _, n := range names {
			if n == "" {
				continue
			}
			switch {
			case b.base:
				if path.Base(n) == b.e.Value {
					return b.e, true
				}
			case b.dir:
				if strings.HasPrefix(n, b.e.Value) {
					return b.e, true
				}
			case n == b.e.Value:
				return b.e, true
			}
		}
	}
	return Entry{}, false
}

// MatchInet is the block that names an IP destination, if one does: an address block by the address, a host block by
// the declared host the contract's entry matched it under (host, "" when none did) or by any address the host was
// resolved to; a port of 0 in the block matches every port. ap's address is compared unmapped, with no scope id.
//
// A block is on a destination, not a spelling of it, so one that names this host (thishost.Names) refuses whatever
// reaches this host (thishost.Reaches): every loopback address, the unspecified ones, each of the host's own (an AnyIP
// range its local routing table sends here among them), and a datagram to a multicast group, a broadcast address or an
// IPv6 anycast address the host joined, which a local server bound to all interfaces hears too. Matched as written, a
// block on 127.0.0.1:P left 127.0.0.2:P, ::1, 0.0.0.0:P and 224.0.0.1:P open. Refusing them all costs at most another
// local server on the block's port, or a group send on it, as agent.GuardAddrMatches says of the models guard. A block
// on a group, a broadcast or an anycast address names no host, so it refuses that address alone. h is what the running
// host can tell of its addresses; nil knows what an address says by itself.
func (s *Set) MatchInet(ap netip.AddrPort, host string, h thishost.Addrs) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	a := ap.Addr().Unmap().WithZone("")
	here := thishost.Reaches(a, h)
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	c := s.now()
	for _, b := range s.net {
		if !s.on(b.w, c) {
			continue
		}
		if b.port != 0 && b.port != ap.Port() {
			continue
		}
		if b.addr.IsValid() {
			if b.addr == a || here && thishost.Names(b.addr, h) {
				return b.e, true
			}
			continue
		}
		if host != "" && host == b.host || here && b.loopback {
			return b.e, true
		}
		for _, x := range b.addrs {
			if x = x.Unmap().WithZone(""); x == a || here && thishost.Names(x, h) {
				return b.e, true
			}
		}
	}
	return Entry{}, false
}

// MatchUnix is the block that names a unix destination, if one does: a pathname (absolute, cleaned) by equality, an
// abstract name by its bytes after "@".
func (s *Set) MatchUnix(pathname string, abstract []byte) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	c := s.now()
	for _, b := range s.unix {
		if !s.on(b.w, c) {
			continue
		}
		switch {
		case len(abstract) > 0:
			if b.sock == "@"+string(abstract) {
				return b.e, true
			}
		case pathname != "" && b.sock == pathname:
			return b.e, true
		}
	}
	return Entry{}, false
}

// MatchPath is the first block refusing an access of acc whose path is p or an ancestor of it, if one is: a path
// block matches every access, a read block AccessRead and a write block AccessWrite. A block's path is its value and,
// when it has one, its Real. p is absolute and cleaned; an acc of 0 matches nothing.
func (s *Set) MatchPath(p string, acc Access) (Entry, bool) {
	if s == nil || !strings.HasPrefix(p, "/") {
		return Entry{}, false
	}
	c := s.now()
	for _, b := range s.fs {
		if b.acc&acc != 0 && beneath(p, b.path) && s.on(b.w, c) {
			return b.e, true
		}
	}
	return Entry{}, false
}

// MatchWithin is the first block refusing an access of acc whose path lies strictly beneath p, if one is: what a
// rename of the folder p would carry to another name, out of the block's reach. p is absolute and cleaned.
func (s *Set) MatchWithin(p string, acc Access) (Entry, bool) {
	if s == nil || !strings.HasPrefix(p, "/") {
		return Entry{}, false
	}
	c := s.now()
	for _, b := range s.fs {
		if b.acc&acc != 0 && b.path != p && beneath(b.path, p) && s.on(b.w, c) {
			return b.e, true
		}
	}
	return Entry{}, false
}

// beneath reports whether p is dir or lies beneath it; both are absolute and cleaned.
func beneath(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}
