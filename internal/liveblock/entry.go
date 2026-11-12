// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Kind is what a live block names: a program, a destination, or a path for every file action, its reads only, or its
// changes only.
type Kind string

// The kinds.
const (
	// KindExec is a program: an absolute path (that file, by any name the supervisor sees for it and by its
	// identity), a directory ending in "/" (every program beneath it), or a bare name ("curl": any program run by
	// that file name).
	KindExec Kind = "exec"
	// KindNet is a destination: host[:port], IP[:port] (IPv6 with a port in brackets), a unix socket path, or an
	// abstract unix name ("@name"). No port means every port.
	KindNet Kind = "net"
	// KindPath is a path and everything beneath it, for the file opens and changes the supervisor decides: both its
	// reads and its changes (AccessRead and AccessWrite).
	KindPath Kind = "path"
	// KindRead is a path and everything beneath it, for its reads only (AccessRead): an open whose access mode reads
	// (O_RDONLY, O_RDWR, O_PATH), and a rename or a hard link with an end at or under it, which would give the file a
	// name outside the block. It refuses no write-only open and no other change. Removing a read from the contract
	// (fs.deny_read added) maps to it.
	KindRead Kind = "read"
	// KindWrite is a path and everything beneath it, for its changes only (AccessWrite): an open for writing, a
	// create, an unlink, a rename or a link at either end, a mkdir, a symlink's own name, a truncate and an attribute
	// change. It refuses no plain read. Removing fs.write, or adding fs.deny_write, maps to it.
	KindWrite Kind = "write"
)

// Kinds lists the kinds the run page's Block now form offers, in that order. ParseKind accepts every kind of
// AllKinds; the read and write kinds are placed by the Rules page's narrowings and `tego block`.
var Kinds = []Kind{KindExec, KindNet, KindPath}

// AllKinds lists every kind an overlay may hold, in the order they were added. A launcher built before a kind was
// added reads an overlay holding it as invalid (its Normalize refuses the kind), so it keeps the blocks it last put in
// force and records live-block-unreadable: an older reader fails closed, never open.
var AllKinds = []Kind{KindExec, KindNet, KindPath, KindRead, KindWrite}

// Access is the class of a file action a path block is matched for: a read, a change, or (a move) both.
type Access uint8

// The access classes.
const (
	// AccessRead is an action that reads a file: an open whose access mode reads.
	AccessRead Access = 1 << iota
	// AccessWrite is an action that changes the file system: every fs action but a pure read.
	AccessWrite
)

// Access is the classes of file action a block of kind refuses: none for exec and net.
func (k Kind) Access() Access {
	switch k {
	case KindPath:
		return AccessRead | AccessWrite
	case KindRead:
		return AccessRead
	case KindWrite:
		return AccessWrite
	}
	return 0
}

// MaxValueBytes bounds an entry's value, the kernel's PATH_MAX.
const MaxValueBytes = 4096

// maxSunPath is sun_path's size: a unix socket name longer than it names nothing a connect can reach.
const maxSunPath = 108

// ErrInvalid is an entry, or an overlay, this package does not accept.
var ErrInvalid = errors.New("liveblock: invalid")

// Entry is one live block: what it names, who added it and when.
type Entry struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	// By names who added it as the writer saw itself: "uid:<uid> pid:<pid> <via>", via "cli" or "dashboard".
	By string `json:"by"`
	// At is when the writer added it.
	At time.Time `json:"at"`
	// Until is when the block ends by itself (ADR 0125 decision 4): from then on it refuses nothing, and the launcher
	// writes its live-block-expired line. Zero is no end: the rest of the run.
	Until time.Time `json:"until,omitzero"`
	// From is when a dormant block refuses again: an unblock with a time limit keeps the block with From at the
	// limit, and it refuses nothing before then. On a fence refusal (Fence) it is when a lift with a limit ends. Zero
	// is a block in force now.
	From time.Time `json:"from,omitzero"`
	// Real is, on a path, read or write block written through a link, the path its value led to when the writer added
	// it (RealPath): the supervisor matches a file action by where the task's lookup lands, so a block on
	// ~/link/secret would otherwise never match /data/secret. The Set refuses both spellings under the value's rule.
	// "" when the value is its own real path, or could not be resolved. An overlay that holds one is VersionReal, so
	// a writer built before it refuses the file rather than drop the real path without notice, and it is written only
	// to a run whose launcher reads it (TakesReal).
	Real string `json:"real,omitempty"`
	// Match is how an exec block on an absolute program path (not a folder) matches the file its value leads to. ""
	// (the default) matches that file by its identity, under every name it has: a block a person places by a path
	// (`tego block`, Block now) refuses the whole file, since Tego cannot know whether a multi-call program pins what
	// it does to the name it is run by. MatchLink refuses what the running contract grants under the exec.allow entry
	// at the value (Set.MatchExec, Grant): the file and the path the value resolved to when the run started, by any
	// name that reaches it there, so another name of a multi-call file is left to the contract. The rules editor's
	// "Also apply now" and Apply now place it when that entry is removed (ADR 0124, amended 2026-11-11). Where the
	// running contract holds no entry at the value it matches the whole file. An overlay that holds one is VersionLink,
	// written only to a run whose launcher reads it (TakesLink); for any other run the writer places the whole-file
	// block instead (AddLink's caller).
	Match string `json:"match,omitempty"`
	// Fence marks a refusal of an Adjustable run's fence entry that the launcher made from its own state (ADR 0125
	// decision 5). It never comes from the overlay file: a writer cannot name one.
	Fence bool `json:"-"`
	// FenceOf is, on a fence refusal of another name of an exec entry (a helper image the kernel layers run because
	// the entry is granted, or the program name an exec.deny entry named), the entry's own value: the refusal then
	// carries the entry's rule, live.fence[exec:<FenceOf>], never one the fence does not hold. "" otherwise.
	FenceOf string `json:"-"`
}

// MatchLink is the Match of an exec block that refuses what the running contract grants under the exec.allow entry
// at its value (Entry.Match).
const MatchLink = "link"

// linkable reports whether a block of kind on value (normalized) can match by link (MatchLink): an exec block on an
// absolute program path, not a folder.
func linkable(kind Kind, value string) bool {
	return kind == KindExec && strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/")
}

// Key is the entry's identity in the overlay: its kind and value, "exec:/usr/bin/curl".
func (e Entry) Key() string { return Key(e.Kind, e.Value) }

// Rule is the rule a refusal under the entry carries: live.block[<kind>:<value>], or live.fence[<kind>:<value>] for
// a fence refusal, so the ledger never names a live block for what the fence refused.
func (e Entry) Rule() string {
	if e.Fence {
		if e.FenceOf != "" {
			return FenceRule(e.Kind, e.FenceOf)
		}
		return FenceRule(e.Kind, e.Value)
	}
	return Rule(e.Kind, e.Value)
}

// Key is the identity of a block of kind on value (normalized).
func Key(kind Kind, value string) string { return string(kind) + ":" + value }

// Rule is the rule name of a refusal under a block of kind on value (normalized).
func Rule(kind Kind, value string) string { return "live.block[" + Key(kind, value) + "]" }

// FenceRule is the rule name of a fence entry of kind on value (normalized): live.fence[<kind>:<value>], carried by a
// refusal under the entry and by an action allowed only because it is lifted (ADR 0125 decision 9).
func FenceRule(kind Kind, value string) string { return "live.fence[" + Key(kind, value) + "]" }

// LiftRule is the rule name a refused lift of kind on value carries when it names no fence entry of the run (a Locked
// run, a lift outside the fence, a forged lift for another path): live.lift[<kind>:<value>], the request, so the
// ledger never names a live.fence[...] rule that run_start.live_fence does not list.
func LiftRule(kind Kind, value string) string { return "live.lift[" + Key(kind, value) + "]" }

// FenceKinds are the kinds a fence entry, and so a lift or a restore, may be of (ADR 0125 decision 2).
var FenceKinds = []Kind{KindRead, KindNet, KindExec}

// ParseKind reads a kind's name.
func ParseKind(s string) (Kind, error) {
	for _, k := range AllKinds {
		if string(k) == s {
			return k, nil
		}
	}
	return "", fmt.Errorf("%w: kind %q is not exec, net, path, read or write", ErrInvalid, s)
}

// Normalize is value as an entry of kind holds it, or why it is not one. Every spelling of one block normalizes to
// one value, so adding it twice adds it once and removing it by another spelling removes it.
func Normalize(kind Kind, value string) (string, error) {
	v := strings.TrimSpace(value)
	if err := plain(v); err != nil {
		return "", err
	}
	switch kind {
	case KindExec:
		return normalizeExec(v)
	case KindNet:
		return normalizeNet(v)
	case KindPath, KindRead, KindWrite:
		if !strings.HasPrefix(v, "/") {
			return "", fmt.Errorf("%w: path %q is not absolute", ErrInvalid, v)
		}
		return filepath.Clean(v), nil
	}
	return "", fmt.Errorf("%w: kind %q is not exec, net, path, read or write", ErrInvalid, kind)
}

// plain refuses an empty value, one past MaxValueBytes, and one holding anything but printable UTF-8.
func plain(v string) error {
	switch {
	case v == "":
		return fmt.Errorf("%w: empty value", ErrInvalid)
	case len(v) > MaxValueBytes:
		return fmt.Errorf("%w: value of %d bytes, more than %d", ErrInvalid, len(v), MaxValueBytes)
	case !utf8.ValidString(v):
		return fmt.Errorf("%w: value is not UTF-8", ErrInvalid)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: value holds a control character", ErrInvalid)
		}
	}
	return nil
}

// normalizeExec is an exec value: an absolute path, cleaned, keeping one trailing "/" for a directory; or a bare
// program name, which holds no "/" and no space.
func normalizeExec(v string) (string, error) {
	if strings.HasPrefix(v, "/") {
		p := filepath.Clean(v)
		if strings.HasSuffix(v, "/") && p != "/" {
			p += "/"
		}
		return p, nil
	}
	if strings.ContainsAny(v, "/ \t") || v == "." || v == ".." || len(v) > 255 {
		return "", fmt.Errorf("%w: program %q is neither an absolute path nor a bare program name", ErrInvalid, v)
	}
	return v, nil
}

// normalizeNet is a destination: a unix socket path or abstract name, or a host or address with an optional port,
// after an optional tcp://, udp:// or unix: prefix (the contract's own spellings). A block names a destination on
// every protocol, so the prefix is dropped.
func normalizeNet(v string) (string, error) {
	for _, pre := range []string{"tcp://", "udp://", "unix:"} {
		if strings.HasPrefix(strings.ToLower(v), pre) {
			v = v[len(pre):]
			break
		}
	}
	switch {
	case strings.HasPrefix(v, "/"):
		p := filepath.Clean(v)
		if len(p) >= maxSunPath {
			return "", fmt.Errorf("%w: unix socket path of %d bytes names no socket (sun_path holds %d)", ErrInvalid, len(p), maxSunPath-1)
		}
		return p, nil
	case strings.HasPrefix(v, "@"):
		if len(v) < 2 || len(v) >= maxSunPath {
			return "", fmt.Errorf("%w: abstract unix name %q", ErrInvalid, v)
		}
		return v, nil
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().WithZone("").String(), nil
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		if ap.Port() == 0 {
			return "", fmt.Errorf("%w: port 0 in %q; leave the port out to block every port", ErrInvalid, v)
		}
		return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()).String(), nil
	}
	host, port := v, ""
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		host, port = v[:i], v[i+1:]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !hostName(host) {
		return "", fmt.Errorf("%w: %q is not a host[:port], an IP[:port], a unix socket path or an @abstract name", ErrInvalid, v)
	}
	if port == "" && strings.Contains(v, ":") {
		return "", fmt.Errorf("%w: empty port in %q", ErrInvalid, v)
	}
	if port == "" {
		return host, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", fmt.Errorf("%w: port %q is not 1 to 65535", ErrInvalid, port)
	}
	return host + ":" + port, nil
}

// hostName reports whether h is a DNS name: dot-separated labels of letters, digits, hyphens and underscores, none
// empty or longer than 63, 253 in all, with a letter somewhere (so "300.1.2.3" is no name).
func hostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	letter := false
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
				letter = true
			case c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return letter
}
