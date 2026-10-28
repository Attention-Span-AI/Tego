// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// liveFence is one Compile call's Adjustable state between the transform (compileLive), which runs before the fs, net
// and exec tables are built, and the marking (markLive), which runs once they are.
type liveFence struct {
	entries []LiveEntry
	// bad marks the entries a finding already refused, so markLive does not report them again.
	bad []bool
}

// compileLive is ADR 0125 decisions 1, 2, 6 and 7 at compile. With no live: key, or Locked with no fence, it changes
// nothing, and RuleTable.Live stays nil. Under live.mode: adjustable it checks the tier and every fence entry, and
// swaps k.c for a copy of the contract with the fence merged in as ordinary entries, which every kernel layer then
// compiles from: a read entry takes out the deny_read entry it names (reads are allowed wherever no deny_read refuses
// them, SEMANTICS §1, so a read entry always names one), a net entry is appended to net.allow, and an exec entry takes
// out the exec.deny entry naming its program and, under an exec allow-list, is appended to exec.allow. The contract
// the table records (RuleTable.Contract) and contract_hash stay the contract as written, live: key included.
//
// It runs after ownState, which the read entries are checked against, and before builtInDenyReadPatterns and fs.
func (k *compiler) compileLive() *liveFence {
	l := k.c.Live
	if l == nil {
		return nil
	}
	switch l.Mode {
	case "", LiveLocked:
		if l.Fence.entries() > 0 {
			k.ds.errorf(k.pos("live.fence"), CodeLiveLockedFence, "live.fence lists what Tego may grant while the run runs, which only live.mode: adjustable does; under locked the kernel enforces the whole contract and nothing loosens while it runs").
				fix("set live.mode: adjustable (docs/user/live-modes.md weighs the two), or remove live.fence")
		}
		return nil
	case LiveAdjustable:
	default:
		k.ds.errorf(k.pos("live.mode"), CodeLiveMode, "live.mode must be locked or adjustable, got %q", string(l.Mode)).
			fix("write live.mode: locked (the default) or live.mode: adjustable")
		return nil
	}
	k.liveTier()
	if k.c.IOUring {
		// ADR 0125 decision 6: every path to a fence entry passes the supervisor. A ring's IORING_OP_CONNECT, OPENAT
		// and SENDMSG never reach the seccomp listener, and where a root tier's plane admits io_uring the kernel
		// layers hold the run to contract plus fence, so an unlifted fence entry would be reachable from the start.
		k.ds.errorf(k.pos("io_uring"), CodeSchema, "live.mode: adjustable requires io_uring disabled: a ring's connects and opens never reach the supervisor that refuses the fence's entries").
			fix("drop io_uring: true, or set live.mode: locked")
	}
	f := l.Fence
	if n := f.entries(); n > MaxLiveFence {
		k.ds.errorf(k.pos("live.fence"), CodeLiveTooMany, "live.fence holds %d entries, more than %d", n, MaxLiveFence).
			fix("keep the fence to the access you may grant while the run runs; grant the rest in the contract")
		k.rt.Live = &LiveTable{Mode: LiveAdjustable}
		return nil
	}
	cp := *k.c
	cp.origins = maps.Clone(k.c.origins)
	if cp.FS != nil {
		fs := *cp.FS
		cp.FS = &fs
	}
	if cp.Net != nil {
		ns := *cp.Net
		ns.Allow = slices.Clone(ns.Allow)
		cp.Net = &ns
	}
	if cp.Exec != nil {
		es := *cp.Exec
		es.Allow = slices.Clone(es.Allow)
		cp.Exec = &es
	}
	lf := &liveFence{}
	seen := map[string]bool{}
	add := func(e LiveEntry, ok bool) {
		key := e.Kind + "\x00" + e.Value
		if ok && seen[key] {
			k.ds.errorf(e.Pos, CodeLiveFenceEntry, "live.fence.%s %q is listed twice", e.Kind, e.Raw).fix("remove one")
			ok = false
		}
		seen[key] = true
		lf.entries = append(lf.entries, e)
		lf.bad = append(lf.bad, !ok)
	}
	var removeDeny []int
	if f != nil {
		for i, raw := range f.Read {
			e, deny, ok := k.liveRead(raw, k.pos("live.fence.read."+strconv.Itoa(i)))
			removeDeny = append(removeDeny, deny...)
			add(e, ok)
		}
		for i, raw := range f.Net {
			e, ok := k.liveNet(&cp, raw, k.pos("live.fence.net."+strconv.Itoa(i)))
			add(e, ok)
		}
		var removeExec []int
		for i, raw := range f.Exec {
			e, deny, ok := k.liveExec(&cp, raw, k.pos("live.fence.exec."+strconv.Itoa(i)))
			removeExec = append(removeExec, deny...)
			add(e, ok)
		}
		for i, e := range lf.entries {
			if e.Kind == LiveKindExec && !lf.bad[i] {
				k.liveExecMeetsRead(lf, i, []string{e.Value})
			}
		}
		if len(f.Read) > 0 {
			k.liveHeldReads(&cp)
		}
		if len(removeDeny) > 0 {
			cp.FS.DenyRead = dropEntries(cp.origins, "fs.deny_read", cp.FS.DenyRead, removeDeny)
			// deny_read: nil is the built-in list, [] turns it off (R6): a fence that takes out every entry the
			// person wrote leaves the built-in credential refusals in force.
			if len(cp.FS.DenyRead) == 0 {
				cp.FS.DenyRead = nil
			}
		}
		if len(removeExec) > 0 {
			// A present empty deny list stays non-nil: its presence is the section's mode (ADR 0048 (1)).
			cp.Exec.Deny = dropEntries(cp.origins, "exec.deny", cp.Exec.Deny, removeExec)
		}
	}
	k.c = &cp
	k.rt.Live = &LiveTable{Mode: LiveAdjustable, Entries: lf.entries, SHA256: liveDigest(lf.entries)}
	return lf
}

// liveTier refuses Adjustable where every run of the table is held at tier landlock (the contract or the machine pins
// it, or `tego run --tier landlock`) or in an --observe run (LiveTierCheck). A run whose auto tier resolves to
// landlock is the launcher's to refuse: compile cannot know where it lands.
func (k *compiler) liveTier() {
	var err error
	switch {
	case k.o.observe:
		err = LiveTierCheck(backend.TierObserve, true)
	case k.heldAt(backend.TierLandlock) || k.o.tierFlag == backend.TierLandlock:
		err = LiveTierCheck(backend.TierLandlock, false)
	}
	if err == nil {
		return
	}
	at := k.pos("live.mode")
	if pin := backend.Tier(k.c.Tier); pin == backend.TierLandlock {
		at = k.pos("tier")
	}
	k.ds.errorf(at, CodeLiveTier, "%s", err.Error()).fix("set live.mode: locked, or tier: cgroup")
}

// related reports whether a is at, beneath or above b.
func related(a, b string) bool { return isAncestorOrSelf(a, b) || isAncestorOrSelf(b, a) }

// relatedAny reports whether either spelling of a path, as declared (made absolute) or resolved, is at, beneath or
// above v. Every containment question a fence entry asks is asked of both: a write entry spelled through a link onto
// the fenced path's parent is the same write entry as one spelled directly (agent-contract E8).
func (k *compiler) relatedAny(declared, v string) bool {
	return related(declared, v) || related(k.resolve(declared), v)
}

// declaredByProfile returns the file a profile that declared the list entry at key was read from, or "" when the
// top-level contract declared it. A fence takes out only the contract's own refusals (ADR 0125 decision 2): a
// profile's deny_read or exec.deny entry is a floor the contract cannot remove (merge.go: a contract's deny_read: []
// cannot disable a profile's entries), so neither can its fence.
func (k *compiler) declaredByProfile(key string) string {
	if p, ok := k.c.origins[key]; ok && p.File != k.top {
		return p.File
	}
	return ""
}

// liveRead checks one live.fence.read entry and returns it with the indexes of the fs.deny_read entries it takes out.
// A read entry names exactly one deny_read entry the person wrote: reads elsewhere are already allowed. It may not
// reach Tego's own state, a write or ask entry (a file could be renamed out from under it), another deny_read or
// ask_read entry, or an exec.allow entry at, beneath or above it, which keeps reads there open, or programs there
// running, whatever the live layer says. The
// built-in refusals are checked once the fs table is built (markLive).
//
// The entry may not be or pass through a symlink: the kernel layers compile a deny_read row at the place its walk
// lands, while the live layer matches the entry's value, so a link entry would take the refusal off the target and
// fence only the link's name. Every relation check is then asked of the other entries' resolved
// spellings as well as their declared ones.
func (k *compiler) liveRead(raw string, pos Pos) (LiveEntry, []int, bool) {
	v := k.abs(raw)
	e := LiveEntry{Kind: LiveKindRead, Value: v, Source: LiveSourceDeny, Raw: raw, Pos: pos}
	if hasGlobMeta(raw) {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q is a pattern; a fence entry is one literal path", raw).
			fix("name the deny_read entry's path itself")
		return e, nil, false
	}
	if rv := k.resolve(v); rv != v {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q names a link or passes through one: it leads to %s, which the kernel layers would stop refusing while the live layer refused only the link's name", raw, rv).
			fix("name the path it leads to, %s, in both fs.deny_read and live.fence.read", rv)
		return e, nil, false
	}
	ok := true
	for _, own := range k.rt.OwnState {
		if k.relatedAny(own, v) {
			k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q reaches %s, Tego's own state, which no run may read", raw, own).
				fix("remove it; Tego's state is never part of a fence")
			return e, nil, false
		}
	}
	fs := k.c.FS
	if fs != nil {
		for _, list := range []struct {
			key     string
			entries []string
		}{{"fs.write", fs.Write}, {"fs.ask", fs.Ask}} {
			for _, w := range list.entries {
				if k.relatedAny(globFreeDir(k.abs(w)), v) {
					k.ds.errorf(pos, CodeLiveFenceWrite, "live.fence.read %q meets %s %q: a file could be renamed out from under it, past the live layer's refusal (ADR 0125)", raw, list.key, w).
						fix("keep the fence's read entries apart from every write and ask entry")
					ok = false
				}
			}
		}
		for _, a := range fs.AskRead {
			if k.relatedAny(globFreeDir(k.abs(a)), v) {
				k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q meets fs.ask_read %q, which holds those reads for a person", raw, a).
					fix("keep the fence apart from ask_read entries")
				ok = false
			}
		}
	}
	if k.c.ExecUnrestricted() {
		// No allow-list (no exec: section, or a deny-list) lets every program run wherever it lies, the fenced folder
		// included, as an exec.allow folder above the entry does: refused for the same reason.
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q needs an exec.allow list: without one any program under it may run, and be read, whatever the live layer refuses", raw).
			fix("add exec.allow naming the programs the agent runs, none of them under %s", raw)
		ok = false
	}
	if k.c.Exec != nil {
		for _, a := range k.c.Exec.Allow {
			w := execAllowProgram(a)
			if !strings.Contains(w, "/") {
				continue
			}
			av := globFreeDir(k.abs(w))
			for _, s := range []string{av, k.resolve(av)} {
				switch {
				case s != v && isAncestorOrSelf(v, s):
					k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q holds exec.allow %q, which keeps that program readable whatever the live layer refuses", raw, a).
						fix("keep the fence's read entries off the programs exec.allow grants")
				case isAncestorOrSelf(s, v):
					// An exec.allow folder at or above the entry gives the kernel layers execute and read on the
					// whole subtree once the fence takes the deny_read out of them, and an exec is decided on exec
					// rules, not read ones: a program under the unlifted entry would run, and its bytes could be
					// read through /proc/<child>/mem.
					k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q lies inside exec.allow %q, which lets every program there run, and be read, whatever the live layer refuses", raw, a).
						fix("keep the fence's read entries outside the folders exec.allow grants")
				default:
					continue
				}
				ok = false
				break
			}
		}
	}
	var deny []int
	if fs != nil {
		for i, d := range fs.DenyRead {
			dv := k.abs(d)
			glob := hasGlobMeta(d)
			if glob {
				dv = globFreeDir(dv)
			}
			switch {
			case !glob && k.resolve(dv) == v:
				if file := k.declaredByProfile("fs.deny_read." + strconv.Itoa(i)); file != "" {
					k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q names fs.deny_read %q, which the profile %s declares; a profile's refusal is never part of a fence", raw, d, file).
						fix("remove the entry; lift a profile's refusal by changing the profile, from the next run")
					ok = false
					continue
				}
				deny = append(deny, i)
			case k.relatedAny(dv, v):
				k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.read %q lies inside or around fs.deny_read %q; a read entry names one deny_read entry exactly", raw, d).
					fix("name that deny_read entry itself: %s", d)
				ok = false
			}
		}
	}
	if len(deny) == 0 {
		if ok {
			k.ds.errorf(pos, CodeLiveFenceAllowed, "live.fence.read %q: the contract already allows reading %s, since it refuses reads only under fs.deny_read", raw, v).
				fix("to refuse it for a while use tego block --for; to fence it, add it to fs.deny_read too")
		}
		return e, nil, false
	}
	return e, deny, ok
}

// liveHeldReads forces fs.reads: held for a fence with read entries (ADR 0069, ADR 0125 decision 6): its refusal is
// checked on the object the open deputy pinned, so a swapped symlink does not get through. fs.reads: direct is
// refused. The finding fs.reads: held makes stands at the fence's read key.
func (k *compiler) liveHeldReads(cp *Contract) {
	if cp.FS == nil {
		return
	}
	if cp.FS.Reads == ReadsDirect {
		k.ds.errorf(k.pos("fs.reads"), CodeLiveReadsDirect, "fs.reads: direct leaves reads unheld, and live.fence's read entries are refused on the object Tego's open deputy pins").
			fix("remove fs.reads: direct (the fence holds reads), or remove the fence's read entries")
		return
	}
	if cp.FS.Reads != ReadsHeld {
		cp.FS.Reads = ReadsHeld
		if _, wrote := cp.origins["fs.reads"]; !wrote {
			cp.origins["fs.reads"] = k.pos("live.fence.read")
		}
	}
}

// liveNet checks one live.fence.net entry and appends it to the copy's net.allow as a TCP destination
// (tcp://<value>). A net fence entry is refused on the connect Tego relays (ADR 0125 decision 2), and only a TCP
// connect is relayed: an addressed datagram batch is decided and then continued, so a sibling thread can rewrite an
// address between the two (supervisor send.go), and a kernel row that admitted the fence entry for UDP would let that
// rewrite reach a destination not yet granted. TCP only keeps the kernel rows refusing every UDP datagram to it.
func (k *compiler) liveNet(cp *Contract, raw string, pos Pos) (LiveEntry, bool) {
	e := LiveEntry{Kind: LiveKindNet, Value: strings.TrimSpace(raw), Source: LiveSourceNew, Raw: raw, Pos: pos}
	v, msg, fix := liveNetValue(raw)
	if msg != "" {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.net %q %s", raw, msg).fix("%s", fix)
		return e, false
	}
	e.Value = v
	if cp.Net == nil {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.net %q: the contract has no net: section, so every destination is already allowed", raw).
			fix("add a net: section naming what the agent may reach, or remove the entry")
		return e, false
	}
	if a, ok := netAllowed(k.c.Net.Allow, v); ok { // the contract's own entries: a fence entry listed twice is its own finding
		k.ds.errorf(pos, CodeLiveFenceAllowed, "live.fence.net %q: net.allow %q already allows it", raw, a).
			fix("to refuse it for a while use tego block --for")
		return e, false
	}
	if liveLocal(v) {
		k.ds.warnf(pos, CodeLiveFenceLocal, "live.fence.net %q is a local destination: a local service may run commands outside the run; Tego cannot tell", raw).
			fix("grant it only to a service you know runs nothing for its callers")
	}
	cp.origins["net.allow."+strconv.Itoa(len(cp.Net.Allow))] = pos
	cp.Net.Allow = append(cp.Net.Allow, liveNetAllow(v))
	return e, true
}

// liveNetAllow is the net.allow entry a net fence value compiles to: the destination for TCP alone (liveNet).
func liveNetAllow(v string) string { return ProtoTCP + "://" + v }

// liveNetValue is a net fence entry as internal/liveblock.Normalize names it: a lower-case host:port, or an IP:port
// with an IPv6 address in brackets. A port is required (net.allow is per port); a unix socket, an abstract name and
// a CIDR are refused, the first two because the user bus and the systemd, docker and tmux sockets start processes
// outside the run. msg and fix are "" for a good value.
func liveNetValue(raw string) (v, msg, fix string) {
	s := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(strings.ToLower(s), "unix:"), strings.HasPrefix(s, "/"), strings.HasPrefix(s, "@"):
		return "", "is a unix socket: such endpoints can start processes outside the run: the user bus, systemd, docker, tmux",
			"grant a socket in net.allow from the next run, where the contract names it"
	case strings.Contains(s, "://"):
		return "", "names a scheme; a fence entry is host:port or IP:port, always for TCP", "write it as host:port"
	case strings.Contains(s, "/"):
		return "", "is a range; a fence entry is one host or address", "name each address as IP:port"
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return "", "has port 0", "name the port, 1 to 65535"
		}
		v = netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()).String()
	} else if _, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return "", "names no port; net rules are per port", "write it as IP:port, such as " + s + ":443"
	} else {
		host, port, found := s, "", false
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			host, port, found = s[:i], s[i+1:], true
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if !liveHostName(host) {
			return "", "is not a host:port or IP:port", "write it as host:port, such as api.stripe.com:443"
		}
		if !found || port == "" {
			return "", "names no port; net rules are per port", "write it as host:port, such as " + host + ":443"
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", "has a port that is not 1 to 65535", "name the port, 1 to 65535"
		}
		v = host + ":" + port
	}
	if _, err := ParseEndpoint(v); err != nil {
		return "", "is not a destination net.allow takes: " + err.Error(), "write it as host:port or IP:port"
	}
	return v, "", ""
}

// liveHostName is internal/liveblock's hostName: dot-separated labels of letters, digits, hyphens and underscores,
// none empty or longer than 63, 253 in all, with a letter somewhere (so "300.1.2.3" is no name).
func liveHostName(h string) bool {
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

// netAllowed returns the net.allow entry that already allows the destination v (a normalized fence value) for TCP,
// as the fence would (liveNet): the same host or address and port, or a range holding the address, for every
// transport or for TCP.
func netAllowed(allow []string, v string) (string, bool) {
	fe, err := ParseEndpoint(v)
	if err != nil {
		return "", false
	}
	for _, a := range allow {
		ep, err := ParseEndpoint(a)
		if err != nil || ep.Proto != ProtoInet && ep.Proto != ProtoTCP || ep.Port != fe.Port {
			continue
		}
		switch ep.Kind {
		case EndpointHost:
			if fe.IP.IsValid() && ep.IP.IsValid() && ep.IP.Unmap() == fe.IP.Unmap() ||
				!fe.IP.IsValid() && strings.TrimSuffix(strings.ToLower(ep.Host), ".") == fe.Host {
				return a, true
			}
		case EndpointCIDR:
			if fe.IP.IsValid() && ep.CIDR.Contains(fe.IP.Unmap()) {
				return a, true
			}
		}
	}
	return "", false
}

// liveLocal reports a loopback, link-local or unspecified address, or localhost.
func liveLocal(v string) bool {
	if ap, err := netip.ParseAddrPort(v); err == nil {
		a := ap.Addr().Unmap()
		return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()
	}
	host, _, _ := strings.Cut(v, ":")
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// liveExec checks one live.fence.exec entry, returns the indexes of the whole-program exec.deny entries it takes out,
// and under an exec allow-list appends it to the copy's exec.allow.
//
// An exec.deny entry that names a program by its bare name refuses every program of that name, wherever it is; taking
// it out lets every one of them past the kernel layers, not only the fenced path. The entry then carries that name
// (LiveEntry.Name), and the live layer refuses every exec of that name until a lift, as exec.deny did. A path that is or passes through a link is refused: the kernel layers decide the file it leads to, the
// live layer the name.
func (k *compiler) liveExec(cp *Contract, raw string, pos Pos) (LiveEntry, []int, bool) {
	e := LiveEntry{Kind: LiveKindExec, Value: raw, Source: LiveSourceNew, Raw: raw, Pos: pos}
	if !filepath.IsAbs(raw) || strings.ContainsAny(raw, " \t") {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.exec %q is not an absolute program path", raw).
			fix("name the program by its absolute path, such as /usr/bin/psql")
		return e, nil, false
	}
	if strings.HasSuffix(raw, "/") {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.exec %q names a directory; a fence entry is one program", raw).
			fix("name each program by its absolute path")
		return e, nil, false
	}
	v := filepath.Clean(raw)
	e.Value = v
	if fi, err := os.Stat(v); err != nil || fi.IsDir() {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.exec %q names no program file on this machine", raw).
			fix("name the program by the absolute path it has here (command -v <name>)")
		return e, nil, false
	}
	if rv := k.resolve(v); rv != v {
		k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.exec %q names a link or passes through one: it leads to %s, which the kernel layers would run while the live layer refused only the link's name", raw, rv).
			fix("name the program it leads to: %s", rv)
		return e, nil, false
	}
	// A program the agent may write is one it may overwrite in place, keeping the inode and so its Landlock EXECUTE
	// grant, and rename past the live layer's name check: the fence entry itself would make the writable, runnable
	// place. Both spellings of every write and ask entry are asked, as for a read entry.
	if fs := k.c.FS; fs != nil {
		for _, list := range []struct {
			key     string
			entries []string
		}{{"fs.write", fs.Write}, {"fs.ask", fs.Ask}} {
			for _, w := range list.entries {
				wd := globFreeDir(k.abs(w))
				if isAncestorOrSelf(wd, v) || isAncestorOrSelf(k.resolve(wd), v) {
					k.ds.errorf(pos, CodeLiveFenceWrite, "live.fence.exec %q lies inside %s %q: the agent could rewrite the program in place and rename it, past the live layer's refusal (ADR 0125)", raw, list.key, w).
						fix("fence a program outside every write and ask entry")
					return e, nil, false
				}
			}
		}
	}
	var deny []int
	if cp.Exec != nil {
		for i, d := range cp.Exec.Deny {
			if execmatch.IsPattern(d) {
				continue
			}
			// exec.deny entries are names, never paths (Load's [exec-rule]): each matches every file of its name.
			w := execmatch.Word(d)
			if w != filepath.Base(v) {
				continue
			}
			if file := k.declaredByProfile("exec.deny." + strconv.Itoa(i)); file != "" {
				k.ds.errorf(pos, CodeLiveFenceEntry, "live.fence.exec %q names exec.deny %q, which the profile %s declares; a profile's refusal is never part of a fence", raw, d, file).
					fix("remove the entry; lift a profile's refusal by changing the profile, from the next run")
				return e, nil, false
			}
			e.Name = w
			deny = append(deny, i)
		}
	}
	if len(deny) > 0 {
		e.Source = LiveSourceDeny
	}
	if cp.Exec == nil || cp.Exec.DenyList() {
		if len(deny) == 0 {
			k.ds.errorf(pos, CodeLiveFenceAllowed, "live.fence.exec %q: the contract already lets it run, since it restricts no program but its exec.deny entries", raw).
				fix("to refuse it for a while use tego block --for; to fence it, add exec.deny: [%s] too", filepath.Base(v))
			return e, nil, false
		}
		return e, deny, true
	}
	cp.origins["exec.allow."+strconv.Itoa(len(cp.Exec.Allow))] = pos
	cp.Exec.Allow = append(cp.Exec.Allow, v)
	return e, deny, true
}

// liveExecMeetsRead refuses the exec entry lf.entries[i] when one of its program files, paths (the entry's own, or the
// helper images compile granted with it), lies at, beneath or above one of the fence's own read entries. liveRead
// asks a read entry about the contract's exec.allow only, and the fence's exec entries join the copy's exec.allow
// after it (liveExec), so a fenced program could lie in a fenced folder: the kernel layers would grant it execute and
// read there once the fence took the folder's deny_read out, and lifting the program alone would let it run, its
// bytes read through /proc/<child>/mem, while the read entry is still refused (as for
// exec.allow). A read entry already refused is skipped: it takes no deny_read out.
func (k *compiler) liveExecMeetsRead(lf *liveFence, i int, paths []string) {
	e := lf.entries[i]
	for j, r := range lf.entries {
		if r.Kind != LiveKindRead || lf.bad[j] {
			continue
		}
		for _, p := range paths {
			if !related(r.Value, p) {
				continue
			}
			what := "lies at or inside"
			if p != e.Value {
				what = "runs " + p + ", which lies at or inside"
			}
			k.ds.errorf(e.Pos, CodeLiveFenceEntry, "live.fence.exec %q %s live.fence.read %q: lifting the program alone would let it run there, and be read, while the read entry is still refused", e.Raw, what, r.Raw).
				fix("fence programs outside the fence's read entries")
			lf.bad[i] = true
			return
		}
	}
}

// dropEntries removes the entries at the indexes drop from list, and moves their positions in o down with them, so a
// finding about a later entry still points at its line. A non-nil list stays non-nil.
func dropEntries(o origins, key string, list []string, drop []int) []string {
	out := make([]string, 0, len(list))
	old := make(map[int]Pos, len(list))
	for i := range list {
		k := key + "." + strconv.Itoa(i)
		if p, ok := o[k]; ok {
			old[i] = p
		}
		delete(o, k)
	}
	for i, s := range list {
		if slices.Contains(drop, i) {
			continue
		}
		if p, ok := old[i]; ok {
			o[key+"."+strconv.Itoa(len(out))] = p
		}
		out = append(out, s)
	}
	return out
}

// markLive runs once the fs, net and exec tables are built. It marks every rule a fence entry added (Fence), so its
// rule name is the fence entry's; refuses a read entry at, beneath or above a built-in deny_read entry (the credential
// refusals are never part of a fence), and an exec entry an exec.allow entry already grants; and states the fence.
func (k *compiler) markLive(lf *liveFence) {
	if lf == nil {
		return
	}
	for i, e := range lf.entries {
		if lf.bad[i] {
			continue
		}
		switch e.Kind {
		case LiveKindRead:
			k.liveReadBuiltIn(e)
		case LiveKindNet:
			for j := range k.rt.Net {
				if r := &k.rt.Net[j]; r.Pos == e.Pos && r.Raw == liveNetAllow(e.Value) {
					r.Fence = true
				}
			}
		case LiveKindExec:
			if imgs := k.liveExecMark(e); len(imgs) > 0 {
				k.rt.Live.Entries[i].Images = imgs
				k.liveExecMeetsRead(lf, i, imgs)
			}
		}
	}
	k.ds.warnf(k.pos("live.mode"), CodeUnenforced, "live.mode: adjustable: the kernel enforces the contract plus the fence (%d entries); Tego's live layer, not the kernel, refuses each fence entry until you lift or grant it (ADR 0125)",
		len(lf.entries)).
		fix("weigh Locked against Adjustable in docs/user/live-modes.md").info()
	if k.rt.Reads.Mode == ReadsHeld && slices.ContainsFunc(lf.entries, func(e LiveEntry) bool { return e.Kind == LiveKindRead }) {
		k.ds.warnf(k.pos("live.fence.read"), CodeHeldReads, "live.fence has read entries, so every read open of the run is held (fs.reads: held, ADR 0069) and a read fence entry is refused on the object the open deputy pins: %s",
			HeldReadCost).
			fix("remove the fence's read entries to read directly").info()
	}
}

// liveReadBuiltIn refuses a read entry that meets a built-in deny_read entry, compiled or absent at compile.
func (k *compiler) liveReadBuiltIn(e LiveEntry) {
	for _, r := range k.rt.FS {
		if r.Kind == FSDenyRead && r.BuiltIn && (related(r.Path, e.Value) || r.Resolved != "" && related(r.Resolved, e.Value)) {
			k.ds.errorf(e.Pos, CodeLiveFenceEntry, "live.fence.read %q meets the built-in deny_read entry %s; the built-in credential refusals are never part of a fence", e.Raw, r.Path).
				fix("remove it; a run that needs that file gets it through an env.pass variable or a contract it is written into")
			return
		}
	}
	for _, a := range k.rt.AbsentDenyRead {
		if related(a.Path, e.Value) || a.Resolved != "" && related(a.Resolved, e.Value) {
			k.ds.errorf(e.Pos, CodeLiveFenceEntry, "live.fence.read %q meets the built-in deny_read entry %s; the built-in credential refusals are never part of a fence", e.Raw, a.Path).
				fix("remove it; a run that needs that file gets it through an env.pass variable or a contract it is written into")
			return
		}
	}
}

// liveExecMark marks the exec rules a fence entry added under an allow-list, and refuses an entry another exec.allow
// entry (or the run's command) already grants. An entry that took out an exec.deny entry marks the rule it shares
// with such a grant: the program runs only because the fence took the refusal out.
//
// The rules the entry added are its own and every helper image compile granted for it (helperImages gives each the
// position of the exec.allow entry that named the tool, here the fence entry's): git's exec-path git is another inode
// than /usr/bin/git, so without the mark a fenced git ran by that path before any lift, named exec[...], a rule no one
// wrote. It returns those images' paths, LiveEntry.Images.
func (k *compiler) liveExecMark(e LiveEntry) []string {
	if k.c.Exec == nil || k.c.Exec.DenyList() {
		return nil
	}
	var images []string
	for j := range k.rt.Exec {
		r := &k.rt.Exec[j]
		switch {
		case r.Pos == e.Pos && r.Raw == e.Value:
			r.Fence = true
			continue
		case r.Pos == e.Pos:
			r.Fence, r.FenceEntry = true, e.Value
			for _, p := range []string{r.Path, r.Resolved} {
				if p != "" && p != e.Value && !slices.Contains(images, p) {
					images = append(images, p)
				}
			}
			continue
		case r.Path == e.Value && e.Source == LiveSourceDeny:
			r.Fence = true
			continue
		case e.Source == LiveSourceDeny:
			continue
		case r.Path == e.Value, r.IsDir && isAncestorOrSelf(r.Path, e.Value):
			k.ds.errorf(e.Pos, CodeLiveFenceAllowed, "live.fence.exec %q: %s already grants it", e.Raw, r.RuleName()).
				fix("to refuse it for a while use tego block --for")
			return nil
		}
	}
	return images
}

// execAllowProgram is the program an exec.allow entry names: a one-word entry's word, or a command pattern's first
// word (a pattern grants running that program, so its file is as readable as a one-word entry's). An entry that does
// not split is returned as written.
func execAllowProgram(entry string) string {
	if !execmatch.IsPattern(entry) {
		return execmatch.Word(entry)
	}
	if words, _, err := execmatch.SplitWords(entry); err == nil && len(words) > 0 {
		return words[0]
	}
	return entry
}
