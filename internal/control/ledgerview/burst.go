// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"net/netip"
	"slices"
	"strings"
)

// A burst is one thing an agent tried, spread over many refusal groups, and it reads as one row. The rows are a display
// fold: every line stays counted, the severity of each is the one its own group got, and Outbound and the verdict read
// the addresses as before.
//
// One host is one row, on any ports and however far apart its connects come. A group already holds a remote host's
// ports, but a group on this machine is one port (groupSubject: each is a different service, a rule can name one, and
// port 53 is a lookup), so a scan of 148 local ports read as 148 High rows. Such a row reads at the highest severity
// of what it holds.
//
// One name is then one row. A host name resolves to several addresses, each of which it tries once, and each address
// is a refusal group of its own (groupKey), so one fetch of a file from GitHub read as eight High rows beside the
// attack. A refused connect names no host, so its row is read from what it does name: the rule that refused it, when
// that rule names a destination (a live block on chatgpt.com refuses every address the name resolves to), or else the
// network range around the address. Such a row holds one severity. This machine's addresses stay apart: 127.0.0.2 is
// not 127.0.0.1's neighbour in any network.
//
// Nothing that could be an attack is folded away. A group next to a secret keeps its own row, and a row never reads
// lower than what it holds.

// A burst's range: the block a network hands out as one (RIR allocations start at these sizes), wide enough for the
// addresses one name resolves to, and never wider than one organisation's block.
const (
	burstBits4 = 16
	burstBits6 = 32
)

// inBurst reports whether a refusal group can join a row: a refused connect neither routine nor next to a secret.
func inBurst(g *Group) bool { return g.Class == "net" && !g.Background && !g.NearSecret }

// connectAddr is the address a connect's subject names, which holds its port on this machine and for port 65535
// (groupSubject). It is false for a subject that names none: a unix socket, netlink, an address family with no address.
func connectAddr(subject string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(subject); err == nil {
		return ap.Addr().Unmap(), true
	}
	a, err := netip.ParseAddr(strings.Trim(subject, "[]"))
	return a.Unmap(), err == nil
}

// hostRow is the row a refusal group reads in on its host: its key, the subject that row shows and the text that finds
// its lines in Logs ("" for the subject). The key is "" for a group that keeps its own row. The severity is left out of
// the key: a row of one host takes the highest it holds (burstSeen.merge).
func hostRow(g *Group) (key, subject, query string) {
	addr, ok := connectAddr(g.Subject)
	if !ok || !inBurst(g) {
		return "", "", ""
	}
	host := addr.String()
	if addr.Is6() {
		host = "[" + host + "]"
	}
	if addr.IsLoopback() {
		query = host + ":" // the port's colon: 127.0.0.1 alone finds 127.0.0.10 too
	}
	return g.Rule + "\x00" + g.Reason + "\x00" + g.Op + "\x00" + host, host, query
}

// nameRow is the row one host's row reads in among the addresses of one name: its key, the subject that row shows and
// the text that finds its lines in Logs. The key is "" for a group that keeps its own row.
func nameRow(g *Group) (key, subject, query string) {
	addr, ok := connectAddr(g.Subject)
	if !inBurst(g) || loopback(g.Subject) || addr.IsLoopback() {
		return "", "", ""
	}
	base := g.Rule + "\x00" + g.Reason + "\x00" + g.Op + "\x00" + g.Severity.String() + "\x00"
	if !defaultRules[g.Rule] {
		return base, ruleDest(g.Rule), g.Rule
	}
	if !ok {
		return "", "", ""
	}
	bits, sep := burstBits4, "."
	if addr.Is6() {
		bits, sep = burstBits6, ":"
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return "", "", ""
	}
	parts := strings.SplitN(addr.String(), sep, 3) // the two groups the range keeps
	return base + prefix.String(), prefix.String(), parts[0] + sep + parts[1] + sep
}

// ruleDest is the destination a rule names: "chatgpt.com:443" for live.block[net:chatgpt.com:443].
func ruleDest(rule string) string {
	_, v, ok := strings.Cut(rule, "[")
	if !ok {
		return rule
	}
	return strings.TrimPrefix(strings.TrimSuffix(v, "]"), "net:")
}

// mergeBursts folds each burst of two groups or more into its first group's place: the ports of one host, then the
// addresses of one name. gs is not changed: a burst's row has its own Targets and Ports.
func mergeBursts(gs []Group) []Group {
	rows, _ := foldRows(gs, hostRow)
	rows, held := foldRows(rows, nameRow)
	for j, s := range held {
		rows[j].Hosts = s.groups // one group per address: hostRow folded the others
	}
	return rows
}

// foldRows folds the groups row gives one key into the first one's place, and says what each folded row holds, by its
// place. A group row gives no key stays as it is, and so does the only group of a key.
func foldRows(gs []Group, row func(*Group) (key, subject, query string)) ([]Group, map[int]*burstSeen) {
	out := make([]Group, 0, len(gs))
	at := map[string]int{}       // each burst's first group's place in out
	held := map[int]*burstSeen{} // what the burst at that place holds
	for i := range gs {
		key, subject, query := row(&gs[i])
		j, seen := at[key]
		if key == "" || !seen {
			if key != "" {
				at[key] = len(out)
			}
			out = append(out, gs[i])
			continue
		}
		b := &out[j]
		s := held[j]
		if s == nil {
			b.Subject, b.Query = subject, query
			b.Targets, b.Ports = slices.Clone(b.Targets), slices.Clone(b.Ports)
			s = newBurstSeen(b)
			held[j] = s
		}
		s.merge(b, &gs[i])
	}
	return out, held
}

// burstSeen is the groups, targets and ports a burst's row holds. A burst is what an agent spraying a range or scanning
// a host makes, and it is merged again for each new version of its run, under the run's lock, so its cost falls on every
// page that reads the run while the attack goes on. Scanning the row for each target took 7 s at 60,000 addresses, and a
// target is a host:port, so a /16 can hold more targets than addresses.
type burstSeen struct {
	groups         int
	targets, ports map[string]bool
}

func newBurstSeen(b *Group) *burstSeen {
	s := &burstSeen{groups: 1, targets: make(map[string]bool, len(b.Targets)), ports: make(map[string]bool, len(b.Ports))}
	for _, t := range b.Targets {
		s.targets[t] = true
	}
	for _, p := range b.Ports {
		s.ports[p] = true
	}
	return s
}

// merge adds g to its burst's row b.
func (s *burstSeen) merge(b, g *Group) {
	s.groups++
	b.Count += g.Count
	b.Severity = max(b.Severity, g.Severity)
	for _, t := range g.Targets {
		if !s.targets[t] {
			s.targets[t] = true
			b.Targets = append(b.Targets, t)
		}
	}
	for _, p := range g.Ports {
		if !s.ports[p] {
			s.ports[p] = true
			b.Ports = append(b.Ports, p)
		}
	}
	if g.First.Before(b.First) {
		b.First = g.First
	}
	if g.FirstSeq < b.FirstSeq {
		b.FirstSeq = g.FirstSeq
	}
	if g.Last.After(b.Last) {
		b.Event, b.Last = g.Event, g.Last
	}
}
