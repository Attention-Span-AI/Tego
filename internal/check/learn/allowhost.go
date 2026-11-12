// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A watched run's record holds the address a program connected to, never the name it looked up, so learn can only
// propose addresses, and the next run, which may pick another address of the same answer, is refused
// (docs design LEARN-NAMES, slice 1). The person names the service instead (tego learn --allow-host <name>): the
// caller looks the name up here, now, through the resolver a run's start uses, and hands learn the answer. Learn then
// writes the name in place of every address the run reached that the answer holds, on the protocols and ports the run
// used. It never chooses a name for an address itself, and it never asks DNS for the name of an address (a reverse
// lookup names the CDN, not the service). The step runs inside proposeNet, before the leak rule's withhold, and refuses
// a name whose answer holds a withheld address: the name would admit that address again. An address no name admits
// (the built-in classes and the machine config's denied_resolved_addresses, Options.DeniedResolved) is never named:
// compile drops it from the answer, so it stays an address.

// HostAnswer is one name given with tego learn --allow-host, and what it resolves to here now.
type HostAnswer struct {
	Host string
	// Port limits the name to the run's destinations on this port; 0 is every port the run used.
	Port int
	// Addrs are the name's answer, as the caller's lookup returned it.
	Addrs []netip.Addr
}

// NamedHost is what one HostAnswer named in the proposal: its answer here now and the run's destinations it covers,
// each as "<proto> <address>:<port>", in the order the proposal lists them.
type NamedHost struct {
	Host    string
	Port    int
	Answer  []netip.Addr
	Reached []string
}

// HostError is a proposal refused because of names given with --allow-host: one sentence per problem, without a
// final period. The caller writes nothing.
type HostError struct {
	Problems []string
	// Refused are the indexes in Options.Hosts of the names refused, in order: a next step names the others alone.
	Refused []int
}

func (e *HostError) Error() string { return strings.Join(e.Problems, "; ") }

// allowHostNote starts the note of an entry named by a HostAnswer.
const allowHostNote = "by name (--allow-host)"

// probeNameNote is the note an entry by name over UDP keeps when the destinations it folds were probes (classify).
const probeNameNote = "possibly the C library's address-sorting probe of the addresses a lookup returns (a UDP connect that sends nothing), " +
	"which the record cannot tell from traffic: remove it unless the agent speaks UDP (QUIC) to this service"

// hostEntry is one net.allow entry a HostAnswer named: the answer, and what it covers.
type hostEntry struct {
	answer  []netip.Addr
	covered []netip.Addr
	probe   bool
}

// note is the entry's remark: what the name resolves to here now, the addresses the run reached that it covers, and
// what tego does not know.
func (h *hostEntry) note() string {
	them, an := "them", "addresses the run reached"
	if len(h.covered) == 1 {
		them, an = "it", "an address the run reached"
	}
	s := fmt.Sprintf("%s: resolves here now to %s; covers %s, %s; tego does not know which name the run looked up for %s",
		allowHostNote, listAddrs(h.answer), listAddrs(h.covered), an, them)
	if h.probe {
		s += "; " + probeNameNote
	}
	return s
}

// maxListed is how many addresses one note or message names; the rest are counted.
const maxListed = 4

// listAddrs is addrs joined, at most maxListed of them, then how many more.
func listAddrs(addrs []netip.Addr) string {
	shown := make([]string, 0, min(len(addrs), maxListed))
	for _, a := range addrs[:min(len(addrs), maxListed)] {
		shown = append(shown, a.String())
	}
	s := strings.Join(shown, ", ")
	if n := len(addrs) - maxListed; n > 0 {
		s += fmt.Sprintf(" and %d more", n)
	}
	return s
}

// protoPort is a net.allow entry's protocol and port, what an entry by name admits on.
type protoPort struct {
	proto string
	port  uint16
}

// destAddr is the address and port of a TCP or UDP destination as the proposal writes it (classify): unmapped, without
// its zone.
func destAddr(k netKey) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(k.dst)
	if err != nil || (k.proto != "tcp" && k.proto != "udp") {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), true
}

// nameHosts is the naming step: for each HostAnswer of the options, the destinations of keys it covers (a TCP or UDP
// destination classify proposes, other than the machine's resolver, on the answer's port if it names one, whose
// address the answer holds and a name can admit), keyed by destination. It refuses, with a HostError naming every problem, a name that covers nothing, a name
// whose answer holds a private address the run did not reach, and a name whose answer holds an address held (the leak
// rule's) on a protocol and port it would be allowed on. p.Named gets what each name covered. With LeaveLeaksToCaller
// it knows no held address, and refuses every name with a plain error.
func (l *Learner) nameHosts(p *Proposal, keys []netKey, held map[netKey]*Leak) (map[netKey][]*HostAnswer, error) {
	if len(l.opts.Hosts) == 0 {
		return nil, nil
	}
	if l.opts.LeaveLeaksToCaller {
		// held is nil then: learn knows no withheld address, so a name could stand for one the caller's verdict would
		// withhold, and the caller, which withholds by address, would not find it under the name.
		return nil, errors.New("learn: Options.Hosts with LeaveLeaksToCaller: a name could stand for an address the caller's leak verdict withholds")
	}
	out := map[netKey][]*HostAnswer{}
	var problems []string
	var refused []int
	for i := range l.opts.Hosts {
		h := &l.opts.Hosts[i]
		answer := make([]netip.Addr, 0, len(h.Addrs))
		for _, a := range h.Addrs {
			if a = a.Unmap().WithZone(""); a.IsValid() && !slices.Contains(answer, a) {
				answer = append(answer, a)
			}
		}
		var covered []netKey
		var reached, kept, resolver []netip.Addr
		var keptWhy []string
		on := map[protoPort]bool{}
		for _, k := range keys {
			ap, ok := destAddr(k)
			if !ok || (h.Port != 0 && int(ap.Port()) != h.Port) || !slices.Contains(answer, ap.Addr()) {
				continue
			}
			if entry, _, left := l.classify(k); entry == "" || left != nil {
				continue
			}
			if l.machineResolver(k) {
				// Not an entry to name: proposeNet leaves it out, or keeps it as the address it is (keepResolvers).
				if !slices.Contains(resolver, ap.Addr()) {
					resolver = append(resolver, ap.Addr())
				}
				continue
			}
			if class, denied := agent.DeniedResolvedClass(ap.Addr(), l.opts.DeniedResolved); denied {
				if !slices.Contains(kept, ap.Addr()) {
					kept = append(kept, ap.Addr())
					keptWhy = append(keptWhy, fmt.Sprintf("%s (%s)", ap.Addr(), class))
				}
				continue
			}
			covered = append(covered, k)
			on[protoPort{k.proto, ap.Port()}] = true
			if !slices.Contains(reached, ap.Addr()) {
				reached = append(reached, ap.Addr())
			}
		}
		before := len(problems)
		if len(covered) == 0 {
			problems = append(problems, l.coversNothing(h, answer, keptWhy, resolver))
			refused = append(refused, i)
			continue
		}
		for _, a := range answer {
			if _, denied := agent.DeniedResolvedClass(a, l.opts.DeniedResolved); !denied && agent.PrivateAddr(a) && !slices.Contains(reached, a) {
				problems = append(problems, fmt.Sprintf("%s resolves here now to %s, among them the private address %s, which the run did not reach:"+
					" an entry by that name would let a later run reach it, and every private address the name resolves to when that run starts",
					h.Host, listAddrs(answer), a))
				break
			}
		}
		var withheld []netip.Addr
		for k := range held {
			if ap, ok := destAddr(k); ok && on[protoPort{k.proto, ap.Port()}] && slices.Contains(answer, ap.Addr()) && !slices.Contains(withheld, ap.Addr()) {
				withheld = append(withheld, ap.Addr())
			}
		}
		if len(withheld) > 0 {
			slices.SortFunc(withheld, netip.Addr.Compare)
			problems = append(problems, fmt.Sprintf("%s resolves here now to %s, among them %s, which learn withheld because the run's secrets"+
				" may have gone there: an entry by that name would allow it again", h.Host, listAddrs(answer), listAddrs(withheld)))
		}
		if len(problems) > before {
			refused = append(refused, i)
			continue
		}
		named := NamedHost{Host: h.Host, Port: h.Port, Answer: answer}
		for _, k := range covered {
			out[k] = append(out[k], h)
			ap, _ := destAddr(k)
			named.Reached = append(named.Reached, k.proto+" "+ap.String())
		}
		p.Named = append(p.Named, named)
	}
	if len(problems) > 0 {
		return nil, &HostError{Problems: problems, Refused: refused}
	}
	return out, nil
}

// coversNothing is the problem of a name whose answer holds no address the run reached that a name can stand for:
// the name may be wrong, or the service's addresses changed since the run, whose age it says when the options give
// the time now. kept are the addresses the run reached that the answer holds but learn keeps as addresses, and
// resolver those it reached only as the machine's resolver (Learner.machineResolver).
func (l *Learner) coversNothing(h *HostAnswer, answer []netip.Addr, kept []string, resolver []netip.Addr) string {
	if len(kept) > 0 {
		return fmt.Sprintf("%s resolves here now to %s; it reached %s, which learn keeps as an address, never by name, and no other"+
			" address of the answer", h.Host, listAddrs(answer), strings.Join(kept, ", "))
	}
	if len(resolver) > 0 {
		return fmt.Sprintf("%s resolves here now to %s; the run reached %s only as the machine's resolver, which tego allows"+
			" itself and learn never writes by name, and no other address of the answer", h.Host, listAddrs(answer), listAddrs(resolver))
	}
	port := ""
	if h.Port != 0 {
		port = fmt.Sprintf(" on port %d", h.Port)
	}
	age := ""
	if now := l.opts.Now; !now.IsZero() && now.After(l.run.ts) {
		age = " (it started " + ago(now.Sub(l.run.ts)) + " ago)"
	}
	return fmt.Sprintf("%s resolves here now to %s; none is an address the run reached%s, so the name may be wrong, or its addresses"+
		" changed since the run%s", h.Host, listAddrs(answer), port, age)
}

// ago is d in the largest whole unit a person reads: days from two days on, hours from two hours, else minutes.
func ago(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	case d >= 2*time.Minute:
		return fmt.Sprintf("%d minutes", int(d/time.Minute))
	}
	return "moments"
}
