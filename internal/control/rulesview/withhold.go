// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/learn"
)

// nearSecretWords is what a withheld item's comment says about it. It is what the leak rule saw (ledgerview.Verdict: a
// first contact next to a secret read, with the send getting through), never what was sent: no line holds a send's bytes.
const nearSecretWords = "first reached next to a secret read, so secrets may have gone there"

// Withhold is a least-privilege proposal (the text learn.Proposal.Contract writes) with every net.allow item that
// names one of dests ("host:port", where a leaking run's secrets went: ledgerview.Verdict.NeverAllow) turned into a
// "# NOT allowed" comment, and the dests it withheld, in the order dests names them. A contract made from a run that
// leaked must never allow where the secrets went (QA PW-1): learn proposes every address the run reached, the
// attacker's among them.
//
// When anything is withheld, a warning line goes on top, a machine's resolver learn left out beside a TCP or UDP
// entry goes back in when none is left (learn.ResolverItem), and an allow list left with no item becomes `allow: []`
// (an empty list allows nothing; a key with no items would not parse as one). Only the net section's items are
// read; the fs and exec lists, and an address named only in a comment, are never touched. With no dests, or none
// that an item names, the text comes back unchanged and the slice is nil.
func Withhold(text string, dests []string) (string, []string) {
	if len(dests) == 0 || text == "" {
		return text, nil
	}
	lines := strings.Split(text, "\n")
	ix := indexDests(dests)
	var withheld []int // places in dests, each once
	held := map[int]bool{}
	inNet := false
	allowAt, kept, dropped, addrKept, ipKept := -1, 0, 0, 0, 0
	var resolverAt []int // the lines that say learn left the machine's resolver out (learn.ResolverItem)
	closeAllow := func() {
		if allowAt >= 0 && dropped > 0 && ipKept == 0 {
			// Learn left the resolver out because another TCP or UDP entry was there, and none is left: put it back,
			// or Landlock would grant the run no port 53 (learn.ResolverItem).
			for _, i := range resolverAt {
				lines[i], _ = learn.ResolverItem(lines[i])
				kept++
			}
		}
		if allowAt >= 0 && kept == 0 && dropped > 0 {
			l := lines[allowAt]
			lines[allowAt] = l[:len(l)-len(strings.TrimLeft(l, " "))] + "allow: []"
		}
		allowAt, kept, dropped, ipKept, resolverAt = -1, 0, 0, 0, nil
	}
	for i, l := range lines {
		indent := len(l) - len(strings.TrimLeft(l, " "))
		trimmed := strings.TrimSpace(l)
		if !inNet {
			inNet = l == "net:"
			continue
		}
		if indent == 0 {
			closeAllow()
			inNet = false
			continue
		}
		if indent <= 2 && strings.HasPrefix(trimmed, "allow:") {
			closeAllow()
			if trimmed == "allow:" {
				allowAt = i
			}
			continue
		}
		if _, ok := learn.ResolverItem(l); ok && allowAt >= 0 {
			resolverAt = append(resolverAt, i)
			continue
		}
		if allowAt < 0 || !strings.HasPrefix(trimmed, "- ") {
			continue
		}
		value, note, ok := netItem(trimmed)
		d := -1
		if ok {
			d = ix.match(value)
		}
		if d < 0 {
			kept++
			if ok {
				ipKept++
				if isAddress(value) {
					addrKept++
				}
			}
			continue
		}
		c := `# NOT allowed: "` + value + `"`
		if note != "" {
			c += " (" + note + ")"
		}
		lines[i] = l[:indent] + c + ": " + nearSecretWords
		dropped++
		if !held[d] {
			held[d] = true
			withheld = append(withheld, d)
		}
	}
	closeAllow()
	if len(withheld) == 0 {
		return text, nil
	}
	if addrKept == 0 { // the header's word on addresses is about the ones withheld: none is left to allow
		lines = slices.DeleteFunc(lines, func(l string) bool { return l == "# WARNING: "+learn.AddressWarning+"." })
	}
	// Name them in dests' order (the closest to the secret first), as the run page's banner does.
	slices.Sort(withheld)
	names := make([]string, len(withheld))
	for i, d := range withheld {
		names[i] = dests[d]
	}
	that := "that address"
	if len(names) > 1 {
		that = "those addresses"
	}
	warn := "# WARNING: secrets may have gone to " + strings.Join(names, ", ") + ": first reached next to a secret read. The proposal leaves " + that +
		" out. Review every entry before you use it."
	return warn + "\n" + strings.Join(lines, "\n"), names
}

// netItem reads a net.allow item line as Contract writes it, trimmed: `- "tcp://D"`, optionally followed by two
// spaces and `# note`. ok is false for any other line, and for a scheme other than tcp:// or udp://.
func netItem(trimmed string) (value, note string, ok bool) {
	rest, found := strings.CutPrefix(trimmed, `- "`)
	if !found {
		return "", "", false
	}
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", "", false
	}
	value, rest = rest[:end], rest[end+1:]
	if strings.ContainsRune(value, '\\') {
		return "", "", false // learn never writes an escaped address
	}
	switch {
	case rest == "":
	case strings.HasPrefix(rest, "  # "):
		note = strings.TrimPrefix(rest, "  # ")
	default:
		return "", "", false
	}
	if !strings.HasPrefix(value, "tcp://") && !strings.HasPrefix(value, "udp://") {
		return "", "", false
	}
	return value, note, true
}

// AddressWarning is learn's warning that a proposal allows addresses, not host names, when text still carries it in
// its header (Withhold drops it with the last address it withholds), and "" when it does not: the dashboard's plan
// from a run says it as a note, so the preview, which reads only the entries, says it too.
func AddressWarning(text string) string {
	if strings.Contains(text, "# WARNING: "+learn.AddressWarning+".\n") {
		return learn.AddressWarning
	}
	return ""
}

// isAddress is whether a tcp:// or udp:// item value names an address, not a host.
func isAddress(value string) bool {
	_, err := netip.ParseAddrPort(value[len("tcp://"):]) // udp:// is as long
	return err == nil
}

// plainAddr is ap's address as learn writes it: unmapped, with no zone.
func plainAddr(ap netip.AddrPort) netip.Addr { return ap.Addr().Unmap().WithZone("") }

// destIndex is dests read once: each as written, and each that parses as an address and port, by its first place.
// A leak's host can stand for an address per DNS answer, and NeverAllow names each: parsing every dest for every item
// took 16 s at 20,000.
type destIndex struct {
	written map[string]int
	parsed  map[netip.AddrPort]int
}

func indexDests(dests []string) destIndex {
	ix := destIndex{written: make(map[string]int, len(dests)), parsed: map[netip.AddrPort]int{}}
	for i, d := range dests {
		if _, seen := ix.written[d]; !seen {
			ix.written[d] = i
		}
		if dp, err := netip.ParseAddrPort(d); err == nil {
			k := netip.AddrPortFrom(plainAddr(dp), dp.Port())
			if _, seen := ix.parsed[k]; !seen {
				ix.parsed[k] = i
			}
		}
	}
	return ix
}

// match is the place of the first dest an item value ("tcp://D" or "udp://D") names, -1 for none. An address and port
// compare as parsed (so one address written two ways still matches); anything else compares as written.
func (ix destIndex) match(value string) int {
	addr := value[len("tcp://"):]
	at := -1
	if i, ok := ix.written[addr]; ok {
		at = i
	}
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		if i, ok := ix.parsed[netip.AddrPortFrom(plainAddr(ap), ap.Port())]; ok && (at < 0 || i < at) {
			at = i
		}
	}
	return at
}
