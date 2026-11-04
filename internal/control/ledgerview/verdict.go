// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/syslookup"
)

// A run's verdict is the one sentence a person reads first: did secrets leave, did Tego stop an attempt, or was there
// nothing to see. It is read from the run's Signal and nothing else, so the run page's banner, the Overview and Runs
// rows and Compare say the same thing about the same run.

// The kinds of a Verdict.
const (
	// VerdictLeak: a secret was read (observed or allowed) next to a send that got through to a destination the
	// contract does not list.
	VerdictLeak = "leak"
	// VerdictProtected: no leak, and Tego refused a secret read or a send next to a secret.
	VerdictProtected = "protected"
	// VerdictWatched: a watched (observe) run read secrets, and no destination was first contacted next to them. It
	// says nothing about a send later than that, or to a destination the run already knew: Reached counts those.
	VerdictWatched = "watched"
	// VerdictQuiet: no attack attempt was seen.
	VerdictQuiet = "quiet"
)

// Verdict is what a run's Signal says happened to its secrets.
type Verdict struct {
	Kind string
	// Partial means some history or unsupported records are outside the verdict.
	Partial bool
	// Observe is a run at tier observe (tego watch): it records only and blocked nothing.
	Observe bool
	// Exposed are the secret paths read next to a send that got through (a leak); Read are the secret paths a
	// watched run read with no new destination next to them.
	Exposed, Read []string
	// Reached counts the destinations a watched run got through to that no contract names: not next to a secret by
	// NearSecretWindow and NearSecretLines, and still where a key can have gone. Lookups and unix sockets are not
	// counted. 0 on any other kind.
	Reached int
	// Dests are the destinations: for a leak where the secrets went (the closest first), otherwise the destinations
	// next to a secret whose sends were refused.
	Dests []string
	// Addrs is, for a leak, the addresses behind each of Dests keyed by a host name (Dest.Addrs): NeverAllow's second half.
	Addrs map[string][]string
	// SecretReads counts refused secret reads (lines) over SecretFiles paths; Sends counts refused sends next to a
	// secret; Asked counts the asks a person answered.
	SecretReads, SecretFiles, Sends, Asked int
	// Lookups counts the refused system and DNS lookups (lookupDst), which the verdict never counts as a send: the
	// banner names them in its second line only.
	Lookups int
	// Kept are the secret paths Tego protected on a protected run: each one whose read it refused, and each one read
	// next to a send it refused (nothing got through for it). Empty on any other kind.
	Kept []string
}

// Protected is how many distinct secrets Tego kept (Kept): the same unit as a leak's len(Exposed), so the Runs and
// Overview Secrets column counts secrets on both sides, never refusals (QA QU-4: "4 protected" for 2 secrets).
func (v Verdict) Protected() int { return len(v.Kept) }

// Stopped is the attempts Tego refused that the verdict counts: secret reads and sends next to a secret. The Runs
// and Overview chip, the run page's banner and Compare's sentence all print this one number.
func (v Verdict) Stopped() int { return v.SecretReads + v.Sends }

// RefusedWords names each refused count with its own destination: "2 secret reads and 1 send to 127.0.0.1:48802",
// "3 sends (to 10.0.0.9:443 and 1 more)", "" when nothing was refused. It adds up to Stopped.
func (v Verdict) RefusedWords() string {
	var parts []string
	if v.SecretReads > 0 {
		parts = append(parts, count(v.SecretReads, "secret read", "secret reads"))
	}
	if v.Sends > 0 {
		w := count(v.Sends, "send", "sends")
		switch {
		case len(v.Dests) == 1:
			w += " to " + v.Dests[0]
		case len(v.Dests) > 1:
			w += fmt.Sprintf(" (to %s and %d more)", v.Dests[0], len(v.Dests)-1)
		}
		parts = append(parts, w)
	}
	return strings.Join(parts, " and ")
}

// Names are the base names of the exposed secret paths, in order: "id_rsa", "token".
func (v Verdict) Names() []string {
	out := make([]string, len(v.Exposed))
	for i, p := range v.Exposed {
		out[i] = path.Base(p)
	}
	return out
}

// Dest is the first destination, "" when there is none.
func (v Verdict) Dest() string {
	if len(v.Dests) == 0 {
		return ""
	}
	return v.Dests[0]
}

// NeverAllow is what a contract made from this run must not allow, closest to the secret first: each destination the
// secrets went to, then the addresses behind it. learn writes addresses, and Dests holds a name where the line held one,
// so a name alone would match no entry and the address would stay allowed. Nil unless the verdict is a leak.
func (v Verdict) NeverAllow() []string {
	if v.Kind != VerdictLeak {
		return nil
	}
	var out []string
	for _, d := range v.Dests {
		out = append(append(out, d), v.Addrs[d]...)
	}
	return out
}

// RunVerdict reads one run's verdict from its signal (Signal(r, ...)).
func RunVerdict(r *Run, s *RunSignal) Verdict {
	v := Verdict{Kind: VerdictQuiet, Partial: r.Cut || r.Bad > 0, Observe: r.Tier == "observe"}
	if s == nil {
		return v
	}
	v.Asked = s.Approved + s.Denied
	var refusedPaths []string
	for _, st := range s.Secrets {
		if st.ReadNearSend {
			v.Exposed = append(v.Exposed, st.Path)
		} else if st.Observed+st.Allowed > st.Unread {
			v.Read = append(v.Read, st.Path)
		}
		if st.Refused > 0 {
			v.SecretReads += st.Refused
			v.SecretFiles++
			refusedPaths = append(refusedPaths, st.Path)
		}
	}
	type dest struct {
		key   string
		dist  uint64
		n     int
		addrs []string
	}
	var leak, refused []dest
	for i := range s.Outbound {
		d := &s.Outbound[i]
		if lookupDst(d) {
			v.Lookups += d.Refused
			continue
		}
		if !d.Background && !d.InContract && d.Observed+d.Allowed > 0 && !strings.HasPrefix(d.Key, "unix:") {
			v.Reached++
		}
		if !sendNearSecret(d) {
			continue
		}
		dist := ^uint64(0)
		for _, st := range s.Secrets {
			dist = min(dist, pairDistance(st.reads, d.sends))
		}
		if dist != ^uint64(0) {
			leak = append(leak, dest{d.Key, dist, d.Observed + d.Allowed, d.Addrs})
		}

		if d.Refused > 0 {
			v.Sends += d.Refused
			refused = append(refused, dest{key: d.Key, n: d.Refused})
		}
	}
	slices.SortStableFunc(leak, func(a, b dest) int {
		if c := cmp.Compare(a.dist, b.dist); c != 0 {
			return c
		}
		return b.n - a.n
	})
	slices.SortStableFunc(refused, func(a, b dest) int { return b.n - a.n })
	switch {
	case len(leak) > 0:
		v.Kind = VerdictLeak
		for _, d := range leak {
			v.Dests = append(v.Dests, d.key)
			if len(d.addrs) > 0 {
				if v.Addrs == nil {
					v.Addrs = map[string][]string{}
				}
				v.Addrs[d.key] = d.addrs
			}
		}
	case v.Stopped() > 0:
		v.Kind = VerdictProtected
		v.Read, v.Exposed = nil, nil
		v.Kept = refusedPaths
		if v.Sends > 0 {
			// No send got through, so a secret read next to a refused send stayed here too.
			for _, st := range s.Secrets {
				if st.NearSend && len(st.reads) > 0 && !slices.Contains(v.Kept, st.Path) {
					v.Kept = append(v.Kept, st.Path)
				}
			}
		}
		for _, d := range refused {
			v.Dests = append(v.Dests, d.key)
		}
	default:
		// No leak and nothing stopped: the secrets a send was near were sent nowhere that got through.
		v.Read = append(v.Read, v.Exposed...)
		v.Exposed = nil
		if v.Observe && len(v.Read) > 0 {
			v.Kind = VerdictWatched
		}
	}
	if v.Kind != VerdictWatched {
		v.Read, v.Reached = nil, 0
	}
	return v
}

// sendNearSecret reports whether a destination is one the verdict reads sends to: off the contract, first contacted
// next to a secret, and neither a lookup (lookupDst) nor background. Its refusals are the verdict's Sends, and Compare's
// Stopped cells for destinations are these and no others.
func sendNearSecret(d *Dest) bool {
	return !lookupDst(d) && !d.Background && !d.InContract && d.NearSecret
}

// nearest is the smallest line distance from seq to one of at.
func nearest(seq uint64, at []uint64) uint64 {
	best := ^uint64(0)
	for _, a := range at {
		d := a - seq
		if seq > a {
			d = seq - a
		}
		best = min(best, d)
	}
	return best
}

// lookupDst reports whether a destination is a system lookup socket (IsSystemLookup) or a resolver (Dest.Resolver,
// ResolverDst): the lookups the C library makes around any connect, which carry none of the run's data. Such a
// destination is never next to a secret, never a send a verdict counts and never where a verdict says secrets went.
func lookupDst(d *Dest) bool { return IsSystemLookup(d.Key) || d.Resolver || ResolverDst(d.Key) }

// ResolverDst reports whether a destination key ("host:port") is a DNS resolver going by the key alone: port 53 on this
// machine. A resolver at any other address is known by its lines' rule (Dest.Resolver). It is syslookup.Resolver, the
// receipt's test too.
func ResolverDst(key string) bool { return syslookup.Resolver(key, "") }

// The marks a timeline row carries on a run whose secrets got through or were read (Verdict.Mark), so the lines the
// banner speaks of stand out from the routine reads around them (QA QU-3).
const (
	// MarkSecret is a read that got through (observed or allowed) of a secret path the verdict names.
	MarkSecret = "secret"
	// MarkSent is a connect that got through to a destination the verdict says the secrets went to.
	MarkSent = "sent"
)

// Mark is what line e is to the verdict: MarkSecret, MarkSent, or "" for every other line. Only a leak or a watched
// run's secret reads mark anything: on a protected run nothing got through, and green says so.
func (v Verdict) Mark(e *Event) string {
	if e == nil || e.Refused() || e.Verdict == "ask" || (v.Kind != VerdictLeak && v.Kind != VerdictWatched) {
		return ""
	}
	switch e.Kind {
	case "fs":
		if e.readNothing {
			return "" // a failed open, a create or a write-only open of the path: nothing was read here
		}
		for _, p := range paths(e.Target) {
			if slices.Contains(v.Exposed, p) || slices.Contains(v.Read, p) {
				return MarkSecret
			}
		}
	case "net":
		if v.Kind != VerdictLeak || !outboundOp(e.Op) {
			return ""
		}
		name, dst := splitNet(e.Target)
		if key, _ := destKey(dst, name); dst != "" && slices.Contains(v.Dests, key) {
			return MarkSent
		}
	}
	return ""
}

// MarkedTimeline is r's timeline (newest first, as TimelineOf) holding only the lines v marks (Mark): the run page's
// "Secrets and sends" filter on a watched run. It is built on each call; the lines it keeps are few.
func MarkedTimeline(r *Run, v Verdict) *Timeline {
	return &Timeline{foldRun(r.AllEvents(), nil, func(_ int32, e *Event) bool { return !e.Mirror && v.Mark(e) != "" })}
}
