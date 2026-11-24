// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func within(path, parent string) bool {
	if path == "" || parent == "" {
		return path == parent
	}
	return path == parent || strings.HasPrefix(path, strings.TrimSuffix(parent, "/")+"/")
}

func fsPath(r agent.FSRule) string {
	if r.Resolved != "" {
		return r.Resolved
	}
	return r.Path
}

func fsAuthority(r agent.FSRule) agent.FSRule {
	r.Raw, r.Pos = "", agent.Pos{}
	// The filesystem's descriptive name does not grant rights. Device and
	// object facts remain, because backend compaction reads them.
	r.Mount, r.Filesystem = "", ""
	return r
}

func fsCovers(x, y agent.FSRule) bool {
	if reflect.DeepEqual(x, y) {
		return true
	}
	xp, yp, xr, yr, xa, ya := x.Path, y.Path, fsPath(x), fsPath(y), x.Access, y.Access
	x.Path, y.Path, x.Resolved, y.Resolved, x.Access, y.Access = "", "", "", "", 0, 0
	return reflect.DeepEqual(x, y) && xa.Has(ya) && within(yp, xp) && within(yr, xr) && (!x.Regular || xp == yp && xr == yr)
}

func filesystem(a, b *agent.RuleTable) Result {
	// An assertion about AppArmor is authority the compiled FS slice does not
	// duplicate. A changed assertion cannot be ordered as a path grant.
	appArmor := func(t *agent.RuleTable) bool {
		return t.Contract != nil && t.Contract.FS != nil && t.Contract.FS.AppArmorAssumeRootNamespace
	}
	if appArmor(a) != appArmor(b) {
		return unknown()
	}
	writes := func(t *agent.RuleTable) (grants, other []agent.FSRule) {
		for _, r := range t.FS {
			r = fsAuthority(r)
			// fs.write: [] emits this root read sentinel. Reads already default
			// to allowed; it adds no write authority and disappears on the first
			// write grant. Every other implicit or refusal change stays visible.
			if reflect.DeepEqual(r, agent.FSRule{Path: "/", Resolved: "/", Kind: agent.FSImplicit}) {
				continue
			}
			if r.Kind == agent.FSWrite {
				grants = append(grants, r)
			} else {
				other = append(other, r)
			}
		}
		return
	}
	ag, ao := writes(a)
	bg, bo := writes(b)
	// Read refusals (deny_read, ask_read and the built-in list) are ordered by fsRefusals; every other
	// non-write row must be equal.
	ad, ar := splitRefusals(ao)
	bd, br := splitRefusals(bo)
	if !reflect.DeepEqual(ar, br) {
		return unknown()
	}
	refusals, ok := fsRefusals(ad, bd, ag, bg)
	if !ok {
		return unknown()
	}
	return merge(compareGrants(ag, bg, fsCovers, func(r agent.FSRule) string { return "Write " + fsPath(r) }), refusals)
}

func fsApprovals(a, b *agent.RuleTable) Result {
	clean := func(in []agent.FSRule) []agent.FSRule {
		out := make([]agent.FSRule, len(in))
		for i, r := range in {
			out[i] = fsAuthority(r)
		}
		return out
	}
	return compareGrants(clean(a.FSAsk), clean(b.FSAsk), fsCovers, func(r agent.FSRule) string { return "Ask to write " + fsPath(r) })
}

func programs(a, b *agent.RuleTable) Result {
	unrestricted := func(t *agent.RuleTable) bool { return t.Contract.ExecUnrestricted() }
	anon := func(t *agent.RuleTable) bool { return t.Contract.ExecAnonymous() }
	var added, removed []string
	if !unrestricted(a) && unrestricted(b) {
		added = append(added, "Run programs without an image allow list")
	}
	if unrestricted(a) && !unrestricted(b) {
		removed = append(removed, "unrestricted programs")
	}
	if !anon(a) && anon(b) {
		added = append(added, "Run anonymous programs")
	}
	if anon(a) && !anon(b) {
		removed = append(removed, "anonymous programs")
	}
	clean := func(in []agent.ExecRule) []agent.ExecRule {
		out := slices.Clone(in)
		for i := range out {
			out[i].Raw, out[i].Pos, out[i].Source = "", agent.Pos{}, ""
		}
		return out
	}
	ag, bg := clean(a.Exec), clean(b.Exec)
	covers := func(x, y agent.ExecRule) bool {
		if reflect.DeepEqual(x, y) {
			return true
		}
		xp, yp, xr, yr, dir, childDir := x.Path, y.Path, x.Resolved, y.Resolved, x.IsDir, y.IsDir
		// A directory covers an image's paths, but only a matching basename
		// grant can cover that image's additional name authority at tier 3.
		if y.ByName && (!x.ByName || x.Basename != y.Basename) {
			return false
		}
		x.Path, y.Path, x.Resolved, y.Resolved, x.IsDir, y.IsDir = "", "", "", "", false, false
		x.Basename, y.Basename, x.ByName, y.ByName = "", "", false, false
		// Basename matching applies only at some tiers. Do not collapse a
		// different name into directory coverage across all tiers.
		return reflect.DeepEqual(x, y) && (dir && within(yp, xp) && within(yr, xr) || !childDir && xp == yp && xr == yr)
	}
	if !unrestricted(b) {
		for _, r := range bg {
			if !unrestricted(a) && !slices.ContainsFunc(ag, func(old agent.ExecRule) bool { return covers(old, r) }) {
				added = append(added, "Run "+r.Path)
			}
		}
	}
	if !unrestricted(a) {
		for _, r := range ag {
			if !unrestricted(b) && !slices.ContainsFunc(bg, func(next agent.ExecRule) bool { return covers(next, r) }) {
				removed = append(removed, r.Path)
			}
		}
	}
	return order(added, removed)
}

func netAuthority(r agent.NetRule) agent.NetRule {
	r.Raw, r.Pos = "", agent.Pos{}
	r.ResolvedAt, r.TTL = time.Time{}, 0
	r.ExpiresAt = r.ExpiresAt.UTC()
	r.IPs, r.Denied = canonicalIPs(r.IPs), canonicalIPs(r.Denied)
	return r
}

func netCovers(x, y agent.NetRule) bool {
	x, y = netAuthority(x), netAuthority(y)
	if reflect.DeepEqual(x, y) {
		return true
	}
	if x.Port != y.Port || x.Verdict != y.Verdict || x.Proto != y.Proto && (x.Proto != agent.ProtoInet || y.Proto != agent.ProtoTCP && y.Proto != agent.ProtoUDP) {
		return false
	}
	x.Proto = y.Proto
	if reflect.DeepEqual(x, y) {
		return true
	}
	// A CIDR containment comparison covers every address, not a probe of its
	// first IP. Other changed resolution facts remain conservatively distinct.
	if x.CIDR != nil && y.CIDR != nil {
		xc, yc := *x.CIDR, *y.CIDR
		x.CIDR, y.CIDR = nil, nil
		x.Host, y.Host = "", ""
		return reflect.DeepEqual(x, y) && xc.Bits() <= yc.Bits() && xc.Contains(yc.Addr())
	}
	return false
}

func netRuntimeChanged(a, b []agent.NetRule) bool {
	for _, x := range a {
		for _, y := range b {
			xx, yy := netAuthority(x), netAuthority(y)
			if reflect.DeepEqual(xx, yy) {
				continue
			}
			// Resolved-address guarantees and runtime expiry affect authority.
			// They are not ordered as destination declarations. Compare their
			// supported scope separately, then require review of these facts.
			xx.ExpiresAt, yy.ExpiresAt = time.Time{}, time.Time{}
			xx.IPs, yy.IPs, xx.Denied, yy.Denied = nil, nil, nil, nil
			xx.PublicAnswer, yy.PublicAnswer = false, false
			if reflect.DeepEqual(xx, yy) {
				return true
			}
		}
	}
	return false
}

func netName(r agent.NetRule) string {
	if r.Raw != "" {
		return r.Raw
	}
	if r.CIDR != nil {
		return fmt.Sprintf("%s://%s:%d", r.Proto, r.CIDR, r.Port)
	}
	if r.UnixPath != "" {
		if r.UnixResolved != "" {
			return "unix:" + r.UnixResolved
		}
		return "unix:" + r.UnixPath
	}
	return fmt.Sprintf("%s://%s:%d", r.Proto, r.Host, r.Port)
}

func destinations(a, b *agent.RuleTable) Result {
	if netRuntimeChanged(a.Net, b.Net) {
		return unknown()
	}
	unrestricted := func(t *agent.RuleTable) bool { return t.Contract != nil && t.Contract.Net == nil }
	if !unrestricted(a) && unrestricted(b) {
		return Result{Direction: Widened, NewlyAllowed: []string{"Connect without a destination allow list"}}
	}
	if unrestricted(a) && !unrestricted(b) {
		return Result{Direction: Narrowed}
	}
	if unrestricted(a) && unrestricted(b) {
		return Result{Direction: Unchanged}
	}
	return compareNetwork(a.Net, b.Net, func(r agent.NetRule) string { return "Connect to " + netName(r) })
}

func netApprovals(a, b *agent.RuleTable) Result {
	if netRuntimeChanged(a.NetAsk, b.NetAsk) {
		return unknown()
	}
	// Ordinary allow entries dominate approval candidates. Omit a candidate
	// already covered by an ordinary grant when comparing the approval scope.
	candidates := func(t *agent.RuleTable) []agent.NetRule {
		var out []agent.NetRule
		for _, r := range t.NetAsk {
			allow := r
			allow.Verdict = agent.VerdictAllow
			if !netCovered(allow, t.Net) {
				out = append(out, r)
			}
		}
		return out
	}
	return compareNetwork(candidates(a), candidates(b), func(r agent.NetRule) string { return "Ask to connect to " + netName(r) })
}

func compareGrants[T any](a, b []T, covers func(T, T) bool, name func(T) string) Result {
	var added, removed []string
	for _, r := range b {
		if !slices.ContainsFunc(a, func(old T) bool { return covers(old, r) }) {
			added = append(added, name(r))
		}
	}
	for _, r := range a {
		if !slices.ContainsFunc(b, func(next T) bool { return covers(next, r) }) {
			removed = append(removed, name(r))
		}
	}
	return order(added, removed)
}
