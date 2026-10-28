// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// LiveMode is live.mode, how a run's rules may change while it runs (ADR 0125 decision 1). Every package, the CLI and
// the dashboard use these two names.
type LiveMode string

const (
	// LiveLocked is the default (no live: key, or live.mode: locked): file, program and network rules are fixed when the run starts, a run
	// may be tightened while it runs (live blocks, pause, ADR 0124) and loosened only from its next run.
	LiveLocked LiveMode = "locked"
	// LiveAdjustable ("Adjustable (live both ways)" in the UI) adds a fence: the kernel layers enforce the contract
	// plus every fence entry, and Tego's live layer refuses each fence entry until the operator lifts or grants it.
	LiveAdjustable LiveMode = "adjustable"
)

// The fence's three kinds (ADR 0125 decision 2). There is no write kind: a file change other than an open cannot be
// completed race-free without a writer for the kernel plane.
const (
	LiveKindRead = "read"
	LiveKindNet  = "net"
	LiveKindExec = "exec"
)

// Where a fence entry comes from (LiveEntry.Source).
const (
	// LiveSourceDeny is an entry that takes out one of the contract's own refusals: an fs.deny_read entry, or an
	// exec.deny entry that names a whole program.
	LiveSourceDeny = "deny"
	// LiveSourceNew is access the contract does not have at all.
	LiveSourceNew = "new"
)

// MaxLiveFence is the most entries a fence may hold (ADR 0125 decision 2).
const MaxLiveFence = 64

// LiveSection is the contract's live: key. Only the top-level contract's counts: a profile that sets it is refused
// ([live-in-profile]).
type LiveSection struct {
	Mode  LiveMode   `yaml:"mode,omitempty" json:",omitempty"`
	Fence *LiveFence `yaml:"fence,omitempty" json:",omitempty"`
}

// LiveFence is live.fence: the access Tego may grant while the run runs. Every entry is refused at start.
type LiveFence struct {
	// Read entries are paths, each with everything beneath it, for reads only.
	Read []string `yaml:"read,omitempty"`
	// Net entries are host:port or IP:port destinations.
	Net []string `yaml:"net,omitempty"`
	// Exec entries are absolute program paths.
	Exec []string `yaml:"exec,omitempty"`
}

// entries is the number of entries the fence holds; 0 for a nil fence.
func (f *LiveFence) entries() int {
	if f == nil {
		return 0
	}
	return len(f.Read) + len(f.Net) + len(f.Exec)
}

// LiveTable is what Compile hands the launcher for an Adjustable contract (RuleTable.Live): the mode and every fence
// entry, each in the form the live overlay names it (internal/liveblock.Normalize).
type LiveTable struct {
	Mode    LiveMode
	Entries []LiveEntry
	// SHA256 is the fence's digest, run_start.live_fence.sha256: lower-case hex sha256 of the JSON array of
	// {"Kind","Value","Source"} objects, one per entry in Entries' order ("[]" for an empty fence), with a "Name" member
	// after Source on an exec entry that has one (LiveEntry.Name).
	SHA256 string
}

// LiveEntry is one fence entry.
type LiveEntry struct {
	// Kind is LiveKindRead, LiveKindNet or LiveKindExec.
	Kind string
	// Value is the entry as the live overlay names it: a read path absolute and cleaned (~ and a relative path
	// resolved as compile resolves fs entries), a net destination as a lower-case host:port or IP:port (an IPv6
	// address in brackets), an exec program as an absolute, cleaned path.
	Value string
	// Source is LiveSourceDeny or LiveSourceNew.
	Source string
	// Name is, for an exec entry that took out an exec.deny entry (Source deny; exec.deny entries are bare names such
	// as psql), that name: the kernel layers then run every program of that name, wherever it is, so the live layer refuses every
	// exec of that name until a lift, as exec.deny did, not only Value. "" for every other entry. It is part of the
	// digest only when set, so the digest of every other fence is the same as without it.
	Name string `json:",omitempty"`
	// Images are, for an exec entry, the other program files the kernel layers run because the entry is granted: the
	// helper images of its tool (git's exec-path git and its dashed helpers, ADR 0048 (2)), each a file of its own
	// that compile grants beside an exec.allow entry naming the tool. The live layer refuses an exec of any of them
	// until the entry is lifted, as it refuses Value (For); without them a fenced git ran by its other path. They are this host's files, found from Value, so they are not part of the
	// digest. nil for every other entry.
	Images []string `json:",omitempty"`
	// Raw is the entry as written.
	Raw string
	// Pos is where it was written.
	Pos Pos
}

// Rule is the rule an event carries when this fence entry refused it, or allowed it only because the entry is
// lifted: live.fence[<kind>:<value>], never a contract rule (ADR 0125 decision 9).
func (e LiveEntry) Rule() string { return LiveFenceRule(e.Kind, e.Value) }

// LiveFenceRule is the rule name of the fence entry of kind and value.
func LiveFenceRule(kind, value string) string { return "live.fence[" + kind + ":" + value + "]" }

// liveDigest is LiveTable.SHA256 for entries.
func liveDigest(entries []LiveEntry) string {
	type keyed struct {
		Kind, Value, Source string
		Name                string `json:",omitempty"`
	}
	ks := make([]keyed, 0, len(entries))
	for _, e := range entries {
		ks = append(ks, keyed{e.Kind, e.Value, e.Source, e.Name})
	}
	b, err := json.Marshal(ks)
	if err != nil { // three strings cannot fail to encode
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Entry returns the fence entry of kind and value exactly, if the fence holds one.
func (t *LiveTable) Entry(kind, value string) (LiveEntry, bool) {
	if t == nil {
		return LiveEntry{}, false
	}
	for _, e := range t.Entries {
		if e.Kind == kind && e.Value == value {
			return e, true
		}
	}
	return LiveEntry{}, false
}

// Covering returns the fence entry that decides a read of path p: the read entry at or above it. A net or exec entry
// covers its own value only (Entry).
func (t *LiveTable) Covering(p string) (LiveEntry, bool) {
	if t == nil {
		return LiveEntry{}, false
	}
	for _, e := range t.Entries {
		if e.Kind == LiveKindRead && isAncestorOrSelf(e.Value, p) {
			return e, true
		}
	}
	return LiveEntry{}, false
}

// For returns the fence entry an action reaches, whatever contract rule the kernel layers matched it by: a read of a
// path at or beneath a read entry (Covering; Path as the run's walk lands it, Canonical), an exec of an entry's path, of
// one of its Images or, for an entry with a Name, of any program of that name, and a TCP connect to an entry's destination. An action it
// returns is refused by the live layer until the entry is lifted, and once lifted it is allowed only because of the
// lift, so its record names LiveEntry.Rule(), never the contract rule that matched (ADR 0125 decision 9): a directory
// exec.allow entry can match an exec the fence took out of exec.deny, and a read outside every deny_read matches no
// rule at all. Every decision core names an allowed action this way (decide.Evaluate); the live layer refuses by it.
//
// A connect is found by its destination as given: a host entry such as api.stripe.com:443 is not found from a connect
// to an address the host resolved to, which is how the supervisor sees an agent's connect (it matches the address,
// Resolver.Match). A live layer refuses such a connect by the net rule the connect matched (ForNet), or by the host the
// resolver matched it to, as supervisor/liveblock.go's MatchInet does for a live block; never by For alone.
func (t *LiveTable) For(a Action) (LiveEntry, bool) {
	if t == nil || t.Mode != LiveAdjustable {
		return LiveEntry{}, false
	}
	switch a.Kind {
	case ActionFSRead:
		if !filepath.IsAbs(a.Path) {
			return LiveEntry{}, false
		}
		return t.Covering(filepath.Clean(a.Path))
	case ActionExec:
		if !filepath.IsAbs(a.Path) {
			return LiveEntry{}, false
		}
		p := filepath.Clean(a.Path)
		for _, e := range t.Entries {
			if e.Kind == LiveKindExec && (e.Value == p || slices.Contains(e.Images, p) || e.Name != "" && filepath.Base(p) == e.Name) {
				return e, true
			}
		}
	case ActionNetConnect:
		if proto := strings.ToLower(a.Proto); proto != "" && proto != ProtoTCP || a.Port < 1 || a.Port > 65535 {
			return LiveEntry{}, false
		}
		return t.Entry(LiveKindNet, liveDest(a.Host, a.Port))
	}
	return LiveEntry{}, false
}

// ForNet returns the fence entry a connect reaches through the net rule it matched: the entry that added r (its Fence
// mark), whatever address the connect named. It is the net counterpart of For for a connect matched by address to a
// host entry's resolved addresses (For).
func (t *LiveTable) ForNet(r NetRule) (LiveEntry, bool) {
	if t == nil || t.Mode != LiveAdjustable || !r.Fence {
		return LiveEntry{}, false
	}
	return t.Entry(LiveKindNet, strings.TrimPrefix(r.Raw, ProtoTCP+"://"))
}

// liveDest is a connect's destination as a net fence value names it (liveNetValue): an IP:port in netip's form, an
// IPv6 address in brackets, or a lower-case host without its final dot.
func liveDest(host string, port int) string {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		return netip.AddrPortFrom(a.Unmap().WithZone(""), uint16(port)).String()
	}
	return strings.TrimSuffix(strings.ToLower(h), ".") + ":" + strconv.Itoa(port)
}

// Adjustable reports whether the table was compiled from a contract with live.mode: adjustable.
func (rt *RuleTable) Adjustable() bool {
	return rt != nil && rt.Live != nil && rt.Live.Mode == LiveAdjustable
}

// ErrLiveTier is wrapped by LiveTierCheck's refusal.
var ErrLiveTier = errors.New("live.mode: adjustable needs tier cgroup or bpflsm")

// LiveTierCheck is ADR 0125 decision 7: an Adjustable run is allowed at tier cgroup and bpflsm only, and never in an
// --observe run, which enforces nothing. Compile asks it of a pinned tier; the launcher asks it of the tier auto
// resolved to.
func LiveTierCheck(tier backend.Tier, observe bool) error {
	switch {
	case observe || tier == backend.TierObserve:
		return fmt.Errorf("%w: an --observe run enforces nothing, so it has no live refusal to lift (ADR 0125); "+
			"observe with live.mode: locked, or run without --observe", ErrLiveTier)
	case tier == backend.TierCgroup || tier == backend.TierBPFLSM:
		return nil
	}
	return fmt.Errorf("%w. At tier %s Tego keeps Adjustable off by policy: its live refusals would rest on the supervisor "+
		"alone, while at cgroup and bpflsm they can move into kernel checks Tego already runs there (ADR 0125). Use "+
		"live.mode: locked, or tier: cgroup (needs root)", ErrLiveTier, tierName(tier))
}

// tierName is t, or landlock for an empty tier (no tier resolved yet reads as the unprivileged one).
func tierName(t backend.Tier) backend.Tier {
	if t == "" {
		return backend.TierLandlock
	}
	return t
}
