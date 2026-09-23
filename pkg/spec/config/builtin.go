// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/netip"
	"time"
)

// Built-in defaults (spec/config/v0/README.md). Every ceiling is unbounded.
const (
	DefaultLedgerRoot = "~/.tego/runs"
	DefaultRetention  = 30 * day
	DefaultStopGrace  = 10 * time.Second
	DefaultAskTimeout = 5 * time.Minute
	// DefaultRingbuf is one run's record ring, and its capture ring when its capture is uprobe (ADR 0026 (2)):
	// the reader drains every 50 ms and is woken at an eighth full, and 2 MiB holds about 6,500 open records,
	// ten times what an open-heavy build (go build, about 12,000 opens a second) writes in one drain interval.
	DefaultRingbuf = ByteSize(2 << 20)
	// DefaultRingBudget caps the memlock of every live run ring on the host (ADR 0026 (2)): about 60 runs with a
	// record and a capture ring at DefaultRingbuf (about 2.1 MB each).
	DefaultRingBudget      = ByteSize(256 << 20)
	DefaultForwarderListen = "127.0.0.1:0"
	DefaultPrices          = "~/.tego/prices.yaml"
	DefaultProfiles        = "~/.tego/profiles"
	DefaultRegistry        = "~/.config/tego" // agent-contract.md R26; outside ~/.tego, which R6a read-denies
	DefaultLogLevel        = "info"
	// DefaultBPFLinger is how long a tier-2 build's pinned programs, maps and host-wide links stay attached
	// after its last run ended, so the next run within it adopts them instead of loading, attaching and later
	// detaching them again (ADR 0022).
	DefaultBPFLinger = 5 * time.Minute
)

// DefaultAskNotify is the default ask.notify list: the run's answer line (cli) and a desktop notice per held request
// where one can be sent (desktop), ADR 0122. ask.notify: [] turns both off.
func DefaultAskNotify() []string { return []string{"cli", "desktop"} }

// Builtin returns the compiled-in layer: every setting at its default with LayerBuiltin
// provenance, every ceiling unbounded, paths still holding their "~/" prefix (Load expands them
// against the invoking user's home directory).
func Builtin() *Machine {
	src := Provenance{Layer: LayerBuiltin}
	return &Machine{
		Tier:       Ceiling[TierSetting]{Value: TierSetting{Auto: true}, Source: src},
		Capture:    Ceiling[CaptureSetting]{Value: CaptureSetting{Auto: true}, Source: src},
		LedgerRoot: Setting[string]{Value: DefaultLedgerRoot, Source: src},
		Prices:     Setting[string]{Value: DefaultPrices, Source: src},
		Profiles:   Setting[string]{Value: DefaultProfiles, Source: src},
		Registry:   Setting[string]{Value: DefaultRegistry, Source: src},
		Retention:  Setting[time.Duration]{Value: DefaultRetention, Source: src},
		GCInterval: Setting[time.Duration]{Source: src},
		StopGrace:  Setting[time.Duration]{Value: DefaultStopGrace, Source: src},
		Limits: Limits{
			CPU: Ceiling[float64]{Source: src}, CPUWeight: Ceiling[int]{Source: src},
			Memory: Ceiling[ByteSize]{Source: src}, MemoryHigh: Ceiling[ByteSize]{Source: src},
			Pids: Ceiling[int]{Source: src}, Tokens: Ceiling[int64]{Source: src},
			CostUSD: Ceiling[float64]{Source: src}, Wall: Ceiling[time.Duration]{Source: src},
			StallAfter: Ceiling[time.Duration]{Source: src}, Repeats: Ceiling[int]{Source: src},
		},
		Ask: AskConfig{
			Timeout: Setting[time.Duration]{Value: DefaultAskTimeout, Source: src},
			Notify:  Setting[[]string]{Value: DefaultAskNotify(), Source: src},
		},
		Record: RecordConfig{Ringbuf: Setting[ByteSize]{Value: DefaultRingbuf, Source: src},
			MaxRunBytes: Ceiling[ByteSize]{Source: src}},
		BPF: BPFConfig{Linger: Setting[time.Duration]{Value: DefaultBPFLinger, Source: src},
			RingBudget: Setting[ByteSize]{Value: DefaultRingBudget, Source: src},
			Plane:      Setting[string]{Value: PlaneAuto, Source: src}},
		Resolver:         Setting[ResolverMode]{Value: ResolverMode{Auto: true}, Source: src},
		DeniedResolved:   Setting[[]netip.Prefix]{Value: []netip.Prefix{}, Source: src},
		Forwarder:        ForwarderConfig{Listen: Setting[string]{Value: DefaultForwarderListen, Source: src}},
		Log:              LogConfig{Level: Setting[string]{Value: DefaultLogLevel, Source: src}},
		Landlock:         LandlockConfig{Audit: Setting[string]{Value: LandlockAuditOff, Source: src}},
		PrivilegedBinary: Setting[string]{Source: src},
		Users:            Setting[map[string]UserPolicy]{Value: map[string]UserPolicy{}, Source: src},
	}
}
