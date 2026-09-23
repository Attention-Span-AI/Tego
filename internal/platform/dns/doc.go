// SPDX-License-Identifier: Apache-2.0

// Package dns answers the two network questions the supervisor asks about a destination it read out of a
// target process: "is this one of the machine's DNS resolvers?" and "does a compiled net.allow entry admit
// this ip:port right now?".
//
// ReadResolvConf/SystemResolvers take the /etc/resolv.conf snapshot a run starts with (SEMANTICS §5: the
// resolver is allowed on UDP and TCP 53 in every tier); an unreadable or empty file yields no addresses and
// the exception then matches nothing (docs/p0/supervisor.md E32).
//
// Set holds the compiled agent.NetRule entries with their live IP sets and matches a netip.AddrPort against
// them (host:port exact, cidr:port, port 0 for ICMP/raw — R7). Host entries are re-resolved on TTL by Refresh
// or by the background Run loop: the merge happens before the swap and a lookup failure keeps the stale
// addresses, so a transient DNS outage never turns into a refusal (R8a, R27, E29). Readers are lock-free: a
// Match reads one atomically-stored immutable snapshot. Refreshed hands the live addresses back as rule-table
// entries, and Stats().Changed counts the refreshes that moved any, so a second enforcer of the same entries
// (tier 2's kernel rows, docs/p0/enforce-cgroup-observe.md E7) can follow the set.
//
// Imports: standard library (net, net/netip), pkg/spec/agent
// Must not import: internal/runtime/*, internal/ledger, internal/check, cilium/ebpf
package dns
