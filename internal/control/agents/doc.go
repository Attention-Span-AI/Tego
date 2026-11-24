// SPDX-License-Identifier: Apache-2.0

// Package agents supplies the Agents page's view, including recorded runs, scan
// coverage, observed refusals and remembered discoveries. No page launches a scan.
// Discoveries are remembered for 30 days in an owner-checked 0600 leaf store at
// ~/.tego/agents/discoveries.json, bounded to 256 entries and 256 KiB. Unreadable
// or oversized state is shown as such and never overwritten. Existing unexpired
// discoveries survive omissions and floods; overflow newcomers are not remembered,
// and the page states list truncation. Oldest last-seen discoveries sort first.
// Relations use current recorded facts. Only a usable latest scan establishes
// omission; historical, failed or unreadable scans request a rescan. A busy
// store lock reads the checked last committed snapshot without writing.
// The found list comes from scans. Tego refuses ordinary writes to these files, even with a whole-home grant at tier landlock; this was shown in guest row whole-home-landlock. With the anchor and ledger outside the home, a whole-home grant with direct reads can leave these files readable at landlock; that read case is derived from code and is owed in a guest. The stages shown for a run do not depend on this list.
// The list never proves that nothing else runs. Same-user processes outside Tego
// can change both files, too. This is the existing own-state limit, GAPS C52.
// Records keep nested deny rule names but not their resolved own-state relation
// and covering write grant. No per-run caution is inferred from these files or a
// current contract; adding that historical fact needs an allocated record minor.
// Unreadable modes or links show fixed repair steps without changing unsafe state;
// every readable recorded row remains visible. The residual direct-read case is owed in a guest.
// Imports: standard library, x/sys, platform/sys, agentid, guide, ledgerview, scan/result, shellword,
// spec/record. Must not import: web, CLI, runtime, policy, BPF, scan collection.
package agents
