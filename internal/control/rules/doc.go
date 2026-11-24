// SPDX-License-Identifier: Apache-2.0

// Package rules is the dashboard's rule service: the seam between the pages (internal/control/web, which decides and writes
// nothing itself and imports neither internal/ledger nor internal/check) and the code that reads a run's line and writes its
// contract (internal/rulefile, internal/check/rule), the same code `tego rule` writes through. It returns plain values
// the pages render.
//
// What it does:
//
//   - ActOn: "make this a rule" from one line of a run, every action at every scope, the picked change, and with a
//     confirm its write (ActReq carries the base the preview showed, the runs to "also apply now" and, for anything
//     but a narrowing, the preview's acknowledgement). A view of a line may carry the read model's offset of it
//     (ActReq.Hint): the line is then read by offset (rulefile.FindAtIn, which checks the hint and scans when it does
//     not hold) instead of decoding every line before it; a write ignores the hint and reads the line as before.
//   - Contracts: the bounded set of contract files the dashboard may change: those a run under this ledger root
//     recorded as its contract_source, and those this root's journal records as set up here (op create) that no run
//     ran yet, each passing every rulefile guard and named by an opaque Ref (never a path from the browser). Ref(path)
//     is that ref of a path a run recorded, which the Rules page names its rules files by.
//   - PlanNew, CreateNew and DescribeNew (new.go): "Set up a new agent". A project folder typed in the form (an
//     existing directory of this user's, not writable by others, not tego's own) and the presets, folders, hosts and
//     command of internal/setup (the code `tego rules create --preset` writes through), or a finished run's least-privilege
//     proposal; the draft's rules as sentences and its compile; then <dir>/agent.yaml written by rulefile.Create,
//     never over a file, journaled.
//   - PlanChange and ApplyChange: one structured edit (rule.ApplyEdits) of one contract; PlanRaw and ApplyRaw: the
//     full new text, a free edit that is confirmed explicitly. Save-eligible new and existing builder previews retain their proposal and one
//     acknowledgement of exact bytes, canonical destination, directory device/inode, dependency digests and
//     compiled result, plus a fresh system-random 192-bit review identity inside the acknowledgement.
//     PreviewOnly plans skip source/review storage; retained composition handles are refused.
//     Equal save-eligible Previews are separate reviews with fixed 30-minute lifetimes. Save claims each review once after
//     validation and before publication; replay and publication failure require review again. Save revalidates and writes those exact bytes, never rebuilding the proposal. Lost drafts
//     ask for review again. Narrowings carry a hidden review value; wider and unclassified families also require
//     explicit confirmation. The publisher verifies the reviewed identity against its final descriptor and
//     rechecks inherited source bytes. Existing saves refuse a base changed after Check; a historical editor warning
//     is cleared only after the submitted base and current source match the retained review. Saves journal under the ledger root.
//   - Revert undoes a journal entry with the history acknowledgement vocabulary; ActOn uses its event vocabulary.
//     These pre-existing paths require explicit confirmation for anything but a narrowing (ack.go).
//
// Production reads, plans, compiles and writes run in the bounded own-image filesystem helper (internal/contracts),
// through internal/control/pathcheck. All checks for one request, including feed and link references, reuse one helper.
// Caller-selected identity, runtime bases, guard homes, evaluation time and config snapshots cross as explicit data; the helper
// keeps its environment empty. A deadline abandons its worker without keeping a
// blocked service goroutine. Catalogue failure keeps ledger-only source entries and disables changes with the
// cannot-tell reason. Initial configuration, selected ledger/anchor and caller identity/current-directory capture remain synchronous inputs.
// A timed-out submitted write has an uncertain outcome and must be checked before repeating it. The service shares
// the initial resolved-source cache and acknowledgement key with its trusted helpers; per-operation file/read caches
// are helper-local and may be lost between page requests. Explicit callback seams are for tests.
//
// Draft compiles use internal/control/draftcompile and internal/nextrun: the machine's profile sources
// (internal/profilesrc), the run's tier, its run command grant, the invoking user's home, chain anchor and runtime
// directories, and the run's exec directories when the dashboard's PATH lacks them, offline and with no DNS. A
// preview (PlanChange, PlanRaw, ActOn without Write) then looks up the host names its change adds to net.allow or
// net.ask, all at once within nextrun.HostBudget (hosts.go), and names each that does not resolve here in the plan's
// Unresolved. Caller-specific resolver settings that cannot be reproduced give a cannot-tell warning instead.
// These are warnings, never refusals, since the next run resolves every host when it starts and does not start
// while one fails. A write does not look them up again.
//
// The draft builder compares every compiled rule family with pkg/spec/agentdiff before a save.
// Widened families list new grants; changed families it cannot order require explicit review.
// The comparison is pure and links no decision engine (ADR 0100, TestControlLinksNoEngine).
//
// Imports: pkg/spec/agentdiff, the standard library, gopkg.in/yaml.v3, golang.org/x/sys/unix, internal/check/rule, internal/check/inforce,
// internal/check/livestatus,
// internal/contracts, internal/control/pathcheck, internal/setup, pkg/spec/identity, internal/control/rulesview,
// internal/control/runact, internal/liveblock (Kind and Normalize only; writes go through runact), internal/ledger,
// internal/control/draftcompile, internal/nextrun, internal/profilesrc, internal/registry, internal/rulefile, internal/runlock, pkg/spec/agent, pkg/spec/backend,
// pkg/spec/config, pkg/spec/record.
// Must not import: the engine (internal/runtime, internal/policy, internal/bpf, internal/cli), internal/control/web.
package rules
