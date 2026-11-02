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
//     command of internal/setup (the code `tego init --preset` writes through), or a finished run's least-privilege
//     proposal; the draft's rules as sentences and its compile; then <dir>/agent.yaml written by rulefile.Create,
//     never over a file, journaled.
//   - PlanChange and ApplyChange: one structured edit (rule.ApplyEdits) of one contract; PlanRaw and ApplyRaw: the
//     full new text, a free edit that cannot be classified and is confirmed like a widening; Revert: a journal entry
//     undone. Every write refuses a stale base, needs an acknowledgement for anything but a narrowing, and is
//     journaled under the ledger root.
//   - The acknowledgement (ack.go) is bound to the preview: every plan carries Ack, an HMAC under a key that never
//     leaves the process of the change's ref, the text's base and the new text's sha256, and a write that is not a
//     narrowing is refused (ErrNeedsAck, ErrAckMismatch) unless it posts the Ack its own plan computes. It is
//     deterministic, so a live region re-rendered on every revision keeps its HTML.
//
// Every compile is the engine's (check.go, CheckContext, through internal/nextrun): the machine's profile sources
// (internal/profilesrc), the run's tier, its run command grant, the invoking user's home, chain anchor and runtime
// directories, and the run's exec directories when the dashboard's PATH lacks them, offline and with no DNS. A
// preview (PlanChange, PlanRaw, ActOn without Write) then looks up the host names its change adds to net.allow or
// net.ask, all at once within nextrun.HostBudget (hosts.go), and names each that does not resolve here in the plan's
// Unresolved: a warning, never a refusal, since the next run resolves every host when it starts and does not start
// while one fails. A write does not look them up again.
//
// Imports: the standard library, gopkg.in/yaml.v3, golang.org/x/sys/unix, internal/check/rule, internal/check/inforce,
// internal/check/livestatus,
// internal/setup, pkg/spec/identity, internal/control/rulesview,
// internal/control/runact, internal/liveblock (Kind and Normalize only; writes go through runact), internal/ledger,
// internal/nextrun, internal/profilesrc, internal/rulefile, internal/runlock, pkg/spec/agent, pkg/spec/backend,
// pkg/spec/config, pkg/spec/record.
// Must not import: the engine (internal/runtime, internal/policy, internal/bpf, internal/cli), internal/control/web.
package rules
