// SPDX-License-Identifier: Apache-2.0

// Package agentdiff compares immutable compiled contracts family by family. It
// is a Layer 0 specification package beside agent's compiler output types. It
// performs no evaluation, I/O, name resolution, path lookup or kernel operation.
// The dashboard can link it without linking the decision engine (ADR 0100).
//
// Compare returns every family's direction: Unchanged, Narrowed, Widened with
// the entries newly admitted by that family, or CannotClassify. Widened includes
// mixed additions and removals. A family is an independent component of the
// final contract: a grant may still meet another family's refusal. Callers must
// show every CannotClassify change and require explicit confirmation for it and
// for every widening. They must not treat CannotClassify as safe composition.
//
// Rows is the exhaustive ownership matrix. TestFamilyCoverage walks RuleTable
// and every Contract field, public or private, rejecting missing or duplicate rows.
// TestClassifiedFieldCoverage separately checks the fields of types whose
// custom classifiers normalize or order individual members, including private
// fields of those nested custom types. The four existing private Contract fields
// (file, origins, loaded and profiles) are explicitly compiler metadata. Synthetic
// private-authority regressions reject an export-only coverage walk. New fields
// require a row decision before they can be silently ignored. Source positions, raw
// spelling, resolution timestamps and filesystem labels are presentation facts;
// metadata rows also name declarations already represented by compiled output.
// Contract.Command has its own row because argument changes need review even
// when they compile to the same image grant.
//
// The row table is the seed of ADR 0153's future composition check: customisation
// must be within the general contract in every family. Extend this matrix and
// its ordered classifiers rather than creating a second comparison. This package
// does not yet prove that composition relation for unclassified families.
//
// Classified rows: filesystem write subtrees and read refusals (a deny_read or ask_read row added or made stricter
// narrows, one removed or made looser widens; fsrefusals.go); filesystem protection's deny_write, approval-scope and
// deny_read pattern rows (each only a refusal); filesystem approval entries; program image grants and unrestricted
// and anonymous modes; destinations and destination approvals (including whole
// CIDR unions and transport containment); inherited environment names and
// refusals; wall duration; every network resource ceiling; approval pending,
// timeout and standing-refusal settings; credential injection authority tuples;
// read recording; process privilege flags. Changed network resolution guarantees, grant expiry deadlines
// and approval hold modes require review; adding or removing the broker is ordered.
// A change between auto and off is also presented for review. Environment assignment
// values never enter comparison messages. Network limits distinguish absent from
// explicit zero.
//
// Fold gives the one direction a set of results has (narrows, widens or mixed): a family that cannot be ordered is
// mixed, never narrowing.
//
// Unclassified rows: the rest of filesystem protection (name rules, own state, absent built-in rows, relaxations, held-read
// mode), program arguments, non-wall run
// limits, listeners, ingress, DNS, proxy, HTTP, gate, live controls, assurance,
// recording, protection tier, capture, harness, launch grants, built-in refusals,
// compile context, machine baseline/replay context, MCP, models, launch command
// and reserved declarations. An effective contract duplicating its own source is
// compared by the existing families; independent effective authority is frozen. Every
// changed field in these rows is visible as CannotClassify. The complete field
// ownership table is returned by Rows and documented in the builder's ADR 0156.
//
// Imports: standard library pure packages and pkg/spec/agent.
// Must not import: internal/, pkg/policy/evaluate, os, io, net, syscall,
// golang.org/x/sys or any package that evaluates decisions or performs I/O.
package agentdiff
