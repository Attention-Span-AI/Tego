// SPDX-License-Identifier: Apache-2.0

// Package agent holds the agent contract: the Go types for agent.yaml v0,
// Load (YAML → Contract with a line and column on every diagnostic, the
// extends merge, every §5 validation rule), Compile (Contract + machine
// ceilings → an immutable RuleTable with resolved paths, loaders, addresses
// and clamped limits), PrintRuleTable for `tego compile`, Canonical and the
// contract_hash, and the types of `compile --test` plus LoadTestTable: the
// Action and EvalResult of a verdict a compiled table gives a hypothetical
// action in one tier, and the YAML table of action/expected-verdict rows the
// CLI evaluates against it. The verdicts themselves are internal/policy/decide's
// (ADR 0028), which registers itself here (RegisterDecider): Evaluate and its
// siblings are deprecated shims that delegate to it.
// External callers that need evaluation import pkg/policy/evaluate, the public
// bridge to that same version-dependent model; importing agent alone does not link it.
//
// The package reads; it never writes a file, opens a socket beyond DNS,
// touches the kernel, prints, or keeps a goroutine or fd past a call.
//
// Imports: standard library, gopkg.in/yaml.v3, pkg/spec/backend,
// pkg/spec/config (parameter type only), pkg/spec/record.
// Must not import: anything under internal/, golang.org/x/sync/errgroup or
// any other third-party module.
package agent
