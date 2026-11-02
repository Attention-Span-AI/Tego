// SPDX-License-Identifier: Apache-2.0

// Package selftest is `tego test` (ADR 0074): a defensive conformance self-check of Tego's own enforcement on this
// machine. In a temporary directory it makes (Tree), it sets up decoys (a fake home with a fake SSH key and .env, a
// small project, a copy of /bin/true (or the true on $PATH), a loopback listener it owns) and runs a fixed list of four harmless actions
// twice: once directly ("baseline", which shows the action works on this machine) and once as the agent of
// `tego run <embedded contract> -- tego __check <name> <workdir>` ("under Tego", where it must be refused). Each
// verdict comes from the run's ledger, read with `tego events <run> --json`: refused, with the rule and reason.
//
// It is a Layer 2 black box: it starts the tego binary through internal/platform/proc and reads what tego prints,
// so it tests the product a user runs, never the engine's Go API. The hidden verb (CheckMain) accepts only a check
// name and a workdir that `tego test` made (it carries Tree's marker), and touches nothing outside it.
//
// A product build runs the embedded contract only. A binary built with -tags tegotesthooks runs the template
// TEGO_TEST_SELFTEST_CONTRACT names instead, when it names one (contract_testhook.go): the integration test changes
// one line of the embedded contract there, to watch tego test report the check it reaches and exit 1.
//
// Imports: internal/platform/proc, pkg/spec/identity, pkg/spec/config (the trust check of the caller's $TEGO_CONFIG
// layer, so tego test acts on no layer tego run refuses), gopkg.in/yaml.v3, the standard library
// Must not import: internal/runtime, internal/policy/decide, internal/bpf, internal/cli (depguard
// selftest-never-imports-runtime)
package selftest
