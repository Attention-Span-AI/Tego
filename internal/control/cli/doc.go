// SPDX-License-Identifier: Apache-2.0

// Package cli is tego-control's command line (ADR 0100 (2)): one file per noun, each registering its command from
// init, a usage generated from the registry and sorted, and a guard that refuses every command at euid 0 or with a
// capability [control-as-root]. The nouns are internal/handoff's list; version and licenses are tego-control's own, as
// tego has its own. A noun whose service has not landed registers a command that says so [not-built] and changes
// nothing; the package that builds the noun replaces that one registration.
//
// serve checks a run's chain against the anchor ledger.AnchorPath names, the rule tego anchors by; it reads that
// chain.log and never writes it. It resolves the ledger_root it shows itself, in ledgerRootOf, by the rule the
// engine's LedgerRoot applies, since it may not import the engine. For an account with no home that root also places
// the chain.log serve reads: the one beside it, where tego anchors the account's runs.
//
// Imports: the standard library, internal/handoff (the noun list and the shared reason codes), internal/buildinfo,
// internal/platform/sys (capabilities), pkg/spec/identity (exit codes), the module root's package (the licence texts
// licenses prints), internal/platform/proc (open starts the browser), and for serve internal/control/web (the
// dashboard), internal/control/rules (its rule service), internal/profilesrc (where a rules file's extends: names are
// read from, as tego reads them), internal/ledger (ledger.AnchorPath), pkg/spec/config (the ledger_root) and
// pkg/spec/record (terminal-safe text).
// Must not import: the engine (internal/runtime, internal/policy, internal/bpf, internal/cli, cilium/ebpf,
// go-landlock): depguard control-links-no-engine and TestControlLinksNoEngine.
package cli
