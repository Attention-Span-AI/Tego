// SPDX-License-Identifier: Apache-2.0

// Package claudecode is the Claude Code adapter (Layer 3): `tego hook claude-code`, the command hook that turns the
// run's new refusals into Claude Code hook output, with a cursor for each harness and a two-step claim for parallel delivery hooks
// (spec/reason/REASON-CHANNEL.md §3, ADR 0063).
//
// One command serves the five events a settings file lists it for (SessionStart, PostToolUse, PostToolUseFailure,
// PostToolBatch, Stop), routed by the payload's hook_event_name (Run). It reads the run's reason file (pkg/spec/
// reason, found through --reason or TEGO_REASON and accepted only as last-refusal.json in a run's runtime directory),
// claims the refusals that are its harness's (or nobody's) and not yet claimed under an exclusive lock on the run's
// hook-state directory (cursors and pending claims in hook-state/state.json), prints them, marks the claim printed
// (a hook stopped before that leaves the refusals for the next hook of its harness: at least once; printed is not
// model-received) as hookSpecificOutput.additionalContext (--mode json) or on stderr with
// explicit whole-run scope and no tool/session attribution. SessionStart reports pending refusals with the run's
// facts. Only the first start claims them; later starts preview them without consuming another session's tool note.
// Pending previews may repeat and are excluded from the claim counters.
// Stderr output uses exit 2 (--mode stderr, for a hook wired by hand; a bare session runs no hook and is not
// provisioned). It fails open for the harness and never
// for the boundary: anything it cannot use costs the agent the note, never the run, and the ledger stays the
// authoritative record.
//
// It runs as the agent, inside the run, on every tool call, so its process names no path but its own executable,
// its own /proc/self entries (exe, uid_map, cgroup, mountinfo, auxv, fd/N; never root, cwd or a path below fd/N),
// the stat line of a process (/proc/<pid>/stat: its own, its ancestors', to find its harness, and a claimer's, to see
// whether it is still there; never another file of a process),
// the Go runtime's own reads (/sys/kernel/mm/transparent_hugepage/hpage_pmd_size and its cgroup's CPU limit under
// /sys/fs/cgroup: cpu.max, or cpu.cfs_quota_us and cpu.cfs_period_us on cgroup v1), the reason file and
// hook-state, makes no bpf(2) call and starts no process: no machine config, no ledger, no ~/.tego, no network, no
// helper and no other tego subcommand. That holds for the whole tego process, the init
// functions of every package cmd/tego links included (depguard no-init-syscalls, and
// TestHookMakesOnlyItsDocumentedSyscalls traces it). A system call the run refuses would add a refusal to every
// tool call it reports on.
//
// Provisioner installs that hook in a claude-code run (ADR 0063 (8)): it returns a per-run settings file,
// <runtime dir>/claude-settings.json, listing the hook for each event in exec form, the user's own --settings merged
// in (settings.go); for a resolved claude command an argv with --settings at index 1 (argv.go); and
// TEGO_CLAUDE_SETTINGS for a wrapper. The launcher makes the file; nothing of Claude Code's own (~/.claude,
// CLAUDE_CONFIG_DIR, a project's .claude/) is written.
//
// Imports: the standard library, golang.org/x/sys/unix, pkg/spec/reason and pkg/spec/harness only in its
// non-test files (depguard claudecode-imports, on top of adapters-never-import-engine)
// Must not import: the engine, internal/ledger, internal/check, internal/cli, internal/bpf, github.com/cilium/ebpf
package claudecode
