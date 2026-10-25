// SPDX-License-Identifier: Apache-2.0

// Package reason is the reason file's format, v1 (spec/reason/REASON-CHANNEL.md §2, ADR 0061): last-refusal.json,
// which the ledger Writer rewrites after refusals and a harness inside the run reads through TEGO_REASON. It holds the
// file's types and codec (File, Entry, Encode, Decode, File.Since), the one sentence each reason code is told in
// (Text), the bounded text an agent is shown (Render), the paragraph that tells an agent the file exists
// (Instructions, and HookInstructions for a hook that reports each refusal, ADR 0063), and where an unprivileged
// run's copy lives (DirFor).
//
// It is Layer 0, data and codecs: no I/O beyond the reader Decode is handed, no clock, no goroutines. It imports
// the standard library and pkg/spec/record only, so the engine that writes the file and a harness adapter that
// reads it share one definition without the adapter importing the engine.
//
// The file is not a ledger line: it carries its own version (v) and no record minor. The ledger line is
// authoritative; the file is a hint, at most one coalescing window behind it.
package reason
