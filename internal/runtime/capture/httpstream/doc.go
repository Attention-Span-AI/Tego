// SPDX-License-Identifier: Apache-2.0

// Package httpstream reassembles HTTP/1.1 from plaintext chunks: keep-alive, chunked encoding, gzip,
// deflate, brotli and zstd, server-sent events; hands complete messages to derive.
//
// One Assembler serves a whole run. State is per ConnKey — an uprobe connection is (cgroup, pid_tgid,
// SSL*), a forwarder connection is its ConnID — so a malformed or h2 connection never disturbs another
// (docs/p0/capture-derive.md §5 R10, R18). Nothing here is decided, written or timed: Feed is pure with
// respect to the clock, the caller owns idle timeouts and calls Close, and every shortfall leaves a Gap
// instead of a silent absence (R37, §8 I4).
//
// Imports: standard library, github.com/andybalholm/brotli, github.com/klauspost/compress/zstd,
// github.com/attention-span-ai/tego/pkg/spec/record (the Source enum on a ConnKey only)
// Must not import: cilium/ebpf
package httpstream
