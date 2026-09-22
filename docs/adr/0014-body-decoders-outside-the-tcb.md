# ADR 0014: brotli and zstd decoders are third-party, and live outside the TCB

Status: accepted 2026-09-22.
Amended by ADR 0031 (proposed), which resolves this ADR's Open item.
Decision: `internal/runtime/capture/httpstream` depends on `github.com/andybalholm/brotli` and `github.com/klauspost/compress/zstd` for the two content codings the standard library does not carry. `gzip` and `deflate` stay on `compress/gzip`, `compress/zlib` and `compress/flate`. No other package may import either module, and neither is reachable from the TCB set of ARCHITECTURE §16 (`launch`, `cgroup`, `enforce/*`, `capture/uprobe`, `bpf/`), whose dependency rule remains "nothing beyond `cilium/ebpf`, `go-landlock`, `x/sys`, `x/net`".
Why: docs/p0/capture-derive.md §5 R15 and ARCHITECTURE §12 require `br` and `zstd` decoding — Cloudflare serves `br` to any client that offers it, and httpx on Python 3.14 offers `zstd` — so a model response that is unreadable without them is a capture gap on ordinary traffic, not an exotic one. Both modules are pure Go and build under `CGO_ENABLED=0`; `klauspost/compress` was already in this repository's module graph transitively. `httpstream` parses bytes a traced process received, never decides anything, and is explicitly not TCB (§1), so a decoder bug there is a wrong or missing ledger body, never a wrong verdict.
Consequence: `httpstream` reads foreign bytes through third-party decoders, so its fuzz target (`FuzzFeed`) covers the decode path, and a decode failure is defined behaviour — the decoded prefix, `Truncated=true`, one `gap why=malformed` (R15) — rather than an error that loses the body. `zstd` decoders are constructed with `WithDecoderConcurrency(1)` and always closed, so the package owns no background goroutine.
Open (2026-09-23): `internal/runtime/capture/uprobe`, a TCB package, imports `capture/httpstream`, so both modules are
in the TCB's import graph after all (`go list -deps -tags tegobpf ./internal/runtime/capture/uprobe`). The decision's
premise and the code disagree; ARCHITECTURE §16 records the condition that resolves it. `klauspost/compress` was
raised to v1.18.7 the same day for GO-2026-5841 (an out-of-bounds read in its `s2` package, which Tego does not
import; govulncheck found it at the module level only).
