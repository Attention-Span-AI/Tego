# internal/runtime/capture + internal/runtime/derive (P0 detailed spec)

## 1. Purpose and boundaries

**capture** (`internal/runtime/capture`, `.../uprobe`, `.../httpstream`, `.../forwarder`) turns TLS plaintext and
proxied HTTP traffic into `ssl_request`/`ssl_response` `record.Event`s plus `gap what=capture` events. It owns
per-process OpenSSL discovery and uprobe attach/detach, HTTP/1.1 reassembly, and the loopback forwarder. It does
**not** decide destinations (a direct connect around the forwarder is `refused` by `enforce`'s compiled
`net.allow`, not by capture); the forwarder alone decides the requests, tunnels and upgrades that reach its own
listeners, by the compiled `net.http` and `net.proxy` policy (`pkg/policy/httppolicy`; network-controls,
proxy-protocols). It does not write `events.jsonl` itself (it emits into the `Sink` the pipeline hands it:
`stampRule → attribute → redact → splitBlobs → Append`), and does not compute cost or stop the run (`limits`
consumes `ssl_response.usage`).

**derive/anthropic** and **steps-by-time** (`internal/runtime/derive`, `.../anthropic`) turn a captured
request/response pair into `decision` events (`tool_use` extraction, unparsed fallback) and populate
`attribution{thread, step, confidence, method}` (E28a: `method: time`) via the pipeline's `attribute` stage. Derive
does not capture bytes, does not redact, and does not persist blobs (capture streams bodies to `ledger.Writer.Blob`
as they arrive; derive parses from the message capture already assembled).

Imports (`doc.go`, `docs/REPO-LAYOUT.md` §Import direction, depguard-enforced):
`capture` → `capture/*`, `internal/ledger`; not `internal/check`. `capture/uprobe` → `internal/bpf`, `cilium/ebpf`;
not `net/http`. `capture/httpstream` → stdlib, `andybalholm/brotli`; not `cilium/ebpf`. `capture/forwarder` →
stdlib `net/http`, `capture/httpstream` (its decoder table, R15); not `cilium/ebpf`. `derive` → `derive/*`, `pkg/spec`; not `cilium/ebpf` or an `net/http` server.
`derive/anthropic` → stdlib only; not other providers. `capture/uprobe` is TCB (ARCHITECTURE §16): the TCB-wide rule
is "no third-party dependency beyond `cilium/ebpf`, `go-landlock`, `x/sys`, `x/net`" (four items, quoted in full
even though `capture/uprobe` itself only needs `cilium/ebpf`/`x/sys`, so a dependency audit against this spec
doesn't flag a permitted `go-landlock`/`x/net` import elsewhere in the TCB as a violation). `capture/forwarder` is TCB
too: it parses the agent's traffic in the launcher and decides its request policy (ARCHITECTURE §16, amended
2026-10-05). The other three packages only shape record content and are not TCB. Every capture package reaches the
run through `internal/runtime/source` (the `Source` contract) and never imports `internal/runtime`, launch, the
supervisor, `enforce`, the DNS broker, the kernel recorder, `limits` or the deputy, and only the forwarder imports the
approval broker `ask` (ADR 0031 (b) step 1; depguard `capture-links-no-engine` and `capture-asks-through-forwarder`;
`TestCaptureLinksNoEngine` checks the whole link closure of every capture package).

**Changes.**
- 2026-10-05, purpose: the forwarder decides `net.http`/`net.proxy` request policy and is TCB; the
  text said capture decides no network policy and only `capture/uprobe` is TCB (true until 2026-10-04).
- 2026-10-19, imports (ADR 0031 (b) step 1): the `Source` contract (`Source`, `Sink`, `RunRef`, `Gap`,
  `ProcessHook`, `ProcessStream`, `KernelFollower`, `LoopbackSource`, `MeteredSink`, `AbandonSink`, `ReportUnmetered`,
  `ReportAbandoned`, `UnavailableCause`, `NewPair`) moved from `internal/runtime` to the leaf `internal/runtime/source`;
  `capture/uprobe` and the forwarder no longer link the engine. Behaviour unchanged.

## 2. Models

Types live under the package named; JSON fields shown are `record.Event.Payload`'s wire form
(`spec/record/v1/README.md`); Go-only types (BPF keys, FSM state) carry no tags.

```go
// package capture
type RunRef struct { ID string; Cgroup uint64 }        // primary cgroup id; descendants adopted too
type Sink interface{ Emit(e record.Event) }             // wraps the 4096-buffered events chan + drop counter;
                                                          // never blocks, never errors (P0-DESIGN §2.4)
type Gap struct { What, Why, Binary string; Count int }  // Why: no-openssl|static-tls-no-symbols|h2|malformed|
                                                          // ring-buffer-drop|size-cap|no-models|
                                                          // mechanism-unavailable (R37)
type Source interface {
    Start(ctx context.Context, run RunRef, sink Sink) error
    Stop() error
    Coverage() []Gap
}
```

```go
// package uprobe
type binKey struct{ Dev, Ino uint64; BuildID string } // ELF identity, never a path string; the stat() pair is
                                                         // the fast path only, BuildID is the correctness key (R7)
type attachedBinary struct {
    Path      string; BuildID string                     // realpath (resolved through /proc/<pid>/root for a
                                                            // containerized target, R39); hex of .note.gnu.build-id
                                                            // if present
    WriteSyms []string                                    // ["SSL_write","SSL_write_ex2"] xor ["SSL_write","SSL_write_ex"]
    ReadSyms  []string                                    // ["SSL_read","SSL_read_ex"], each entry+return
    Links     []link.Link; RefCount int                   // cilium/ebpf links; closed at RefCount 0 (R7,R8);
                                                            // one count per (source, pid) reference, R8
}
// bpf2go-generated from bpf/uprobe_ssl.bpf.c
type sslScratchKey struct{ PidTgid, SslPtr uint64 }       // LRU_HASH key, 16 bytes (R5)
type sslScratchVal struct{ Buf, LenPtr uint64; Dir uint8; EnterNs uint64 }
type chunkEvent struct {                                  // one ring-buffer record per probe hit, ≤32 KiB (R6)
    CgroupID, PidTgid, SslPtr uint64
    Dir uint8; Seq uint32; Trunc uint8; Len uint32; Data [32768]byte   // Seq: the kernel's, one count per
                                                            // (PidTgid, SslPtr) for both directions (I2)
    Skipped uint64                                        // bytes of the call after Data not emitted (R6's
                                                            // tail, an unreadable chunk)
}
// A second record kind, the SSL_free close {Hdr, SslPtr}, ends a connection (R3a).
```

```go
// package httpstream
type ConnKey struct { Src record.Source; CgroupID, PidTgid, SslPtr, ConnID uint64 } // ssl fields | forwarder ConnID
type Direction uint8 // DirRequest=0, DirResponse=1
type Message struct {
    Method, Path, Proto string; Status int
    Header http.Header; Body io.ReadCloser        // decoded (gzip/deflate/br/zstd stripped)
    ContentEncoding string; SSE, WireSSE bool; RetryOf string; Truncated bool
}
type connState int // Idle,ReqLine,Headers,Body,Chunked,SSE,GapH2,GapMalformed,Done
type conn struct { state connState; pending []*inflightReq; partial bytes.Buffer; chunkParser chunkedReader; bodyLeft int64 }
```

```go
// package forwarder
type Listener struct { Model agent.ModelEndpoint; Addr net.Addr; Upstream *url.URL; Transport *http.Transport }
type retryKey [32]byte // design name, built as forwarder.RetryKey (internal/runtime/capture/forwarder/retry.go); sha256(method‖0x00‖path‖0x00‖sha256(body)‖0x00‖sha256(credential))
type inflightReq struct { Key retryKey; RequestID string; Started, ExpiresAt time.Time }
```

```go
// package derive
type Parser interface { Host() []string; Parse(req, resp *httpstream.Message) ([]record.Event, error) }
type Dispatcher struct{ byHost map[string]Parser }
type StepState struct { Step int; OpenSince time.Time; InFlight bool } // one per (run, tid), owned by `attribute`
```

```go
// package anthropic — JSON tags mirror the Messages API wire format verbatim (not record v1)
type Request struct {
    Model string `json:"model"`; Messages []Message `json:"messages"`
    System json.RawMessage `json:"system,omitempty"`; Tools []Tool `json:"tools,omitempty"`; Stream bool `json:"stream,omitempty"`
}
type Message struct { Role string `json:"role"`; Content json.RawMessage `json:"content"` }
type Tool struct { Name string `json:"name"`; InputSchema json.RawMessage `json:"input_schema"` }
type Usage struct { InputTokens, OutputTokens, CacheReadInputTokens, CacheCreationInputTokens int `json:"...,omitempty"`
    CacheCreation *derive.CacheCreation `json:"cache_creation"`; ServerToolUse derive.ServerToolUse `json:"server_tool_use"` }
type Response struct { ID, Model, StopReason string; Content []ContentBlock; Usage Usage }
type ContentBlock struct { Type, Text, ID, Name string; Input json.RawMessage } // Type: text|tool_use|thinking|redacted_thinking
type StreamEvent struct { Type string; Index int; Delta json.RawMessage; Usage *Usage } // one per SSE `data:` line
```

Validation: `Request.Model` non-empty or unparseable (`decision: unparsed why=schema`); `Usage` fields default 0,
never clamped negative — a negative wire value is a schema error. `ContentBlock.Input` for `tool_use` must itself be
valid JSON before `input_hash` (sha256 of the raw bytes, never re-marshaled) is computed — R31.

**Changes.**
- 2026-09-29: `retryKey` is built as `forwarder.RetryKey`; `chunkParser`, `resolveLibrary` and `sslScratchKey` are design names with no Go symbol of that spelling.
- 2026-09-24, `chunkEvent`: `Skipped` added; `Seq` is the kernel's per-connection count; the
  `SSL_free` close record added.
- 2026-09-24, `anthropic.Usage`: `cache_creation` and `server_tool_use` read (R29).

## 3. Repositories and storage

Capture/derive own no independent store; each row is a kernel object, an in-process cache, or a pass-through write
to `internal/ledger`.

| What | Where | Perm/format | Owner | Concurrency | Durability |
|---|---|---|---|---|---|
| SSL scratch map | BPF `LRU_HASH`, 8192 entries (R5) | kernel memory | one per host, first-attach lifetime | atomic per-CPU update; LRU eviction is silent loss → `gap why=size-cap` | none; empty on reboot/reload |
| Chunk counter | BPF `LRU_HASH` `tego_ssl_seq`, 16384 entries, key `(pid_tgid, ssl_ptr)` → `u32`, pinned by name beside the ring | kernel memory | one per host per `bpf_hash`, like the scratch map | written only by the thread its key names, one increment per chunk before the reserve (I2) | none; an evicted row restarts its count, which gaps that connection |
| Chunk ring buffer | a BPF `RINGBUF` per run, at the run's slot in the ring outer `tego_capture_events` (a `HASH_OF_MAPS` keyed by `run_idx`, pinned by name at `/sys/fs/bpf/tego/<bpf_hash>/maps/tego_capture_events` beside the build's shared maps and declared in every object, ADR 0026 (1), (3)) | `record.ringbuf` bytes (2 MiB default, `/etc/tego/config.yaml` only), made by the tier-2 backend's `Prepare` only for a run whose capture is `uprobe` and that records, and only when it fits `bpf.ring_budget` (enforce-cgroup-observe.md R16) | written by the probes the build's runs share (R9, ADR 0026 (7)), each chunk into the ring of the run the calling process belongs to; a run with no ring gets nothing, and the probe counts the hit in `tego_capture_miss` at the run's slot | one reader by construction: the run's own uprobe source, which opens the ring at its slot (edge case #26); one goroutine, batch drain | none; loss → `gap why=ring-buffer-drop count=n`, counted in capture's own `tego_capture_lost` (a `u64` per `run_idx`, zeroed at `Prepare`, ADR 0026 (4); never the record's `tego_lost`, so neither mechanism reports the other's drops), read at the run's slot and once more at `Stop` before it is closed. A chunk whose plaintext could not be read reaches the ring carrying its hole (R6) and is not a drop |
| Attach cache | in-process `map[binKey]*attachedBinary` | launcher-process memory | one per launcher (the "or `tegod`" host-shared cache, §11, is not pursued: ADR 0042 (7) keeps parsing in the user's `tego run`; 2026-10-05) | `sync.RWMutex`; chunk path lock-free | none; rebuilt from `/proc/*/maps` on restart |
| Forwarder listeners | TCP `127.0.0.1:0`, one per `models[]` entry, at most `DefaultMaxConns` (2048) connections open each, a keep-alive one closed after `DefaultIdleTimeout` (2 min) idle (R27) | ephemeral port | run's `forwarder.Manager`, closed at `run_end` | one `net/http.Server` tree per listener | none; dies with the run, correctly |
| Retry-attach cache | in-process LRU, 256 entries (R24) | memory | one per `Listener` | `sync.Mutex` | none; a restart cannot outlive the run anyway |
| Forwarder capture buffers | in-process byte budget, `MaxCaptureBytes` (64 MiB default; floor one exchange at its largest, `5 × MaxBody`: its request and the request event's copy of it, then either its response off the wire with the decoded form being read out of it or that decoded form with the response event's copy, plus headroom for a buffer being copied into a larger one and for the escaping an event's copy adds to text) over every array capture holds: request body, response body, decoded form, and each event's JSON copy of a body. Each is counted by its capacity, not its length, so no array holds more than was reserved for it: a buffer of unknown size reserves each larger array before copying into it and returns the old one after, and is trimmed to its length once that is known when the budget has room for the trimmed copy (without it the buffer keeps its headroom, which stays counted); a decoded form is reserved on top of the compressed bytes it is read from, since both are live until the decode ends. An event's copy is encoded once, without HTML escaping, into an array of its exact size (text costs about its own length; a control byte JSON has no two-character escape for costs six, and is counted at six), and it stays reserved until the collector finds it unreachable: the run queue holds it until the ledger writer is done with it and `source.Sink` has no signal for that, so a writer that falls behind cannot make capture hold more. Not counted, and so outside this bound: the fixed per-exchange state (the pump's 32 KiB chunk buffer, and the decoder of each content-coding layer: a `gzip`/`deflate` layer's window and tables, about 42 KB even at a zero grant, or a `br` or `zstd` layer's history, up to the window its stream declares — 16 MiB for `br`, RFC 7932; 8 MiB for `zstd`, the RFC 9659 cap `httpstream` enforces — which only an upstream answering in a coding the request did not offer can cost, since R20 narrows `Accept-Encoding` to `gzip`, `deflate` and `identity`). Every layer of a stacked coding is open until the decode ends, and a list of more than `httpstream.MaxCodings` (2) is not decoded (R15), so this term is at most two layers' windows per exchange, 32 MiB at its worst, rather than one window per name a response header can fit; an event's own fields (its request target and allow-listed headers, bounded per event at 1 MiB — the listener's `http.Server` `MaxHeaderBytes` for a request, the `MaxResponseHeaderBytes` `NewTransport` sets to the same `http.DefaultMaxHeaderBytes` for a response, where net/http's `Transport` would otherwise allow 10 MiB — and in number by the run queue's 4096 slots and each listener's 1,024-entry emit queue, I1); what `derive` and the ledger's stages allocate while they read a body the budget holds, which grows with that body; and arrays capture has let go of, which the collector reclaims on its own pacing (`GOGC`). What capture adds to the launcher's heap is therefore a multiple of `MaxCaptureBytes` plus those per-exchange and per-event terms, not `MaxCaptureBytes` itself | launcher-process memory | one per run's `forwarder.Manager`, shared by its `Listener`s | atomic reserve; an array a buffer outgrew or trimmed goes back at once; the buffers when the exchange is derived, or where they are dropped for an exchange that never reaches derive (`budget.give`); an event's copy when the collector finds it unreachable, and a reservation that comes up short of the room its caller cannot do without while copies are counted starts a collection, at most one per 100 ms: the bytes in hand for a write, and any room at all for a read of unknown length, which a short grant leaves with none and so cuts the body unless it ends right there (one short only of a buffer's doubling, of a read's speculative chunk, of a declared length reserved ahead of its bytes, or of a trim, stops no byte being kept and starts none) | none; exhaustion keeps less of a body (`gap why=size-cap`) — none of a compressed one decoded at a full budget, and a prefix cut between runes, or none, of an event's copy — and never fails the agent's call |
| Uprobe capture bodies | in-process byte budget, `httpstream.Options.MaxBytes` (256 MiB default; floor three `MaxBody` arrays: a request body pending for derive while its response's body grows from its old array into a new one), over every body array the uprobe path holds: each connection's body in flight in `httpstream`, and each request body the source keeps until its response arrives, counted by capacity; and each half's unparsed bytes of a start line, header block or chunk-size line still arriving (R13), past a 4 KiB head allowance per half (`httpstream.headAllowance`) that is not charged, so a line split across two chunks never gaps a connection because bodies elsewhere hold the budget: the allowance adds at most `MaxConns` × 2 × 4 KiB (32 MiB at the default 4096 connections) to what the budget bounds. A completed body's array goes with its message, and a half's unparsed bytes are parsed where the chunk lies and copied only when some are left, so an idle connection holds none. A body's decoded form is counted too, for the one `Feed` that completed it (`feedAllowance`, R15). An SSE body retains its decoded framing in the array already counted; framing is interpreted by derive, without a second full-body array. Not counted: arrays let go of, which the collector reclaims at its own pace | launcher-process memory | the run's `httpstream.Assembler` (`Budget`), owned by the uprobe source alone | atomic reserve; a growing body reserves its new array before copying and returns the old one after; a body's reservation goes back when it completes, or when its connection gaps or closes, and a half's unparsed bytes' when the half has none left or its connection gaps or closes; a pending request's when its response is derived, its connection gaps, or the source stops | none; exhaustion keeps a prefix of a body (`Truncated`, `gap why=size-cap`), and a pending request past it reaches derive without its body, with the same gap; a head past it gaps its connection (`gap why=size-cap`) |
| Bodies | `ledger.Writer.Blob`, `<ledger_root>/<run>/blobs/<sha256>` | `0600` in `0700` dir | `internal/ledger`, called by `httpstream` as bytes decode (streaming hash, R15) | one blob writer per run, plus the uprobe source's own handle on the same directory (`ledger.NewCountedBlobRepository`, which adds what it stores to the Writer's own count, `BlobBytes`, so its bodies count against `record.max_run_bytes`); content addressing makes a body both store the same file (record-ledger R14) | `write(2)` per chunk, no per-event fsync; fsynced before `run_end` is durable (record-ledger R6): the writer's own in its `Close`, the uprobe source's in its `Stop`, which the run calls first |

No SQL, no config file owned here — `models[]`/`capture:` mode come from the compiled `agent.RuleTable`.

**Changes.**
- 2026-09-24, chunk counter: the per-connection sequence map added.
- 2026-09-24, ring drops: capture counts its own drops in `tego_capture_lost`, diffed from its
  value at `Start` (it shared `tego_lost` and diffed from zero, so a clean run reported earlier runs' drops).
- 2026-09-24, uprobe capture bodies: one byte budget over every body the uprobe path holds.
- 2026-09-24, forwarder listeners: a connection cap and an idle timeout per listener.
- 2026-09-24, uprobe capture bodies: the budget covers each half's unparsed head bytes too.
- 2026-09-24, uprobe capture bodies: each half's first 4 KiB of unparsed head bytes is uncharged.
- 2026-09-24, chunk ring buffer (ADR 0026 (1), (3), (4)): a capture ring per uprobe run at its slot, a per-run lost
  counter and a miss counter; the one-reader-per-build rule holds by construction.

## 4. Functions and contracts

**capture facade** — `func Select(rt *agent.RuleTable, tier backend.Tier, probe *doctor.Probe) ([]Source, []Gap)`.
Pre: `rt.Capture` resolved (`auto|uprobe|forwarder|off`). Post: returns the `Source` set to start — both `uprobe`
and `forwarder` may run concurrently under `auto` at tier ≥ `cgroup` (R33 note); a contract that pins
`capture: uprobe` itself (`agent.RuleTable.PinsUprobe`) runs the uprobe source alone wherever the tier runs uprobes,
and where it cannot, tops out at the forwarder as `Compile` and `AtTier` lower it; `off` returns `nil,nil`, no
gap. A pinned `uprobe` never runs the forwarder beside the probes where the tier runs uprobes: the forwarder's
`ANTHROPIC_BASE_URL` would send every request of an SDK agent to its loopback listener, whose upstream TLS is the
launcher's, the probes would read none of it, and kill test 7 (b), "a system-Python agent via uprobes" (FEATURES,
P0-DESIGN §10), could never record `source=ssl`. `Compile` reserves the forwarder's variables by the same predicate
(SEMANTICS §9), so a pinned-uprobe contract's own `ANTHROPIC_BASE_URL` passes through where the tier `Compile`
resolved runs uprobes. That tier is a prediction (an unpinned tier resolves to the machine's ceiling unprobed); a
run whose tier runs no uprobes (`landlock`, `--observe`) starts the forwarder after all, its base URL overrides the
contract's value, and `tego run` prints `env-runtime-reserved` for it on stderr (agent-contract R12). A
machine ceiling lowers a pinned uprobe to the forwarder before any of this: a capture ceiling of `forwarder` at any
tier, or a tier ceiling of `landlock`; `Compile` resolves the table to `forwarder`, and warns `model-direct-bypass`
for a `net.allow` entry naming a `models[]` endpoint (agent-contract E27). Where
the tier runs uprobes and the machine admits them, a pinned uprobe never falls back to the forwarder: a uprobe source that cannot start there
(an object the kernel refuses, a run the host's `bpf.ring_budget` left without a capture ring) is its
`mechanism-unavailable` gap, and the
run's model traffic is then uncaptured, which that gap says. The one exception is a run with a `tokens`, `cost_usd`
or `repeats` budget that nothing else captures: the runtime refuses it before `run_start`, exit 125
`[capture-unavailable]`, rather than run it unmetered (limits-check-doctor-cli.md R32). Otherwise `Select` never
fails `run` start: an attach failure becomes a `Coverage()` gap, not an error, and a wanted mechanism
that cannot run is one selection gap naming it (`no-models` for a forwarder with no `models[]` to serve, else
`mechanism-unavailable`, R37). `run_start.capture` then records the mechanism that did start — `uprobe` when the
uprobe source runs, `forwarder` when the forwarder runs alone, `off` when neither does — never `rt.Capture`, which
is resolved against the machine's ceiling rather than the tier that ran.

**uprobe** — `New(Options{Kernel: true, ...}) *Uprobe`, built by `internal/cli` only in a binary that carries the
compiled capture object (`-tags tegobpf`; any other build has no factory and `Select` records
`mechanism-unavailable binary=uprobe`). `Start/Stop` per §2's `Source`, idempotent per run id, attach failures
wrapped `ErrAttachFailed` but never returned fatally. The source is a `source.KernelFollower`: once the tier-2
handle has prepared the run, the run calls `FollowKernel(bpf_hash)` with the build its handle pinned and adds the
source as a `source.ProcessHook` to the kernel record (`observe.Recorder.AddProcessHook`), both before anything
starts. The recorder starts before the source, and when its `Start` leaves it reading nothing for the run (no row
or no ring for the run) the run withdraws the build again (`FollowKernel("")`), so the source starts with
`mechanism-unavailable` rather than beside a recorder that will never hand it an exec. A hook the recorder calls before the
source has started is ignored: the source has no attacher yet, and the agent is released only after every source
has started, so what the recorder can report then is the launcher's own child stage. `Start` then reads the run's slot from its own cgroup's row in the build's pinned run set, opens the run's own
capture ring at that slot and its lost counter at the same slot, loads the capture object under that build's pins
(`LoadCollection`), and attaches through it, pre-attaching the host's own libssl (not under `record: off`), within a
bounded time, before it returns and so before the agent exists (R4). A run with no row, no capture ring at its slot
(the host's `bpf.ring_budget` had no room for it, enforce-cgroup-observe.md R16), a load or open that fails, or a run
whose kernel record is not running (so `FollowKernel` never came), is one `gap what=capture
why=mechanism-unavailable binary=uprobe` with no count and an inert source that loads, attaches and drains nothing,
never a failed run; the source names its cause (`UnavailableCause`), which the runtime's refusal of a budgeted run
carries (limits-check-doctor-cli.md R32; `TestIntegrationARunWithoutACaptureRingDoesNotCapture`). Another run of
the build does not stop it (ADR 0026 (5), `TestSourceRunsBesideAnotherRunOfItsBuild`): the probes are shared per
library (ADR 0026 (7)) and emit each call once, into the ring of the run the calling process belongs to. A chunk is
the run's when it carries the run's slot, a guard on a ring no other run writes. `OnExec` and `OnOpen` adopt no
cgroup. Each reassembled response is derived with the same dispatch the forwarder
runs (`Options.Deriver`, `derive.NewDispatcher` over the linked parsers, R25): the `ssl_response` carries the
parser's model, usage and `parser_version` (R32, I6) and its decisions follow it, so `limits` counts a
uprobe-captured run's tokens as it does a forwarded one's. `Stop` syncs the bodies the source stored (§3
"Bodies") before it returns. Internals: `OnExec(pid, cgroupID, path)` (`path` is the exec record's, R4), `OnOpen(pid, cgroupID, path)` and `OnExit(pid)`, driven by
`observe`'s drain of the kernel record (R4, R8); `resolveLibrary(pid) ([]libCandidate, error)` — never errors on
zero candidates, the caller gaps; `chooseWriteSymbols(f *elf.File) ([]string, error)` (R1/R2); `attach(binKey,
path, syms) (*attachedBinary, error)`; `OnExit` dropping the calling source's own reference for that pid (R8),
closing links at 0. Budget: `resolveLibrary`+`attach` together ≤ 50 ms per exec; on timeout the attach is
abandoned for that exec and retried on the tree's next exec, else gapped. The hooks run off the recorder's drain
goroutine, on a queue of the follower's own (`runtime.hookQueue`), in the recorder's order, so an exit still follows
its exec: a hook reading a file a traced process named, or attaching to it, never holds the kernel record or the
run's `Stop`. The drain never waits for room. The queue takes execs and only the opens R4 acts on (an absolute path
whose final component matches `libssl\.so(\.\d+)*`, the check `OnOpen` still makes itself); past 4,096 calls it
drops execs and opens and counts them. A dropped exec or libssl open is a process the source never attached at,
whose model traffic is then unmetered: the run's first drop is recorded at once, `gap what=capture
why=hook-queue-full count=1 binary=<source>`, and reported as unmetered spend (limits-check-doctor-cli.md R1 (j)),
which ends a run with a token or cost budget; the rest are counted in the `hook-queue-full` gap written when the
queue closes. An exit is never dropped for a pid the follower was given an exec or open of: it is queued past the
bound, in order, one entry per such pid, so a follower never holds a dead pid a reused pid could be taken for; an
exit for a pid it was never given (a fork that exits without an exec, or whose exec was dropped and counted) is not
queued, so a fork-and-exit flood cannot grow the queue (`TestHookQueueDoesNotGrowOnExitsItHoldsNoStateFor`). The queue
is closed once the recorder has stopped, and shutdown waits up to 5 s for the calls it holds before the follower's
own `Stop` (`TestHookQueueNeverWaitsAndCountsWhatItDrops`, `TestAFollowerHeldInOneCallDoesNotHoldStop`: a follower
held in `OnExec`, 5,000 libssl opens, and the recorder's `Stop` returns within its `StopDrain`;
`TestHookQueueNeverDropsAnExit`). A candidate is opened `O_PATH` and read only once that descriptor shows a regular
file.

**httpstream** — `NewAssembler(maxHeader, maxChunk int) *Assembler` (an `Options` struct in the code, among it
`BodyScanner`, the factory of the scanner a request body kept only as a prefix is fed to, R10; httpstream knows no
provider, so the capture wiring supplies it); `Feed(key, dir, data, ts, mono)
([]*Message, error)` returns 0+ complete messages (>1 under pipelining), never panics (`ErrMalformed` wraps the
cause, the connection gaps and further `Feed` calls on that key are no-ops until `Close`). The
resynchronizations are three, each one counted `gap why=malformed` with the connection kept (R18): a response
that answers no request the connection saw, decided at the first byte of it `Feed` is given (nothing queued, owed
or arriving on the request half then), whatever is queued after that byte, between two pieces of its status line
included; a response whose status line was missed, passed over chunk by chunk until a chunk starts a status line;
and, only as the first request capture sees on a connection, request bytes that begin no request line (a request
whose head was missed), passed over chunk by chunk until a chunk starts a request line, its response passed over
with it and not counted again. R18 names what still gaps the connection instead, among it a request tail shaped
like the start of a request line; `Feed` never resynchronizes on a later CRLFCRLF. `Close(key)` flushes a partial
message as a gap rather than dropping it
silently; idempotent. No internal timeouts — callers own idle timeout and call `Close`.

**forwarder** — `NewListener(model, run, sink, opts) (*Listener, error)`; `Serve(ctx) error` blocks until
cancellation/close; `ServeHTTP` streams status/headers (minus hop-by-hop)/body byte-for-byte via `io.Copy`,
regardless of upstream success, mapping failures per R26 rather than returning a bare Go error to the client; not
idempotent (each call forwards exactly once — client retries are recognized, not suppressed, R23).
`computeRetryKey(method, path, body, cred) retryKey`.

**derive** — `NewDispatcher(parsers ...Parser) *Dispatcher`; `Handle(reqMsg, respMsg, meta) ([]record.Event,
error)` — a nil `respMsg` is valid (mid-flight at `run_end` → `gap why=malformed`); never returns an error for an
unparseable body (exactly one `decision: unparsed`, R29); a returned `error` only signals a precondition bug (nil
`reqMsg`), never a runtime condition. `NewSteps(hosts...) *Steps` and its `Stage(next)` (E28a, the pipeline's
`attribute` stage), whose attribution by time (`Steps.byTime`) is R33–R36's rule.

**derive/anthropic** — `(*Parser).Parse(req, resp *derive.Message) (derive.Facts, error)`, which checks the request
half (`validateRequest`: valid JSON, typed fields, a model named, R28) and keeps nothing of it; `ParseResponse(status, body)
(*Response, error)` (non-streaming); `ParseStream(body) (*Response, []StreamEvent, error)` (SSE, assembled);
`ParseStreamEvent(event, data) (*StreamEvent, error)`. `const ParserVersion = "anthropic-2026-10-5"`, bumped on any
wire-shape change the parser depends on, and on any change to what it reads off the same wire (`-2` reads metering
keys case-exactly, reads a failed stream on for its usage, spends nothing on an error event before
`message_start`, charges a cut stream `max_tokens`, and reads the 1-hour cache writes and server-tool counts; `-3`
reads the OpenAI-compatible endpoint's keys case-exactly too, and its line's usage may come from the forwarder's
wire usage scanner, which now reads as derive does; `-4` fails closed on a declared host's paths outside `/v1`,
sums server-tool names past the cap, treats a 2xx message with no usage as unmetered, and keeps the usage of a
stream frame whose other members are malformed; `anthropic-2026-10-3` rejects ambiguous accounting keys,
requires explicit compatible-chat counters, and reports extra/unreadable iteration spend as unmetered;
a ledger line keeps the version that derived it).
`ParseStream` returns the events and the text of each block; the parser's own path keeps neither, since a decision
reads only a `tool_use` block's input, so a body of text deltas costs a small multiple of its size.
`StreamUsageScanner` reads an event stream's usage off bytes written in pieces, by the same decode and fold as
`ParseStream`; `MaxTokensScanner` and `RequestMaxTokens` read a request's `max_tokens`; `BoundCutStream` applies a
`max_tokens` a capture source read to the stream derive could not bound. Capture reads through these and has no
reading of its own. `ParseStream` accumulates `usage` across `message_start` (input) and
`message_delta` (each count folded as the larger of the cumulative totals reported) without double-counting. A JSON syntax error, unknown stream `type`, or a delta
targeting an unopened block index is `ErrSchema`, mapped to `why=schema`, never a panic (fuzz target).

**Changes.**
- 2026-10-19 (ADR 0029 (4)): the attribute stage is `Steps` (`NewSteps`, `Stage`; R33–R36's rule is
  `Steps.byTime`) and the request half is checked by `Parser.Parse`; `AttributeByTime` and `ParseRequest`, which only
  tests called, left the API for the tests' own files, where `AttributeByTime` stays the snapshot oracle R36's
  differential test compares the stage with. R35 and R36 name the survivors.
- 2026-09-22, uprobe: each reassembled exchange is derived (the source derived nothing; `ssl_response` had no
  model, usage or `parser_version`).
- 2026-09-23, `Select`: a pinned `uprobe` no longer runs the forwarder beside the probes (kill test 7 (b)).
- 2026-09-23, httpstream: the text claiming a CRLFCRLF resynchronization, which never existed, removed.
- 2026-09-24, uprobe hooks: hooks moved off the recorder's drain onto `runtime.hookQueue`.
- 2026-09-24, uprobe hooks: the drain never waits; libssl opens only; past 4,096
  calls a counted drop.
- 2026-09-24, uprobe hooks: the first drop is reported unmetered at once
  (limits-check-doctor-cli.md R1 (j)); exits are never dropped.
- 2026-09-29, uprobe hooks: an exit is queued only for a pid the follower was given an
  exec or open of; the queue no longer grows with a fork-and-exit flood.
- 2026-09-29, `ParserVersion`: `anthropic-2026-09-4`; `ParseResponse`'s signature and R29's
  `message_delta` fold (larger of the cumulative totals) written as the code has them; a stream frame whose other
  members are malformed keeps its usage, as the wire scanner reads it; the parser's stream path keeps no events or text.
- 2026-09-24, `ParserVersion`: `anthropic-2026-09-2`.
- 2026-09-24, derive/anthropic: `StreamUsageScanner` and `BoundCutStream` exported for capture;
  capture/maxtokens removed; `ParserVersion` `anthropic-2026-09-3`.
- 2026-09-24, uprobe (ADR 0026 (1)-(6)): the source reads its own capture ring by slot; the refusal beside another
  run of the build and the `FollowKernel` floor withdrawn; no capture ring is `mechanism-unavailable` naming the
  ring budget.
- 2026-09-24, `Select`: a budgeted run whose capture mechanism could not start is refused, 125
  `[capture-unavailable]` (limits-check-doctor-cli.md R32); the uprobe source names its cause (`UnavailableCause`).

## 5. Business rules

**Uprobe attach (E20)**
- **R1.** `SSL_write` is always hooked when present — the universal entry point Node, libcurl and CPython ≤3.9 call.
  `SSL_sendfile` is a **known non-hook**: `SSL_write(3ssl)` declares it beside `SSL_write`/`SSL_write_ex` and it is
  "available only when Kernel TLS is enabled", handing an fd's contents to the kernel zero-copy, so no plaintext
  passes through a userspace buffer and its `(fd, offset, size, flags)` arguments are not `SSL_write`'s `(buf, num)`
  — any R1–R3 program pointed at it would read a descriptor as a buffer pointer. Capturing it needs a program of
  its own on the bpf side plus a way to read the file, neither of which exists. Until then a connection that uses it
  is captured in one direction and raises no `gap`: one of the two places capture knowingly falls short of I4 (the
  other is R4's attach latency), accepted because exposure
  is server-side kTLS (nginx and the like), not the client libraries an agent uses.
- **R2.** Exactly one `_ex` variant is additionally hooked, by existence probe: `SSL_write_ex2` (3.3+) preferred;
  else `SSL_write_ex`; never both (`_ex` tail-calls `_ex2` when both exist, so hooking both double-counts).
- **R3.** Reads always need entry+return: `SSL_read` (len = return, valid only if >0), `SSL_read_ex` (len =
  `*readbytes`, valid only if return is `1`). Non-positive/zero is not an event.
- **R3a.** `SSL_free` is hooked at entry beside the reads and writes, first of a
  binary's probes, and writes a close record (`struct tego_ev_ssl_close`: the header and the `SSL*`) on the capture
  ring; it also removes the calling thread's chunk counter for the pointer (I2). The source closes every connection
  of that process on that pointer, whichever threads did its I/O, as `Stop` closes a connection (edge case #28).
  Without an end to see, glibc handing the freed `SSL_CONNECTION` to the next `SSL_new` at the same address would
  make the new connection continue the old one's framing: after an aborted `Content-Length` response the new
  responses would be swallowed as the old body; after an aborted chunked one every later exchange would be lost
  under one count; a close-delimited one would end only at `Stop`. A close record lost to a full ring still ends the
  connection when the free was on the thread that did its I/O: its count restarts at 1, and the source closes what
  the key held before feeding that chunk. A free on another thread whose record is lost is covered for a
  close-delimited response only: a request line on the key while its response is close-delimited ends that response
  first (RFC 9112 §6.3, rule 8: such a body ends only with the connection, and no request follows on a connection its
  server is closing), and the requests the ended connection still had queued are counted and forgotten. `SSL_free`
  drops a reference and frees only at the last (`SSL_up_ref`), so a record can precede the object's end; I/O that goes
  on after it is a new connection to the reader, whose mid-message bytes are passed over and counted (R18), never
  paired.
- **R4.** Library discovery is per-process at first `exec` sighting: parse `/proc/<pid>/maps` for
  `libssl\.so(\.\d+)*` or any mapped ELF exporting `SSL_write`/`SSL_read`; if none, fall back to the process's own
  `/proc/<pid>/exe` (static-link case). A mapped file that is not an ELF at all (`/etc/ld.so.cache`, which every
  dynamically linked process maps, a locale archive) is nothing to attach to, never an attach failure.
  The exec is not the last chance. At `sched_process_exec` the dynamic loader has not run, so a libssl
  the process links is not mapped yet, and CPython's is `dlopen`ed by `import ssl` long after; so discovery also
  runs at every open of a file named like a libssl that the kernel record sees the process make (`OnOpen`), and
  attaches that file through `/proc/<pid>/root` (R39). A uprobe belongs to the file, not to a mapping, so a probe
  placed at the open fires once the process maps it. What the exec finds uncaptured is therefore held, not
  recorded: it becomes its gap when the process execs a new image, exits, or the source stops, and is withdrawn if
  an open attaches the process first (recorded at the exec, it would put a `static-tls-no-symbols` line in the
  ledger for a process whose every exchange was captured). **Pre-attach, and what stays late**: the
  attach at the open is asynchronous to the process, late by the recorder's drain of the open plus one attach, and a
  CPython client that wrote its first request straight after `import ssl` wrote it before the probes on every run
  on the Debian 13, AL2023 6.1 and AL2023 6.12 kernels and on some on RHEL 9 (the 2026-09-23 acceptance run). So `Start` attaches the host's own libssl before the run's first process exists, which is before
  the ack lets the agent exec (runtime-launch.md §4.1 step 8): every libssl `/etc/ld.so.cache` names, then every
  one in the loader's default directories (`/lib/<triplet>`, `/usr/lib/<triplet>`, `/lib64`, `/usr/lib64`,
  `/lib`, `/usr/lib`, `/usr/local/lib64`, `/usr/local/lib`), each file once by R7's identity with its build id,
  a 64-bit ELF of the build's own machine only, at most 8 (`MaxPreattach`). A library a process opens by name
  is attached at its open, at most 64 distinct ones per run (`MaxOpenAttach`, one the agent chose is six
  probes, link fds and pin and lock files held while the process lives); each past it is one `gap why=size-cap`
  naming it and is not attached (the source keeps at most 256 distinct named gaps, `derive.MaxCoverageKeys`; past that the count goes into the reason's one binary-less entry). The symbol tables `readBinary` reads are bounded at 8 MiB each and their string tables at 32 MiB, and their names are compared in place against the six wanted symbols, never copied per entry (a name outside its string table is `ErrNotELF`; one not NUL-terminated within 64 bytes is not a wanted name), so entries naming one long string cost the sum of the two tables, not their product (a real
  libssl's is under 1 MiB; the official Node's `.strtab` is 10 MiB), `.symtab` is read when `.dynsym` lacks a write or a read symbol, and a binary still missing one half after both tables is attached for the half it has and raises a `no-openssl` gap naming the binary (plus an unmetered report when the read half is missing), never a silent one-direction capture, a table over the bound with nothing found in the other is `ErrSymbolTableTooLarge` (no-openssl with the size in its detail, not cached, never the static-tls-no-symbols verdict), and an undefined symbol is never an export. The agent waits on it, so it is
  bounded: by `PreattachBudget` (1 s by default) and the run's context, checked before each file after the
  first, which is always attempted; what the bound leaves is logged as a warning and attached at its open, late
  as below. A read or an attach already under way is not interrupted, as `OnExec`'s budget does not interrupt
  one. A uprobe belongs to the file, so these fire for every process on the host that calls into that libssl
  while the run lasts, and the capture programs' run-set lookup (R9) drops every call from outside a run: a host
  process outside the run pays one uprobe trap and one run-set lookup per `SSL_write`, and two of each per
  `SSL_read` (its entry probe and its return probe), for the whole run, and does so even when no process of the
  run ever loads that libssl (a Bun, Go or bundled-OpenSSL agent); before pre-attach it paid them only from the
  run's first open of the library, and not at all under a run that never opened it. Under `record: off` nothing
  is attached at all, at `Start`, at an exec or at an open (`capturesNothing`): the capture programs record nothing
  for the run, so the probes would cost every host process that calls the library and capture nothing. The kernel
  record carries no opens under `off` but still hands the source the run's execs, and an exec attaches nothing
  there either: a libssl mapped at exec, or an OpenSSL linked into the executable, would otherwise have its
  probes placed on the host's file for the whole run (`TestNothingAttachesUnderRecordOff`). Nothing is recorded
  for those processes either, since such a run keeps no capture to report against. The run's reference on them
  goes at `Stop` (R8). *Amended 2026-10-19 (limits-check-doctor-cli.md R4):* that is a
  `record: off` run with no stall budget. One whose `stall_after` is bounded, and whose source follows the tier's
  kernel record, is *activity-only* (only a contract that pins `capture: uprobe` has a uprobe source under `off`: an
  `auto` one compiles to the forwarder there, Changes 2026-10-16, R4) (`stampsActivity`): it pre-attaches the host's
  libssl at `Start` and attaches at an exec as a capture run does, so that the probes the build's runs share stamp its
  TLS calls into its slot of `tego_activity` (R9), which its stall check reads; it opens no capture ring, captures
  nothing, and reports nothing but the one `mechanism-unavailable` gap, so `run_start.capture` still says capture did
  not run; what it could not attach is logged, never a gap, since it keeps no capture to measure a process against. It
  holds each library's lock `LOCK_SH` and its attach-cache reference as a capture run does, so the last holder out,
  activity-only or not, hands the probes to the detacher (ADR 0026 (7)). `OnOpen` is never driven under `off`, the
  kernel record carrying no opens, so a libssl dlopened from a path pre-attach does not name is not probed: a stated
  residual. The price is the probes' trap, about 2.4 us per TLS call of every host process while the run lives (ADR
  0026 (9)), which a `record: off` run with a stall budget now accepts; `capture: off`, or no `stall_after`, keeps the
  zero probes (`TestRecordOffWithAStallBudgetAttachesForActivity`,
  `TestActivityOnlyNeedsAStallBudgetAndAKernelRecord`, `TestIntegrationRecordOffStampsWithoutCapture`,
  `TestIntegrationRecordOffActivityIsIsolated`, `TestRecordOffWithoutStallBudgetPlacesNoProbe`). A process's open of a
  pre-attached file only takes its own reference; the open still attaches what pre-attach did not name, and
  only that is still late: a private libssl (a venv's, a bundled OpenSSL, one on `LD_LIBRARY_PATH` or a
  `RUNPATH`) and a container's own, which is another file (R39). The open path goes by name only, so a library
  loaded after the exec under another name (an auditwheel-mangled `libssl-<hash>.so.3`, a renamed private copy)
  is never probed: a stated residual, its traffic a gap whose cause names the executable (`static-tls-no-symbols`). **What late costs, and why the probe order
  matters.** `attach` places a binary's probes one at a time while the process runs, and a uretprobe fires only
  for a call entered after it was placed, so every read probe, entry and return, is placed before any write
  probe (`probesFor`). With the writes first, a blocking client's request written between two attaches was
  captured and the `SSL_read` it then entered for the response was not: the response never came, and
  `httpstream` paired every later response on the connection with the request before its own (I3), with one gap
  at `Close` for the one request left over. With the reads first, a request is captured only once every read
  probe is in place, so the read of its response, entered after the request is written, is captured too, and
  what a late attach splits is an exchange `httpstream` passes over as one `gap why=malformed` counted for it,
  keeping the connection (R18): a request written before the write probes whose response is read after them (a
  response with no request); a response whose head was read by a call entered before the read probes (the rest
  of a response with no request); a request whose head went in an `SSL_write` before the write probes and its
  body in one after, as httpx writes them (a request with no head, passed over only as the first request capture
  sees on the connection). Not every request with no head is passed over. A tail that looks like the start of a
  request line fails the connection closed. Two shapes fail as soon as they are parsed, whatever comes after
  them: a whole first line of a token and a space (a `text/plain` body such as `hello world`), parsed as a request
  line and malformed; and a first chunk of a token and a space with no line end within the 8 KiB start-line cap
  (`maxStartLine`), a `text/plain` body over 8 KiB written in one `SSL_write` (a capture chunk holds up to 32 KiB),
  which is a start line over the cap, a known method's (`GET me ` and 8 KiB more) included. The third, a known
  method whose line has not ended within the cap (`P`, `POST /x`, `GET me a coffee`), holds the request half
  waiting for the rest of its line, and fails the connection when its response comes before the next request,
  which is the order a client that reads each response before it writes the next produces: that response begins
  while a request may still be arriving and is a response with no request in flight. Each is one `gap
  why=malformed` counting 1 while every later exchange on the connection is lost, a loss the count understates.
  The waited bytes are not passed over once a response starts, because they can be the first piece of a real
  request line, whose rest would then be taken for a request of another method. A
  JSON body written whole in an `SSL_write` of its own, which is what the model APIs' requests carry, begins with
  `{` and is passed over. An exchange whose request and response both came before the
  probes is missed with no gap — the second place
  capture knowingly falls short of I4, beside R1's `SSL_sendfile`. What a late attach can still mispair (I3)
  needs a client that, on one thread, writes a request before it has read the response to the one before: one
  that pipelines (R11), whose pipeline the write probes split so an earlier request is missed and a later one
  seen. A response then pairs with a request it did not answer. An HTTP/1.1 client that reads each
  response before it writes the next request does not do this, and nothing in the bytes capture sees tells a
  split pipeline from one seen whole, so this stays a named shortfall of a late attach; a pre-attached library
  has no late attach. A client that reads on one thread while another writes on the same `SSL*` cannot be
  mispaired, because capture keys a connection by thread as well as by `SSL*` (`ConnKey`'s `pid_tgid`, edge case
  #11): its reads and its writes are two connections, every response on the reading thread's is passed over as
  one with no request (a `gap why=malformed` count each), and the writing thread's requests are recorded with no
  response (counted at `Close`, or as `size-cap` past R11's depth), so none of its exchanges is paired, attached
  late or not. Under
  `record: off` the capture programs record nothing (`tego_recording`), and the source discovers and attaches
  nothing, though the kernel record still hands it the run's execs (it carries no opens): there is nothing to
  capture. The source then records the one gap that says its mechanism did not run, `gap what=capture
  why=mechanism-unavailable binary=uprobe`, and no process's coverage, so `run_start.capture` is not `uprobe` and
  `capture.model_traffic` is `false` for a run whose model traffic no line records. The watcher's token, cost and
  repeats budgets see none of that traffic. Only a contract that pins `capture: uprobe` gets a uprobe source under
  `record: off`: `Compile` lowers an `auto` contract's uprobe capture to `forwarder` there, at every tier
  (`recordOffCapture`, amended 2026-10-16), since the forwarder, which `capture.Select` starts
  beside the probes for an unpinned contract with a `models:` endpoint, is the capture such a run really has, and the
  table's mode is what every component reads: as `forwarder` the models[] endpoints are guarded (R38,
  `RuleTable.GuardedModels`), so a direct connection to the model host is refused and the forwarder is the agent's
  only route to its model, as at tier landlock. Compiled as `uprobe` the table guarded nothing, and a direct
  connection was neither captured (no probe) nor refused, so any agent that ignored the forwarder's base URL went
  around a token, cost or repeats budget (`TestRecordOffAutoCapturesWithTheForwarder`). Rejected: guarding under a
  `uprobe` mode whenever the record mode is `off` (each guard reader would repeat the condition, and the table would
  still name a capture the run does not have), refusing the run (it can be metered whole), and lowering only when a
  model budget is set (the table's capture would then turn on its limits, and `measure`'s totals would still miss a
  direct connection).
  `Compile` warns for a `record: off` table whose capture is `uprobe` (a pinned `capture: uprobe`, which runs no
  forwarder) that has any of the three budgets: `[budget-unmetered]` for a budget the contract declares, whose run
  is refused, `[unenforced]` for one a machine ceiling alone imposes (limits-check-doctor-cli.md R32); the
  forwarder records what it relays under `record: off` and keeps them. The table's record mode is the run's: under
  `tego run --record off` over a contract that does not say `off`, the warning names the flag, sits at the first
  budget the contract declares that it leaves unseen, and its fix is to run without the flag (amended 2026-10-16: it said `set record: summary` to a contract that already did); when the contract says `record: off`
  itself, which the flag repeats, it names both, sits at the `record:` key, and its fix is to run with
  `--record summary` and set `record: summary`, since running without the flag changes nothing; and a budget only
  the machine's ceiling sets is named as the ceiling's, with the layer that set it (amended 2026-10-16); under `--record off` over a contract that declares no such budget the warning sits at the
  contract's first line, for want of a key of its own (wording corrected 2026-10-16: this
  said it was no longer placed at line 1). `--record off` lowers an `auto` contract's capture the same way.
  **What an uncaptured process is recorded as** (R37):
  `static-tls-no-symbols`, naming the executable, when every candidate R4 could read — the executable
  included — exports none of R1–R3's symbols. That is also what a process with no TLS stack at all gets
  (`/usr/bin/true`, a shell): without E71's signature scan a static TLS stack with no symbols (Bun's BoringSSL,
  rustls, Go) cannot be told from none, so the line says what was found, no symbols, and one line per binary
  carries a count rather than one per process. `no-openssl` is a discovery that could read nothing: maps the
  kernel refused (#31), a process that had exited before its library could be read, an attach refused (§7). The
  source decides only what discovery read (the file it reports the process against, and that file's R1–R3
  symbols) and settles each verdict in the run's `derive.Coverage`, so the reason on every per-binary line is
  `derive.Classify`'s, one classifier for all of them (E25, S8). A process that has exited before the kernel
  record's exec of it reaches `OnExec` — a Go binary that runs for milliseconds — takes `/proc/<pid>` with it, so R4
  reads nothing and its line is `no-openssl`; the binary it names is the path the exec record carries (the sample's
  `bprm->filename`), because `/proc/<pid>/exe` is gone, and nothing when that path names no file of its own (relative,
  or a `/proc`/`/dev/fd` alias). While the process lives, `/proc/<pid>/exe` names it. The launcher's own child stage
  (`tego __child`, the run's first exec, of the launcher's binary) never reaches `OnExec`: the run holds it back
  (enforce-cgroup-observe.md §2 "Process hook"), because it is not a process of the agent and a line naming tego
  says nothing about the agent.
- **R5.** Scratch-map key is `{pid_tgid, ssl_ptr}` so two threads sharing one `SSL*` and one thread's two `SSL*`
  objects never collide; 8192 `LRU_HASH` entries, sized for the default `pids: 4096` ceiling at ~2 in-flight calls
  per pid; eviction under a burst is `gap why=size-cap`: a read whose scratch row is gone at its return still takes
  its connection's next number as a zero-length chunk marked evicted, and the source records the gap and starts the
  connection afresh as for #3's stale read; one whose `tego_ssl_current` row is gone names no connection and is
  counted in `tego_capture_lost` (`ring-buffer-drop`). Either way a read that moved bytes never vanishes.
- **R6.** A chunk carries ≤32 KiB (headroom over one 16 KiB TLS record — RFC 8446 §5.1 "Record Layer" fixes the
  TLSPlaintext fragment length at up to 2^14 bytes; §5.2 is "Record Payload Protection," not the size limit). Its
  ring-buffer record is reserved at the smallest of three size classes that holds it — 512 B, 4 KiB or 32 KiB of
  data after the 80-byte head — each a compile-time constant at its reserve, so a stream of small reads costs the
  ring what it carries: one fixed 32 KiB record let about 255 chunks of any size fill the default 8 MiB ring.
  `bpf_ringbuf_reserve_dynptr` would size each record exactly but needs 5.19, and RHEL 9 is 5.14 (ARCHITECTURE
  §14). One call moving more is split into up to 4 chunks (128 KiB) by a bounded unrolled
  loop; beyond that the remainder drops, `Trunc=1` on the last chunk, `Message.Truncated=true`. The last chunk
  carries how many bytes it dropped (`skipped`, a `__u64` in the chunk header), and a chunk whose plaintext
  `bpf_probe_read_user` could not read is submitted with no data and its own length as `skipped` rather than
  counted as a lost sample: `Trunc=1` alone does not say where the hole ends, and a request's `Content-Length`
  that still counted the dropped bytes would never complete (CPython hands a whole body to one `SSL_write_ex`;
  `num=400061` was seen). `httpstream` steps over a hole inside a body — a
  `Content-Length` body or one chunk's data shortens by it, a close-delimited body ends later — keeps the prefix
  before it, marks the message `Truncated` and keeps the connection; a hole that crosses the framing (past the
  body's end, or in a start line, a header block or a chunk-size line) gaps the connection, `why=malformed`.
  `Trunc` means only that an earlier part of the same call never reached the ring.
- **R7.** Attach cache keys on `binKey{dev,ino}` (fast path), `BuildID` (`.note.gnu.build-id`) as the correctness
  key across hosts/runs; two processes mapping the same `(dev,ino)` share one `attachedBinary`/`RefCount`; a
  binary replaced on disk under a running process keeps the old inode mapped (kernel semantics) — no re-attach race.
  `BuildID` is part of the cache key, not a check applied after a hit, and it gates the offset cache, the
  `attachedBinary` table and §7's failure record alike: the cache is host-wide and outlives runs (§9), and R39 puts
  every candidate on overlayfs, where with layers not all on one fs and `xino` off "both [st_dev and st_ino] can
  change over the lifetime of a non-directory object" (`Documentation/filesystems/overlayfs.rst`, "Inode
  properties"), matching ADR 0010's finding on btrfs subvolumes. A second file reaching a pair the first one left
  behind must inherit neither its symbol offsets (a probe at a byte that is not an instruction boundary) nor the
  failure recorded against it (a permanent `no-openssl` gap on a hookable libssl, since nothing retries).
  **Limitation:** a binary carrying no build id keys on the pair alone — nothing in the file tells it from another
  file that reaches the same pair — so a stripped binary can still collide where inode numbers are reused. Closing
  that needs ADR 0010's identity for capture too: an O\_PATH fd held per attached binary rather than a `stat()`
  pair, which is a design decision beyond the cache.
  A candidate's path is resolved once: it is opened `O_PATH` (a regular file only), and the identity's stat, the
  build id, the ELF parse and every probe's attach go through that descriptor's `/proc/self/fd/<n>` link, which
  the kernel resolves to the inode held. The path is one the traced process named and can rename a symlink over;
  resolved again at attach, the probes would land at the parsed file's offsets in whatever file it names by then
  (a host library, written into for every process on the host).
  The build id is read only from a note of at most 1 KiB that lies inside the file the headers came from (a GNU
  build id is a 20-byte hash behind a 16-byte header). The section header's size is the file's own claim, and every
  open of a libssl-named file reads the build id before any cache is consulted: a sparse 4 KiB candidate claiming a
  512 MiB note would otherwise make `sec.Data()` allocate 2.6 GiB in the launcher. A note over the bound reads as
  no build id, which keys the file on its `(dev, ino)` pair alone. `debug/elf` itself reads the section-name
  table, and for `e_shnum` 0 section 0's `sh_size` headers, on the file's claim, so it reads through a 16 MiB
  budget: a sparse file claiming more is `ErrSymbolTableTooLarge` (not soft, not cached).
- **R7a.** A request the `uprobe` source keeps for its response keeps only what a parser reads (method, path,
  body, content coding): its header map, up to R13's 64 KiB outside the byte budget, is not kept. One connection
  keeps at most `2 × DefaultMaxPipeline` (16) waiting requests — R11's depth and as many again for requests whose
  responses `httpstream` passed over, which the next answered response clears — and past that the oldest goes, with
  its body's reservation; a refused request (R11) is never kept at all. Without the bound, 4000 unanswered requests
  with 30 KiB headers were held until `Stop`, 117 MiB outside any bound. Every path that gives up a waiting request
  applies one rule (`unanswered`, ADR 0035, ADR 0037): a request whose target is unreadable (R10), or whose `Host` is
  a model host (a `models[]` entry, or one the parsers claim) or unknown, is reported unmetered
  (limits-check-doctor-cli.md R1 (e), (f)). The paths are:
  - a connection gapped by a sequence hole, a framing error or an `SSL*` split across threads (`loseConn`, limits-check-doctor-cli.md R1 (f)):
    every request it held lost its response; with none waiting, the connection's last `Host` decides, unknown
    counting as a model's;
  - an h2 connection (R17's gap), by `loseConn`'s rule: a preface on a fresh connection names no `Host` and is
    reported; an h2c upgrade from a learned non-model host is not (limits-check-doctor-cli.md R1 (g), (q));
  - a connection that ends cleanly — an `SSL_free` close record, a count restarting at 1 on its key, or `Stop` —
    with requests still waiting (`closePending`, limits-check-doctor-cli.md R1 (e)); a connection with none waiting reports nothing;
  - a waiting request older than the one a response answers: R11's refused requests and those whose head capture
    missed are never kept, so what reaches there is a request `httpstream` gave up when its connection ended under
    the same key (`endCloseDelimited`) (limits-check-doctor-cli.md R1 (e));
  - the oldest request the `2 × DefaultMaxPipeline` bound evicts, whose answer would be recorded without derive
    (limits-check-doctor-cli.md R1 (e));
  - a pipelined request past R11's depth, refused: its answer is passed over unread, so it is reported when it is
    emitted (limits-check-doctor-cli.md R1 (e)).
  A successful answer on a model host whose body the byte budget cut (`Message.SizeCut`) is reported the same way
  (limits-check-doctor-cli.md R1 (d)). Not reported, and stated: an exchange passed over because capture missed its request's start (R4's
  attach race, or a connection's first chunk lost to a full ring, which `gap why=ring-buffer-drop` counts)
  (limits-check-doctor-cli.md R1 (p)).
- **R8.** Detach decrements `RefCount` on process exit (from `observe`'s exit event, `OnExit`); links close at 0. A binary
  still mapped by another run's process is never detached while that run's contribution to `RefCount` stands.
  A reference is one source's hold on one process, keyed by the pair and never by the pid alone: pids are
  reused and an exit event can be missed, so a pid one run attached and never saw exit can later be another
  run's live process on the same binary, and giving back "the pid" would detach that run with no gap to say so
  (I4). An exit, or a run's `Stop`, gives back only that source's own references. A run's pre-attach (R4) is one
  reference of its own, under no process, given back at `Stop`. `Stop`'s sweep is final: an
  exec still being handled when it runs gives its reference back itself rather than recording it after the
  sweep, and an exec that arrives after `Stop` attaches nothing, so no reference outlives its run (I9).
  In production the links a binary's refcount holds are the build's, shared per library across the build's runs
  (ADR 0026 (7)): the first run places them and pins them under `<bpf_hash>/uprobes/<dev>-<ino>-<build id>/`, a
  run that finds them pinned, and running the build's programs over its pinned maps, adopts them and places nothing
  (*amended 2026-11-02*, below), and each run holds the library's lock in
  `/run/tego` shared while its refcount stands. Refcount zero then closes only the launcher's descriptors and
  gives the hold back; the last hold out stamps the lock and, once the run is over and its fanotify marks are
  gone (ADR 0021 (3)), `tego run` starts `tego __uprobe-detach`, which removes the library's probes 2 s after
  the stamp (`ProbeGrace`) unless a run holds it again. The detacher runs in `tego.slice/helpers.scope` at the
  cgroup2 root (`cgroup.StartHelper`), not the launcher's cgroup, so stopping the launcher's unit, CI job or scope
  does not kill it; one that cannot be put there starts in the launcher's cgroup with `TEGO_HELPER_UNPLACED`
  naming why. A detacher that dies anyway is made up for: each run's source as it starts, and `tego doctor` and
  `tego gc` as root, remove every library no run holds whose grace is over (`SweepLibraries`,
  `TestSweepLibrariesRemovesOnlyOverdueUnheldProbes`, `TestIntegrationProbesWhoseDetacherDiedGoAtTheNextStart`).
  A detach is never on a run's path: removing six probes
  took 0.40-0.55 s on 6.17, and a placement that met a detach still under way waited for it, 75-340 ms (test/vm
  README, kill test 4). A kernel that cannot pin a uprobe link keeps the probes per run, as before
  (`TestIntegrationSharedProbesAreAdoptedAndCaptureOnce`, `TestTheLastHoldOutHandsTheProbesOnAndNoOtherDoes`,
  `TestDetachAfterKeepsHeldProbesAndRemovesIdleOnes`, `TestDetachAfterWaitsOutTheGraceFromTheLastStamp`).
  *Amended 2026-11-02:* a complete set of a library's individual probes was adopted on its count alone. One pinned
  before the build's maps were re-created (a build removal that failed part way at the probes, or one made by hand)
  runs the old programs over a run set that names no run of the build, so the run that adopted it captured nothing
  on that library and reported no gap. A set is now adopted only when each link is a perf-event link running its
  probe's program, the run's own or the same code over the build's pinned maps (`sameProgram`, which a multi pair is
  held to), and, where the kernel reports the probe (6.6 and later), on the probe's kind and offset. A set that is not
  is never adopted, and never left in use beside a second set: when no other run holds the library (the run's
  exclusive attempt on its lock succeeds), nothing captures through it, so it is unpinned and the run places its own;
  while another run holds it, the library is refused, the Failure modes table's "Uprobe attach fails" row, with the
  reason in the gap's detail, as a multi pair the run cannot prove is the build's is refused
  (`TestPinnedProbesAreTheBuildsOnlyWhenTheyRunItsProgramsOverItsMaps`,
  `TestProbesNotTheBuildsAreRefusedWhileAnotherRunHoldsTheLibrary`,
  `TestProbesNotTheBuildsArePlacedAgainWhenNoOtherRunHoldsThem`, `TestIntegrationProbesOverRecreatedMapsArePlacedAgain`).
- **R9.** Per-cgroup filtering happens in-kernel (`bpf_get_current_cgroup_id()` against the host-wide cgroup→run
  map, same pattern as `observe`): a process in no run's cgroup produces no chunk. That map is every run's of the
  build, and the probes are the build's runs' shared ones (ADR 0026 (7)), so after the run-set hit a probe looks up
  the capture ring at the process's `run_idx` and writes the chunk there, stamped with that `run_idx`; a run with no
  capture ring (capture `off` or `forwarder`, or one the ring budget left out) gets nothing, and the hit is counted in
  `tego_capture_miss` at its slot, so no TLS plaintext of such a run is written anywhere
  (`TestIntegrationACaptureOffRunBesideACaptureRunLeavesNoChunk`). Userspace reads only its own run's ring and keeps
  a chunk only when its `run_idx` is the run's own slot (§4 uprobe, edge case #26). *Amended 2026-10-19
  (limits-check-doctor-cli.md R4):* right after the run-set hit, before the record mode or the ring is
  looked at, an `SSL_write`/`_ex` that asks to move bytes and an `SSL_read`/`_ex` return that moved some stamp the
  run's slot of `tego_activity` (a `bpf_ktime_get_ns` reading, written at most once a jiffy) for a run whose row
  carries `TEGO_RUN_ACTIVITY`, which the backend sets when `stall_after` bounds the run, in every record mode: a
  response streaming for longer than `stall_after` has no line between its two ends, and its reads are the agent's
  work. The run's recorder reads the slot once a tick for the stall check. The stamp reads registers only; read
  entries and `SSL_free` stamp nothing; under `record: off` each probe returns right after it, having read no user
  memory and made no scratch row, chunk number, ring reserve or miss count, so no TLS plaintext of the run is read
  or written anywhere (`TestTLSProbesStampBeforeTheModeAndReadNothingUnderOff`). A probe stamps the call of any
  stall-bounded run of the build it fires for, whichever run placed it (R4's sharing, ADR 0026 (7)).
- **R39.** For an adopted Docker container's process, R4's `/proc/<pid>/maps` path is only meaningful inside that
  process's own mount namespace: capture resolves it to `/proc/<pid>/root/<path-from-maps>` before opening the ELF
  (symbol lookup, `BuildID`, `binKey{dev,ino}` per R7 all read through this resolved path), matching ARCHITECTURE.md
  §9: container capture needs uprobes "attached to the container's own libssl through `/proc/<pid>/root` or the
  injected forwarder variables." A bare `maps` path opened against the launcher's own namespace would silently miss
  the library for every containerized process. The resolved path names one process's `/proc` entry and dies
  with it, so an attach always uses the live process's own spelling of the file; what the R7 cache carries
  between processes is the offsets and `BuildID`, which belong to the file, never the path.

**httpstream (E21)**
- **R10.** One FSM per `ConnKey`: request line → headers → (`Content-Length` | chunked | no body) → next request
  (keep-alive) or close.
  `httpstream` hands the request target over as the wire had it, and the `uprobe` source reads it as RFC 9112 §3.2
  does (`derive.SplitTarget`) before recording or deriving. Origin-form (`/v1/messages`) and asterisk-form (`*`) take
  their host from `Host`. Absolute-form (`POST https://api.anthropic.com/v1/messages HTTP/1.1`) takes its host from
  the URL's authority, ignoring `Host` (§3.2.2: the upstream routes it by the URL), and its path and query from the
  URL: the `ssl_request` line's `host` and `endpoint` are the URL's, its `path` stays the raw target, and derive
  reads the URL's path (taken from `Host` and the raw target, the path would normalize to
  `/https:/api.anthropic.com/v1/messages`, outside `/v1`, and a Messages call would spend nothing). `CONNECT`'s
  target is authority-form by definition (RFC 9112 §3.2.3): a `CONNECT` target of host and port is the host the
  tunnel reaches, and the exchange is recorded as a tunnel, never derived. `httpstream` frames a 2xx to `CONNECT`
  with no body and parses nothing on the connection after it (`becomeTunnel`): the tunnel's bytes on both halves are
  neither messages nor gaps. A 2xx tunnel to a model host is reported unmetered (limits-check-doctor-cli.md R1 (i)),
  the h2 rule (R17, ADR 0035): the TLS session inside it is read only if its client runs it through a probed `SSL*`,
  which capture cannot tell. One to another host reports nothing (limits-check-doctor-cli.md R1 (q)); a refused `CONNECT` is an ordinary
  exchange. Any other target (authority-form outside `CONNECT`, a `CONNECT` target that is not a host and port, a
  relative path, a URL with no host or a scheme other than `http`/`https`) fails closed: derive's Anthropic parser
  treats it as a path it does not read (unparsed, R25), and the source reports a 2xx answer to it — or its loss with
  its connection — unmetered whichever host `Host` names (limits-check-doctor-cli.md R1 (h), (e), (f)), never as an endpoint that spends
  nothing. When a request body stops being kept whole (`MaxBody`, the byte budget), `httpstream` reads its top-level
  `max_tokens` off every later body byte (`Message.MaxTokens`) with the scanner the capture wiring supplies
  (`Options.BodyScanner`: the uprobe source gives it the shared scanner in derive/anthropic), so derive's
  cut-stream bound (R29) does not need the whole body.
- **R11.** Pipelining: up to 8 queued requests awaiting responses; a 9th is `gap why=size-cap` on that request,
  connection otherwise continues. Its response, which comes after the 8th's (RFC 9112 §9.3), is passed over with
  no second gap, and a request queued once the FIFO has room again pairs with its own response (the refused request
  keeps its place, so that later request is never paired with the refused one's response). A refused request is
  handed over marked `Refused`, for its
  `ssl_request` line alone: its body is not decoded (nothing will ever pair a response with it, so a decoder run for
  it is launcher memory spent on bytes the record only sizes), `Message.Body` is nil and `WireBytes` carries the
  length the wire did (counted as the bytes are consumed, so a body the budget or `MaxBody` cut, or a kernel hole (R6) stepped over, still reports its whole length). The `uprobe` source records it with that size, stores no blob of it under `record: full`, and
  keeps nothing of it pending.
- **R12.** `Expect: 100-continue`: an interim `100 Continue` line is consumed and discarded (not emitted); the
  assembler waits for the next status line as the real response; a client that sends the body without waiting is
  still reassembled normally.
- **R13.** Header cap: 64 KiB total, 128 lines (Envoy-like default); over either is `ErrSizeCap`
  → connection gaps, one `gap why=size-cap` per connection, not per byte. The cap bounds one half, not how many
  halves hold a head at once, so the bytes a half keeps while a start line, header block or chunk-size line is still
  arriving are reserved from R14's assembler-wide byte budget like a body's (4096 connections parked on 63 KiB heads
  each way would otherwise add 500 MiB outside it); a head the budget cannot hold gaps its connection,
  one `gap why=size-cap`. A line arriving in pieces is searched for its end once per byte, not once per piece.
- **R14.** Body handling is a streaming window (64 KiB), not a total cap: bytes go to the blob writer as they
  decode (R15); no upper bound on total blob size. `Truncated` is set only by R6 propagating up, never a body-total cap.
  **Implementation condition (P0).** The streaming handoff does not exist yet: `httpstream` assembles a whole decoded
  body in launcher memory and `uprobe` blobs the finished `Message.Body`, so R14's "no upper bound" is, as built, no
  bound on the launcher's address space — chosen by whatever server the traced agent talks to, and unbounded by any
  wire cost once the body is compressed (a few hundred KiB of `gzip` expands as far as it likes). The launcher holds
  the ledger writer and the seccomp supervisor, so an OOM there ends enforcement and the audit trail together and
  leaves no `gap` behind to explain it (I4). Until a body streams, `Options.MaxBody` therefore defaults to
  **64 MiB** per message: past it the body is cut and the message marked `Truncated`, with no `gap` (the cut is this
  package's own bound, not a peer's framing error); the `ssl_request` and `ssl_response` lines then carry `truncated: true` and `wire_size`, so a blob that holds a prefix does not read as a whole body (record-ledger §2.2). The R6 kernel cut is marked the same way. 64 MiB keeps the "32 MB body handled" acceptance whole with
  headroom. Wiring the decoded stream into `ledger.Writer.Blob` (`PutStream` already takes a reader) and keeping only
  the prefix derive parses restores R14 as written, at which point the default is lifted, not tuned.
  `MaxBody` bounds one body, not how many are held (24 connections holding 48 MiB unfinished bodies would grow the
  launcher by 1.5 GiB), so a completed body's array goes with its message, and every
  body the path holds — in flight in `httpstream`, or pending in `uprobe` for derive — is reserved from one
  assembler-wide byte budget (`httpstream.Options.MaxBytes`, 256 MiB by default, never below three `MaxBody`
  arrays; §3). A body past it keeps its prefix, is marked `Truncated`, and is one `gap why=size-cap`; a pending
  request past it goes to derive without its body (the blob still has it whole), with the same gap.
- **R15.** Decode order: identify `Content-Encoding`, wrap the body reader in the matching decoder
  (`gzip|deflate|br|zstd`) before derive or the blob writer see it, so `blob(sha)` hashes decoded content and
  `content_encoding` records what the wire used. A mid-stream decode error emits the decoded prefix as the blob,
  `Truncated=true`, `gap why=malformed`; the body was framed whole, so the decode failure costs that body alone and the connection goes on (`httpstream` counts one gap per failed body and returns no error). One decoder table serves both capture paths: `httpstream` owns it
  (`Codings`, `Open`) and the forwarder undoes a response through it, a listed `Content-Encoding` from the right.
  `x-gzip` is `gzip` (RFC 9110 §8.4.1.3); `deflate` is the zlib wrapper RFC 9110 §8.4.1.2 defines, or the bare
  stream many servers send instead; a `zstd` frame whose window exceeds RFC 9659's 8 MB is a decode error, because
  the decoder allocates the declared window before decoding a byte and the library's own ceiling is 512 MiB. A
  list of more than `httpstream.MaxCodings` (2) codings is not decoded at all, by either path: every layer is a
  decoder with a window of its own, a header names one in a few bytes, and the forwarder holds all of them open at
  once, so thirty `zstd` layers in a 271-byte body cost 270 MB of launcher heap. Such a body is kept as the wire
  carried it, as for a coding with no decoder: the forwarder records it undecoded (`decision: unparsed
  why=encoding`), and `httpstream` handles it as it handles any decode error above; an SSE response in such a coding also keeps its wire bytes, without attempting provider framing. On the forwarder too, a body
  whose decode failed mid-stream, and a response the client left before its end, are `Truncated` with one `gap
  why=malformed`; a body cut short that way, or by the upstream failing, is not also counted as `size-cap`, which is
  kept for the capture budget and the decode limit. A compressed copy already cut short by any of these, whose
  decode then fails where it was cut, is that one cut and its one gap, not also a decode failure's `malformed`. A forwarder line whose body member is a prefix of the body — cut at `MaxBody`, by the capture budget (the body's or the event's copy of it), by the client leaving, the upstream failing or a decode — carries `truncated: true` and `wire_size` as R14's cut does: for `ssl_request` the bytes the client sent, for `ssl_response` the bytes the relay read before any coding it undoes, or the declared length when that is more; a line with no body member carries neither. In `httpstream` a body's decoded form is inside the byte budget
  (106 bytes of `br` are 64 MiB of zeros, and one `Feed` can complete many messages): every array a decode makes is
  reserved from the budget as it grows, and a decode the budget cannot pay for stops there:
  the prefix is kept, `Truncated`, one `gap why=size-cap`. The decoded bytes of one call into the assembler (a
  `Feed`, a `Close`, `CloseWhere`, `CloseAll`) are bounded together at one `MaxBody` — one body at its largest,
  which is what one call completes in traffic a server answers; a body past that allowance is cut the same way and
  counted the same way. The reservations of the bodies a call completes, wire and decoded, are held until the call
  returns, where the messages become the caller's (the `uprobe` source reserves again what it keeps pending). A
  request R11 refused is not decoded at all (R11). The forwarder already reserved its decoded form (`decodeWith`).
- **R16.** SSE is reassembled as **one** `Message` (`SSE=true`) retaining the decoded stream, including event names, empty data fields, comments and separators. Both capture paths hand this same representation to derive with `WireSSE=true`, selecting wire framing so a JSON-looking unknown field cannot be mistaken for a legacy collected payload; individual frames are not separate `record.Event`s. Provider framing is shared by the full parser and incremental usage scanner: CR, LF and CRLF terminate lines, including CRLF split across capture chunks; an initial UTF-8 BOM is skipped, unknown fields (including colonless names) and comments are ignored, and event-only frames without data are not dispatched. The lines of one event are joined by LF. An empty named accounting frame is dispatched and makes accounting incomplete; a later valid usage report cannot erase it. Removing framing in capture would lose this evidence and event names used when a payload omits `type`. A request labelled `text/event-stream` keeps its body as sent (`SSE=false`), as the forwarder records it.
- **R17.** An h2 preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) or ALPN `h2` on the traced handshake aborts
  reassembly immediately: `gap what=capture why=h2`, no partial `Message` ever emitted from h2 bytes. **Condition:**
  the ALPN half is not implemented (reading the negotiated protocol needs a probe on the handshake or on
  `SSL_get0_alpn_selected`, which a client calls only when it asks); h2 is known by its preface alone, which an h2
  client writes as its connection's first bytes (RFC 9113 §3.4), so any h2 connection capture sees from its start
  is the `h2` gap. The gap this leaves: an h2 connection whose preface capture missed (a probe placed after it) is
  framing HTTP/1.1 cannot follow, `why=malformed` rather than `why=h2`, one per connection. The `h2` gap is not only
  a gap: on the `uprobe` path an h2 connection to a model host, or to a host capture never learned, is reported
  unmetered (R7a, limits-check-doctor-cli.md R1 (g)), which ends a run with a token or cost budget (ADR 0035).
- **R18.** Malformed input (bad line, header without `:`, bad chunk-size hex, `Content-Length`+`Transfer-Encoding`
  both present, a `Content-Length` that is not 1*DIGIT such as `+5`, a `Transfer-Encoding` that does not end in
  `chunked`; a transfer coding before `chunked` is undone as a content coding applied last) never panics: `ErrMalformed`, one `gap why=malformed` per occurrence, other connections unaffected
  (state is per-`ConnKey`). What R4's late attach leaves is not a framing failure, and each is passed over as one
  `gap why=malformed` counted for its exchange, the connection going on: a response that answers no request the
  connection saw, which is decided at the first byte of it capture sees, before its status line is whole, so a
  request capture sees after that byte, even between two pieces of the status line, is never its partner (a
  request's `SSL_write` is captured at its entry, before the server can have read it); the rest of a response
  whose status line was missed; and, as the first request capture sees on a connection, request bytes that begin
  neither a known method nor a token and a space, the tail of a request whose head was missed, whose response is
  then passed over with it and not counted again. What stays fail-closed, because which request a response
  answers could not be told: a response that begins while a request is still arriving and ends before that
  request does, which may be its early answer, and that includes the response to a request tail that is a known
  method whose line has not ended (R4); a first request line of a token and a space that does not parse, or that
  runs past the 8 KiB start-line cap, which may be a tail as well (R4); request bytes that begin no request line
  while a response is arriving, or once the connection has carried a whole request; and a request that completes before the response to a headless one,
  pipelined behind it or following that one's early answer. The `Content-Length`+`Transfer-Encoding` case: RFC 9112 §6.1 "Transfer-Encoding" lets a
  server reject the request and requires it close the connection; §6.3 "Message Body Length" states the smuggling
  framing directly ("Transfer-Encoding overrides Content-Length... might indicate an attempt to perform request
  smuggling... ought to be handled as an error") — §6.3 is the operative citation, §6.1 only for reject-and-close.

**forwarder (E22)**
- **R19.** One listener per `models[]` entry, `127.0.0.1:0`, plaintext HTTP/1.1 only (loopback never negotiates h2).
  A `forwarder.listen` that pins a non-zero port gives that port to the first entry's listener; each later entry
  binds port 0 on the same loopback host, and the run logs a warning, so no entry loses its listener to the port
  the first one holds.
- **R19a.** A listener serves only the run it was bound for. As a connection is first read — before a byte of its
  first request, so before R22's local answer, the h2/`CONNECT` refusals and any body — the peer is placed in the run's cgroup or
  its request is answered `403` and the connection closed: the connection's 4-tuple resolves to the peer socket's inode
  by one exact `SOCK_DIAG_BY_FAMILY` lookup (sock_diag(7); `/proc/net/tcp`/`/proc/net/tcp6` when that is
  unavailable), and one of the processes the run's cgroup subtree lists in its `cgroup.procs` must hold that inode
  in its `/proc/<pid>/fd`, and still be in that subtree by its own `/proc/<pid>/cgroup` when it is named (the agent
  is cloned straight into that cgroup with `CLONE_INTO_CGROUP` and has no write access to the cgroup tree, so it
  cannot leave it). The verdict is decided once per connection, not per request. Its cost does not grow with the
  connections already open: the listener remembers each run process's descriptor links, looks for a new socket
  first at a number a closed connection freed and just past the process's highest, and lists a descriptor table
  only when those miss (a walk of all of `/proc` and every descriptor per connection measured 4.8 ms with none
  open and 28.6 ms with 4000); when the run's cgroup cannot be listed, the walk of `/proc` answers instead. That
  table search is what every peer outside the run costs, and that peer chooses how often it connects, so it is
  bounded by rate as well as R27's count: one search runs at a time, for every connection waiting on one when it
  starts, and a search that leaves a socket unfound holds the next back for three times as long as it took
  (`searchPace`), so outsiders take at most a quarter of one core of the launcher however fast they connect, and
  a connection of the run's the memory cannot place waits at most the search in progress, that pause and one
  search more (`TestOutsiderSearchesAreSharedAndPaced`, `BenchmarkOutsiderAdmission`). A loopback bind is not an authorization: every process on the host, of any uid and any cgroup, and a
  page in the developer's browser by way of a cross-origin POST that is never preflighted, can reach
  `127.0.0.1:<port>` — CVE-2025-52882 (Claude Code's IDE extensions, CWE-1385, CVSS 8.8) and CVE-2025-49596 (MCP
  Inspector, CWE-306, CVSS 9.4) are exactly this shape — and an unauthenticated writer here appends `ssl_request`
  lines the agent never made to a chain that is authenticated as to ordering and not as to origin, holds the run's
  capture budget (§3) so that the agent's own exchanges record truncated, and moves the budget `limits` stops the
  run on. Fail-closed in every direction: a peer that cannot be resolved, a peer socket its process has already
  closed (orphaned, so both lookups give it inode 0, which every descriptor that is not a socket also reads as), a
  run whose cgroup id is unknown, a
  `/proc` that cannot answer, and a big-endian host whose tcp table this parser does not read are all refusals, not
  passes. A refusal is **not** a `gap what=capture` — nothing of the agent's own traffic was missed, the mirror of
  R38 — so it is counted and logged rather than recorded; the missing record shape is §11's.
- **R19b.** The harness variables (`spec/identity/RUN-IDENTITY.md`, `Manager.Vars`) point each provider's SDKs at
  its listener: `ANTHROPIC_BASE_URL` and Gemini's three at the listener's origin, `OPENAI_BASE_URL` and
  `OPENAI_API_BASE` at the origin plus `/v1`, because the OpenAI SDKs take the API root with its version and append
  `/chat/completions` or `/responses` to it while the listener forwards the path it receives unchanged. A variable
  holds one URL, so a provider declared twice in `models[]` gets the first declared entry's; the later entry's
  listener stays bound and admitted, is reached by nothing the run installs, and is logged at construction.
  Codex takes no variable: codex-cli 0.155.1 ignores `OPENAI_BASE_URL` (checked 2026-09-22: with it set, the CLI
  called `api.openai.com`) and, per its configuration reference, reads `openai_base_url` only from the user-level
  `config.toml` under `CODEX_HOME`, never from a project's `.codex/config.toml`; with that file pointing at a local
  listener the same CLI sent every call there, trying a WebSocket `GET /v1/responses` first — which R20 strips of
  `Upgrade` — and falling back to HTTPS `POST /v1/responses`. `identity.CodexConfig` renders that file from the
  `OPENAI_BASE_URL` value, tego's key first and the user's own file after it unchanged, so a user file that sets
  `openai_base_url` too makes the file invalid TOML, and Codex refuses to start ("Error loading config.toml:
  duplicate key", exit 1) rather than route around the forwarder. The launcher writes that file: an unprivileged
  run whose forwarder has an openai listener and that has a runtime directory makes `$XDG_RUNTIME_DIR/tego/<run>/codex`
  (`0700`) holding `config.toml` (`0600`) — `identity.CodexConfig` over the listener's `OPENAI_BASE_URL` and the
  user's own `config.toml` from the `CODEX_HOME` the agent would have inherited, else `~/.codex` (not read at all when a `deny_read` entry covers it, so the agent cannot reach through the copy what the contract denies it), opened
  `O_NOFOLLOW`, regular, at most 1 MiB, left out with a line in the own log when it cannot be read — and puts
  `CODEX_HOME` in `ForwarderVars`, so Codex sends its calls to the forwarder; the directory goes with the runtime
  directory at the end of the run (`internal/runtime` `codexhome.go`, 2026-09-22). Codex keeps its sessions and SQLite
  state under `CODEX_HOME`, and the run grants the agent write access to exactly that directory on its own authority
  (*resolved 2026-10-16*, agent-contract.md R10a): the write entry `fs.codex_home[<path>]`
  (`agent.CodexHomeGrant`), as `net.capture[<addr>]` is for the listener's port, which `IsRuntimeRule` keeps drift
  from counting as an undeclared entry and `run_start.runtime_grants` records. The directory is made, and the grant
  added, before the enforcement tier is prepared (`runtime-launch.md` §4.1 step 3), so every tier builds with it.
  Before, contracts granted `$XDG_RUNTIME_DIR/tego/`, which reached every other run's private directory; compile
  and the launcher now refuse such an entry. With an openai listener and no absolute `XDG_RUNTIME_DIR` the run is
  refused, exit 125, naming the fix: it used to go on with Codex unrouted and say nothing. A root launcher writes no
  `CODEX_HOME`: its runtime directory is root's `0700`, which the agent, dropped to the invoking uid, cannot
  enter, so routing Codex under `sudo` also waits on a runtime directory the agent may enter; until then such a run
  writes `gap what=capture why=codex-unrouted binary=codex` after `run_start` (*amended 2026-10-16*,
  agent-contract.md R10a (3)), and the `models[]` guard keeps Codex from reaching the model around the forwarder. A `CODEX_HOME` of
  the run's own hides the user's `auth.json`, so an API-key login works (`CODEX_API_KEY`) and a ChatGPT login,
  which talks to `chatgpt.com` rather than the openai provider, is I4's adapter decision; verifying capture against
  a real Codex needs an OpenAI API key. Resolution of the E22/I4 priority conflict: E22's P0 scope is the
  forwarder's routing and this rendering; running Codex with a generated `CODEX_HOME` is I4 (P2).
- **R20.** Rewrite `Host`/SNI to `model.Host`; strip RFC 7230 §6.1 hop-by-hop headers (`Connection` and everything
  it names, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`,
  `Upgrade`); strip `Expect`, which the listener answered itself when it read the body (the upstream leg would
  otherwise hold the already-read body back for an interim 100 it may never send). Stripping `Upgrade` and
  `Connection` declines an upgrade offer (an h2c offer, a WebSocket attempt), which RFC 9110 §7.8 lets a server
  do: the request is forwarded as HTTP/1.1 (*amended 2026-10-05:* this holds for a listener with neither
  `net.http` nor `net.proxy`; under `net.http` an upgrade is refused with 400 and under `net.proxy` it is a
  WebSocket route decision, SEMANTICS §5. The `net.proxy` work had refused every upgrade offer on a
  capture-only listener with 400 and a malformed gap, so `curl --http2` and Java's `HttpClient` failed every
  call, `TestCaptureOnlyUpgradeOfferIsStrippedAndForwarded`); forward everything else
  byte-for-byte; add `X-Tego-Run` and rewrite `traceparent`/`tracestate`
  exactly per `RUN-IDENTITY.md` (fresh `00-<sha256(run id)[:16]hex>-<8 random non-zero bytes>-01` when absent/
  invalid, discarding incoming `tracestate`; else keep the client's trace id, replace only the parent id; for
  `tracestate`, read every incoming `tracestate` line as one comma-joined list (W3C Trace Context), first remove
  any prior `tego` member already present on the incoming header — a nested tego run
  or spoofed input could otherwise send one — then prepend `tego=<run id>`, and drop members past 32 counting from
  the right). Removing the prior member is its own step, not folded into prepend+truncate: skipping it leaves two
  `tego=` members on a request that already carried one, contradicting `RUN-IDENTITY.md`'s explicit "any prior
  `tego` member removed."
  `Accept-Encoding` is the one end-to-end header not forwarded byte-for-byte: the upstream picks the response's
  coding from it, so it is narrowed to the client's own members naming `gzip`, `x-gzip`, `deflate` or `identity`,
  each kept as written (q-values included), and becomes `identity` when none is left and identity is acceptable; an explicit identity refusal or `*;q=0` is preserved. If no supported coding remains acceptable, the listener answers 406 without contacting the upstream; a positive wildcard can supply gzip or deflate when identity is refused. An absent header stays absent
  (net/http's `Transport` then asks for `gzip` itself and hands back the decoded body). Passed untouched, a client
  offering a coding nothing here decodes would get an answer recorded as compressed bytes — `decision: unparsed
  why=encoding`, no `usage`. The forwarder decodes `br` and `zstd` too (R15), but their decoders hold up to the
  window a stream declares outside the capture budget (§3), so they are not offered: fail-closed on both the budgets
  and the launcher's memory, at the price of `gzip` where a client would have taken `br`.
- **R21.** No response buffering: `io.Copy`/flush-per-chunk streaming only, matching E22. Under a stall budget
  every chunk the response relay reads from the upstream, and every chunk either pump of a `CONNECT` or WebSocket
  tunnel carries, is activity for the run's stall check (limits-check-doctor-cli.md R4), in every record mode: one
  meter per run's forwarder reports at most one chunk per 100 ms with the listener's monotonic reading
  (`Options.Activity`, set by the runtime through `Manager.SetStreamActivity` before `Start`). Response headers are
  not a chunk, and a connection that carries nothing reports nothing, so a model that stops producing still stalls
  (amended 2026-10-05: a response streaming for longer than `stall_after` had a line at its two ends only, and the
  run was killed while its model answered; `TestAStreamingResponseIsActivity`, `TestASilentUpstreamIsNoActivity`,
  `TestATunnelIsActivity`, `TestActivityMeterIsCoalesced`, `BenchmarkForwardStallBudget`).
- **R22.** `HEAD /api/hello` answered locally: `200`, `Content-Length: 0`, no upstream contact, regardless of
  upstream reachability.
- **R23.** Retry recognition: `computeRetryKey` over the raw body and hashed credential; a match against a
  pending/recent key (R24), or `x-stainless-retry-count > 0` (naming that process's most recent request), sets
  `retry_of` and does not open a new E28a step (R27/R33) — it extends the original. Both look only among the
  requests of the same run process (the pid admission resolved, R19a): a retry is a repeat by the same caller, so a
  byte-identical request from another process on the same credential is a request of its own. `x-stainless-retry-count: 0` is a first attempt, never tagged. A request whose
  body capture was truncated has no key: the hash would be over a prefix, and two requests differing only past the cap
  (one long conversation's consecutive turns) would collide into a false `retry_of` that R33 folds into one step — so a
  truncated capture is neither looked up nor remembered by key, leaving the counter path as its only attachment.
- **R24.** Retry window: 256-entry LRU, TTL 650 s (600 s longest observed client wait + 50 s margin); past TTL, a
  same-key request is a new step, not a retry (stated limit — indistinguishable from a legitimate late duplicate).
- **R25.** Dispatch to `derive` is by `model.Provider`/upstream host, not content sniffing; a non-POST to `/v1/messages` answered with no body is silent (nothing was spent), and one that carries a body is read; an unrecognized
  provider produces `decision: unparsed why=schema`, never a silent drop; its absence is not a capture gap.
  The Anthropic parser fails closed on paths: only an allow-list of endpoints that spend nothing is silent —
  `/v1/models*`, `/v1/messages/count_tokens`, a batch's listing, status, deletion and cancellation, `/v1/files*`,
  and anything outside `/v1` (the root path, the health check, a harness's telemetry and account calls under
  `/api/...` — the billed API is versioned under `/v1`) (limits-check-doctor-cli.md R1 (l)). That last rule is
  `api.anthropic.com`'s (`DefaultHosts`): on any other host a `models[]` entry declares for provider `anthropic`
  (a gateway serving Claude at `/anthropic/v1/messages`, a Bedrock-style `/model/<id>/invoke`), and on an unknown
  host, the only silent paths outside `/v1` are the root path and `/api/...` paths none of whose segments is
  inside `/v1` by the reading below (`/api/event_logging/batch` is silent, `/api/v1/messages` is not); every other
  path there is one the parser does not read (`derive.HostScoped`). "Outside `/v1`" is
  decided on the normalized path's first segment, lowercased, with any `;params` cut off: a first segment that
  begins with `v1` in any case is inside `/v1` (`/V1/messages`, `/v1;x/messages`, which a server may route to the
  Messages API). An ambiguous first segment is inside too: one holding a backslash, a percent left after one decode, a control byte, a space or a
  non-ASCII byte, and an empty first segment other than the root path (`/;x/v1/messages`). Inside `/v1`, no
  silent subpath is read from such a spelling either: a path holding a backslash, a `;`, a `%` left after the one decode (a double-encoded spelling), or a control, space or
  non-ASCII byte in any segment is a path the parser does not read (`/v1/models/..;/messages` is not silent, as a
  server may serve it as `/v1/messages`). `/v1/messages` is read
  as R29 says. `/v1/chat/completions` (Anthropic's OpenAI-compatible endpoint) is read minimally in the OpenAI
  shape: `model`, and `usage.prompt_tokens` (less `prompt_tokens_details.cached_tokens`, counted as cache reads) and
  `completion_tokens`, whole or from the last streamed chunk that carries usage (a 2xx answer with none is an
  unparsed body); its tool calls are not derived (the openai parser's, P2). Creating a batch (`POST
  /v1/messages/batches`) is one `decision: unparsed why=schema`, and a batch's `/results` is a path the parser does
  not read. Any other path inside `/v1` is an unparsed body. On a 2xx answer each of these — a batch creation, an
  unparsed body on a claimed endpoint, and a declared provider with no parser — sets `Facts.Unmetered`, which the
  capture source reports to the run (limits-check-doctor-cli.md R1 (a), (b)). The parser classifies an
  absolute-form target by its URL's path, and a target that is neither origin-form, `*` nor an `http`/`https` URL
  as a path it does not read (R10). The dispatch host, and the host a `models[]` entry is matched against on the
  `uprobe` path, compare as R33's step hosts do, without a trailing dot (`Host: api.anthropic.com.` is the
  declared host).
- **R26.** Errors to the client: dial/TLS failure → `502`; headers received but body read times out before any
  bytes are written → `504` (once streaming starts, the connection is simply closed, never a late `504`);
  malformed request before `Transport` is reached → `400`. Every mapped error is also an event, never only a status code.
- **R27.** No forwarder-imposed response timeout (must not beat the client's own ceiling, ARCHITECTURE §7);
  `ReadHeaderTimeout: 30s` on the inbound loopback side only, and between requests an `IdleTimeout` of 2 minutes
  (`DefaultIdleTimeout`, `Options.IdleTimeout`), longer than every SDK pool's idle expiry, so a keep-alive
  connection gone quiet is closed rather than held for as long as its peer likes. A listener holds at most 2048
  of the run's connections at once (`DefaultMaxConns`, `Options.MaxConns`); one of the run's past that is closed
  before a byte of it is read and counted as one `gap why=size-cap`, and reports nothing unmetered, since nothing
  of it reached the model host (limits-check-doctor-cli.md R1). Only a connection R19a admitted counts against
  that cap, so a process outside the run can neither take the run's slots nor add to its gaps: R19a's outsiders are
  bounded apart, at most 64 (`DefaultMaxOutsiders`) waiting for the request their `403` answers, and one past that
  is closed as it is placed and counted as a refusal, not a gap; the CPU their placing costs is bounded by R19a's
  pacing of the table search, not by these counts; connections not yet placed are at most
  `MaxConns` too, and one accepted past that is placed before the next accept, so a connect flood waits in the
  kernel's backlog rather than being refused unplaced. A response write that makes no progress for 30 s
  (`DefaultWriteStallTimeout`, `Options.WriteStallTimeout`) gives the exchange's record copy back to the capture
  budget and cuts it there, `gap why=size-cap` with (e)'s unmetered rule, while the relay carries on writing for as
  long as the client lets it: a client that stops reading otherwise held up to `MaxBody` of the budget each, and
  eight at the defaults held all of it.
  The request side is bounded so an upload cannot hold the capture budget (eight uploads that declare `MaxBody` and
  send one byte would otherwise hold the whole 64 MiB budget, and every later call's usage would go unread):
  - (a) A request body is read with an idle deadline, 30 s without a byte by default (`Options.BodyIdleTimeout`),
    and a total deadline from its first read to its end, 10 minutes by default (`DefaultBodyTimeout`,
    `Options.BodyTimeout`); each read's deadline is the earlier of the two, set per read through
    `http.ResponseController` and lifted when the body ends, so it never reaches the response. A body that stalls,
    or is still arriving at the total deadline, is answered `400` and gives its reservation back, and its connection
    is closed after the reply (net/http would otherwise drain the unread rest of a small body with no deadline).
    The body a health check (R22) drains is read under the same deadlines. Ten minutes is
    far past any body an SDK writes: the Messages API refuses a request over 32 MB, which takes about 4.5 minutes
    even at a 1 Mbit/s uplink (the upstream leg reads the body past `MaxBody` as it arrives), and a local agent
    writes to loopback in under a second.
  - (b) The array is reserved as bytes arrive — 64 KiB first, then doubling up to the declared length — and a
    buffer is filled before a larger one is asked for, so a stalled upload holds what it sent.
  - (c) The forwarder's wire usage scanner reads the usage of an identity-coded event stream off every byte the
    response pump relays, on a listener whose exchanges the Dispatcher gives the Anthropic parser (by declared
    provider, else host, R25; *amended 2026-10-05:* it ran on every provider's stream, and its incomplete verdict
    counted a malformed gap on an OpenAI Responses frame past its 64 KiB bound) (`message_start`'s `message.usage` and model, each `message_delta`'s usage, one line and
    one frame's data of at most 64 KiB held). It is derive's own reading (`anthropic.StreamUsageScanner`): the
    stream framed as `ParseStream` frames it (a type from the `event:` line when the payload has none, several
    `data:` lines joined, a type spelled with JSON escapes, a last line with no newline, and a line that is not a
    field ending the reading), keys read as written and each counter folded as R29 reads and folds them, so taking the larger of its reading and derive's never charges
    a key derive would not read. It is independent of the capture budget and of `MaxBody`, and records whether a
    `message_delta` carried usage. Its usage completes derive's when the record's copy was cut or
    yielded none, and replaces derive's `max_tokens` bound (R29), or derive's verdict of no bound, when it read a
    `message_delta` — also when the record's copy was whole but derive stopped short of it (derive stops reading a
    stream at its first line it cannot parse; the scanner reads every `message_delta` line). The exchange is then
    metered. A scanner that saw only `message_start` does not clear an exchange derive reported unmetered for want
    of a `max_tokens`, and its placeholder output is never charged as a count: where derive read no final count
    and no bound of its own, the exchange is charged the request's `max_tokens` as a bound (read as (d) reads it),
    or is unmetered when there is none.
  - (d) A request body larger than capture kept is read for its top-level `max_tokens` as the upstream leg takes it
    (a tee on the uncaptured remainder), by the shared scanner in derive/anthropic, so a cut stream whose request
    stated one is bounded (R29) rather than unmetered.
  - (e) A successful answer from which no usage was read either way is reported unmetered to the run
    (limits-check-doctor-cli.md R1 (a), (c)), which ends a run with a token or cost budget. The scanner reads only
    an identity-coded stream, so a successful answer whose record copy was cut by size (the capture budget or the
    decode limit, `gap why=size-cap`) and from which the scanner read no usage is reported unmetered, the uprobe
    path's `SizeCut` rule (limits-check-doctor-cli.md R1 (d)).
  - (f) A round trip that fails before any response byte is reported unmetered, as is an exchange Close finds in
    flight (ADR 0037, limits-check-doctor-cli.md R1 (e)); only a failed dial, which sent nothing, is exempt (limits-check-doctor-cli.md R1 (o)).

**derive/anthropic (E26)**
- **R28.** Request parsing extracts `model`, `messages` (kept `json.RawMessage` per item, the exact bytes the ledger
  stores by hash), `tools`, `system`, `stream`; empty `model` is `ErrSchema`. The dedup itself does not go through
  derive: the ledger's blob stage finds the same items in the request body it stores (record-ledger.md R11, which says
  what "by hash" holds to: an item over 4 KiB once per run, a smaller one once per group of neighbours it is stored
  in), so it holds on a run whose provider no parser claims.
- **R29.** Non-streaming: `usage` read directly. Streaming: `message_start.message.usage` seeds input/cache,
  `content_block_*` build `Content` (a `tool_use`'s `input` accumulates from `input_json_delta` fragments, parsed
  once at `content_block_stop`), `message_delta.usage` folds each count into the running total as the larger of the values reported (the API's counts are cumulative), `message_stop`
  closes it. Anything matching neither shape is `decision: unparsed`: `why=schema` for structural problems
  (including a body truncated by R6/R14's caps and a mid-stream close, since `spec/record/v1/README.md`'s closed
  `why` set has no dedicated value for either — `schema` is the closest of the three), `why=encoding` when decoded
  bytes still fail UTF-8/JSON after R15, `why=h2` only as a defensive fallback (should not occur given R17).
  The request path is compared after normalization (percent-decoding, collapsed slashes, dot segments):
  `/v1/%6Dessages`, `//v1/messages` and `/x/../v1/messages` reach the Messages API and are parsed as it. An event
  type or a delta type this parser does not know (`citations_delta`, and what the API adds later) is ignored, as
  the API asks, rather than voiding the stream.

  *Keys are read as the API writes them.* A response body and every stream event are decoded with
  `encoding/json/v2`, whose names match case-sensitively: `type`, `model`, `usage` and the counters inside it are
  read only from the key spelled exactly so, and another spelling is an unknown member, ignored as the API ignores
  it. Repeated known accounting/routing names, including escaped spellings, are ambiguous and fail closed;
  unrelated extension and tool-input names and invalid UTF-8 remain lenient, so a tool input cannot void the
  usage beside it. v1's
  case-insensitive, last-match-wins reading would let `{"usage":…,"USAGE":…}` choose its own charge. It is one
  decode pass with a bounded check of the known accounting fields. The same holds for the OpenAI-compatible endpoint's `usage` and `model`, and for the forwarder's
  wire usage scanner, which is the same decode. Where the request's keys set a charge, the reading fails closed: `max_tokens` is read by the shared
  scanner in derive/anthropic — the exact-case key of the top-level object, a positive integer only, the object
  must end; a case variant or a second exact key is no `max_tokens` — the same scanner capture uses on a body it
  kept only as a prefix, so the two readings cannot differ; the `model`, read only where it prices the exchange (a
  response naming none), is the exact key with any repeated name refused, and a request with none is an unparsed
  decision. A compatible-chat usage requires explicit non-null `prompt_tokens` and `completion_tokens`;
  malformed accounting in a stream cannot be repaired by a later usage chunk. Its stream preserves the
  response model and id across usage-only chunks, rejects conflicting identities or a second usage report,
  and accepts only JSON objects and the exact `[DONE]` terminator as nonempty data payloads. Both stream
  formats use the shared SSE framing, including BOM, CR/LF/CRLF and multiline data fields.

  *Usage.* The usage object's `cache_creation.ephemeral_1h_input_tokens` and `server_tool_use` are read too, whole
  or streamed (each folded as the larger of the values reported), and by the forwarder's wire usage scanner,
  which is derive's own code. They become `usage.cache_write_1h`
  and `usage.server_tool`; `cache_write` is raised to the sum of the two lifetimes when the response reported
  less. `server_tool_use` keeps each member whose value is a nonzero integer, at most 8 names in name order, and
  sums the rest, and any name that is not a short lower-case identifier, under `other_requests`, so the reply
  cannot grow the record a key per name and no count is lost. Two reports (a stream's `message_start` and
  `message_delta`) merge name by name as the larger of the two, `other_requests` too, and the names past the first 8
  of the merge, in name order, are then summed under `other_requests`: a name one report kept and the other folded
  may be counted twice, never dropped; a negative count in either object is a schema error,
  as in the other counters. A numeric server-tool value outside the representable integer range is a schema
  error, never silently dropped as non-count metadata. A cost budget prices both (limits-check-doctor-cli.md R2). The billing modifiers
  `speed`, `service_tier` and `inference_geo` (any value but `standard`, `standard` and `global`/`not_available`)
  and `iterations` (anything but one `message` entry; compaction and refusal-fallback attempts are billed on top of
  the top-level counts, possibly at another model's rates) set `usage.modified`, a flag folded as an OR: a value
  that cannot be read is a modifier. The price table has no rate for it (limits-check-doctor-cli.md R2).
  Extra or unreadable iterations also make accounting incomplete and the exchange unmetered: no multiplier
  bounds the attempts omitted from the counters. Known usage remains visible, but a token or cost budget fails
  closed. Absent, null, empty and one unambiguous exact-case `type: message` iteration stays metered.

  *A stream that fails or is cut.* A stream that fails after `message_start` (an `error` event, a cap or a close
  that cut it, a malformed frame, a `tool_use` input that is not valid JSON, which fine-grained tool streaming
  allows) keeps what it already reported, its model, id and usage above all, and records the failure as one
  `decision: unparsed` (`why=schema`) beside it; the frames after the failure are still read, for a
  `message_delta`'s usage only, so a stream whose wire carried the real count is charged it (limits-check-doctor-cli.md R1 (m)). The output
  count of a stream is carried only by its final `message_delta`; `message_start`'s is a placeholder. A `message_delta` whose usage names no `output_tokens` (`"usage":{}`) carries no
  count and is not the final usage. A 2xx stream
  with no `message_delta` carrying usage (cut after `message_start` by the client, the upstream, a cap or an
  `error` event) is charged the request's `max_tokens` as output (or the reported output if larger), and its usage
  carries `output_bound: true` (ADR 0036, limits-check-doctor-cli.md R1 (m)). The `max_tokens` is read from the whole request body, or, when
  capture kept the body only as a prefix, by the shared scanner off every byte of it on either capture path (R10,
  R27 (d)); that bound is applied only to an Anthropic 2xx stream derive left unmetered with its usage. A request
  whose `max_tokens` is unknown (absent, not a positive integer, repeated or in another case, unreadable) leaves no
  bound, and the exchange is `Facts.Unmetered` (limits-check-doctor-cli.md R1 (c)). So is a request that declares a
  server-side tool (a `tools[]` entry whose `type` is not `custom`, a `tools` key this reading cannot follow, or a
  top-level `mcp_servers` key in any case, the MCP connector):
  the tool's request counts and the input its loop grows are carried only by the `message_delta` a cut stream lost,
  so `max_tokens` bounds nothing there (ADR 0036 note 2026-09-30). An `error` event before `message_start` (an
  `overloaded_error` on a `200`) is an error answer: no message began and nothing was spent, so it parses to zero
  usage, no bound and no decision (limits-check-doctor-cli.md R1 (k)); an `error` event after `message_start` keeps the bound. A request that
  got no response bytes at all is not a cut stream: it is unmetered by ADR 0037 (limits-check-doctor-cli.md R1 (e)).
- **R30.** One `decision` per `tool_use` block, in order: `tool_use_id`, `tool`(name), `input_hash`(sha256 of the
  raw `input` bytes), `text: false`. Plain `text` blocks produce no `decision` (the full body is already a blob).
- **R31.** `input_hash` is over exact wire bytes, no re-marshaling/key-sorting — deliberate byte identity so
  `limits.repeats` only matches true repeats.
- **R32.** `parser_version` is stamped on every `ssl_response` this parser produces, never omitted.

**Steps by time — E28a**
- **R33.** A request to a declared `models[]` host that is not side traffic (`side`, R40) opens step N+1 for the requesting thread if none is already
  open; stays open until that thread's response arrives, its process exits, the run ends, or the capture source gives up on the request (`Steps.Abandon` by the pair token): for `uprobe` a lost or closed connection or a response given up waiting for; for `forwarder` an exchange derived with no response (the upstream leg failed or dropped the connection, the client left, or `Close` claimed it), on a silent path too, after which the thread is not in flight and its next request opens a new step. A `retry_of` request extends the
  original step rather than opening a new one. A forwarder request (no `tid`) on a thread whose step is still open, and not a retry, follows a turn that never got an `ssl_response` (the forwarder frees a lane only after its exchange is recorded): it opens step N+1. Hosts are compared in one spelling, `agent.CanonicalHost` (lower
  case, no port, an IPv6 literal without brackets, no trailing dot, an IP literal in one spelling of its address:
  `0:0::1` as `::1`, an IPv4-mapped IPv6 address as its IPv4 address), so a raw `Host: api.anthropic.com:443` opens a
  step; the same function is used where the `uprobe` source matches a host to a `models[]` entry (`provider`,
  `endpoint`, both sides normalized), where derive's dispatcher looks a host up among its parsers', and where the
  `models[]` guard names an endpoint. The host an absolute-form request reaches is its URL's (R10). An `ssl_response` closes
  its thread's model step only when it answers a model request, known by the in-process pair token its request
  carried, so the answer to a non-model request on the same thread (an event loop) leaves the model step open.
- **R34.** An action event during exactly one thread's open step: `{method: time, confidence: likely}`. Zero open
  steps: `{method: time, confidence: unattributed}`. More than one open step (concurrent tool-use fan-out):
  `{method: time, confidence: unattributed}` — never guessed. This is the fallback of R42, which reads the
  replies' tool windows and the threads' tids first.
  A `decision` takes its own thread's step, and time decides only when that thread has none. The forwarder's lines
  carry the pid of the run's process that holds the connection (R19a's admission resolves it) and `tid` 0, since a
  socket belongs to a process and not to the thread that wrote on it (stamped with the launcher's pid and tid, every
  forwarder turn of a run would be one thread, and at tier 1 the forwarder is the only capture). In place of the
  tid, each turn takes a lane among its process's turns in flight (the lowest free, from 1, shared by the run's
  listeners, a retry taking its original's lane when free), carried in process only (`record.Event.Lane`). The
  thread a turn is keyed by is `t<pid>` for lane 1 and `t<pid>.<lane>` after it. Two turns in flight at once are
  two threads, so an action between them is `unattributed`; sequential turns take lane 1 whichever connection they
  come on, so a single-threaded agent stays one thread even when its SDK's pool opens a new connection for a turn
  (a thread per connection would make every action between such turns `unattributed`).
- **R35.** Attribution by time (`Steps.byTime`) never lowers a confidence a richer method (`tool_id`/`tid`) already set,
  whether a producer set it or R42's rule did; R42 runs ahead of time and time decides only what R42 leaves.
- **R36.** Step numbers are one shared, per-run counter across all threads (not per-thread), matching
  `record.Attribution.Step int`, so cross-thread step comparison in `status` is meaningful. `derive.Steps` keeps
  the in-flight threads apart and counts the threads that have a step, which is all R34 reads, so an action costs
  the same at any thread count (`BenchmarkStepsThreads`; a full copy per action cost 3 ms an event at 10,000
  threads on the pipeline's one goroutine); the tests' `AttributeByTime` (`export_test.go`) stays the rule over a full snapshot, and a
  differential test holds the stage to it over random streams. The kernel record's process exits (`ProcessHook.OnExit`,
  tier 2 and 3; no event carries them) retire the exited process's threads: a retired thread still counts as one
  with a step, a thread whose response is outstanding is no longer in flight (its process is gone, and a response that never
  comes would otherwise hold every later action's attribution), and an event of a retired
  thread that was still queued behind the exit brings it back as it was, so retiring changes no attribution. The
  last 4,096 retired threads are remembered; a tid that comes back after more retirements than that is folded as a
  new thread, which changes no action's attribution (by then more than one thread has had a step) but can change
  that thread's own `decision` step, and, when its first request is a retry, open a step the old stage would have
  continued. A reused tid makes neither before a request of its own. At tier 1 nothing reports an exit; the
  forwarder's events carry the peer's pid and a lane (R34), so its threads are never retired there.

**Gap taxonomy**
- **R37.** One run keeps at most 256 distinct (`binary`, `why`) pairs, since the agent names its binaries (a test loop execs a fresh path each time); past that a gap is counted into one line per `why` with no `binary`, and the total count is kept. `gap what=capture` is closed: `no-openssl` (R4 found nothing), `static-tls-no-symbols` (a candidate
  exists but exports none of R1–R3's symbols: Bun/BoringSSL, rustls), `h2` (R17), `malformed` (R18: framing that
  could not be followed, and one count per exchange passed over because capture missed its request's start),
  `ring-buffer-drop` (kernel loss, and a chunk of the run left on the ring past `Stop`'s drain budget, edge case
  #28; `count` set), `size-cap` (R5/R6/R13), `emit-queue-full` (the forwarder's emit queue was full and events were dropped, §3; `count` set) — what a running mechanism failed to see —
  and two that §4's `Select` writes once, right after `run_start`, for a mechanism that never ran, naming it in
  `binary` and carrying no `count` (a mechanism that never ran lost no event): `no-models` (capture is on but the contract declares no `models[]` entry, so the forwarder has nothing
  to bind a listener for, R19; `binary=forwarder`) and `mechanism-unavailable` (this binary does not carry the
  mechanism, or its constructor failed for this run); neither is `no-openssl`, which is R4's finding about a
  process's libraries and is false of a forwarder and of a uprobe source that never started. `gap.why` is an
  unenumerated string in `spec/record/v1`, so the two values are new values of an existing field, not a schema
  change. R4 settles the two per-process values: `static-tls-no-symbols` is every process whose readable
  candidates, its own executable included, export
  none of R1–R3, which without E71 includes a process with no TLS at all; `no-openssl` is a discovery that could
  read nothing. `mechanism-unavailable` also covers a uprobe source that found no row for its own run in the run set,
  or no capture ring at its slot, when it started (§4, edge case #26), and a forwarder listener whose accept loop
  failed mid-run: logged when it fails, and one gap at run end with `binary` naming the listener's upstream host,
  no `count`, since the agent's calls to that endpoint are refused from then on rather than passed uncaptured. A symbol is attached only where its address lies in the bytes the file holds for
  an executable `PT_LOAD` segment: below the segment's `Filesz` as well as its `Memsz`, and at a file offset
  before the file's end, taken from the descriptor the headers were read through. An address in the zero-filled
  tail past `Filesz` has no byte of the file behind it, and the file offset computed for it named whatever
  followed the segment in the file. debug/elf never checks a segment's `Off`+`Filesz` against the file's length,
  so a segment can also claim bytes past the end, where the kernel refuses the probe (`EINVAL`). A candidate
  that exports an R1–R3 function at either kind of address is refused whole (`ErrSymbolOutsideFile`, not soft):
  unless another of its candidates attaches, the process is `no-openssl`, its detail naming the symbol, as for an
  attach the host refused, and not `static-tls-no-symbols`, since the candidate does export R1–R3. A function a
  linker places has bytes in the file, so this refuses a malformed or crafted file. The candidate is refused
  whole rather than attached without the symbol: a candidate that kept `SSL_write` and lost its reads would capture
  requests and never their responses with no `gap`, a shortfall I4 does not list; refused whole, the process's
  shortfall is its `gap`. The refusal is a read failure and, like the others, is not kept
  as the binary's one attempt (§7), so each process that maps the file reads it again and is counted in the
  `gap`. An address no executable segment maps at all is passed over (`FuzzReadBinary` found the tail
  case, `elf.go` `fileOffset`).
- **R38.** A forwarder bypass is **not** a capture gap — it is `net verdict=refused reason=net-not-allowed` from
  `enforce`: the supervisor guards known model endpoints even if `net.allow` names them, and a named model's
  port additionally refuses unknown destinations without an explicit allowance (supervisor R7). The synthetic
  forwarder listener grant stays reachable. Capture only reports what it failed to see.

- **R40. Labeling side traffic.** Traffic is labeled by destination first: a request to a `models[]`
  endpoint is an `ssl_request`/`ssl_response` pair naming that entry's provider (the forwarder's `endpoint`, or the
  uprobe connection's peer), and every connection anywhere else is a `net` event naming its host and port, allowed
  or refused by `net.allow` (a telemetry host a harness calls on the side is one of these, and
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` keeps Claude Code from making it). On a model host it is then
  labeled by shape: `derive/anthropic` classifies the path (`paths.go`): a model turn (`/v1/messages`,
  `/v1/chat/completions`) yields decisions and usage, an endpoint that spends nothing (model listing, token counting,
  a batch's status, the Files API) yields none, a batch creation is one unparsed, unmetered decision, and any other
  path is an unparsed body with spend unknown (R25). *Amended 2026-10-20:* the shape is now written as a
  label. An `ssl_request` on a parser's host whose path the parser calls silent (`derive.SilentPaths`: a harness's
  telemetry and account calls such as `/api/event_logging/batch`, token counting, a model listing, a health check)
  carries `side: true`; derive reads it off the request alone as it is captured (`Dispatcher.ReadRequest`, stamped by
  the forwarder before its round trip and by the uprobe source when the request is assembled), and the attribute
  stage takes it as no model request: it opens no step (R33), its answer ends no wait, and it closes no tool window
  (R42). Before, such a request opened a step like a turn, so a telemetry batch beside a turn made two threads in
  flight and every action between them unattributed. So the four kinds of traffic read off the record: model
  traffic is an `ssl_request` with no `side`, MCP traffic an `mcp` line (R41) or a `net` line under `mcp[<name>]`,
  tool traffic a `net` line attributed to a reply (R42, `method: tool_id`), and side traffic an `ssl_request` with
  `side: true`.
  Condition: a logging host other than a model host — a harness's telemetry
  endpoint it reaches directly — is a `net` line naming its host and port and is not labelled `side`, because the
  contract names no logging hosts and a label read off the host name would be a guess. Its line says what it was
  (the host, allowed or refused by `net.allow`), and its attribution says whether a reply's tool window covered it;
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` keeps Claude Code from making such connections at all. Labelling them
  needs a contract field naming the run's logging hosts (agent-contract), which this rule does not add.

- **R42. Attribution by the model's reply (E28, E29, E30).** *Added 2026-10-20.* The
  attribute stage (`derive.Steps`) ties an action to the reply that asked for it by the reply's `tool_use` id, and
  falls back to the thread's own step by its tid and then to time (R34), recording which rule decided in
  `attribution.method`. Nothing is judged by a model and nothing is guessed: each rule reads only what the wire and
  the kernel record carried.
  - *Tool windows (E29).* A `decision` line with a `tool_use_id` (R30) opens that reply's tool window, on the
    decision's thread, in the step it was numbered into. A model request closes the windows whose results it reports:
    derive reads, off the request alone as it is captured, the `tool_use_id` of every `tool_result` block in the
    request's last message (`anthropic.RequestToolResults`; the API requires a reply's results in the user message
    that follows it, so the last message holds the results of the previous reply, and earlier ones, which every
    request repeats, are not read again) and the capture source writes them on the `ssl_request` as `tool_results`
    (an empty list when it reported none). A request derive could not read — no parser reads its path, its body was
    cut (R6, R14) or stayed coded, a last message or a block of it that is not an object, a key the reading uses
    (`messages`; the last message's `role` and `content`; a block's `type` and `tool_use_id`) written twice or in
    another case, Unicode folds included (servers keep the first, the last, or fold the case), a `tool_result` without
    a string id, more than 256 results or an id longer than 256 bytes — carries no `tool_results`, and every window
    of the run becomes one of unknown state: the request may have reported any of them, not only its own thread's (the
    next turn's request can come on another forwarder lane, since a lane is freed only once its exchange is recorded,
    or from another thread of the agent, and a conversation can go on in another process), or none of them (it can be
    a concurrent conversation's, a subagent's on another lane or thread). Left open on a guess, a window would claim
    every later action, since no later request reports its result again; closed on a guess, its tool could still run
    while a window that opened later looked like the only one, and the tool's actions would be named after that
    window's reply. A window of unknown state is no candidate, and while any is, rule (2) names no window and rule (1)
    names none of its thread's; a read request that reports its result ends it. A window a read request does not
    report stays open: a harness's side call or a subagent's turn on the same thread leaves the tool running. A
    decision whose id a model request has already reported opens no window: a source writes a reply's decisions once
    it has read the reply's last byte, which the agent may have read first, so the next turn's request line (on another
    forwarder lane) can reach the stage before them, and the window would stay open for good with its result reported.
    The stage remembers the last 4,096 ids reported while no window of them was open. For the same reason a decision
    folded after a request derive could not read, numbered into a step opened before that request, opens its window
    of unknown state: the request may have reported it, or not. A decision takes its thread's step (R34), and a step's
    request line reaches the stage before the step's reply exists, so a reply the unread request could report is in
    such a step, and the unread request's own reply, in the step it opened, opens its windows; the reply of a retry or
    of a request that joined a step already open is in a step opened before it, and its windows are of unknown state.
    That holds of a decision that follows its own reply's response. A source writes a reply's decisions right after
    its `ssl_response`, on its thread, but the forwarder writes each declared host's lines through a queue of its own
    while a process's turns to two hosts share its lanes (R34), so another host's request on the same lane can come
    between the two, and a queue can drop the response line: a decision folded after a later model request of its own
    thread, or with no response of the thread since its latest one, takes that thread's step, which is not known to be
    its reply's, and its window is of unknown state. Windows are not closed at a process's exit (a tool's children may
    outlive it), so retiring a thread (R36) changes no attribution. At most 4,096 windows are open or of unknown state
    at once; past that the stage reads no window for the rest of the run, since one it did not keep could make another
    look like the only one.
  - *The rule, first match wins, after R35.* (1) **tid (E30, in-process tools)**: an action whose `tid` names a
    thread the uprobe source named by its tid (its latest model request came with `source: ssl` and a tid), while
    that thread has a step, is that thread's own: with exactly one of its windows open, none of unknown state, and no
    model request of its own in flight it is that reply's, `{method: tool_id, tool_use_id, step, thread, likely}`; otherwise it is the
    thread's current step, `{method: tid, step, thread, likely}`. A step stays its thread's until the thread's next
    model request (R33 as built), not only while its reply is awaited, so this answer outlives the step's reply: an
    action the thread makes after its last reply (a transcript write, exit-time cleanup) is its last step's, `likely`,
    as long as the thread is remembered (R36), as time puts a lone thread's after-reply actions in its last step. A
    forwarder thread is named after its process and a lane (R34), so no action's tid says anything about it, and this
    rule never applies to it. (2) **the run's one window**: an action of any other thread, while exactly one window
    is open in the whole run, none is of unknown state, and no model request is in flight anywhere, is that reply's,
    `method: tool_id` — the one
    tool the model asked for and has not been told the result of; a tool's child processes and a forwarder run's
    actions are attributed here. (3) **time**: R34.
  - *Late actions.* The pipeline folds lines in the order they were queued, and the kernel's recorder (tiers cgroup
    and bpflsm) can queue a tool's action after the model traffic of a later turn: the KVM run of
    `TestRootRetrieverRunTiesActionsToReplies` saw the summary write reach the stage after step 2's reply, and by the
    state at arrival it was named step 2's reply (time alone had put it in step 2 as well). So the stage keeps the last
    64 transitions (a model request, a model answer, a reply's window, and a wait an exit or an abandoned request
    ended), each with the monotonic time it took effect, what rules (2) and (3) answered from then on, and, for every
    thread it changed, rule (1)'s answer for that thread just before. An action whose own `mono_ns` is before the
    latest transition is answered as the state was after the last transition at or before its time: rule (1) by its
    thread's answer then (the one the first later transition that changed the thread kept, or its answer now when none
    did), and otherwise that transition's rules (2) and (3). A transition keeps rule (1)'s earlier answer for at most 64
    threads (transitions folded into one epoch, at one time, share the 64): one that changed more (an exit of a process
    with more model threads, a request reporting or closing more threads' windows, the windows lost while more threads
    held one) keeps the first 64 in the order it changes them and is taken as having changed every other thread's. That
    order is the exit's threads as they first asked from the process, a request's results in wire order, retirements
    oldest first, and, where one change reaches every thread holding a window (an unread request, the windows lost),
    the holders by thread name: they have no order of their own, and which were kept must not depend on the order a
    map is walked in, so a replay of one ledger gives every late action the same answer. It is unattributed when it is
    older than all 64 transitions; when a transition after it changed more threads' answers than it kept, its thread's
    was not among those kept, and a model request of the run had named some thread by its tid by then (in a run where
    none had, rule (1) applied to no thread, and rules (2) and (3) answer it); and when it falls in an interval no
    epoch describes: a transition line can
    itself be folded after a later one (a request line is queued when its body has been read, so concurrent turns'
    lines can swap), and it then takes effect at the latest transition's time, so the state between its own time and
    that one is not known. A change with no time of its own (an exit, which the recorder reports beside the queue; an
    abandoned request; a model line without `mono_ns`, as in an old ledger) takes effect at the latest transition's
    time, the order the stage folds it in, so a late action from then on is answered as one folded in order is. But for
    the time such a change is given, a late action is never answered by a state it did not happen in, and never by
    another thread's reply in place of its own thread's answer. A line with no `mono_ns` of its own at this stage (the supervisor's, which is synchronous with the agent)
    is taken in arrival order.
  - *Confidence.* Every answer is `likely`. Each rule reads where and when an action happened against what the wire
    said, and none can see what caused it: a harness's own work during a tool's window (its transcript, its
    statusline) is attributed to that tool as time attributes it to the step. `exact` is never written. Two windows
    open at once (a reply with two `tool_use` blocks, two threads' tools) are two candidates and time decides,
    never one of them.
  - *Record.* `attribution.tool_use_id` (written between `step` and `confidence`) names the reply's `tool_use`,
    exactly under `method: tool_id`; `ssl_request.side` and `ssl_request.tool_results` are the request's reading.
    All three are optional within v1, at `record_minor` 29 (`record.MinorAttribution`). A ledger below 29 replays
    with no `tool_results`, so each model request leaves every window open at it of unknown state, which no later
    request reports: rule (2) names no reply after the first model request that found a window open, and rule (1)
    none of a thread with a window of unknown state; time and tid answer instead (`TestFixtureAttributesEveryAction`).
  - *Not built, disclosed.* E30's match of an exec'd child to one of several open windows by its argv or cwd is not
    built: a child process (no tid of a model thread) is attributed only by rule (2), so a reply with parallel tool
    calls leaves its children to time. A forwarder run whose turns overlap in time (a harness's concurrent side calls
    or subagents on lanes) reaches rule (2) only between turns, when nothing is in flight. A source writes a reply's
    `ssl_response` and decisions once it has read the reply's last byte, which the agent may have read first, so an
    action the agent makes at once on reading a reply can reach the stage before the reply's window opens: it is
    attributed by time to the same step (its turn is still in flight), never to another reply.
  - *Decision and rejected options.* Chosen: windows closed by the request's reported results, the request read as
    it is captured (before the forwarder's round trip, and on the uprobe source when the request is assembled), and
    the reading written on the `ssl_request` so a ledger says why an action was tied to a reply; and a window whose
    result an unread request may or may not have reported, or whose decision came out of its reply's order, kept as
    one of unknown state, which keeps rules (1) and (2) from naming another window as the only one until a read
    request reports it: it costs detail where requests go unread, and never names a running tool's actions after
    another reply. Rejected: closing a
    thread's windows at its next model request whatever it reports (a side call or a subagent turn on the thread
    would close a tool still running, and its actions would go to the side call's step); closing only the windows of
    a request's own thread (as built earlier) or of its own process when the request was not read
    (the next turn can come on another lane, from another thread or, in a resumed session or a helper process making
    the calls, from another process, and a window it reported then stayed open for good and named every later action
    after its reply); keeping a window a late decision opens after an unread request (it may have been reported, with
    the same effect); closing every window of the run at an unread request, and dropping a late decision's window
    with no record of it (as built until: the request can be another conversation's, and the tool
    it did not report, still running, had its actions named after a window that opened later and looked like the
    only one); numbering a decision folded after a later model request of its thread into the step its thread was in
    at its latest response (a queue that drops a response line would number the decisions after it into the step
    before, and the stage cannot tell the two orders apart, so the decision keeps its thread's step, R34, and its
    window is of unknown state); numbering decisions by the in-process pair token of their exchange (a ledger carries
    no pair, so a replay could not recompute which windows opened); reading the request in the
    attribute stage from the `ssl_request`'s inline body (the body is there only under `record: full`, escaped as a
    string, and on the pipeline's one goroutine for every turn); keeping the reading in process only (the record
    could not say why an action was tied to a reply, and a ledger replay could not recompute it); matching tool input
    against argv (a heuristic over each tool's own schema, left to E30's later half); and `exact` for any of these
    (none of them observes causation).
  - *Tests.* `TestToolWindowAttributesActionsToTheReply`, `TestToolWindowsNeverGuess`,
    `TestToolWindowOutlivesAnotherConversation`, `TestUnreadRequestLeavesEveryWindowUnknown`,
    `TestWindowOfUnknownStateBlocksTheOnlyOne`, `TestDecisionAfterItsThreadsNextRequest`, `TestSideTrafficOpensNoStep`, `TestTIDAttributesAThreadsOwnActions`, `TestForwarderLanesAreNoTIDs`,
    `TestToolWindowsBound`, `TestLateActionIsPlacedWhenItHappened`, `TestLateActionOfAThreadIsItsOwn`,
    `TestTurnFoldedLateLeavesItsIntervalUnattributed`, `TestLateActionSeesWhatEndedAWait`,
    `TestResultReportedBeforeItsWindowOpens`, `TestUnopenedResultsBound`, `TestLateActionPastAnExitOfManyThreads`;
    past the bounds of what the stage remembers, `TestForgottenThreadKeepsItsLateAnswer`,
    `TestLostWindowsKeepALateActionsOwnAnswer`, `TestTransitionPastTheTouchedBound`,
    `TestMergedEpochPastTheTouchedBound`, `TestWindowHoldersPastTheTouchedBound` and `TestEpochPastTheBoundInATIDRun`;
    `TestStepsMatchesTheReference` holds the incremental stage to a full-scan reference over random streams with
    monotonic times, missing and late ones included, that reach all three methods in order and late; `TestRequestToolResults`, `FuzzRequestToolResults`,
    `TestReadRequestLabelsWhatARequestSaysAlone`; both sources' `TestRequestLineCarriesWhatDeriveReadOffIt`; and
    `TestRetrieverRunTiesEachActionToItsReply`, a retriever run replayed from its captured traffic
    (`internal/runtime/derive/testdata/retriever-5.2/traffic.jsonl`) through the Dispatcher and the stage, as the
    uprobe source and as the forwarder record it: the warehouse connection, the MCP `db_query` call, the tool's
    `gzip` and the summary write are step 1's reply `toolu_8812`; the approved queue connection and the refused
    `~/.netrc` write are step 2's `toolu_8813`; the telemetry batch is `side` and no step. The same run through the
    real CLI (`test/workloads/retriever-agent` against a scripted model, capture forwarder):
    `TestIntegrationRetrieverRunTiesActionsToReplies` at tier landlock and `TestRootRetrieverRunTiesActionsToReplies`
    at tiers cgroup and bpflsm, where the kernel's recorder writes the tools' actions; every warehouse and queue
    connect and the summary and refused `.netrc` writes name their reply in its step, and the three requests report
    `[]`, `[toolu_8812]` and `[toolu_8813]`.

- **R41. MCP tool calls (E31).** *Added 2026-10-19.* `internal/runtime/derive/mcp` reads
  the JSON-RPC 2.0 messages an MCP client sends its server, on both transports the protocol defines: stdio
  (newline-delimited, `mcp.Stdio`, at most 8 MiB held of one unfinished line, a longer one skipped and counted)
  and HTTP (one message or a batch per POST body, `mcp.ReadHTTPRequest`, which serves the streamable transport and
  the older HTTP+SSE one alike). It reads only what every server's parser reads alike, and counts the rest as
  unreadable, never guessed at: a message that is not JSON-RPC 2.0; one whose keys the reader uses (`jsonrpc`,
  `id`, `method`, `params`, `result`, `error`, and `name`, `arguments` in a call's `params`) servers could read
  differently — a key spelled in another case or by a Unicode fold (Go's `encoding/json` folds it onto the field,
  a JavaScript or Python server does not), or one of them twice (most parsers keep the last, serde refuses it); an
  `initialize` or `tools/call` with no `id` (a notification, which the SDKs drop unanswered for these methods); and
  a call whose `name` is not a non-empty string. So a call it names is the call any server reads, and one it cannot
  name with certainty is an unparsed marker, never a different tool or nothing (`TestReadAsAServerReads`,
  `FuzzRead`, which checks every call against `encoding/json`'s reading). Only the client's direction is read: a tool call is
  the client's request, and an answer says nothing about whether the call was made.
  - *Which exchanges.* A declared HTTP server's (agent-contract R16a): `derive.WithMCP` gives the dispatcher the
    contract's `mcp[].url`s, and an exchange whose host and port (`Meta.Port`; the uprobe source reads it off the
    `Host` header, 443 when it names none) are one URL's, and which no `models[]` provider claimed, is that
    server's. Dispatch is by destination, never by body (R25), and the destination is the one the request names:
    the `Host` header the client wrote inside the TLS session, not the socket's peer, which an SSL call does not
    carry. A governed agent that writes its own HTTP chooses it, so a call to the declared server under another
    `Host` (its address, an alias) is an exchange no parser reads (one `decision: unparsed`, R29) and no `mcp`
    line, and a `tools/call` body sent to another TLS peer with the server's `Host` is an `mcp` line of that
    server: the line says a call was sent addressed to the server, and the connection it went over is the `net`
    line its connect wrote. The condition that closes it is a capture record that carries the socket's peer
    (`internal/runtime/capture/uprobe`, `bpf/uprobe_ssl.bpf.c`), which the connect's kernel or supervisor line could
    then be matched by. The uprobe source is the reader, since it sees every TLS peer of the run; the forwarder
    serves model endpoints only.
  - *What it derives.* One `mcp` line per client `initialize` (the connection, transport `http`) and per
    `tools/call` (with `tool`, at most 256 bytes), in wire order, read when the request is captured
    (`derive.Dispatcher.HandleRequest`) and written right after its `ssl_request`, with the request's own time
    and the thread that wrote it; the `ssl_response`, when one comes, carries `parser_version: mcp/1` and derives
    nothing more. So a call is numbered into the step it was sent in, however long the tool ran or streamed, and
    a call is recorded whether or not its answer ever comes: the source's `Stop`, the connection's end and the
    pending bound give a request up without deriving it, which is what hid one before. `rule: mcp[<name>]`, `verdict: observed` (no mechanism of the run decided the message; it was read
    after the connection a rule admitted), `authority: rule`, and the attribution the attribute stage gives every
    action, which numbers it into the step it fell in by time (E28a): `mcp call db_query, step 1`. A body
    nothing can read, or an unreadable batch member, is one `decision: unparsed` beside the lines (R29), `why:
    encoding` when capture could not undo its `Content-Encoding`; a request R11's pipelining depth refused is not
    decoded, so it is read as a cut body, one such decision. A panic in the reader is recovered in the Dispatcher
    as a parser's is (the failure table below). `Dispatcher.Handle`, given such an exchange whole, derives the
    same lines from its request, and the gap every unanswered exchange derives when it is given no response; the
    uprobe source does not call it for one it read already. Nothing is unmetered.
  - *Producers.* `run_start.parsers["mcp"]` is the `+`-joined list of the run's MCP producers: `exec` (the
    supervisor's exec path records a stdio server's start) and `mcp/1` (this reader, when the uprobe source is the
    run's capture); `record: off` names neither. drift reads an idle server as unused only when a producer of its
    transport is named (limits-check-doctor-cli R15).
  - *Not covered, disclosed.* A plain `http://` server's exchanges pass no TLS library, and an HTTPS one reached
    through a TLS stack capture does not probe (R1–R4), so neither derives a call: the connection is still a `net`
    line under `mcp[<name>]`. A stdio server's messages pass through pipes no capture source reads: `mcp.Stdio` is
    built and tested on recorded bytes, and reading them in a run waits for provisioning (FEATURES I6d), which
    launches the server and can relay its stdin.

**Changes.**
- 2026-10-20, R42 amended: a model request derive could not read closed every
  window of the run, and a decision folded after it from a step opened before it was dropped with no record, so when
  the request was another conversation's, a tool it never reported, still running, had its actions named after a
  window that opened later and looked like the only one; such windows are now of unknown state, which keep rule (2)
  from naming any window and rule (1) from naming one of their own thread's until a read request reports them. A
  decision folded after a later model request of its own thread (the forwarder's per-host queues can put another
  host's request on the lane between a reply's response and its decisions, and a queue can drop the response line)
  was numbered into the thread's new step, passed an unread request's watermark and opened a window no request would
  report again, which named every later action after its reply; its window is now of unknown state. A ledger below
  `record_minor` 29 names a reply by rule (2) only until the first model request that finds a window open.
- 2026-10-20, R42 amended: an unread request and the windows lost touched every window
  holder in a map's order, so past 64 holders (or past the room an epoch had left when it was folded into another
  transition) which threads kept a late action's answer changed from one replay to the next; the holders are now
  touched in the order of their thread names. Tests pin both ways an epoch past the bound learns that a tid was
  named: the request that makes it, and one folded into it.
- 2026-10-20, R42 amended: a model request derive could not read closed
  only its own thread's windows, so after an unread request on another forwarder lane or from another tid a window
  its turn reported stayed open for good and named every later action after its reply; it now closes every window of
  the run, and a decision folded after it, in a step opened before it, opens none. A transition that changed more than
  64 threads' answers dropped all of them for a late action; it now keeps the first 64 (a merged epoch too, which had
  dropped a later transition's when that one overflowed), and the windows lost keep the answers of the threads that
  held one. A late action carrying a tid past such a transition is unattributed only once a model request had named a
  thread by tid; in a forwarder run rules (2) and (3) answer it. Tests reach the retired-thread, window and per-epoch
  bounds.
- 2026-10-20, R42 amended: a late action kept only rules (2) and (3)'s
  answer of its time, so one of a uprobe-named thread was named another thread's reply; each epoch now keeps rule
  (1)'s earlier answer for the threads it changed. A transition folded after a later one leaves the interval from its
  own time unattributed instead of answering it by a state without it. An exit, an abandoned request and an untimed
  model line now take effect at the latest transition, so a late action after them is answered as one in order. Rule
  (1)'s answer outliving its step's reply is stated. A decision whose id a request already reported (its line folded
  after the next turn's request) opens no window; it used to stay open for good.
- 2026-10-20, R42 amended: `role`, `content` and `type` in another case made a request read
  with no results, which left its thread's windows open; every key the reading uses is now refused in another case or
  twice, as `messages` and `tool_use_id` were, and a last message or block that is not an object is not read.
- 2026-10-20, R42 added and R35, R40 amended: actions are attributed to the reply that asked for
  them by `tool_use` id (tool windows), to their own thread's step by tid, then by time, with the method recorded;
  a model host's side traffic is labelled `side` and opens no step; `ssl_request` carries `side` and `tool_results`
  and `attribution` carries `tool_use_id` (`record_minor` 29). Host-level logging labels stay a recorded condition.
- 2026-10-19, R41 added: MCP `initialize` and `tools/call` derived from a declared HTTP server's captured
  exchanges as `mcp` lines; `run_start.parsers["mcp"]` names producers per transport.
- 2026-10-19, R41 amended: a message whose used keys servers could read differently
  (another case or Unicode fold, a key twice), an id-less `initialize` or `tools/call`, and a null or empty tool
  name are unreadable; the reader compared keys exactly and kept the last, so a Go server could run a tool the
  ledger did not name, and a null name read as a connection.
- 2026-10-19, R41 amended: a declared server's request
  is read when it is captured, stamped with its own time and writing thread, so an unanswered call (pending at
  `Stop`, its connection closed first, past the pending bound) is recorded and a long tool's call falls in the
  step it was sent in (it was stamped with the answer's end, and an unanswered one derived nothing); an R11-refused
  request is unparsed; the MCP reader runs inside the Dispatcher's recover, and both recovers write the panic to
  the own log; the server is identified by the `Host` the client wrote, disclosed with the condition that closes it.
- 2026-09-30, R4: `.symtab` is read for a missing write or read half; a binary still one-sided after both tables
  raises a `no-openssl` gap (and unmetered for a missing read half) instead of capturing in one direction silently.
- 2026-09-30, R14: the assembler row says the budget belongs to the uprobe source alone, as the code has it.
- 2026-09-22, R4: discovery also runs at every libssl-named open; an exec's uncaptured verdict is held;
  the exec record's path names a short-lived process; the launcher's child stage never reaches `OnExec`.
- 2026-09-30, R4: opens attach by libssl name only; a renamed or mangled libssl loaded after the exec
  is a stated residual, not covered.
- 2026-09-22, R9: the cgroup→run map is every run's of the build; userspace keeps its own slot's chunks.
- 2026-09-24, R9 (ADR 0026 (1), (3)): each chunk goes to its run's own capture ring; a run with none gets nothing.
- 2026-10-19, R9: a TLS call that moved bytes stamps a stall-bounded run's `tego_activity` slot in
  every record mode, before the mode or the ring is looked at; nothing else of an off run's call is read or written.
- 2026-10-19, R4 and edge case #2: a `record: off` run with a bounded
  `stall_after` places the shared probes, at `Start` and at an exec, for its activity stamp alone: no ring, no
  capture, no coverage, its gap the mechanism's own. "Under `record: off` nothing is attached" holds without a stall
  budget only.
- 2026-09-22, R15: the `MaxCodings` cap on stacked codings.
- 2026-09-22, R20: `Accept-Encoding` narrowed to codings decoded inside the capture budget.
- 2026-09-22, R37: `no-models` and `mechanism-unavailable` split from `no-openssl`; R4 settles the per-process
  values.
- 2026-09-23, R4 (the acceptance run): pre-attach of the host's libssl; read probes before
  write probes; nothing attaches under `record: off`; the split-client text corrected.
- 2026-09-23, R11: a refused request keeps its place in the FIFO.
- 2026-09-23, R18: a request completing before a headless one's response fails closed.
- 2026-09-23, R37: symbols outside a file's bytes refuse the candidate whole.
- 2026-09-24, R37 (ADR 0026): `mechanism-unavailable` no longer covers another run of the build; it covers a run
  with no capture ring.
- 2026-09-24, R3a: `SSL_free` hooked; a close ends the connection.
- 2026-09-24, R4: `record: off` records `mechanism-unavailable binary=uprobe`.
- 2026-09-24, R6: `skipped` carries a hole's length; `httpstream` steps over holes in a body.
- 2026-09-24, R6: chunk records are reserved at the smallest of three size classes.
- 2026-09-29, R6 (kernel matrix): each size class's read is clamped to the class at the call, behind
  `barrier_var`; the 6.1 and 6.8 verifiers refused the write probes and the read return without it.
- 2026-09-24, R5: an evicted read is a numbered hole with its gap, or a counted drop.
- 2026-09-24, R7: the build-id note is read only at most 1 KiB and inside the file.
- 2026-09-29, R7: a candidate is resolved once; identity, parse and attach share one descriptor.
- 2026-09-24, R7a: pending requests bounded and header-free; a lost connection
  and a size-cut answer are reported unmetered.
- 2026-09-24, R7a, R17 (ADR 0035): h2 to a model or unlearned host and requests
  waiting at a clean close are reported unmetered.
- 2026-09-24, R7a (ADR 0037): one `unanswered` rule on every path that gives a request up.
- 2026-09-24, R8 (ADR 0026 (7), kill test 4): probes shared per library across a build's runs, removed off the
  run's path 2 s after the last run out.
- 2026-09-24, R19a: the peer's inode by sock_diag, the run's processes by `cgroup.procs`, descriptor
  links remembered.
- 2026-09-29, R19a: an orphaned peer socket, inode 0, is refused, not matched to a non-socket fd.
- 2026-09-30, R19a, R27: the descriptor-table search is shared by the connections waiting on it and paced after a miss (`searchPace`), so outsiders cannot spend the launcher's CPU at their own rate.
- 2026-09-24, R27: `IdleTimeout`, the per-listener connection cap, and a stalled response write
  gives its record copy back.
- 2026-09-24, R10: targets read per RFC 9112 §3.2; absolute-form by its URL; an
  unreadable target fails closed.
- 2026-09-24, R10: `CONNECT` is a tunnel; `max_tokens` read off a prefix-only body.
- 2026-09-24, R11: a refused request is not decoded or kept.
- 2026-09-24, R13: heads still arriving are reserved from the byte budget; a line searched once.
- 2026-09-24, R13: an over-cap head is recorded `why=size-cap`, as the code always has (the text said malformed).
- 2026-09-24, R14: one assembler-wide byte budget.
- 2026-09-24, R15: forwarder decode failures `Truncated`; decoded forms
  inside the budget.
- 2026-09-29, R25: "outside `/v1` is silent" holds for `api.anthropic.com` only; a declared host
  keeps the root path and `/api/...` telemetry.
- 2026-09-29, R29: server-tool names past the cap in a merge of two reports are summed, not
  folded by max.
- 2026-09-29, R16: SSE reduction applies to responses only; a request keeps its body.
- 2026-09-30, R15, R11, R3a: a decode failure gaps the body, not the connection; an undecodable SSE body is kept as the wire carried it; `WireBytes` counts the wire, not the kept prefix; a dead SSL* revives on Seq 1 and counts each request passed over; the uprobe budget row counts a decoded form.
- 2026-09-30, R11, R14, R37: a refused request's pair is kept so its abandonment reaches derive; `WireBytes` counts bytes a kernel hole stepped over; a full connection table is one `size-cap` gap per refused key, not per chunk; a cut body's lines carry `truncated` and `wire_size`; a thread split gives up both keys' requests.
- 2026-09-30, R11, edge case 11: a refused connection's later chunks add no unmetered count and no log line (`ErrRefusedAgain`); the pointer table keeps given-up pointers when it starts afresh.
- 2026-09-30, R15: a compressed copy already cut short is one gap, not also a decode's malformed.
- 2026-09-30, R15: a forwarder line whose body is a prefix carries `truncated` and `wire_size`, as R14's cut does.
- 2026-09-30, R19a, R27: a peer is placed as its connection is first read; only the run's
  connections count against the cap and its gap; outsiders are bounded apart and closed after their `403`.
- 2026-09-24, R17: the ALPN half removed; h2 known by its preface (kept as a condition).
- 2026-09-24, R25: the Anthropic parser fails closed on paths; chat completions read;
  batch creation unmetered.
- 2026-09-24, R25: absolute-form and trailing-dot hosts; `/V1` and
  `;params` paths inside `/v1`.
- 2026-09-24, R27 (ADR 0037): request-body
  deadlines and reservation, the wire usage scanner, prefix `max_tokens`, unanswered round trips unmetered.
- 2026-09-24, R29 (ADR 0036): a failed stream keeps its usage; a cut stream is
  charged `max_tokens` or is unmetered; 1-hour cache writes and server-tool counts; keys read case-exactly; an
  early `error` event spends nothing. R29's former letters (l), (m), (n) map to limits-check-doctor-cli.md R1 (c), (m), (k).
- 2026-09-24, R33, R34: hosts normalized; a model step closes only on a model
  answer; forwarder lines carry the peer's pid and a lane.
- 2026-09-24, R10, R27, R29, R33: the forwarder's usage scanner is derive's (keys read as
  written); chat completions read as written; httpstream's body scanner supplied by the wiring; one host
  normalization.
- 2026-09-24, R36: step attribution costs the same at any thread count; exits
  retire threads.
- 2026-09-29, R33, R36: an exit ends the wait of the exiting process's threads, whose
  response never comes, so a dead process's request no longer skews the attribution of later actions.
- 2026-09-24, forwarder: the wire usage scanner frames the stream as `ParseStream` does; its
  placeholder output is bounded by `max_tokens` or unmetered, never charged.
- 2026-09-24, R33: `CanonicalHost` gives an IP literal one spelling.
- 2026-09-24, R40: the side-traffic labeling written as the rule the code follows.
- 2026-09-29, R37, R33: `emit-queue-full` joins the closed why set (nine values); a forwarder request left without a response no longer holds its lane's step open.
- 2026-09-29, R37: a run keeps at most 256 distinct (binary, why) capture gaps; the rest count into one binary-less line per why.
- 2026-09-29, R33: a request the uprobe source gave up on no longer holds its thread's step in flight (`Steps.Abandon`).
- 2026-09-29, R25: a non-POST to `/v1/messages` answered with no body derives nothing instead of an unmetered schema error.
- 2026-09-29, R29: a stream's content blocks and deltas are decoded as written (case-sensitive), like the non-stream response.
- 2026-09-29, R37: a forwarder listener that stops serving mid-run is logged then and recorded as `mechanism-unavailable` naming its upstream host.
- 2026-09-24, R8: the detacher runs in tego's helper cgroup, and a run's start, doctor and gc remove
  the probes of a library whose detacher died.
- 2026-09-29, R20: `Expect` is not forwarded upstream.
- 2026-09-30, R20: several incoming `tracestate` lines are one list; none is dropped.
- 2026-09-30, R27: the health check's drain is under the body deadlines; a failed body
  closes its connection.
- 2026-09-30, R25, R29, R33: a `%` left after decoding is an ambiguous path; a `message_delta` with no `output_tokens` is not final usage; `mcp_servers` is a server tool; Abandon's pre-arrival memory evicts its oldest pair, not all (`TestSilentSubpathsFailClosedOnAmbiguousSpellings`, `TestMessageDeltaWithoutOutputIsNotFinalUsage`, `TestCutStreamWithServerToolsIsUnmetered`, `TestStepsAbandonedMemoryEvictsOldestOnly`).
- 2026-09-30, R25, R29: no silent subpath under `/v1` is read from an ambiguous spelling; a cut
  stream of a request declaring a server tool is unmetered, not bounded; `usage.modified` marks a response billed
  under a speed, tier, geo or iterations modifier (`TestSilentSubpathsFailClosedOnAmbiguousSpellings`,
  `TestCutStreamWithServerToolsIsUnmetered`, `TestUsageBillingModifiers`).
- 2026-09-30, R33: a forwarder exchange derived with no response is reported abandoned, as the uprobe source's is (`TestUnansweredRequestIsAbandoned`, `TestCloseClaimedRequestIsAbandoned`).
- 2026-09-30, R23: retry recognition, by key and by the SDK counter, is scoped to the requesting process (`TestRetryIsRecognizedOnlyWithinItsProcess`).
- 2026-09-30, R7: symbol names are compared in place, not copied per entry; `elf.NewFile`
  reads through a 16 MiB budget (`TestSymbolNamesAreNotMultiplied`, `TestSparseShstrtabClaimIsBounded`,
  `TestSparseSectionCountClaimIsBounded`).
- 2026-09-30, R7: the uprobe source's agent-named gaps are capped at 256 keys with a
  binary-less overflow entry per reason, as `derive.Coverage`'s are (`TestAgentNamedGapKeysAreCapped`).
- 2026-09-30, R11: a full connection table is rescanned for a victim only once a
  connection may have become retirable, not on every chunk of a refused key (`TestRefusedKeyDoesNotRescanTheTable`).
- 2026-09-30, R19: a pinned `forwarder.listen` goes to the first `models[]` entry; later entries bind an ephemeral port instead of failing the whole forwarder (`TestPinnedListenWithTwoModelsBindsEveryEntry`).
- 2026-09-30, R27: a request body that fails while the upstream leg reads it marks the reply `Connection: close` from the handler goroutine, never the transport's (`TestRestReadFailureOffTheHandlerDoesNotTouchTheReplyHeader`).
- 2026-09-30, R19b: the user's codex `config.toml` is not copied into the run's when a `deny_read` entry covers it (`TestCodexConfigUnderDenyReadIsNotCopied`).
- 2026-10-05, R21: the response relay and the tunnel pumps report their chunks to the stall check,
  in every record mode, at most one per 100 ms per run.
- 2026-10-16, R4: under `record: off` an `auto` contract compiles to capture `forwarder` at every
  tier, so its models[] endpoints are guarded and a direct connection cannot go around a budget; only a pinned
  `capture: uprobe` keeps a uprobe source there, and compile reports its budgets.

## 6. Edge cases

1. Process execs and calls `SSL_write` before attach completes: first 1–2 calls lost; if attach exceeds the 50 ms
   budget, one `gap why=size-cap binary=<path>` with an estimated count is emitted from the binary's next `exec`.
2. `dlopen`'d libssl after process start (CPython's `import ssl`), or a linked one the loader maps after the exec: R4
   finds no libssl at `exec` time, so the exec's verdict is held, not recorded. The host's own libssl is already
   probed: `Start` pre-attached it before the process existed (R4), so its first `SSL_write` is captured however
   late the kernel record's open of the library reaches `OnOpen`, which then takes the process's reference and
   withdraws the verdict. A libssl pre-attach did not name (a private copy, a container's) is attached at that open,
   through `/proc/<pid>/root`, and the verdict is withdrawn the same way. A library that does not
   keep a `libssl.so*` name is not seen at the open (residual, R4). If the process execs again, exits or the
   run stops first, the held verdict becomes its gap (`static-tls-no-symbols` naming the executable, R37); a
   library whose process had already exited when its open reached the source was never read, and is `no-openssl`
   against the process's image. For a library attached only at its open, the read probes go on before the write
   probes (R4), so an exchange the attach splits — its request, or its request's head, written before the write
   probes and its response read after — is one `gap why=malformed` (count 1) and the connection's later exchanges
   are kept (R18), except a request whose tail looks like the start of a request line (a whole line of a token
   and a space, or one that runs past the 8 KiB start-line cap, either failing as it is parsed; or a known method
   whose line has not ended when its response begins), which fails the connection closed under that one count
   while its later exchanges are lost (R4 names the shapes); an exchange whose request
   and response both come before it is missed with no gap (R4, I4); and
   a client that pipelines, writing a request before reading the previous response on the same thread, can have
   one response paired with a request it did not answer (R4, I3); a client that reads on one thread and writes on
   another is two connections to capture and has nothing paired (R4, #11). Under `record: off` nothing is
   attached: `Start` pre-attaches nothing, and an exec, which the kernel record still hands on, attaches nothing
   either (R4), unless the run's `stall_after` is bounded, when the probes are placed for its activity alone and
   capture nothing (R4, amended 2026-10-19). A missed first request costs its own exchange, not every exchange of the keep-alive connection
   (without pre-attach and with the write probes first, kill test 2 captured 0 of 20 on three kernels).
3. pid reuse within the scratch map's lifetime: a stale entry could pair with a new process's `SSL*` at the same
   address; mitigated by `EnterNs` sanity-bounding the return probe: a pair more than 30 minutes apart
   (`TEGO_SSL_MAX_CALL_NS`, three times the 10-minute default request timeout of the Anthropic and OpenAI SDKs, so
   a slow first byte is never caught by it) has its buffer left unread, and the read is still numbered and emitted
   as a zero-length chunk marked stale whose `skipped` is the length the call reported. The source records
   `gap why=size-cap` for it, gives up the connection's waiting request and starts the connection afresh, so the
   next response pairs with its own request; a read dropped with no number made the next response on a keep-alive
   connection pair with this one's request.
4. Symlinked libssl path: R4 resolves to the target's `(dev,ino)` before caching, so two names share one entry.
5. A fresh exec of a re-stripped interpreter copy after an in-place upgrade is a new `(dev,ino)`: fresh R4/attach,
   symbol lookup fails, `gap why=static-tls-no-symbols`.
6. musl vs glibc: `debug/elf` reads both `.dynsym` and `.symtab`; Alpine binaries attach identically to glibc ones.
7. `SSL_write_ex2` present but dead-code-eliminated at the caller: harmless — the hook simply never fires; real
   traffic through `_ex` still reaches it via the tail-call, per R2.
8. One call >128 KiB: remainder dropped, `Trunc=1`, `Message.Truncated=true`; derive still attempts the truncated
   prefix and reports `decision: unparsed why=schema` rather than crashing on invalid JSON. The last chunk carries
   the dropped length (R6), so the request completes, the prefix is recorded, and the connection's later exchanges
   pair.
9. `SSL*` pointer reuse after free within one process: `SSL_free`'s close record ends the connection (R3a), so
   the new connection starts afresh; the FSM alone cannot tell (a `Content-Length` body would take the new
   connection's bytes as its own).
10. `fork()` after `SSL_new`, child later writes on the inherited `SSL*`: new `pid_tgid` key, correctly
    attributed if the child stayed in the run's cgroup, else filtered (that escape is `enforce`'s gap, not capture's).
11. Two threads sharing one `SSL*` under an external mutex: R5 still disambiguates by `pid_tgid`, but
    `httpstream.ConnKey` includes `pid_tgid` too, so the two threads become two connections sharing one wire —
    each seen as a malformed half-message rather than one coherent one; a stated fidelity gap, not a crash. With
    one thread writing an exchange's request and another reading its response, the first thread's connection would
    pair the request with the next exchange's response, so the source keeps each process's `SSL*` on one thread.
    When its I/O moves to another, a connection the old
    thread left idle between exchanges (nothing waiting, both halves at a message boundary: a pool handing the
    connection over) is closed as a new connection's first chunk closes it, and nothing is lost. Otherwise both
    threads' connections are given up (`Assembler.Abandon`), with one `gap why=malformed`; the requests they held
    are lost and reported (limits-check-doctor-cli.md R1 (f)), and the pointer's chunks are passed over until its
    `SSL_free` (R3a). A pointer freed with its close record lost and reused on another thread is given up the same
    way: fail closed. The table holds 8192 pointers; past that the followed ones are forgotten and the given-up ones stay given up.
12. `SIGKILL` between an `SSL_write` entry and return probe: no data lost for plain `SSL_write`/`_ex2`/`_ex` (length
    known at entry); only `SSL_read`'s length (known at return) can be lost, surfacing as `gap why=malformed` at `Close`.
13. `SSL_read_ex` returns 1 with `*readbytes` never written by OpenSSL internals: the return probe reads into a
    zero-initialized stack slot, so an unwritten value reads as 0 ("no data"), never garbage. A `*readbytes` the
    probe cannot read at all (a page the non-sleepable uretprobe cannot fault in, or a slot another thread of the
    agent unmapped between OpenSSL's store and the return) is not "no data": the call returned 1 and moved bytes,
    so it is a numbered hole of unknown length (`SSLHoleNoLength`, skipped 0), which the source gaps as it gaps #3's
    stale read (`gap why=size-cap`, the connection starts afresh), never a read that vanishes unnumbered.
14. TLS renegotiation/`KeyUpdate` produces zero-length application-data calls: no chunk event emitted (`Len=0`
    skips the ring-buffer write); httpstream never sees it.
15. Out-of-order pipelined responses (a server violating HTTP/1.1): the `pending` FIFO always matches response N
    to request N first; true reordering is `ErrMalformed`, never silently reshuffled.
16. Server skips the `100 Continue` interim and goes straight to the final status (RFC 9110-permitted): R12's
    "wait for the next status line" handles this identically — nothing to skip.
17. Chunk size-line split across two `SSL_write` calls: `chunkParser` state persists across `Feed` calls on the
    same key, so this reassembles correctly — the reason state is per-connection, not per-chunk-event.
18. Compressed stream truncated exactly at the 128 KiB cap, mid-codeword: decoder errors on the next read; the
    successfully-decoded prefix is blobbed, `Truncated=true`, `gap why=malformed`.
19. SSE with `:heartbeat` comments and a `retry:` directive: both retained in the decoded body and ignored by derive's SSE reader;
    `Last-Event-ID` reconnection is out of scope for P0 (a dropped SSE stream is one `gap why=malformed`).
20. h2 negotiated by an intermediary in front of the traced process while the traced process itself speaks h1:
    R17 keys off the *traced* process's own bytes (its preface), so this correctly stays h1, no false-positive gap.
21. `Content-Length` and `Transfer-Encoding: chunked` both present (RFC 9112 §6.1/§6.3 smuggling ambiguity, R18):
    treated as malformed rather than guessing which governs.
22. Server declares `Content-Length: 500`, sends 300 bytes, closes: httpstream waits for the declared length until
    the caller's idle timeout calls `Close`; the short body flushes as-is, `Truncated=true`, `gap why=malformed`.
23. Non-ASCII header bytes (a client violating RFC 9110's Latin-1 superset): header values are handled as opaque
    byte strings until placed in `http.Header`, preserved losslessly as bytes; only outright parse invalidity
    (missing `:`) fails.
24. Multi-gigabyte SSE body: no total-size cap (R14); the blob streams to disk; only the run's own wall/token/cost
    limits and host disk space bound it, independent of capture. Under R14's implementation condition this is the
    one edge case the P0 build does not yet meet: the body is cut at the 64 MiB `MaxBody` default and the message
    marked `Truncated`, a recorded loss rather than an OOM-killed launcher, until bodies stream to the blob writer.
25. Host clock stepped by NTP mid-run: `TS` (wall clock) may look non-monotonic, but R33's step windows and R24's
    retry TTL key off `MonoNS` (`CLOCK_MONOTONIC (the ledger's clock; docs/p0/record-ledger.md)`), which NTP steps never touch.
26. Two concurrent runs of one build: they share the run set and the probes placed on each library (ADR 0026 (7)),
    and each has its own capture ring and kernel record ring at its own slot, with its own lost counters (ADR 0026
    (1)-(5)). A probe writes each call once, into the ring of the run the calling process belongs to, so each run's
    source reads only its own chunks and its recorder only its own samples; no ring has a second reader, which would
    duplicate and tear its samples. The slot table hands out no slot a run-set row still carries (a dead launcher's
    orphan), so a leftover never reaches a new run's ring (enforce-cgroup-observe.md R12). 2, 8 and 32 concurrent
    runs each captured their own exchange exactly once and recorded their own opens and execs whole
    (`TestIntegrationConcurrentRunsOfOneBuild`, `TestTier2ConcurrentRunsOfOneBuild`, which also meters each run
    under a token budget). What bounds the number of such runs is `bpf.ring_budget`: a run whose capture ring does not
    fit captures nothing, says `mechanism-unavailable`, and is refused when it carries a token, cost or repeats budget
    (limits-check-doctor-cli.md R32). The attach cache is one per launcher.
27. `tego` binary upgraded mid-run (rename-replace): the live launcher keeps its own inode and `bpf_hash`'s
    pinned programs; a new run after the upgrade attaches under the new hash; both coexist per the build-lock
    protocol — capture code itself is unaware, it only ever sees its own process's `bpf_hash`.
28. `Stop()` mid-request: one final ring-buffer drain before the reader exits; any non-`Done` connection is
    `Close()`d, producing `gap why=malformed` (or nothing, if genuinely idle) rather than a silent half-message.
    As built: `Stop` (and cancellation of the run's context) halts the drain goroutine without closing
    the ring (`ringbuf.Reader.Flush` wakes it), and `Stop` then drains, which the run does once its processes are
    gone. The drain reads the bytes the ring holds when it begins and no further, because the ring is every run's of
    the build and another run's probes can keep it from ever being empty; every chunk of this run lies within them.
    Chunks are reassembled for `Options.StopDrain` (2 s) and past it only counted, this run's into `gap
    why=ring-buffer-drop` with its count, so the drain is bounded by the ring's size. The kernel record's `Stop` drains
    its ring the same way (enforce-cgroup-observe.md §4); neither closes its reader before draining, so a run's
    last response, and the exits and opens that end it, are kept. On a cancelled run (a failed worker, a cancelling
    caller) the run gives the killed tree `killTimeout` to empty on a context of its own, and a tree that outlasts
    that is `gap what=record why=ringbuf-undrained` with no count (enforce-cgroup-observe.md §4, §7). The events the
    drain reassembles go to the run's events queue, which the run keeps writing to the ledger while its sources stop;
    a drain that outruns the ledger by more than the
    queue's depth is still counted there. The uprobe source's `TestCancelLeavesTheRestToStop` holds the order every
    run stops in, cancellation first and `Stop` after.
29. `x-stainless-retry-count` non-numeric or negative: treated as absent; R23 falls back to the hash-match path only.
30. `HEAD /api/hello` with an unexpected body/extra headers: still answered locally per R22; any body is drained
    and discarded, never forwarded — the local answer depends only on method and path.
31. Uprobe attach against a setuid/privileged target, or under a restrictive Yama `ptrace_scope`: R4's
    `/proc/<pid>/maps` read is itself gated by the kernel's ptrace-access check (`PTRACE_MODE_ATTACH_REALCREDS`),
    the same restriction ARCHITECTURE.md §5/§7 already documents for `ask` (a non-dumpable target — its own
    `PR_SET_DUMPABLE=0` or a setuid exec under `privileged: true` — is readable only by a supervisor holding
    `CAP_SYS_PTRACE`; Yama scope 3 disables this outright). An unprivileged attach against such a target fails the
    R4 read itself, not just symbol resolution; not distinguished from `no-openssl` in the closed `why` set (R37),
    it falls to the Failure modes table's generic "Uprobe attach fails" row — conservatively `gap why=no-openssl`,
    detail only to `~/.tego/tego.log`. A dedicated `why` value is a §11 candidate, not a P0 change.
32. TLS 1.3 session tickets / 0-RTT early data (RFC 8446 §2.3, §4.2.10): a client sending early application data
    before the handshake completes may exercise `SSL_read_early_data`/`SSL_write_early_data` in some OpenSSL
    configurations rather than the R1–R3 entry points. Uncovered by any hook in this spec; a stated P0 limitation
    (early data is aggregate-rare for the CLI-agent traffic this component targets) rather than a rule.
33. Two `models[]` entries resolving to the same upstream host:port: R25 dispatches `derive` by
    `model.Provider`/upstream host, ambiguous when two declared models share a host — the dispatcher picks
    whichever `Parser` registered for that host first, a stated P0 limitation rather than silent misrouting (no
    normative doc requires per-listener disambiguation). Separately, `spec/policy/SEMANTICS.md` has the launcher
    re-resolving upstream DNS "on TTL," repointing a live `Listener.Transport`'s connections mid-run; forwarder
    dispatch is unaffected (it keys on declared `model.Host`, not resolved IP), but two models sharing a host
    inherit the same re-resolution independently per `Listener`.
34. A `retry_of`-tagged request whose original was gapped by `run_end`/`Stop()` racing the response (edge case
    #28) before the retry arrives: the retry-attach cache entry (R24) for the now-gapped original is not itself
    invalidated by the gap — a same-key request inside the TTL still extends the original per R23, even though its
    step already closed via #28. Consistent with R24's stated "indistinguishable from a legitimate late duplicate"
    limitation; not a new failure mode, just confirmation that #28 and R23/R24 compose without a special case.
35. Peer admission's residual gaps (R19a): the check is made after `accept`, so a peer that closes and whose
    ephemeral port is reused by another process between the accept and the `/proc` read is a TOCTOU window one
    connection wide; a socket passed over `SCM_RIGHTS` to a process inside the run's cgroup would be admitted as
    that process's own; and a process in the run's cgroup is the agent's own trust domain, so an agent that runs a
    browser inside its sandbox and lets a page POST to the forwarder is not a boundary crossing this rule refuses.
    All three are narrower than the unauthenticated listener they replace, and closing them properly needs a peer
    credential the TCP socket itself carries (`SO_PEERCRED` on a unix socket, or `INET_DIAG_CGROUP_ID` over
    `sock_diag`) rather than a `/proc` lookup after the fact — a listener-transport decision §11 records as open.
36. A thread of the traced process rewrites a buffer another thread is passing to OpenSSL: the write probe copies
    `SSL_write`'s buffer at entry, before OpenSSL encrypts it, and the read return probe copies `SSL_read`'s after
    the call returns, so a rewrite between the probe's copy and the encryption (write), or between the decryption
    and the probe's copy (read), leaves the ledger holding X while the wire carried Y. No probe placement closes
    it: the buffer is the agent's own memory, and the agent's own trust domain (#35). An accepted residual:
    capture is best-effort evidence of what a cooperative agent exchanged, not a tamper-proof record against a
    hostile multi-threaded one (§7, and GAPS.md A3, where such an agent bypasses uprobe capture outright with its
    own TLS stack). What the probes do guarantee is that every call they see is numbered: none is dropped
    without a hole the reader finds.

**Changes.**
- 2026-09-22, #2: a libssl found after the exec is attached at its open (no `no-openssl` at the exec).
- 2026-09-22, #26: the attach cache is per launcher; one reader per kernel-record ring (per run since ADR 0026).
- 2026-09-23, #2: pre-attach and read probes first (kill test 2).
- 2026-09-23, #28: `Stop` drains before closing; a cancelled run's tree gets `killTimeout`, else
  `ringbuf-undrained`; the events queue is read while sources stop.
- 2026-09-24, #8: a >128 KiB call records its dropped length; the connection goes on.
- 2026-09-24, #9: `SSL_free` ends a reused pointer's connection.
- 2026-09-24, #11: an `SSL*` is kept on one thread; a split fails closed.
- 2026-09-24, #20: R17 keys off the preface, not ALPN.
- 2026-09-24, #26: capture's own lost counter.
- 2026-09-24, #26 (ADR 0026 (1)-(6)): a ring per run; concurrent runs of a build each capture and record whole.
- 2026-09-24, #3: the read bound is 30 minutes, and a read past it is a numbered stale hole with its gap.
- 2026-09-29, #13: an unreadable `*readbytes` is a numbered hole of unknown length, not "no data".
- 2026-09-29, #36: the same-process buffer rewrite race is an accepted residual.

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | User sees |
|---|---|---|---|---|
| No OpenSSL in a process | R4 could read nothing: maps refused (#31), the process gone before its library was read | that process uncaptured; others unaffected | `gap what=capture why=no-openssl` | `measure`/`status` show the gap, run continues |
| Static TLS, no symbols | no readable candidate, the executable included, exports R1–R3 (also a process with no TLS at all, R4, R37) | forwarder fallback if not pinned to `uprobe` | `gap what=capture why=static-tls-no-symbols` | kill-test 7's expected gap line. Not written under `capture: forwarder`, where no uprobe source runs R4 on any process: FEATURES' "capture: uprobe unavailable (static BoringSSL, no symbols); forwarder active" for Claude Code is held with its condition (2026-09-23) |
| h2 negotiated | R17 | connection abandoned for capture only; TLS itself unaffected | `gap what=capture why=h2` | uncaptured connection in `measure` |
| Forwarder bypass | `enforce`'s compiled rules | connect refused (R38) | `net verdict=refused reason=net-not-allowed` | agent's own connect error, never silent |
| Ring-buffer full | cilium/ebpf loss stats | userspace keeps draining, kernel never blocks the traced process | `gap what=capture why=ring-buffer-drop count=n` | dropped events noted in `measure` |
| Malformed HTTP | R18 | that connection's rest ignored; others unaffected. A response with no request, or the first request capture sees on a connection arriving with no head, is that one exchange passed over, the connection kept, unless that request's tail looks like the start of a request line (R4) | `gap what=capture why=malformed` | that pair missing, explained |
| Blob write failure (disk full, EIO) | `ledger.Writer.Blob` error | agent's proxied response is still delivered; capture is best-effort against the agent, never fails the call | `gap what=capture why=malformed`; a systemic ledger failure is `run_end reason=error` (owned by `runtime.Run`) | measure shows a gap; operator sees disk pressure via `doctor`/monitoring |
| Uprobe attach fails (verifier, permission, old kernel, ptrace/Yama per edge case #31) | `attach()` error | that binary stays uncaptured, one attempt per `(dev,ino)`, no retry storm; the attempt is spent only on a failure the binary or the host owns, never on a candidate path that vanished with the process that mapped it (R39), which would bar every later process from a hookable library. An `ENOENT` (or `ESRCH`) is split by whether the path still resolves, never by the errno alone, because on the uprobe PMU `perf_event_open`'s `ENOENT` is the kernel's lookup of the path while a kernel without `CONFIG_UPROBE_EVENTS` answers every attach with `ENOENT` from the tracefs `uprobe_events` file cilium/ebpf falls back to; any other errno (`EPERM`, `EINVAL`, `ENOTSUPP`) is a refusal the host owns, recorded without a lookup | conservatively `gap why=no-openssl` (capture cannot distinguish cause without widening the closed `why` set, §11); detail to `~/.tego/tego.log` at `log.level: debug` | `doctor` catches systemic cases before any run starts |
| Capture object will not load, the run has no capture ring at its slot (the ring budget left it out) or it will not open, no kernel record is running to drive attaches, or the run set holds no row for this run | `LoadCollection`/`openPinned`/`RingOf` error at `Start`, no `FollowKernel` before `Start`, or the run set read at `Start` (edge case #26) | the source stays inert for the run: no probe is placed and no hook call does anything; the run continues | one `gap what=capture why=mechanism-unavailable binary=uprobe`, no count; the cause to `~/.tego/tego.log` as a warning | the gap at `run_end`; with a token, cost or repeats budget the run is refused before `run_start`, exit 125 `[capture-unavailable]` naming the cause (limits-check-doctor-cli.md R32) |
| `derive/anthropic` or `derive/mcp` panic (fuzz target, should not happen) | `recover()` in the `Dispatcher` (`parse`, `mcpRequest`) | converted to `decision: unparsed why=schema`; panic and stack trace to own log (`derive.WithLogger`), never the ledger | `decision: unparsed why=schema` | run continues uninterrupted |
| Retry storm / fast client retries | no special detection; distinct `retryKey`s are distinct steps | `limits.repeats` (a different component) is what actually intervenes | ordinary `ssl_request`/`ssl_response` pairs | `measure` shows many steps until `limits` fires |
| Upstream TLS handshake failure | `Transport.RoundTrip` error pre-response | `502` to the client (R26) | `ssl_request` with no response, closed to `gap why=malformed` at `run_end`/`Close` | agent sees a `502` from what it believes is the model API |

## 8. Invariants

- **I1.** Capture never blocks the traced process. The run's capture lane is not a sink that never waits: a full
  lane holds its producer up to its bounded wait (5 s, `runtime.captureBacklogWait`) and then drops and counts.
  Neither capture path puts that wait on the traced process. On the uprobe path the kernel side never waits (a full
  ring drops, `gap why=ring-buffer-drop`); only the user-space drain waits. On the forwarder path the client's
  request and response never wait on the ledger. A handler appends its events, and its unmetered reports, to its
  listener's emit queue (1,024 entries) without waiting, and returns. One goroutine per listener, started when
  there is work, hands them to the sink in the order they were appended, so an exchange's lines keep their order.
  That goroutine may use the capture lane's bounded wait. When the queue is full an entry is dropped, never waited
  for. Each drop is counted in the run's gap report (`gap what=capture why=emit-queue-full`), and the listener's
  first drop is reported unmetered (limits-check-doctor-cli.md R1 (s)), which ends a run with a token or cost
  budget. `Close` waits up to 5 s for the queue to empty and then counts what is left as dropped. This way nothing
  reaches the sink after the run's drain (`TestStalledSinkDoesNotDelayTheClient`,
  `TestEmitQueueOverflowIsAGapAndUnmetered`).
- **I2.** Chunk order within one `(pid_tgid, ssl_ptr)`/`ConnID` is preserved; `Seq` lets the reader detect (never
  silently accept) a gap; `httpstream.Feed` rejects out-of-`Seq` data as malformed. Tested by a two-writer race integration test.
  `Seq` is the kernel's, not a count assigned on arrival, which could not contain a hole (a response lost whole to
  a full ring would pair the next response with the request before its own). The kernel numbers every chunk of a
  connection from `tego_ssl_seq`, an LRU map keyed by
  `(pid_tgid, ssl_ptr)` and shared by both directions, before its reserve, so a failed reserve still uses its number;
  `httpstream` checks one sequence per connection and gaps the connection (`why=malformed`) at the next chunk in
  either direction. One counter for both directions, not one per direction: a per-direction count cannot show the
  loss of a direction's first chunk, which is the first response of a connection. Two losses still show no hole: one
  at the very start of a connection the reader has not seen (where its numbers start is unknown to it), and a row
  the LRU evicted, whose restarted count gaps a live connection instead (fail-closed); both are counted in
  `ring-buffer-drop`.
- **I3.** An `ssl_response` always has a matching earlier `ssl_request` in the same run — `httpstream` only ever
  hands derive a pair, never a bare response. Tested by `internal/check`'s fixture consistency check. One stated
  exception, R4's: a library attached late under a client that writes a request before it has read the response
  to the one before, on the same thread (pipelining), can pair a response with a request it did not answer; a
  reader on another thread is another connection to capture (edge case #11) and pairs with nothing; the read
  probes going on before the write probes is what keeps an ordinary client out of it. A reader thread blocked in
  `SSL_read` is not a way to mispair.
- **I4.** `gap` is the only representation of a capture shortfall — no silent absence. Tested by kill test 2's
  "every missing pair is explained" acceptance line. Two stated exceptions, both chunks no probe saw: an
  `SSL_sendfile` connection's kTLS direction (R1) and an exchange whose request and response a process both
  makes within the attach latency after it loads a libssl `Start` did not pre-attach (R4). One the attach splits
  — a response with no request, the rest of a response, a request with no head — is a `gap why=malformed`
  counted for that exchange (R18), except a request with no head whose tail looks like the start of a request
  line, which gaps the connection under one count however many exchanges it held (R4). A shortfall of the kernel
  record that drives discovery is represented by that record's gap,
  `what=record why=kernel-record-unavailable` for a run whose recorder reads nothing (edge case #26), `why=ringbuf-full`
  or `why=ringbuf-undrained` with its count (edge case #28), not by a capture gap per process. A chunk left on the
  capture ring past `Stop`'s drain budget is `ring-buffer-drop` with its count.
- **I5.** Credentials never reach a `record.Event.Payload`: `forwarder` only ever computes a hash of the header
  value; no field in this component's types holds the raw value. Tested by grepping golden fixtures for a known test credential.
- **I6.** `parser_version` is set on every `ssl_response` derive produces, never empty. Tested per golden fixture.
- **I7.** `attribution.step` is non-decreasing across a run's `seq`-ordered stream (R36). Tested by the fixture
  ledger and `drift`'s consistency pass.
- **I8.** No `(dev,ino)`×symbol-set is ever double-attached; `RefCount` guards every `attach()`, and a claim on
  the binary serializes the first attach of it, so processes exec'd together that map one libssl wait for one
  attempt and take a reference on its outcome rather than each attaching. Tested by the concurrent-`OnExec` unit
  tests (one source, and two sources on one cache), run under `-race`.
- **I9.** Detach eventually matches process exit: no `RefCount==0` entry keeps live links past the next
  `Stop`/sweep. Tested by an integration test asserting no tego uprobe links survive the last interested run.
  With the probes shared per library (R8), the links outlive the last interested run by `ProbeGrace` (2 s) and
  no more while its launcher lives to start the detacher; a launcher that dies first leaves them pinned until the
  build is removed (ADR 0022), and `tego doctor` lists them meanwhile.
- **I10.** `Message.Body` bytes are identical to what `blob(sha)` references — derive reads a tee, never a second
  independent drain of the primary stream. Tested by comparing parsed `decision` content against the on-disk blob hash.
- **I11.** `uprobe` and `forwarder` never both emit events for the same HTTP exchange: the forwarder only sees
  loopback traffic its own base-URL env var routed to it; uprobe only sees real upstream TLS; a correctly compiled
  contract makes the forwarder the only allowed route once active (R38). Cross-component integration test only.

**Changes.**
- 2026-09-22, I4: the kernel record's own gaps stand for discovery's shortfall.
- 2026-09-23, I3, I4: read probes first; the split-reader case is not a mispairing; the final drain's gap.
- 2026-09-24, I2: `Seq` is the kernel's per-connection count, shared by both directions.
- 2026-09-24, I9 (ADR 0026 (7)): shared links outlive the last run by `ProbeGrace`, or to the build's removal.
- 2026-09-29, I1: the capture lane's bounded wait held a forwarded request for up to 5 s. Forwarder events now go through a per-listener emit queue, whose overflow is a gap and unmetered.
- 2026-09-29, R16, R18: `Content-Length` must be 1*DIGIT (`+5` and `-0` are malformed); a multi-line SSE event reaches derive as one line.
- 2026-09-29, R4, R7: at most 64 libraries opened by name per run; symbol tables bounded at 8 MiB; undefined symbols are not exports.
- 2026-09-29, R15, R18: a bodiless or empty message carrying a `Content-Encoding` is not malformed; `Transfer-Encoding` must end in `chunked` and its earlier codings are decoded; the trailer cap holds at exactly 8 KiB.
- 2026-09-29, §10: the SSL probe source is `bpf/uprobe_ssl.bpf.c` (the spec named a `sslprobes.bpf.c` that never existed).
- 2026-09-30, R4, R14: `.symtab` is read only when `.dynsym` lacks the symbols and an unreadable oversize table is `ErrSymbolTableTooLarge`, not no-symbols (string tables bounded at 32 MiB); an SSE body is reduced in place, inside the budget.

## 9. Conventions and best practices

- **Naming.** Domain nouns from `docs/REPO-LAYOUT.md` §Naming reused exactly (`Event`, `Verdict`, `Source`,
  `Backend`, `Gap`); no `util`/`helpers`; each package is one concept.
- **Errors.** One `var Err*` sentinel per package, wrapped with `%w` at every boundary; `record.Reason`/
  `agent.Diagnostic` are never constructed here — this component only ever produces `ssl_request`, `ssl_response`,
  `decision`, `gap` kinds.
- **Logging.** Own log only (`~/.tego/tego.log`) for anything that is not itself a `record.Event`, `run=<id>` on every line.
- **Context.** Every long-lived goroutine runs under the run's `context.Context` and stops under `errgroup.Wait()`
  (P0-DESIGN §6); only the host-wide ring-buffer reader and attach cache outlive one run, shut down when the last
  interested run exits.
- **Goroutine ownership.** One reader per host per ring buffer (shared); one `Assembler` per run; one
  `net/http.Server` tree per `Listener`, run-scoped.
- **Resource lifetimes.** `link.Link`s outlive individual runs when refcounted (R7/R8); listener sockets,
  assembler state, retry cache are exactly run-scoped, closed at `Stop()`.
- **Fuzzing** (P0-DESIGN §7): `httpstream`'s line/header/chunked parsers and `derive/anthropic`'s JSON/SSE parsers
  are Go fuzz targets seeded from the golden fixtures — every reader of network-controlled bytes gets one.
- **Benchmarks.** Uprobe entry+return pair (target 2–4 µs), forwarder per-request (~100 µs), `httpstream.Feed`
  per-chunk, under `test/e2e/overhead`'s hyperfine harness, per tier and record mode (P0-DESIGN §9).
- **Doc comments.** Every exported symbol documented; `doc.go` states purpose/imports/must-not-imports exactly as
  quoted in §1; CI fails when `depguard` disagrees.
- **CGO.** `CGO_ENABLED=0`; `debug/elf` (pure Go) for symbol lookup, never a cgo ELF binding.

## 10. Tests

**Unit:** `uprobe` symbol-choice table across OpenSSL 1.1.1/3.0/3.3/3.5 fixtures (R1/R2); `resolveLibrary` against
fixture `maps` snapshots incl. a symlink, a static binary, and a containerized-process `/proc/<pid>/root`-relative
case (R39); attach-cache refcount tests (I8, I9). `httpstream` golden per encoding and for SSE; chunked-split-across-
`Feed` golden; pipelining (2 and 8 in-flight) golden; `100-continue` golden; malformed-input table (bad line, bad
header, `CL`+`TE`, h2 preface) asserting the right `gap`/no panic — doubles as the fuzz seed corpus. `forwarder`
hop-by-hop stripping table against RFC 7230 §6.1; `traceparent`/`tracestate` golden vectors from `RUN-IDENTITY.md`
including a case with a prior `tego` member on the incoming `tracestate` (asserting it is removed, not
duplicated, R20); `computeRetryKey` determinism; `x-stainless-retry-count` edge cases; peer admission (R19a) —
`/proc/net/tcp` v4/v6 address-cell decoding and peer-side row selection against real rows, `mountinfo` cgroup2
parsing, and, over a live loopback connection, a run whose cgroup holds the connecting process (served) against one
whose cgroup holds nothing (`403`, no `ssl_request`, no gap). `derive/anthropic` golden
per API shape (non-streaming/streaming, 0/1/N `tool_use` blocks split across deltas, usage accumulation, malformed
JSON, unknown event type); `input_hash` byte-identity test (R31). `derive` dispatcher: `AttributeByTime` table
over R33–R36.

**BPF map logic:** `sslScratchKey`/`sslScratchVal` LRU behavior under >8192 concurrent entries (eviction → gap,
never a wrong pairing); `bpftool` load test of `bpf/uprobe_ssl.bpf.c` in CI's generate-diff check.

**Integration** (`//go:build integration`, root, VM): uprobe on system Python + `httpx`/`anthropic` on OpenSSL 3.0
and 3.5 (kill test 2: ≥95% pairs, every miss gapped); forwarder with Claude Code and both Agent SDKs (kill test 7:
every request `source=forwarder`, a deliberate bypass refused, never silent); two concurrent runs sharing one
libssl (#26); orphan sweep / `Stop()` mid-request (#28) closes cleanly with a gap, not a hang; a Docker-adopted
container's uprobe attach resolving through `/proc/<pid>/root` (R39).

**E2E kill tests:** test 2 → R4–R9, R39, R37, I3, I4. Test 7 → R19–R27, R33, I11. Overhead benchmark (test 3)
measures exactly what R6/R19–R21 are sized for.

**Fixtures:** `spec/record/v1/fixtures/` carries at least one `ssl_request`/`ssl_response` pair with `retry_of`
set and one `decision: unparsed` row, so `internal/check` views are exercised against this component's real shapes.

## 11. Open questions

- **capture mode concurrency.** `spec/config/v0/README.md` defines the field explicitly: `` capture: auto  #
  ceiling; ordered off < forwarder < uprobe; auto = uprobe where the tier allows it `` — a single ordered scalar,
  worded the same way as `tier:`'s single-ceiling field, which reads most naturally as "pick the one highest
  mechanism the tier allows," not "run every mechanism the tier allows, concurrently." Against that,
  `spec/backend/CAPABILITIES.md`'s capability matrix lists the "capture model traffic" cell for both tier 2
  (`cgroup`) and tier 3 (`bpflsm`) as "uprobes and forwarder" (conjunction, not "uprobes only"), `Deps.Capture
  []capture.Source` is a slice, and Claude Code's example contract (`spec/agent/v0/example.retriever.yaml`) sets
  `capture: forwarder` specifically because uprobe cannot see its traffic — which only makes sense as a deliberate
  override if `auto` would otherwise also run the forwarder alongside uprobe. Neither `P0-DESIGN.md` nor
  `ARCHITECTURE.md` states which reading governs; this spec assumes the concurrent reading (R33's note, §4's
  `Select`) as the only one consistent with the capability matrix and the Claude Code case, while flagging that the
  config spec's own wording leans toward "pick one." *Resolved 2026-09-23 for the pinned case:* a contract that
  writes `capture: uprobe` itself runs the uprobes alone (§4 `Select`), because kill test 7 (b) needs the agent's
  own TLS read by the probes and a forwarder beside them takes every request of a harness that honours its base-URL
  variable; `auto` keeps the concurrent reading, which is what keeps Claude Code captured at tier ≥ `cgroup`.
- **`decision: unparsed` reason completeness.** `why` is closed to `encoding|schema|h2`
  (`spec/record/v1/README.md`), but several genuine P0 shapes (a body truncated by R6/R14's caps, a mid-stream
  close, an attach refused by Yama/ptrace per edge case #31) don't map cleanly onto any of the three; this spec
  assigns the first two to `schema` as the closest bucket (R29) and the third to the existing generic
  "no-openssl" capture gap rather than a new `why` value (edge case #31). A fourth `gap`/`decision` reason value
  (e.g. `truncated`, `denied`) may be worth adding in a later `spec/record/v2`.
- **No record shape for a refused peer.** R19a turns away a process that is not the run's, and the ledger has no
  line for it: `gap what=capture`'s `why` is closed to R37's nine values and none of them is true of it (nothing of
  the agent's traffic was missed), while `refused` is the supervisor's own shape, whose `reason` set and
  `last-refusal.json` mirror both describe the agent being refused, not a stranger at the forwarder. So the
  refusal is counted on the listener and logged, and an attempt on a run's forwarder leaves no trace in the
  append-only record that is the product. Closing this needs a value another component owns — a seventh
  `gap why` or a `refused reason` in `internal/runtime/derive` and `spec/record/v1` — and is deliberately not
  borrowed from an existing one, which would misdescribe it in every view built on the closed set.
- **Exact numeric caps.** The 32/128 KiB chunk caps (R6), 8192-entry scratch map (R5), 64 KiB/128-line header caps
  (R13), 8-deep pipelining (R11), the 4096-connection table and the 64 MiB body default (R14's implementation
  condition), and 256-entry/650 s retry cache (R24) are this component's own defaults — no normative document sets
  them — and should be confirmed against real traffic. The connection table is a bound and
  not an ending: at 4096 the assembler retires a finished or already-gapped connection rather than refusing the new
  one, because nothing in the uprobe path could tell it a connection is over (there was no `SSL_free` probe, so
  `Close(key)` was never called per connection; R3a closes them since 2026-09-24, and retiring stays for a free
  capture does not see) and refusing would silently stop capture for the rest of the run. A
  retired connection whose key returns restarts at message index 0 with no `Seq` continuity across the boundary — the
  price, paid on connections that have finished rather than on traffic being captured now.
- **Host-shared attach cache under `tegod`.** P0-DESIGN/ARCHITECTURE §15 anticipate one writer per host at scale,
  but `tegod` is not built; how a run "unregisters" interest in a shared attach cache
  without detaching a binary other runs still use is open.
- **Identity propagation.** R20 (forwarder trace header rewriting) is built; `docs/FEATURES.md` E44 lists it.

## Resolved conflicts
Resolved in the normative docs (2026-09-22): the forwarder listens on TCP 127.0.0.1 only; `$XDG_RUNTIME_DIR/tego/<run>/` holds the P1 control socket and the P2 Docker proxy socket (P0-DESIGN §3.3). A forwarder bypass is a `net verdict=refused` event, never a capture gap. Under `capture: auto` both sources run concurrently and never see the same request (P0-DESIGN §2.9, config README); a contract that pins `capture: uprobe` runs the uprobes alone where the tier allows them (§4).

- 2026-10-01, R27/R29: both streamed and JSON message usage require an explicit, non-null input count. Missing or malformed stream accounting stays incomplete after later output deltas; `max_tokens` bounds output only and cannot restore missing input/cache accounting. A budgeted run ends with error when that successful exchange is unmetered. Explicit zero input remains valid, and malformed tool/text bodies can still retain complete readable usage.

- 2026-10-03, R16: the uprobe HTTP assembler preserves decoded SSE framing for the shared provider parser. The former reducer dropped empty named accounting events and event-name fallback; an incomplete response could therefore appear metered on uprobe while the forwarder refused it. End-to-end capture/derive regressions retain known usage while refusing completeness; body preservation uses the existing budgeted array.
- 2026-10-03, R16, R32: `anthropic-2026-10-4` selects wire framing explicitly for current capture messages and the forwarder usage scanner. A bare JSON line is an unknown wire field, including before the first data frame or past the scanner retention bound, and contributes no usage. Standalone `ParseStream` and the scanner zero value retain legacy collected-payload compatibility.
- 2026-10-05, R25, R32: `anthropic-2026-10-5` treats a percent escape left after one decode as an ambiguous first segment, including each segment of a declared gateway's `/api/...` path. `/api/%2576%2531/messages` cannot silently bypass unknown-spend reporting. Root and ordinary telemetry paths retain their silent classification; the parser performs no second decode.
- 2026-10-05, R20: a forwarder with neither `net.http` nor `net.proxy` again strips `Upgrade`, `Connection` and what it names from an upgrade offer and forwards the request as HTTP/1.1; the `net.proxy` work had refused every such offer there with 400 and a malformed gap. `net.http` and `net.proxy` listeners keep their refusal and WebSocket route decision (`TestCaptureOnlyUpgradeOfferIsStrippedAndForwarded`).
- 2026-10-05, R27 (c): the forwarder's wire usage scanner and its incomplete verdict apply only where the Dispatcher resolves the listener's declared provider, else host, to the Anthropic parser. A non-Anthropic stream with one frame over 64 KiB no longer counts a malformed capture gap; such an exchange stays unmetered as before, because no linked parser reads it (`TestWireUsageVerdictIsTheAnthropicParsersOnly`).
