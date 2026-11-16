// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Plaintext capture: uprobes on OpenSSL's write and read entry points, filtered by cgroup, streaming the
 * bytes a traced process sent and received before TLS encrypted them (docs/p0/capture-derive.md §5 R1-R9,
 * ARCHITECTURE §12).
 *
 * Attach points (userspace chooses which symbols exist and where; this file only says what runs there):
 *   - tego_ssl_write       SSL_write(SSL *, const void *buf, int num)
 *   - tego_ssl_write_ex    SSL_write_ex(SSL *, const void *buf, size_t num, size_t *written) and
 *                           SSL_write_ex2(SSL *, const void *buf, size_t num, uint64_t flags, size_t *written)
 *   - tego_ssl_read        SSL_read(SSL *, void *buf, int num) entry
 *   - tego_ssl_read_ex     SSL_read_ex(SSL *, void *buf, size_t num, size_t *readbytes) entry
 *   - tego_ssl_read_return the shared uretprobe for both reads
 *   - tego_ssl_free        SSL_free(SSL *) entry: the connection is over (R3a)
 *
 * Why writes need no return probe and reads do (R1-R3): a write's length is its own argument, known at
 * entry, so a process SIGKILLed between entry and return loses nothing (§6 edge case #12). A read's length
 * exists only after the call: SSL_read reports it as the return value and only when positive, SSL_read_ex
 * through *readbytes and only when the return is 1. Exactly one _ex write variant is ever attached, because
 * SSL_write_ex tail-calls SSL_write_ex2 where both exist and hooking both would double-count (R2) — a
 * userspace rule this file cannot enforce and does not try to.
 *
 * What entry-only write capture costs, and why it is documented rather than fixed (the converse of §6 #12,
 * which reasons about data lost and never about data gained). SSL_write's return value is not its `num`
 * argument: openssl/ssl.h defines SSL_MODE_ENABLE_PARTIAL_WRITE as "Allow SSL_write(..., n) to return r with
 * 0 < r < n (i.e. report success when just a single record has been written)", and SSL_write(3ssl) requires a
 * call that failed with WANT_READ/WANT_WRITE to "be repeated with the same arguments". probesFor() places no
 * return probe for a write, so all three of these emit bytes the wire did not carry once:
 *
 *   - a write that fails outright (reset connection, an abandoned non-blocking BIO) still emits at entry, so
 *     the ledger can assert request bytes that were never sent;
 *   - the mandated retry fires the entry probe again over the same buffer, and httpstream concatenates both
 *     copies into one stream: the recorded request becomes the request followed by a copy of itself;
 *   - under partial-write mode the caller resumes at buf+written and the tail is emitted twice.
 *
 * None of it can be decided at entry, and the obvious in-kernel repair is worse than the disease. Suppressing
 * a following write whose buffer range lies inside the previous one — the shape both the retry and the
 * partial-write tail take, since openssl/ssl.h makes the same address the default contract
 * (SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER exists to relax it and "is not the default") — would hand the traced
 * process an evasion channel: it controls the buffer, so it can write X, let the ledger record X, overwrite
 * the same bytes with Y and write again, and the suppressed second call puts Y on the wire with only X in the
 * ledger. Content equality cannot be checked here either — comparing the bytes means reading them, and
 * reading them is the emit. A hostile process must never be able to make this file drop a call it saw
 * without a trace (SECURITY.md puts bpf/ in the trusted computing base), so the duplicate stands and the
 * fidelity claim is corrected instead.
 *
 * What that guarantee does not cover (capture-derive.md §6 #36, an accepted residual): the bytes recorded are
 * the buffer at the probe's copy, not the bytes OpenSSL encrypted or decrypted. A second thread of the traced
 * process can rewrite a write's buffer after the entry probe copies it and before OpenSSL encrypts it, or a
 * read's after OpenSSL decrypts into it and before the return probe copies it, and the ledger then holds X
 * while the wire carried Y. No placement of these probes closes that window, since the buffer is the agent's
 * own memory: against a hostile multi-threaded agent capture is best-effort evidence, not a tamper-proof
 * record. What holds is that every call the probes see is numbered, so none vanishes without a hole. Closing it properly needs a write uretprobe emitting min(ret, num), which trades away the SIGKILL
 * resilience R1/#12 bought and needs a sixth program plus its userspace attach (probesFor, internal/bpf's
 * SSLPrograms) — outside this file.
 *
 * Filtering (R9): every program's first act is one tego_run_set lookup on the current cgroup id. A process
 * outside every live run costs one map lookup and produces nothing, which is what lets one host-wide attach
 * serve every run and keeps run A's plaintext out of run B's sink (§6 edge case #26).
 *
 * Activity (limits R4, A-REC-1, A-REC-5): right after the run-set hit, and before the record mode or the run's ring
 * is looked at, a write that asks to move bytes (num > 0) and a read that returned some (> 0, both reads) stamp the
 * run's slot in tego_activity (tego_activity_stamp), for a run whose row carries TEGO_RUN_ACTIVITY (a stall_after
 * bounds it), in every record mode: a model response streams for longer than stall_after with no line between its
 * two ends under summary and none at all under off, and its reads are the agent's work. The stamp reads nothing but
 * registers and writes one slot, at most once a jiffy; read entries and SSL_free stamp nothing. Under record: off
 * each program returns right after it, as before: no scratch row, no chunk number, no bpf_probe_read_user, no ring,
 * no miss count, so no plaintext of an off run is read or written anywhere.
 *
 * Chunking (R6): one chunk carries at most TEGO_SSL_CHUNK_MAX bytes and one call is split into at most
 * TEGO_SSL_CHUNKS_MAX chunks, emitted by four explicit calls rather than a loop. Past that the remainder is
 * dropped and the last chunk says how many bytes it dropped (skipped). It used to say only truncated=1, and
 * userspace could not tell how far the hole reached: the request's Content-Length still counted the dropped
 * bytes, so the request never completed and the connection was lost with every later exchange on it
 * (CPython hands a whole request body to one SSL_write_ex). With the length, httpstream steps over
 * a hole inside a body and records the prefix, which is what §6 #8 promises.
 * A record is reserved at the smallest of three size classes (512 B, 4 KiB, 32 KiB of data) that holds its
 * chunk, each a compile-time constant at its reserve: reserve, fill, submit, never a retry and never a second
 * copy (§8 I7). One fixed 32 KiB record let about 255 chunks fill the default 8 MiB ring, however few bytes a
 * streamed response's reads carried. Chunks of one call reach the ring in order, which is the order one
 * reader drains them in.
 *
 * What a lost chunk costs (§8 I2). Every chunk carries its number on its connection, seq, one counter per
 * (pid_tgid, ssl_ptr) for both directions in tego_ssl_seq, taken before the reserve. Userspace used to number
 * chunks on arrival, which structurally cannot contain a hole: a whole response lost to a full ring made the
 * next response on the connection pair with the request before its own, and every later one after it (a
 * response 1 ms after its request was recorded with latency_ms=500). A reserve that fails still
 * uses its number up, so the reader finds the hole at the connection's next chunk, whichever direction it is
 * in, and gaps the connection. Only a loss at the very start of a connection the reader has not seen yet shows
 * no hole, since the reader cannot know where a connection's numbers start; it is counted, below. Besides the
 * hole, two of the three loss paths are marked here:
 *
 *   - a failed bpf_probe_read_user still submits its reserved record, as a zero-length chunk whose skipped is
 *     the bytes it could not read, so the reader knows which (cgroup, ssl_ptr, direction) lost how many bytes
 *     and where (R6);
 *   - a part of a call that was lost marks every later part of the same call truncated, and userspace raises
 *     Message.Truncated instead of asserting a whole body.
 *
 * The third cannot be marked from here: when a reserve fails there is no record to carry the mark. Its only
 * in-band trace is the hole in seq, and the run's tego_capture_lost counter userspace diffs into gap
 * why=ring-buffer-drop says how many chunks went.
 *
 * Rings (ADR 0026 (1), (3)): every chunk goes to the capture ring of the run the calling process belongs to,
 * looked up by the run's slot after the run-set hit; a run with none gets nothing (tego_capture_ring).
 *
 * Nothing here decides anything. Every record is TEGO_V_OBSERVED, and a connection this file cannot
 * capture is userspace's gap to record, never a refusal.
 */
#define TEGO_CAPTURE_MAPS
#include "maps.h"

char _license[] SEC("license") = "Dual BSD/GPL";

/* BTF anchors: see bpf/cgroup_track.bpf.c. Naming each struct once makes bpf2go emit a Go mirror of it that
 * internal/bpf's hand-written mirrors are asserted against. */
const struct tego_ev_ssl_chunk *tego_btf_ev_ssl_chunk;
const struct tego_ssl_key *tego_btf_ssl_key;
const struct tego_ssl_scratch *tego_btf_ssl_scratch;
const struct tego_ev_ssl_close *tego_btf_ev_ssl_close;

/* Returns the run's capture ring, or NULL when the run has none: a run whose capture is not uprobe (capture: off, the
 * forwarder) or whose ring did not fit the host's budget. The probes are shared by every run of the build (ADR 0026
 * (7)), so they fire for such a run's TLS calls too; nothing of them is read or written, and the miss is counted
 * at the run's slot (ADR 0026 (3)). */
static __always_inline void *tego_capture_ring(const struct tego_run *run)
{
    void *ring = tego_ring_of(&tego_capture_events, run);

    if (!ring)
        tego_lost_inc(&tego_capture_miss, run->run_idx);
    return ring;
}

/* Takes the next chunk number of this thread's connection on ssl_ptr (tego_ssl_seq). Only this thread writes
 * its own rows, and a uprobe program runs to completion on its thread before the next can fire there, so the
 * plain increment needs no atomic. The number wraps past 0, which the reader's check skips. A row that cannot
 * be made (never, for an LRU map) numbers the chunk 1, which the reader sees as a hole on a live connection:
 * failing closed. */
static __always_inline __u32 tego_ssl_next_seq(__u64 ssl_ptr)
{
    struct tego_ssl_key key = {};
    __u32 *slot, first = 1;

    key.pid_tgid = bpf_get_current_pid_tgid();
    key.ssl_ptr = ssl_ptr;
    slot = bpf_map_lookup_elem(&tego_ssl_seq, &key);
    if (!slot) {
        bpf_map_update_elem(&tego_ssl_seq, &key, &first, BPF_ANY);
        return first;
    }
    *slot += 1;
    if (*slot == 0)
        *slot = 1;
    return *slot;
}

/* Fills a reserved chunk record's head. */
static __always_inline void tego_ssl_meta(struct tego_ev_ssl *m, __u32 size, const struct tego_run *run,
                                           __u64 cgroup_id, __u64 ssl_ptr, __u8 dir, __u32 len, __u8 trunc,
                                           __u32 seq, __u64 skipped)
{
    tego_hdr_fill(&m->hdr, TEGO_EV_SSL_CHUNK, size, run, cgroup_id);
    m->ssl_ptr = ssl_ptr;
    m->len = len;
    m->direction = dir;
    m->truncated = trunc;
    m->hole = TEGO_SSL_HOLE_NONE;
    m->pad = 0;
    m->seq = seq;
    m->pad2 = 0;
    m->skipped = skipped;
}

/* Records one chunk of plaintext in a record of `cls` data bytes, one of R6's size classes, and reports whether
 * it reached the ring. The caller has chosen the smallest class that holds n; n is clamped to it again here so
 * the verifier sees the user read bounded by the reserve, whatever the caller's branch told it. The reserve is a
 * compile-time constant in each inlined copy, so the ring buffer is written exactly once (§8 I7).
 *
 * The clamp is written twice and each follows barrier_var(n), and the second sits right before the read, with no
 * call between them, because a plain clamp did not survive clang (verifier-log regression, kernel matrix
 * 2026-09-29). The caller's branches already prove n <= cls, so clang deleted `if (n > cls) n = cls` as dead, and
 * it kept n in two stack slots across the calls in between: the class tests ran on one copy and the read's size
 * was filled from the other. 6.12+ verifiers carry the tested bounds to the other slot through the spilled
 * scalars' shared id; 5.14 happened to pass; 6.1 and 6.8 did not, and refused every write program with "R2
 * unbounded memory access" and the read return with "invalid access to memory, mem_size=592 off=80 size=32768"
 * (a 512 B record read at the 32 KiB bound), so capture was unavailable on the CI distro. barrier_var makes n
 * opaque to clang, so the clamp stays as instructions, and with nothing between it and the helper the size's
 * bound is in the register the helper is passed on every kernel. bpf/tests TestSSLEmitClampsBeforeTheRead holds
 * the shape.
 *
 * Returns 1 when this chunk never reached the ring, so the caller can mark the rest of the call (I2): a hole
 * userspace cannot see in seq is a body recorded as complete that is not. A chunk whose bytes could not be read
 * reached it, carrying the hole's length, and returns 0. */
static __always_inline __u8 tego_ssl_emit_class(void *ring, const struct tego_run *run, __u64 cgroup_id,
                                                 __u64 ssl_ptr, __u8 dir, const __u8 *buf, __u32 n, __u8 trunc,
                                                 __u64 skipped, __u32 seq, const __u32 cls)
{
    const __u32 size = sizeof(struct tego_ev_ssl) + cls;
    struct tego_ev_ssl_chunk *e;

    barrier_var(n);
    if (n > cls)
        n = cls;
    e = bpf_ringbuf_reserve(ring, size, 0);
    if (!e) {
        /* With no record there is nothing to carry a mark: the connection's next chunk shows the hole in
         * seq, and the run's counter says how many chunks went (I7). It is capture's own counter, not the
         * record's tego_lost, which each source would otherwise report as its own drops (ADR 0026 (4)). */
        tego_lost_inc(&tego_capture_lost, run->run_idx);
        return 1;
    }
    tego_ssl_meta(&e->meta, size, run, cgroup_id, ssl_ptr, dir, n, trunc, seq, skipped);
    /* The tail of data past len is not cleared: userspace reads exactly len bytes, and zeroing the class per
     * chunk would cost more than the copy itself. The header's len is what bounds every reader. */
    barrier_var(n);
    if (n > cls)
        n = cls;
    if (bpf_probe_read_user(e->data, n, buf) != 0) {
        /* The record is already reserved, so this loss can be named instead of discarded: a zero-length chunk
         * whose hole is this chunk's own bytes and whatever tail it carried tells the reader exactly which
         * (cgroup, ssl_ptr, direction) lost how many bytes, and httpstream steps over it inside a body as over
         * R6's tail. Nothing reached the ring out of order and nothing is missing from it, so it is not a
         * ring-buffer drop, and the call's later parts need no mark. */
        e->meta.len = 0;
        e->meta.hole = TEGO_SSL_HOLE_UNREADABLE;
        e->meta.skipped = skipped + n;
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Records one chunk of plaintext, and reports whether its bytes reached the ring (tego_ssl_emit_class). The
 * record is the smallest of R6's size classes that holds the chunk, so a stream of small reads costs the ring
 * what it carries and not 32 KiB a chunk.
 *
 * skipped is how many bytes of the call follow this chunk's and are not emitted (R6's tail), carried on the
 * record so the reader knows where the hole ends (#8). */
static __always_inline __u8 tego_ssl_emit(void *ring, const struct tego_run *run, __u64 cgroup_id,
                                           __u64 ssl_ptr, __u8 dir, const __u8 *buf, __u32 len, __u8 trunc,
                                           __u64 skipped)
{
    __u32 n = len, seq;

    if (n == 0)
        return 0;
    if (n > TEGO_SSL_CHUNK_MAX)
        n = TEGO_SSL_CHUNK_MAX;
    /* Numbered before the reserve, so a chunk that never reaches the ring still uses its number up and the
     * reader finds the hole at the connection's next chunk (I2). */
    seq = tego_ssl_next_seq(ssl_ptr);
    if (n <= TEGO_SSL_CLASS_SMALL)
        return tego_ssl_emit_class(ring, run, cgroup_id, ssl_ptr, dir, buf, n, trunc, skipped, seq,
                                    TEGO_SSL_CLASS_SMALL);
    if (n <= TEGO_SSL_CLASS_MEDIUM)
        return tego_ssl_emit_class(ring, run, cgroup_id, ssl_ptr, dir, buf, n, trunc, skipped, seq,
                                    TEGO_SSL_CLASS_MEDIUM);
    return tego_ssl_emit_class(ring, run, cgroup_id, ssl_ptr, dir, buf, n, trunc, skipped, seq, TEGO_SSL_CHUNK_MAX);
}

/* Records a call whose bytes are not read at all as one zero-length chunk: it takes the connection's next
 * number and says how many bytes the call moved (skipped) and why none are here (hole). A read whose scratch
 * row outlived TEGO_SSL_MAX_CALL_NS is one (§6 #3): the buffer the row names may be another process's, so it
 * is not read, but the call's bytes were on the wire, and dropping them without a number let the next response
 * on the connection pair with this one's request. The record is the head alone. */
static __always_inline void tego_ssl_hole(void *ring, const struct tego_run *run, __u64 cgroup_id,
                                           __u64 ssl_ptr, __u8 dir, __u64 skipped, __u8 why)
{
    struct tego_ev_ssl *e;
    __u32 seq = tego_ssl_next_seq(ssl_ptr);

    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_capture_lost, run->run_idx);
        return;
    }
    tego_ssl_meta(e, sizeof(*e), run, cgroup_id, ssl_ptr, dir, 0, 0, seq, skipped);
    e->hole = why;
    bpf_ringbuf_submit(e, 0);
}

/* Emits chunk number `chunk` of one call, if the call reached that far, and returns whether anything of the
 * call has been lost by the end of it. `lost` is that same answer for the parts before this one: it marks
 * this chunk truncated, so the reader learns of the hole that precedes it, and passes straight through when
 * this part is past the end of the call. The last part a call can have carries the length of the tail R6
 * drops, so the reader knows where the hole ends (#8). */
static __always_inline __u8 tego_ssl_part(void *ring, const struct tego_run *run, __u64 cgroup_id,
                                           __u64 ssl_ptr, __u8 dir, const __u8 *buf, __u64 total, __u8 chunk,
                                           __u8 lost)
{
    __u64 off = (__u64)chunk * TEGO_SSL_CHUNK_MAX;
    __u64 left, skipped = 0;

    if (off >= total)
        return lost;
    left = total - off;
    if (left > TEGO_SSL_CHUNK_MAX)
        left = TEGO_SSL_CHUNK_MAX;
    if (chunk == TEGO_SSL_CHUNKS_MAX - 1)
        skipped = total - off - left;
    return lost | tego_ssl_emit(ring, run, cgroup_id, ssl_ptr, dir, buf + off, (__u32)left, lost, skipped);
}

/* Splits one call into at most TEGO_SSL_CHUNKS_MAX chunks (R6). The four calls are written out rather than
 * looped: a loop here would be a verifier risk for no gain, and the ring-buffer discipline of §8 I7 is
 * easiest to check when every reserve is on a straight line. The `lost` value is threaded through them so a
 * chunk that never reached the ring marks the ones that follow it in the same call (I2). */
static __always_inline void tego_ssl_capture(void *ring, const struct tego_run *run, __u64 cgroup_id,
                                              __u64 ssl_ptr, __u8 dir, const void *buf, __u64 total)
{
    const __u8 *base = (const __u8 *)buf;
    __u8 lost = 0;

    if (!base || total == 0)
        return;
    lost = tego_ssl_part(ring, run, cgroup_id, ssl_ptr, dir, base, total, 0, lost);
    lost = tego_ssl_part(ring, run, cgroup_id, ssl_ptr, dir, base, total, 1, lost);
    lost = tego_ssl_part(ring, run, cgroup_id, ssl_ptr, dir, base, total, 2, lost);
    (void)tego_ssl_part(ring, run, cgroup_id, ssl_ptr, dir, base, total, 3, lost);
}

/* Records an in-flight read so the return probe can find its buffer. Both rows are last-write-wins: a
 * thread re-entering SSL_read from a callback pairs its inner call correctly and loses the outer one, which
 * is a missing read rather than a wrong one. */
static __always_inline void tego_ssl_enter(__u64 ssl_ptr, __u64 buf, __u64 len_ptr, __u8 call)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct tego_ssl_key key = {};
    struct tego_ssl_scratch val = {};

    key.pid_tgid = id;
    key.ssl_ptr = ssl_ptr;
    val.buf = buf;
    val.len_ptr = len_ptr;
    val.enter_ns = bpf_ktime_get_ns();
    val.call = call;
    bpf_map_update_elem(&tego_ssl_reads, &key, &val, BPF_ANY);
    bpf_map_update_elem(&tego_ssl_current, &id, &ssl_ptr, BPF_ANY);
}

/* Returns the SSL* of this thread's innermost in-flight read and forgets it, or 0. */
static __always_inline __u64 tego_ssl_take_current(__u64 id)
{
    __u64 *slot = bpf_map_lookup_elem(&tego_ssl_current, &id);
    __u64 ssl_ptr;

    if (!slot)
        return 0;
    ssl_ptr = *slot;
    bpf_map_delete_elem(&tego_ssl_current, &id);
    return ssl_ptr;
}

/* Copies out the scratch row for (pid_tgid, ssl_ptr) and forgets it. Returns 0 on success. */
static __always_inline int tego_ssl_take_scratch(__u64 id, __u64 ssl_ptr, struct tego_ssl_scratch *out)
{
    struct tego_ssl_key key = {};
    struct tego_ssl_scratch *row;

    key.pid_tgid = id;
    key.ssl_ptr = ssl_ptr;
    row = bpf_map_lookup_elem(&tego_ssl_reads, &key);
    if (!row)
        return -ENOENT;
    *out = *row;
    bpf_map_delete_elem(&tego_ssl_reads, &key);
    return 0;
}

/* SSL_write(SSL *ssl, const void *buf, int num): the universal entry point Node, libcurl and CPython 3.9
 * call, and the one always hooked when present (R1). num is an int, so it is narrowed before use and a
 * non-positive value is not a call that moved anything. */
__attribute__((always_inline))
SEC("uprobe")
int tego_ssl_write(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    void *ring;
    __s32 num;

    if (!run)
        return 0;
    num = (__s32)PT_REGS_PARM3(ctx);
    if (num > 0)
        tego_activity_stamp(&tego_activity, run);
    if (!tego_recording(run))
        return 0;
    ring = tego_capture_ring(run);
    if (!ring)
        return 0;
    if (num <= 0)
        return 0;
    tego_ssl_capture(ring, run, cgroup_id, (__u64)PT_REGS_PARM1(ctx), TEGO_SSL_WRITE,
                      (const void *)PT_REGS_PARM2(ctx), (__u64)(__u32)num);
    return 0;
}

/* SSL_write_ex(SSL *, const void *buf, size_t num, size_t *written) and SSL_write_ex2(SSL *, const void
 * *buf, size_t num, uint64_t flags, size_t *written): the third argument is a size_t in both, and it is the
 * length the caller asked for. Exactly one of the two is ever attached (R2). */
__attribute__((always_inline))
SEC("uprobe")
int tego_ssl_write_ex(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    void *ring;

    if (!run)
        return 0;
    if ((__u64)PT_REGS_PARM3(ctx) > 0)
        tego_activity_stamp(&tego_activity, run);
    if (!tego_recording(run))
        return 0;
    ring = tego_capture_ring(run);
    if (!ring)
        return 0;
    tego_ssl_capture(ring, run, cgroup_id, (__u64)PT_REGS_PARM1(ctx), TEGO_SSL_WRITE,
                      (const void *)PT_REGS_PARM2(ctx), (__u64)PT_REGS_PARM3(ctx));
    return 0;
}

/* SSL_read(SSL *ssl, void *buf, int num) entry: the buffer is empty now, so only where it is and when the
 * call began are recorded (R3). */
__attribute__((always_inline))
SEC("uprobe")
int tego_ssl_read(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    void *ring;

    if (!run || !tego_recording(run))
        return 0;
    ring = tego_capture_ring(run);
    if (!ring)
        return 0;
    tego_ssl_enter((__u64)PT_REGS_PARM1(ctx), (__u64)PT_REGS_PARM2(ctx), 0, TEGO_SSL_CALL_READ);
    return 0;
}

/* SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes) entry: the length will be at *readbytes,
 * whose address is recorded with the buffer. CPython 3.10+ uses only the _ex calls. */
__attribute__((always_inline))
SEC("uprobe")
int tego_ssl_read_ex(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    void *ring;

    if (!run || !tego_recording(run))
        return 0;
    ring = tego_capture_ring(run);
    if (!ring)
        return 0;
    tego_ssl_enter((__u64)PT_REGS_PARM1(ctx), (__u64)PT_REGS_PARM2(ctx), (__u64)PT_REGS_PARM4(ctx),
                    TEGO_SSL_CALL_READ_EX);
    return 0;
}

/* The shared return probe for both reads. A uretprobe sees no arguments, so the thread's own row in
 * tego_ssl_current names the SSL* whose scratch row holds the buffer (R5).
 *
 * The length rule is R3's, and it is the whole of the difference between the two entry points: SSL_read's
 * length is its return value and only a positive one counts; SSL_read_ex's is *readbytes and only when the
 * return is 1. A zero length is a renegotiation or KeyUpdate moving no application data and produces no
 * record at all (§6 edge case #14).
 *
 * A pair further apart than TEGO_SSL_MAX_CALL_NS is not trusted: pid reuse inside the scratch map's lifetime
 * could pair a stale row with a new process's SSL* at the same address (§6 edge case #3). Its buffer is not
 * read, but the call it returns from did move bytes on this connection, so it is still numbered and emitted
 * as a hole (tego_ssl_hole): dropped without a trace, it let the next response on a keep-alive connection
 * pair with this one's request. An SSL_read_ex that returned 1 but whose *readbytes cannot be read is a hole
 * of unknown length, skipped 0: TEGO_SSL_HOLE_STALE when its row is stale, TEGO_SSL_HOLE_NOLENGTH otherwise.
 * A readable *readbytes of 0 is edge case #13's "no data" and emits nothing (#14).
 */
__attribute__((always_inline))
SEC("uretprobe")
int tego_ssl_read_return(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    void *ring;
    struct tego_ssl_scratch val = {};
    __u64 id, ssl_ptr, length = 0, readbytes = 0;
    __s32 ret;
    int stale;

    if (!run)
        return 0;
    /* Both reads return > 0 exactly when they moved application data: SSL_read its byte count, SSL_read_ex 1. */
    ret = (__s32)PT_REGS_RC(ctx);
    if (ret > 0)
        tego_activity_stamp(&tego_activity, run);
    if (!tego_recording(run))
        return 0;
    ring = tego_capture_ring(run);
    if (!ring)
        return 0;
    id = bpf_get_current_pid_tgid();
    ssl_ptr = tego_ssl_take_current(id);
    if (ssl_ptr == 0) {
        /* No row names the SSL* (the LRU evicted it, or a read re-entered from a callback took it), so no
         * connection can be marked; a call that moved bytes (both reads return > 0 exactly then) is counted
         * as a lost chunk, which userspace reports as a gap rather than the read vanishing (R5). */
        if (ret > 0)
            tego_lost_inc(&tego_capture_lost, run->run_idx);
        return 0;
    }
    if (tego_ssl_take_scratch(id, ssl_ptr, &val) != 0) {
        /* The connection is known but the read's row is gone, evicted under a burst (R5): its buffer and,
         * for SSL_read_ex, its length are unknown, so it is a hole of unknown length (skipped 0) that still
         * takes the connection's next number. Dropped without one, the next response on the connection
         * paired with this one's request. */
        if (ret > 0)
            tego_ssl_hole(ring, run, cgroup_id, ssl_ptr, TEGO_SSL_READ, 0, TEGO_SSL_HOLE_EVICTED);
        return 0;
    }
    stale = bpf_ktime_get_ns() - val.enter_ns > TEGO_SSL_MAX_CALL_NS;
    if (val.call == TEGO_SSL_CALL_READ) {
        if (ret <= 0)
            return 0;
        length = (__u64)(__u32)ret;
    } else {
        if (ret != 1 || val.len_ptr == 0)
            return 0;
        if (bpf_probe_read_user(&readbytes, sizeof(readbytes), (const void *)val.len_ptr) != 0) {
            /* The call succeeded, so it moved bytes, but how many is unknown: the slot faulted (a page the
             * non-sleepable probe cannot fault in, or another thread unmapped it). A hole of unknown length
             * takes the connection's next number; returning here without one let the next response on a
             * keep-alive connection pair with this one's request. Stale or not, the buffer is not read. */
            tego_ssl_hole(ring, run, cgroup_id, ssl_ptr, TEGO_SSL_READ, 0,
                           stale ? TEGO_SSL_HOLE_STALE : TEGO_SSL_HOLE_NOLENGTH);
            return 0;
        }
        length = readbytes;
    }
    if (stale) {
        tego_ssl_hole(ring, run, cgroup_id, ssl_ptr, TEGO_SSL_READ, length, TEGO_SSL_HOLE_STALE);
        return 0;
    }
    tego_ssl_capture(ring, run, cgroup_id, ssl_ptr, TEGO_SSL_READ, (const void *)val.buf, length);
    return 0;
}

/* SSL_free(SSL *ssl) entry: the connection this SSL* named is over, which nothing else here can see (R3a).
 * glibc hands a freed SSL_CONNECTION's chunk to the next SSL_new, so without this a new connection at the
 * same address on the same thread continued the old one's framing: after an aborted Content-Length response the
 * new connection's responses were swallowed as the old body and recorded as a complete one; after an aborted
 * chunked one every later exchange was lost; a close-delimited one ended only at Stop. The close record names
 * the pointer and the process, and userspace closes that process's connections on it, whatever thread did
 * their I/O.
 *
 * The thread's own chunk counter for the pointer goes too, so a new connection on it counts from 1: were this
 * record lost to a full ring, the new connection's first chunk is still a hole on the old one, which the reader
 * gaps rather than splice. A free on another thread than the one that did the I/O leaves that thread's counter,
 * which the record's close makes harmless: the reader starts the new connection wherever its count starts.
 *
 * SSL_free drops a reference, and frees only at the last (SSL_up_ref takes another), so a record can come
 * before the SSL* is really gone; a connection that goes on after it is a new one to the reader, whose first
 * bytes are the rest of a message and are passed over and counted (R18), never paired. */
__attribute__((always_inline))
SEC("uprobe")
int tego_ssl_free(struct pt_regs *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct tego_run *run = tego_run_lookup(&tego_run_set, cgroup_id);
    void *ring;
    struct tego_ev_ssl_close *e;
    struct tego_ssl_key key = {};
    __u64 ssl_ptr;

    if (!run || !tego_recording(run))
        return 0;
    ring = tego_capture_ring(run);
    if (!ring)
        return 0;
    ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    if (ssl_ptr == 0)
        return 0;
    key.pid_tgid = bpf_get_current_pid_tgid();
    key.ssl_ptr = ssl_ptr;
    bpf_map_delete_elem(&tego_ssl_seq, &key);
    e = bpf_ringbuf_reserve(ring, sizeof(*e), 0);
    if (!e) {
        tego_lost_inc(&tego_capture_lost, run->run_idx);
        return 0;
    }
    tego_hdr_fill(&e->hdr, TEGO_EV_SSL_CLOSE, sizeof(*e), run, cgroup_id);
    e->ssl_ptr = ssl_ptr;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Fixed operation cookies: bounded userspace offsets select the same existing
 * handlers, which each require both run membership and that run's capture ring.
 * Unknown cookies do nothing, including leaving another read's scratch intact. */
#define TEGO_SSL_COOKIE_WRITE 1
#define TEGO_SSL_COOKIE_WRITE_EX 2
#define TEGO_SSL_COOKIE_READ 3
#define TEGO_SSL_COOKIE_READ_EX 4
#define TEGO_SSL_COOKIE_FREE 5

SEC("uprobe.multi")
int tego_ssl_multi_enter(struct pt_regs *ctx)
{
    switch (bpf_get_attach_cookie(ctx)) {
    case TEGO_SSL_COOKIE_WRITE:
        return tego_ssl_write(ctx);
    case TEGO_SSL_COOKIE_WRITE_EX:
        return tego_ssl_write_ex(ctx);
    case TEGO_SSL_COOKIE_READ:
        return tego_ssl_read(ctx);
    case TEGO_SSL_COOKIE_READ_EX:
        return tego_ssl_read_ex(ctx);
    case TEGO_SSL_COOKIE_FREE:
        return tego_ssl_free(ctx);
    default:
        return 0;
    }
}

SEC("uretprobe.multi")
int tego_ssl_multi_return(struct pt_regs *ctx)
{
    __u64 cookie = bpf_get_attach_cookie(ctx);
    if (cookie == TEGO_SSL_COOKIE_READ || cookie == TEGO_SSL_COOKIE_READ_EX)
        return tego_ssl_read_return(ctx);
    return 0;
}
