// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* ADR 0048 P2's exec-pin MAC: SipHash-2-4 under a run's 128-bit key over a framed input (a domain byte, the input's
 * length as 4 little-endian bytes, then the bytes), the kernel half of internal/execpin.MAC. The plane recomputes it
 * at sched_process_exec over the new image's own [arg_start, arg_end) and compares it with the pin the supervisor
 * wrote; the K0 probe (bpf/testonly/exec_pin_facts.bpf.c) holds this code to the Go implementation on every row.
 *
 * The input is absorbed 8 bytes at a time: after the 5-byte frame, every 8 bytes of data complete a message word
 * that starts 5 bytes into one data word and ends 3 bytes into the next, so a data word is split once (acc keeps the
 * part of the next message word it starts) and no byte loop runs except over the last partial word. No state field
 * is branched on, so a bpf_loop callback that absorbs words is verified the same way whatever the first state is
 * (bpf/tests callback_state_test.go). */
#ifndef TEGO_EXEC_PIN_H
#define TEGO_EXEC_PIN_H

/* The MAC domains, internal/execpin's Domain* values. */
#define TEGO_PIN_DOM_COVERED 1
#define TEGO_PIN_DOM_SCRIPT 2
#define TEGO_PIN_DOM_TAIL 3
#define TEGO_PIN_DOM_NAME 4 /* the image's final name, as its dentry holds it */
#define TEGO_PIN_DOM_PATH 5 /* bprm->filename: the spelling the kernel looked the image up by */

/* The frame's length in bytes: the domain byte and the 4-byte length. The data's words are split at it. */
#define TEGO_PIN_FRAME 5

/* The chunk the plane reads the argument area in, and the largest area a pin covers (supervisor.md R16's
 * DefaultMaxArgv, 128 KiB). */
#define TEGO_PIN_CHUNK 256
#define TEGO_PIN_MAX_LEN (128 * 1024)

struct tego_sip {
    __u64 v0, v1, v2, v3;
    __u64 acc;   /* the frame's tail and then each data word's last 3 bytes: the next message word's first 5 */
    __u32 total; /* message bytes absorbed so far, frame included; the final word takes its low byte */
    __u32 pad;
};

#define TEGO_ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

static __always_inline void tego_sip_round(struct tego_sip *s)
{
    s->v0 += s->v1;
    s->v1 = TEGO_ROTL64(s->v1, 13);
    s->v1 ^= s->v0;
    s->v0 = TEGO_ROTL64(s->v0, 32);
    s->v2 += s->v3;
    s->v3 = TEGO_ROTL64(s->v3, 16);
    s->v3 ^= s->v2;
    s->v0 += s->v3;
    s->v3 = TEGO_ROTL64(s->v3, 21);
    s->v3 ^= s->v0;
    s->v2 += s->v1;
    s->v1 = TEGO_ROTL64(s->v1, 17);
    s->v1 ^= s->v2;
    s->v2 = TEGO_ROTL64(s->v2, 32);
}

static __always_inline void tego_sip_compress(struct tego_sip *s, __u64 m)
{
    s->v3 ^= m;
    tego_sip_round(s);
    tego_sip_round(s);
    s->v0 ^= m;
}

/* tego_sip_begin starts a MAC of len data bytes in domain dom under the key (k0, k1), the key's two little-endian
 * halves, and absorbs the frame. */
static __always_inline void tego_sip_begin(struct tego_sip *s, __u64 k0, __u64 k1, __u8 dom, __u32 len)
{
    s->v0 = k0 ^ 0x736f6d6570736575ULL;
    s->v1 = k1 ^ 0x646f72616e646f6dULL;
    s->v2 = k0 ^ 0x6c7967656e657261ULL;
    s->v3 = k1 ^ 0x7465646279746573ULL;
    s->acc = (__u64)dom | (__u64)len << 8;
    s->total = TEGO_PIN_FRAME;
}

/* tego_sip_fix turns 8 data bytes loaded as one native word into the little-endian word SipHash defines. */
static __always_inline __u64 tego_sip_fix(__u64 w)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    w = __builtin_bswap64(w);
#endif
    return w;
}

/* tego_sip_le64 reads 8 data bytes at p as that word. */
static __always_inline __u64 tego_sip_le64(const __u8 *p)
{
    return tego_sip_fix(*(const __u64 *)p);
}

/* tego_sip_word absorbs 8 data bytes, w little-endian: the message word is acc's 5 bytes then w's first 3. */
static __always_inline void tego_sip_word(struct tego_sip *s, __u64 w)
{
    tego_sip_compress(s, s->acc | w << (8 * TEGO_PIN_FRAME));
    s->acc = w >> (64 - 8 * TEGO_PIN_FRAME);
    s->total += 8;
}

/* tego_sip_end absorbs the last n data bytes (0 to 7, the low bytes of w; the rest of w is ignored) and returns the
 * MAC. With the frame's 5 bytes in acc, n bytes make 5 + n: one more full word when n >= 3. */
static __always_inline __u64 tego_sip_end(struct tego_sip *s, __u64 w, __u32 n)
{
    __u64 last;

    n &= 7;
    w &= n ? (~0ULL >> (64 - 8 * n)) : 0;
    s->total += n;
    if (n >= 3) {
        tego_sip_compress(s, s->acc | w << (8 * TEGO_PIN_FRAME));
        last = w >> (64 - 8 * TEGO_PIN_FRAME);
    } else {
        last = s->acc | w << (8 * TEGO_PIN_FRAME);
    }
    last |= (__u64)(s->total & 0xff) << 56;
    tego_sip_compress(s, last);
    s->v2 ^= 0xff;
    tego_sip_round(s);
    tego_sip_round(s);
    tego_sip_round(s);
    tego_sip_round(s);
    return s->v0 ^ s->v1 ^ s->v2 ^ s->v3;
}

#endif
