# SPDX-License-Identifier: Apache-2.0
"""Builds the chain vectors' inputs (spec/record/v1/CHAIN.md, ADR 0017, ADR 0146).

Each case below is an input made from the frozen fixture run `../../fixtures/profiles.jsonl` (run_start, one write,
run_end) and its anchor, changed one way, and an expectation written by hand from CHAIN.md: the `expect` literals are
the vectors' content, never computed. The script computes only what a writer would have: the ids of lines it rewrites
(sha256 of the line with the id zeroed, CHAIN.md §4, with Python's hashlib, a third implementation of the digest beside
Go's and Rust's). Run it from anywhere; it rewrites every NNN-*.json here.

Segments: {"text": s} is s as UTF-8; {"hex": h} raw bytes; {"repeat": s, "count": n} s n times.
"""

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "..", "fixtures")
RUN = "r-3f9c2a1b-0dllq06ts7400-p3fl15"
OTHER = "r-3f9c2a1b-0dllq06ts7400-aaaaaa"
ZERO = "0" * 64

with open(os.path.join(FIX, "profiles.jsonl"), "rb") as f:
    BASE = f.read().split(b"\n")[:3]
with open(os.path.join(FIX, "profiles.chain.log"), "rb") as f:
    ANCHOR = f.read()


def rehash(line: bytes) -> bytes:
    """Sets the id of a canonical line to the digest of its bytes (CHAIN.md §4)."""
    m = re.match(rb'(\{"v":-?\d+,"seq":\d+,"id":")([0-9a-f]{64})(")', line)
    assert m, line[:60]
    zeroed = line[: m.start(2)] + ZERO.encode() + line[m.end(2):]
    return line[: m.start(2)] + hashlib.sha256(zeroed).hexdigest().encode() + line[m.end(2):]


def id_of(line: bytes) -> bytes:
    return re.search(rb'"id":"([0-9a-f]{64})"', line).group(1)


def set_prev(line: bytes, prev: bytes) -> bytes:
    return re.sub(rb'"prev":"[0-9a-f]*"', b'"prev":"' + prev + b'"', line, count=1)


def chain(lines):
    """Rewrites prev and id of each line in order, as a writer would have written them."""
    out, prev = [], b""
    for l in lines:
        l = rehash(set_prev(l, prev))
        out.append(l)
        prev = id_of(l)
    return out


def sub(line: bytes, old: bytes, new: bytes) -> bytes:
    assert old in line, old
    return line.replace(old, new, 1)


L0, L1, L2 = BASE
assert chain(BASE) == BASE, "the fixture must be a chain already"


def nl(lines, end=b"\n"):
    return b"".join(l + end for l in lines)


def anchor_for(head: bytes, run=RUN) -> bytes:
    return run.encode() + b" " + head + b"\n"


def text(b: bytes):
    return [{"text": b.decode("utf-8")}] if _utf8(b) else [{"hex": b.hex()}]


def _utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


CASES = []


def case(name, rule, expect, events=None, anchor=None, dir=RUN, events_segments=None):
    """events: bytes, or None for no events.jsonl; anchor: bytes, None (not given) or "absent"."""
    v = {"name": name, "rule": rule, "dir": dir}
    if events_segments is not None:
        v["events"] = events_segments
    else:
        v["events"] = None if events is None else text(events)
    if anchor is None:
        v["anchor"] = None
    elif anchor == "absent":
        v["anchor"] = "absent"
    else:
        v["anchor"] = text(anchor)
    v["expect"] = expect
    CASES.append(v)


def E(verdict, reason, lines=None, head_line=None, line=None, **kw):
    e = {"verdict": verdict, "reason": reason}
    if line is not None:
        e["line"] = line
    if lines is not None:
        e["lines"] = lines
    if head_line is not None:
        e["head_line"] = head_line
    e.update(kw)
    return e


good = nl(BASE)
H2 = id_of(L2)

# --- Good chains ---
case("good-anchored", "§5, §7: a whole run whose head chain.log anchors",
     E("match", "ok", lines=3, head_line=2, anchored=True), good, ANCHOR)
case("good-unanchored", "§7: without an anchor the chain alone is checked",
     E("match", "ok", lines=3, head_line=2, anchored=False), good)
case("good-not-ended-empty-anchor", "§7: a run that has not ended owes no anchor line",
     E("match", "ok", lines=2, head_line=1, anchored=False), nl([L0, L1]), b"")
torn = b'{"v":1,"seq":2,"id":"927b0221'
case("good-torn-tail", "§2: an unterminated tail that does not read as a line is a torn tail, skipped",
     E("match", "ok", lines=2, head_line=1, torn_bytes=len(torn)), nl([L0, L1]) + torn)
newer1 = sub(L1, b'{"v":1,', b'{"v":2,')
nb = chain([L0, newer1, L2])
case("good-newer-line", "§5: a newer version's line is linked by its chain fields and counted",
     E("match", "ok", lines=3, head_line=2, newer=1, anchored=True), nl(nb), anchor_for(id_of(nb[2])))
case("good-last-line-lost-newline", "§2: an unterminated last line that reads as a line is a line",
     E("match", "ok", lines=3, head_line=2, anchored=True), nl([L0, L1]) + L2, ANCHOR)
crl = []
prev = b""
for l in BASE:
    l2 = rehash(set_prev(l, prev) + b"\r")
    crl.append(l2)
    prev = id_of(l2)
case("good-crlf-hashed", "§2: a \\r before the \\n is a byte of the line, hashed, and white space to JSON",
     E("match", "ok", lines=3, head_line=2, anchored=True), nl(crl), anchor_for(id_of(crl[2])))
case("good-copy-under-another-name", "§6: a directory whose name is no run id checks the first line's run",
     E("match", "ok", lines=3, head_line=2, anchored=True), good, ANCHOR, dir="latest-copy")

# --- A changed byte in each field class (ids as written) ---
case("changed-common-string", "§4: a changed byte in agent", E("mismatch", "id-mismatch", lines=1, head_line=0, line=1),
     nl([L0, sub(L1, b'"agent":"retriever"', b'"agent":"retrievex"'), L2]), ANCHOR)
case("changed-common-number", "§4: a changed digit in pid", E("mismatch", "id-mismatch", lines=1, head_line=0, line=1),
     nl([L0, sub(L1, b'"pid":48212', b'"pid":48213'), L2]), ANCHOR)
case("changed-payload", "§4: a changed byte in a payload value", E("mismatch", "id-mismatch", lines=1, head_line=0, line=1),
     nl([L0, sub(L1, b'out/a.md', b'out/b.md'), L2]), ANCHOR)
case("changed-id", "§4: a changed digit in the id itself", E("mismatch", "id-mismatch", lines=1, head_line=0, line=1),
     nl([L0, sub(L1, b'"id":"2657', b'"id":"3657'), L2]), ANCHOR)
case("changed-first-line", "§4: a changed byte in run_start", E("mismatch", "id-mismatch", lines=0, line=0),
     nl([sub(L0, b'"commit":"5330a30"', b'"commit":"5330a31"'), L1, L2]), ANCHOR)
case("changed-prev-rehashed", "§5: prev not the id before it, the line's own id recomputed",
     E("mismatch", "chain-broken", lines=2, head_line=1, line=2),
     nl([L0, L1, rehash(sub(L2, b'"prev":"2657', b'"prev":"3657'))]), ANCHOR)
case("changed-seq-rehashed", "§5: seq not the line's number, id recomputed",
     E("mismatch", "chain-broken", lines=1, head_line=0, line=1),
     nl([L0, rehash(sub(L1, b'"seq":1,', b'"seq":5,')), L2]), ANCHOR)
ra = chain([L0, sub(L1, RUN.encode(), OTHER.encode()), L2])
case("changed-run-rehashed", "§6: a line of another run, its chain intact",
     E("mismatch", "run-mismatch", lines=2, head_line=1, line=1), nl(ra), anchor_for(id_of(ra[2])))
rs = chain([L0, sub(L1, b'"kind":"fs"', b'"kind":"run_start"'), L2])
case("changed-kind-rehashed", "§6: run_start where only line 0 may be one",
     E("mismatch", "run-shape", lines=2, head_line=1, line=1), nl(rs), anchor_for(id_of(rs[2])))
ts = chain([L0, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2026-09-22T09:00:00.002"'), L2])
case("changed-ts-rehashed", "§3: ts with no zone is no RFC 3339 date-time",
     E("mismatch", "line-malformed", lines=1, head_line=0, line=1), nl(ts), anchor_for(id_of(ts[2])))
mk = chain([L0, sub(L1, b'"agent":', b'"agenx":'), L2])
case("changed-key-rehashed", "§3: a common field missing",
     E("mismatch", "line-malformed", lines=1, head_line=0, line=1), nl(mk), anchor_for(id_of(mk[2])))

# --- Lines removed, moved, repeated, cut ---
case("removed-line", "§5: a line removed", E("mismatch", "chain-broken", lines=1, head_line=0, line=1),
     nl([L0, L2]), ANCHOR)
case("swapped-pair", "§5: two lines swapped", E("mismatch", "chain-broken", lines=1, head_line=0, line=1),
     nl([L0, L2, L1]), ANCHOR)
case("duplicated-line", "§5: a line written twice", E("mismatch", "chain-broken", lines=2, head_line=1, line=2),
     nl([L0, L1, L1, L2]), ANCHOR)
case("truncated-tail-anchored", "§7: run_end cut off; only the anchor tells",
     E("mismatch", "anchor-mismatch", lines=2, head_line=1), nl([L0, L1]), ANCHOR)
case("truncated-tail-unanchored", "§7: run_end cut off and no anchor given: not seen, said so",
     E("match", "ok", lines=2, head_line=1, anchored=False), nl([L0, L1]))
case("after-run-end-line", "§6: a whole line chained after run_end",
     E("mismatch", "after-run-end", lines=3, head_line=2, line=3),
     nl(chain([L0, L1, L2, sub(L1, b'"seq":1,', b'"seq":3,')])), anchor_for(id_of(chain([L0, L1, L2])[2])))
case("after-run-end-bytes", "§6: a torn tail after run_end",
     E("mismatch", "after-run-end", lines=3, head_line=2), good + b'{"v":1,"se', ANCHOR)
case("blank-line", "§2, §3: an empty line is a line and malformed",
     E("mismatch", "line-malformed", lines=1, head_line=0, line=1), nl([L0]) + b"\n" + nl([L1, L2]), ANCHOR)
case("crlf-converted", "§4: \\r\\n added after writing changes the hashed bytes",
     E("mismatch", "id-mismatch", lines=0, line=0), nl(BASE, b"\r\n"), ANCHOR)

# --- The anchor ---
case("anchor-wrong-head", "§7: chain.log anchors another line's id",
     E("mismatch", "anchor-mismatch", lines=3, head_line=2), good, anchor_for(id_of(L1)))
case("anchor-other-run-only", "§7: an ended run with no anchor line",
     E("mismatch", "anchor-missing", lines=3, head_line=2), good, anchor_for(H2, OTHER))
case("anchor-absent-file", "§7: an anchor path naming no file anchors nothing",
     E("mismatch", "anchor-missing", lines=3, head_line=2), good, "absent")
case("anchor-garbage-line", "§7: one line that is no anchor line makes the file unreadable",
     E("mismatch", "anchor-malformed", lines=3, head_line=2), good, ANCHOR + b"not an anchor line\n")
case("anchor-two-heads", "§7: two heads for the run",
     E("mismatch", "anchor-malformed", lines=3, head_line=2), good, ANCHOR + anchor_for(id_of(L1)))
case("anchor-same-line-twice", "§7: the same line twice is one anchor",
     E("match", "ok", lines=3, head_line=2, anchored=True), good, ANCHOR + ANCHOR)
case("anchor-torn-last-line", "§7: the run's line unterminated is a torn append, skipped",
     E("mismatch", "anchor-missing", lines=3, head_line=2), good, anchor_for(H2, OTHER) + ANCHOR[:-1])
case("anchor-trailing-space", "§7: nothing but one space between run and head",
     E("mismatch", "anchor-malformed", lines=3, head_line=2), good, ANCHOR[:-1] + b" \n")
case("anchor-run-id-invalid", "§7: with an anchor, a run with no run id cannot be looked up",
     E("mismatch", "run-id-invalid", lines=0), b"", ANCHOR, dir="latest-copy")
case("empty-ledger-anchored", "§7: an empty events.jsonl under an anchored run",
     E("mismatch", "anchor-mismatch", lines=0), b"", ANCHOR)
case("empty-ledger", "§6: no run_start is no run to check", E("cannot-check", "no-run-start"), b"")
case("no-ledger-anchored", "§7: events.jsonl gone under an anchored run", E("mismatch", "ledger-missing"), None, ANCHOR)
case("no-ledger", "§7: no events.jsonl and nothing anchors the run", E("cannot-check", "no-ledger"), None)

# --- Bounds ---
pad_key = b',"zpad":"'
def padded(total):
    """L1 with a payload string padded so the line, its \\n included, is total bytes."""
    base = L1[:-1] + pad_key + b'"}'
    n = total - len(base) - 1
    return rehash(L1[:-1] + pad_key + b"a" * n + b'"}')
def big_case(name, rule, expect, total):
    l1 = padded(total)
    assert len(l1) + 1 == total
    c = chain([L0, l1, L2])
    head, tail = c[1].split(b"a" * 64, 1)
    rest = tail.lstrip(b"a")
    count = len(c[1]) - len(head) - len(rest)
    segs = [{"text": (nl([c[0]]) + head).decode()}, {"repeat": "a", "count": count}, {"text": (rest + b"\n" + nl([c[2]])).decode()}]
    case(name, rule, expect, anchor=anchor_for(id_of(c[2])), events_segments=segs)
big_case("line-at-bound", "§2: a line of exactly 2 MiB, its \\n included",
         E("match", "ok", lines=3, head_line=2, anchored=True), 2 << 20)
big_case("line-over-bound", "§2: a line one byte over 2 MiB", E("mismatch", "line-too-long", lines=1, head_line=0, line=1),
         (2 << 20) + 1)
case("line-over-bound-garbage", "§2: an oversized line is refused before it is read",
     E("mismatch", "line-too-long", lines=1, head_line=0, line=1), anchor=ANCHOR,
     events_segments=[{"text": nl([L0]).decode()}, {"repeat": "x", "count": 2 << 20}, {"text": "\n"}])
def depth(n):
    return chain([L0, L1[:-1] + b',"deep":' + b"[" * n + b"1" + b"]" * n + b"}", L2])
d = depth(9999)
case("depth-at-bound", "§3: nesting 10000 deep, the line's object counted", E("match", "ok", lines=3, head_line=2, anchored=True),
     nl(d), anchor_for(id_of(d[2])))
d = depth(10000)
case("depth-over-bound", "§3: nesting 10001 deep", E("mismatch", "line-malformed", lines=1, head_line=0, line=1),
     nl(d), anchor_for(id_of(d[2])))

# --- Duplicate keys, UTF-8, escapes ---
def one(name, rule, expect, l1, finding=None):
    c = chain([L0, l1, L2])
    case(name, rule, expect, nl(c), anchor_for(id_of(c[2])))
    if finding:
        CASES[-1]["finding"] = finding
OK3 = E("match", "ok", lines=3, head_line=2, anchored=True)
BAD1 = E("mismatch", "line-malformed", lines=1, head_line=0, line=1)
one("duplicate-key", "§3: a top-level key twice", BAD1, sub(L1, b'"op":"open"', b'"op":"open","op":"open"'))
one("duplicate-key-escaped", "§3: a top-level key twice, once escaped", BAD1, sub(L1, b'"op":"open"', b'"op":"open","\\u006fp":"x"'))
one("duplicate-common-key", "§3: a common field twice", BAD1, sub(L1, b'"pid":48212', b'"pid":48212,"pid":48212'))
one("duplicate-key-nested", "§3: a key twice inside a payload object is content", OK3, sub(L1, b'"flags":577', b'"flags":577,"o":{"k":1,"k":2}'))
one("invalid-utf8-in-string", "§3: a byte that is no UTF-8 inside a string reads as U+FFFD", OK3, sub(L1, b'out/a.md', b'out/a\xff\xfe.md'))
one("invalid-utf8-outside-string", "§3: a byte that is no UTF-8 between members is no JSON", BAD1, sub(L1, b',"op":', b',\xff"op":'))
one("lone-surrogate-escape", "§3: a lone surrogate escape reads as U+FFFD", OK3, sub(L1, b'out/a.md', b'out/\\ud800a.md'))
one("lone-surrogate-key", "§3: a key with a lone surrogate escape", OK3, sub(L1, b'"flags":577', b'"flags":577,"\\udc00":1'))
one("control-char-in-string", "§3: a raw control character in a string is no JSON", BAD1, sub(L1, b'out/a.md', b'out/a\x01.md'))
one("trailing-comma", "§3: a trailing comma is no JSON", BAD1, L1[:-1] + b",}")
case("leading-space", "§4: white space before the object is not the canonical start", BAD1, nl([L0, b" " + L1, L2]), ANCHOR)
case("id-upper-case", "§4: an id in upper-case hex", BAD1, nl([L0, sub(L1, id_of(L1), id_of(L1).upper()), L2]), ANCHOR)

# --- Integer boundaries ---
one("mono-ns-max", "§3: mono_ns at 2^64-1", OK3, sub(L1, b'"mono_ns":812347000000', b'"mono_ns":18446744073709551615'))
one("mono-ns-over", "§3: mono_ns at 2^64", BAD1, sub(L1, b'"mono_ns":812347000000', b'"mono_ns":18446744073709551616'))
one("pid-max", "§3: pid at 2^63-1", OK3, sub(L1, b'"pid":48212', b'"pid":9223372036854775807'))
one("pid-min", "§3: pid at -2^63", OK3, sub(L1, b'"pid":48212', b'"pid":-9223372036854775808'))
one("pid-over", "§3: pid at 2^63", BAD1, sub(L1, b'"pid":48212', b'"pid":9223372036854775808'))
one("cgroup-negative", "§3: cgroup below 0", BAD1, sub(L1, b'"cgroup":44821', b'"cgroup":-1'))
one("cgroup-negative-zero", "§3: unsigned fields are digits only, so -0 is not one", BAD1, sub(L1, b'"cgroup":44821', b'"cgroup":-0'))
one("pid-negative-zero", "§3: pid is a - and digits, so -0 is one", OK3, sub(L1, b'"pid":48212', b'"pid":-0'))
one("tid-fraction", "§3: tid with a fraction", BAD1, sub(L1, b'"tid":48212', b'"tid":48212.0'))
one("step-exponent", "§3: attribution.step with an exponent", BAD1, sub(L1, b'"step":1', b'"step":1e0'))
one("step-case-wrong-type", "§3: attribution's Step, case aside step, holding a string", BAD1, sub(L1, b'"step":1', b'"Step":"one"'))
one("attribution-unknown-member", "§3: an attribution member the check does not read", OK3, sub(L1, b'"step":1', b'"step":1,"x":[1]'))

# --- Versions ---
case("version-zero", "§3, §5: v 0 is neither this version nor a newer one", BAD1,
     nl(chain([L0, sub(L1, b'{"v":1,', b'{"v":0,'), L2])), ANCHOR)
bad_newer = sub(nb[1], b'"path":"/srv/proj/out/a.md"', b'"path":"/srv/proj/out/b.md"')
case("newer-line-bad-digest", "§5: a newer line whose id is not its digest",
     E("mismatch", "id-mismatch", lines=1, head_line=0, line=1), nl([nb[0], bad_newer, nb[2]]), anchor_for(id_of(nb[2])))

# --- ts readings Go and the spec may read differently ---
one("ts-offset", "§3: ts with a +HH:MM offset", OK3, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2026-09-22T11:00:00.002+02:00"'))
one("ts-leap-day", "§3: ts on 29 February of a leap year", OK3, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2024-02-29T09:00:00Z"'))
one("ts-no-leap-day", "§3: ts on 29 February of a common year", BAD1, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2026-02-29T09:00:00Z"'))
one("ts-second-60", "§3: ts at second 60", BAD1, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2026-09-22T09:00:60Z"'))

one("ts-comma-fraction", "§3: a comma is no RFC 3339 fraction separator", BAD1, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2026-09-22T09:00:00,002Z"'))
one("ts-one-digit-hour", "§3: RFC 3339 hours are two digits", BAD1, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2026-09-22T9:00:00.002Z"'))
one("ts-lower-case-t", "§3: the date and time are joined by T", BAD1, sub(L1, b'"ts":"2026-09-22T09:00:00.002Z"', b'"ts":"2026-09-22t09:00:00.002Z"'))

# --- Unicode simple folding and signed version boundaries ---
one("attribution-dotless-i-unknown", "§3: U+0131 does not simple-fold to ASCII I; confıdence is unknown", OK3,
    sub(L1, b'"step":1', '"step":1,"confıdence":0'.encode()))
one("attribution-dotted-i-unknown", "§3: U+0130 does not simple-fold to ASCII I; confİdence is unknown", OK3,
    sub(L1, b'"step":1', '"step":1,"confİdence":0'.encode()))
one("version-max", "§3, §5: v at 2^63-1 is a newer version",
    E("match", "ok", lines=3, head_line=2, newer=1, anchored=True),
    sub(L1, b'{"v":1,', b'{"v":9223372036854775807,'))
one("version-over", "§3, §5: v at 2^63 is outside the signed 64-bit version range", BAD1,
    sub(L1, b'{"v":1,', b'{"v":9223372036854775808,'))
one("version-min", "§3, §5: v at -2^63 fits the version integer but is unsupported", BAD1,
    sub(L1, b'{"v":1,', b'{"v":-9223372036854775808,'))
one("version-under", "§3, §5: v below -2^63 is outside the signed 64-bit version range", BAD1,
    sub(L1, b'{"v":1,', b'{"v":-9223372036854775809,'))
one("attribution-long-s-wrong-type", "§3: U+017F simple-folds to ASCII S, so ſtep requires an integer", BAD1,
    sub(L1, b'"step":1', '"ſtep":"one"'.encode()))

# --- A refused timestamp cannot hide a whole final record as a torn tail ---
for name, timestamp in [
    ("comma-fraction", b"2026-09-22T09:00:00,003Z"),
    ("one-digit-hour", b"2026-09-22T9:00:00.003Z"),
    ("offset-hour-24", b"2026-09-22T09:00:00.003+24:00"),
    ("offset-minute-60", b"2026-09-22T09:00:00.003+00:60"),
]:
    for rewritten in [False, True]:
        final = sub(L2, b"2026-09-22T09:00:00.003Z", timestamp)
        if rewritten:
            final = rehash(final)
        for terminated in [True, False]:
            suffix = "terminated" if terminated else "unterminated"
            digest = "rehashed" if rewritten else "stale-digest"
            case(f"final-ts-{name}-{digest}-{suffix}",
                 "§2, §3: a complete JSON object is a record line; a refused timestamp is line-malformed even with a stale digest",
                 E("mismatch", "line-malformed", lines=2, head_line=1, line=2, torn_bytes=0),
                 nl([L0, L1]) + final + (b"\n" if terminated else b""), b"")

# --- Framing stays independent of grammar and semantic depth limits ---
final_deep = rehash(L2[:-1] + b',"deep":' + b"[" * 10000 + b"0" + b"]" * 10000 + b"}")
case("final-depth-over-bound-unterminated", "§2, §3: a closed final container is a line despite exceeding the JSON depth bound",
     E("mismatch", "line-malformed", lines=2, head_line=1, line=2, torn_bytes=0),
     nl([L0, L1]) + final_deep, b"")
final_bad_grammar = rehash(sub(L2, b'"reason":"exit"', b'"reason":'))
for terminated in [True, False]:
    suffix = "terminated" if terminated else "unterminated"
    case(f"final-closed-bad-grammar-{suffix}", "§2, §3: a closed final container is a line even when its JSON grammar is malformed",
         E("mismatch", "line-malformed", lines=2, head_line=1, line=2, torn_bytes=0),
         nl([L0, L1]) + final_bad_grammar + (b"\n" if terminated else b""), b"")

# --- Closing a value commits the entire final chunk to record checking, including its suffix ---
for suffix_name, suffix in [("garbage-byte", b"x"), ("opened-object", b'{"v":'), ("whitespace", b" \t\r")]:
    for bad_timestamp in [False, True]:
        final = L2
        if bad_timestamp:
            final = sub(final, b"2026-09-22T09:00:00.003Z", b"2026-09-22T09:00:00,003Z")
        for anchor_name, anchor in [("no-anchor", None), ("empty-anchor", b""), ("populated-anchor", ANCHOR)]:
            timestamp_name = "refused-ts-" if bad_timestamp else ""
            reason = "line-malformed" if bad_timestamp or suffix_name != "whitespace" else "id-mismatch"
            case(f"final-closed-{timestamp_name}{suffix_name}-{anchor_name}",
                 "§2, §3, §4: after a value closes, its entire unterminated chunk is checked; JSON whitespace is allowed but hashed",
                 E("mismatch", reason, lines=2, head_line=1, line=2, torn_bytes=0),
                 nl([L0, L1]) + final + suffix, anchor)

# Whitespace after a closed value is a complete line, not malformed JSON. Its digest covers the whitespace.
final_spaced = rehash(L2 + b" \t\r")
for anchor_name, anchor, expect in [
    ("no-anchor", None, E("match", "ok", lines=3, head_line=2, anchored=False, torn_bytes=0)),
    ("empty-anchor", b"", E("mismatch", "anchor-missing", lines=3, head_line=2, anchored=False, torn_bytes=0)),
    ("populated-anchor", anchor_for(id_of(final_spaced)), E("match", "ok", lines=3, head_line=2, anchored=True, torn_bytes=0)),
]:
    case(f"final-closed-whitespace-rehashed-{anchor_name}",
         "§2, §3, §4, §7: trailing JSON whitespace without a newline is a complete record line; its bytes are hashed",
         expect, nl([L0, L1]) + final_spaced, anchor)

for anchor_name, anchor in [("no-anchor", None), ("empty-anchor", b""), ("populated-anchor", ANCHOR)]:
    case(f"final-scalar-zero-digit-suffix-{anchor_name}",
         "§2, §3: the number zero closes before a second digit; retain the entire chunk and refuse its non-object shape",
         E("mismatch", "line-malformed", lines=2, head_line=1, line=2, torn_bytes=0),
         nl([L0, L1]) + b"01", anchor)

CASES = [c for c in CASES if c]


def main():
    for f in os.listdir(HERE):
        if re.match(r"\d{3}-.*\.json$", f):
            os.remove(os.path.join(HERE, f))
    for i, v in enumerate(CASES, 1):
        with open(os.path.join(HERE, f"{i:03d}-{v['name']}.json"), "w") as f:
            json.dump(v, f, indent=1, ensure_ascii=False)
            f.write("\n")
    print(f"{len(CASES)} vectors", file=sys.stderr)


if __name__ == "__main__":
    main()
