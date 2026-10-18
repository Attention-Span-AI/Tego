#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""soak_analyze.py -- reads a soak's samples.csv (soak.sh, soak_sample.py) and says what the run cost and what 20 hours of
it would cost, from the measured trends: tego's memory and descriptors, cpu, the agent's own progress rate, the
ledger's growth, and whether the ledger ever dropped, refused or stalled anything.

Usage: soak_analyze.py SOAK_DIR [ARM...]      (default: every arm under SOAK_DIR; also writes ARM/analysis.txt)
"""
import csv
import math
import os
import sys

TWENTY_H = 20 * 3600.0
TREND_MIN_S = 1200  # a trend fitted to less than this is noise: start-up, not growth


def fit(xs, ys):
    """Least-squares slope and intercept of ys over xs; no slope for a series shorter than TREND_MIN_S."""
    n = len(xs)
    if n < 3 or max(xs) - min(xs) < TREND_MIN_S:
        return 0.0, ys[-1] if ys else 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return slope, my - slope * mx


def fit_any(xs, ys):
    """Least-squares slope and intercept of ys over xs, whatever xs is."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return 0.0, my
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    return slope, my - slope * mx


def pct(vals, p):
    vals = sorted(vals)
    return vals[min(len(vals) - 1, int(math.ceil(p / 100 * len(vals))) - 1)] if vals else 0.0


def mb(kb):
    return "%.1f MB" % (kb / 1024)


def load(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            if k != "run":
                r[k] = float(v)
    return rows


def analyze(arm, rows, out):
    p = lambda *a: print(*a, file=out)
    segs = sorted({int(r["segment"]) for r in rows})
    live = [r for r in rows if r["tego_alive"] == 1]
    # one time axis across segments: each segment's own elapsed seconds, laid end to end
    t = {}
    offset = 0.0
    for s in segs:
        rs = [r for r in rows if int(r["segment"]) == s]
        for r in rs:
            t[id(r)] = offset + r["elapsed_s"]
        offset += max(r["elapsed_s"] for r in rs)
    span = offset
    p("== arm %s: %d samples in %d segment(s), %.2f h of run" % (arm, len(rows), len(segs), span / 3600))
    if not live:
        p("   no live sample")
        return
    warm = [r for r in live if t[id(r)] >= min(600, span * 0.1)]  # skip the first 10 minutes (or 10%): start-up growth
    warm = warm or live

    # -- events and the ledger ---------------------------------------------------------------------------------
    last = {s: [r for r in rows if int(r["segment"]) == s][-1] for s in segs}
    events = sum(r["events"] for r in last.values())
    ledger = sum(r["ledger_bytes"] for r in last.values())
    dirkb = sum(r["ledger_dir_kb"] for r in last.values())
    kinds = {k: sum(r[k] for r in last.values()) for k in ["ev_fs", "ev_exec", "ev_net", "ev_refused", "ev_model", "ev_gap", "ev_other"]}
    rate = events / span if span else 0
    bpe = ledger / events if events else 0
    sx = [t[id(r)] for r in warm]
    lslope, _ = fit(sx, [r["ledger_bytes"] for r in warm])  # bytes per second in steady state
    p("-- ledger")
    p("   events %d (%.1f/s)  fs %d  exec %d  net %d  refused %d  model-request %d  gap %d  other %d" % (
        events, rate, kinds["ev_fs"], kinds["ev_exec"], kinds["ev_net"], kinds["ev_refused"], kinds["ev_model"],
        kinds["ev_gap"], kinds["ev_other"]))
    p("   events.jsonl %.1f MB, %.0f bytes per event, directory %.1f MB on disk" % (ledger / 1e6, bpe, dirkb / 1024))
    p("   steady-state growth %.1f KB/s = %.1f MB/h" % (lslope / 1e3, lslope * 3600 / 1e6))
    free = min(r["disk_free_kb"] for r in live)
    p("   %s gap events: %d.  free space on the ledger's disk never below %.1f GB" % (
        "NO" if kinds["ev_gap"] == 0 else "SOME", kinds["ev_gap"], free / 1048576))

    # -- tego's own cost ---------------------------------------------------------------------------------------
    p("-- tego (the supervisor process)")
    rss = [r["tego_rss_kb"] for r in warm]
    slope, _ = fit(sx, rss)
    first, lastv = rss[0], rss[-1]
    p("   resident memory: after warm-up %s, end %s, max %s; trend %s" % (
        mb(first), mb(lastv), mb(max(r["tego_hwm_kb"] for r in live)),
        "%+.1f KB/h" % (slope * 3600) if span >= TREND_MIN_S else "n/a (under 20 minutes)"))
    if len(warm) >= 10 and warm[-1]["events"] > warm[0]["events"]:
        # growth per event: the same fit against the events seen so far, which is what a faster arm exercises
        ev_slope, _ = fit_any([r["events"] for r in warm], rss)
        p("   resident memory against events: %+.2f KB per million events (the fit over %d samples, %.2f million events)" % (
            ev_slope * 1e6, len(warm), (warm[-1]["events"] - warm[0]["events"]) / 1e6))
    fds = [r["tego_fds"] for r in live]
    fslope, _ = fit([t[id(r)] for r in live], fds)
    p("   open descriptors: min %d, max %d, end %d; trend %+.2f per hour" % (min(fds), max(fds), fds[-1], fslope * 3600))
    thr = [r["tego_threads"] for r in live]
    p("   threads: min %d, max %d" % (min(thr), max(thr)))
    cpu = []
    for a, b in zip(live, live[1:]):
        dt = b["ts"] - a["ts"]
        if dt > 0 and int(a["segment"]) == int(b["segment"]):
            cpu.append((b["tego_cpu_s"] - a["tego_cpu_s"]) / dt * 100)
    # the last row of a segment may be taken after tego ended (its counters read -1): the cpu is that of the last live row
    live_last = {s: [r for r in live if int(r["segment"]) == s][-1] for s in segs if any(int(r["segment"]) == s for r in live)}
    total_cpu = sum(r["tego_cpu_s"] for r in live_last.values())
    live_span = sum(r["elapsed_s"] for r in live_last.values())
    p("   cpu: %.1f%% of one core on average (p95 of the minutes %.1f%%, max %.1f%%); %.1f cpu-seconds in all" % (
        total_cpu / live_span * 100 if live_span else 0, pct(cpu, 95), max(cpu or [0]), total_cpu))

    if span >= 3600:  # the first and the last window after the first ten minutes: the same load, most of the run apart
        w = min(1800, span / 4)
        first_w = [r for r in live if 600 <= t[id(r)] < 600 + w]
        last_w = [r for r in live if span - w <= t[id(r)] <= span]

        def mean_of(rs, key):
            return sum(r[key] for r in rs) / len(rs) if rs else 0.0

        def rate_of(rs, key):
            return (rs[-1][key] - rs[0][key]) / max(t[id(rs[-1])] - t[id(rs[0])], 1) if len(rs) > 1 else 0.0
        p("   first %d minutes after warm-up against the last %d: resident %s -> %s (%+.2f MB), events/s %.1f -> %.1f, tego cpu %.2f%% -> %.2f%%" % (
            w / 60, w / 60, mb(mean_of(first_w, "tego_rss_kb")), mb(mean_of(last_w, "tego_rss_kb")),
            (mean_of(last_w, "tego_rss_kb") - mean_of(first_w, "tego_rss_kb")) / 1024,
            rate_of(first_w, "events"), rate_of(last_w, "events"),
            rate_of(first_w, "tego_cpu_s") * 100, rate_of(last_w, "tego_cpu_s") * 100))

    # -- the agent ----------------------------------------------------------------------------------------------
    p("-- the agent (what tego governs)")
    ag = [r for r in live if r["agent_alive"] == 1]
    if ag:
        a_rss = [r["agent_rss_kb"] for r in ag]
        aslope, _ = fit([t[id(r)] for r in ag], a_rss)
        p("   python process: resident %s at the start, %s at the end, max %s; trend %+.1f KB/h; open descriptors max %d" % (
            mb(a_rss[0]), mb(a_rss[-1]), mb(max(a_rss)), aslope * 3600, max(r["agent_fds"] for r in ag)))
        p("   its whole tree (python, the test script): peak %s; run cgroup memory.peak %s; pids max %d" % (
            mb(max(r["agent_tree_rss_kb"] for r in ag)), mb(max(r["cg_mem_peak_kb"] for r in ag)), max(r["cg_pids"] for r in ag)))
        cg = [r for r in ag if r["cg_cpu_s"] >= 0]
        p("   cpu of the run's cgroup: %.1f%% of one core" % (cg[-1]["cg_cpu_s"] / max(t[id(cg[-1])], 1) * 100 if cg else 0))
        steps = [(t[id(r)], r["agent_steps"]) for r in ag if r["agent_steps"] >= 0]
        if len(steps) > 4:
            q = max(1, len(steps) // 4)
            def srate(chunk):
                return (chunk[-1][1] - chunk[0][1]) / max(chunk[-1][0] - chunk[0][0], 1) * 60
            r1, r4 = srate(steps[:q + 1]), srate(steps[-q - 1:])
            p("   progress: %d steps in all; %.1f steps/min in the first quarter, %.1f in the last (%+.1f%%)" % (
                steps[-1][1], r1, r4, (r4 / r1 - 1) * 100 if r1 else 0))

    # -- the extrapolation --------------------------------------------------------------------------------------
    p("-- extrapolated to 20 hours (the measured steady state, linear; not a promise beyond what was run)")
    p("   ledger on disk: events.jsonl %.2f GB (%.0f events/s x %.0f bytes), directory about %.2f GB" % (
        lslope * TWENTY_H / 1e9, rate, bpe, dirkb / span * TWENTY_H / 1048576 if span else 0))
    more = max(0.0, TWENTY_H - span)
    p("   tego memory at 20 h: %s (end of this run %s, trend %+.1f KB/h)" % (
        mb(lastv + max(slope, 0) * more / 3600), mb(lastv), slope * 3600))
    p("   the events of 20 h at this rate: %.1f million; this run saw %.2f million" % (rate * TWENTY_H / 1e6, events / 1e6))
    p("   tego descriptors at 20 h: %d (end of this run %d)" % (fds[-1] + max(fslope, 0) * more, fds[-1]))
    p("   `tego events --verify` of a 20 h ledger reads %.2f GB once, start to end" % (lslope * TWENTY_H / 1e9))
    return {"rate": rate, "bpe": bpe, "slope": slope}


def main():
    soak = sys.argv[1]
    arms = sys.argv[2:] or sorted(d for d in os.listdir(soak) if os.path.exists(os.path.join(soak, d, "samples.csv")))
    for arm in arms:
        rows = load(os.path.join(soak, arm, "samples.csv"))
        with open(os.path.join(soak, arm, "analysis.txt"), "w") as f:
            analyze(arm, rows, f)
        with open(os.path.join(soak, arm, "analysis.txt")) as f:
            sys.stdout.write(f.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
