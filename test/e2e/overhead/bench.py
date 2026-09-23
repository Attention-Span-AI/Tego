#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""bench.py — one benchmark cell for the overhead harness (test/e2e/overhead/run.sh).

A "cell" is one (workload, enforcement) pair: a prepare command that resets state (not timed) and
a run command that is timed, warmed up first and repeated a fixed number of times so the reported
number is a median with a spread, never a single sample (docs/BENCHMARKS.md explains why: process
launch and file-cache state are both noisy enough on a shared dev box that one run proves nothing).

Two measurement paths, chosen at import time so the harness works on a box without hyperfine:
  - hyperfine, if on PATH: `-p/--prepare` before every run, `-r/--runs` for an exact, reported
    count, `--export-json` so this script reads hyperfine's own per-run times rather than
    re-deriving them (single source of truth for the numbers that end up in the table).
  - a built-in loop: the same prepare/warmup/measure shape by hand, timed with
    time.perf_counter(). Slower to reach the same confidence (no outlier detection, no shell
    warmup tricks) but exercises the identical command sequence, so a box without hyperfine still
    gets real numbers instead of nothing.

Either path fails loudly (nonzero exit, message on stderr) the first time the timed command itself
fails: a benchmark that quietly averages in a broken run is worse than one that refuses to run at
all: it "never flatters the thing it measures."

Usage:
  bench.py measure --prepare CMD --command CMD --warmup N --runs N [--meta k=v ...]
      Prints one JSON object to stdout: the timing stats plus every --meta pair echoed back, so
      the caller (run.sh) never has to keep its own side table of which line was which cell. Runs
      exactly once, in the order called — used directly by the fixed-cost noop probe, where there
      is only ever one cell in flight; the workload matrix goes through "cell" + "run-matrix"
      instead, below, so it can be order-randomized.

  bench.py cell --workload W --tier T --record R --prepare CMD --command CMD [--meta k=v ...]
      Prints one JSON cell descriptor (kind: "cell") to stdout: run.sh appends these for every
      (workload, tier, record) combination up front, before any of them are timed, so the whole
      matrix can be built (contracts written, caches primed) before run-matrix decides what order
      to actually run them in.

  bench.py run-matrix CELLS.jsonl --warmup N --runs N --passes P [--seed N] [--meta k=v ...]
      Reads the cell descriptors, shuffles them (a fresh independent shuffle per pass — the matrix
      always ran "full" first and "off" last before this existed, which a monotonic drift in
      ambient machine load over a 15-minute run turns into a fake record-mode effect; P
      independent passes, each in its own random order, is what makes that impossible to hide
      behind) and measures each one, printing one JSON result per (cell, pass) as it completes.
      The seed used is printed to stderr so a run can be reproduced; --seed pins it.

  bench.py skip --meta k=v ...
      Prints one JSON object recording a matrix cell run.sh could not reach on this machine (a
      tier the doctor probe says is unavailable, a missing interpreter). Same --meta mechanism as
      measure, so a reason string is never hand-assembled into JSON by the shell.

  bench.py render FILE.jsonl
      Reads the measure lines (one JSON object per line: measured cells and the skipped rows
      run.sh appends for tiers this machine cannot reach) and prints the results table in the
      exact column order docs/BENCHMARKS.md commits to: workload, tier, record mode, bare median,
      enforced median, fixed cost, marginal cost, total overhead, runs, kernel, CPU. Every number
      is computed once, here, from the medians in the jsonl — never per-sample — so the table is
      reproducible from the raw file alone. Fixed cost comes from the "noop" workload's own
      bare-vs-enforced delta per (tier, record): a binary that does nothing isolates the run's
      fixed per-invocation cost by construction, and every other workload's delta has that term
      subtracted out to get a marginal, per-syscall cost distinct from the total percentage. Two
      passes that disagree by more than their combined spread are reported as disagreeing, in the
      table, rather than averaged into a number that looks precise and is not ("never
      flatters the thing it measures").
"""
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time


def run_shell(cmd, check=True):
    return subprocess.run(["bash", "-c", cmd], check=check)


def measure_hyperfine(prepare, command, warmup, runs):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    hf_cmd = [
        "hyperfine", "--shell", "bash",
        "--warmup", str(warmup), "--runs", str(runs),
        "--export-json", out_path,
    ]
    if prepare:
        hf_cmd += ["--prepare", prepare]
    hf_cmd += [command]
    try:
        proc = subprocess.run(hf_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stdout)
            sys.stderr.write(proc.stderr)
            raise SystemExit(f"bench.py: hyperfine exited {proc.returncode}: {command!r}")
        with open(out_path) as f:
            data = json.load(f)
    finally:
        # The export is read once and is not evidence; left in TMPDIR it piles up (the guest's /tmp is a tmpfs).
        try:
            os.unlink(out_path)
        except OSError:
            pass
    r = data["results"][0]
    bad = [c for c in r["exit_codes"] if c != 0]
    if bad:
        raise SystemExit(f"bench.py: {len(bad)}/{len(r['exit_codes'])} timed runs failed (exit {bad[0]}): {command!r}")
    return {
        "median_s": r["median"], "stddev_s": r["stddev"],
        "min_s": r["min"], "max_s": r["max"],
        "n": len(r["times"]), "method": "hyperfine", "times_s": r["times"],
    }


def measure_fallback(prepare, command, warmup, runs):
    # No outlier rejection, no shell-startup calibration: it is the loop hyperfine would run
    # without hyperfine's own care, which is why the harness prefers hyperfine when it is present.
    samples = []
    for i in range(warmup + runs):
        if prepare:
            run_shell(prepare)
        t0 = time.perf_counter()
        proc = run_shell(command, check=False)
        dt = time.perf_counter() - t0
        if proc.returncode != 0:
            raise SystemExit(f"bench.py: run {i} exited {proc.returncode}: {command!r}")
        if i >= warmup:
            samples.append(dt)
    return {
        "median_s": statistics.median(samples),
        "stddev_s": statistics.pstdev(samples) if len(samples) > 1 else 0.0,
        "min_s": min(samples), "max_s": max(samples),
        "n": len(samples), "method": "fallback-loop", "times_s": samples,
    }


def measure_one(prepare, command, warmup, runs):
    if shutil.which("hyperfine"):
        return measure_hyperfine(prepare, command, warmup, runs)
    return measure_fallback(prepare, command, warmup, runs)


def parse_meta(args, i, meta):
    k, _, v = args[i + 1].partition("=")
    meta[k] = v
    return i + 2


def cmd_measure(args):
    opts = {"prepare": "", "command": None, "warmup": 3, "runs": 10, "meta": {}}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--prepare":
            opts["prepare"] = args[i + 1]; i += 2
        elif a == "--command":
            opts["command"] = args[i + 1]; i += 2
        elif a == "--warmup":
            opts["warmup"] = int(args[i + 1]); i += 2
        elif a == "--runs":
            opts["runs"] = int(args[i + 1]); i += 2
        elif a == "--meta":
            i = parse_meta(args, i, opts["meta"])
        else:
            raise SystemExit(f"bench.py measure: unknown argument {a!r}")
    if not opts["command"]:
        raise SystemExit("bench.py measure: --command is required")
    stats = measure_one(opts["prepare"], opts["command"], opts["warmup"], opts["runs"])
    stats.update(opts["meta"])
    stats["kind"] = "measured"
    print(json.dumps(stats))


def cmd_cell(args):
    cell = {"prepare": "", "meta": {}}
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--workload", "--tier", "--record", "--prepare", "--command"):
            cell[a[2:]] = args[i + 1]; i += 2
        elif a == "--meta":
            i = parse_meta(args, i, cell["meta"])
        else:
            raise SystemExit(f"bench.py cell: unknown argument {a!r}")
    for req in ("workload", "tier", "record", "command"):
        if req not in cell:
            raise SystemExit(f"bench.py cell: --{req} is required")
    cell["kind"] = "cell"
    print(json.dumps(cell))


def cmd_run_matrix(args):
    if not args or args[0].startswith("-"):
        raise SystemExit("bench.py run-matrix: CELLS.jsonl path is required first")
    cells_path = args[0]
    opts = {"warmup": 3, "runs": 10, "passes": 2, "seed": None, "meta": {}}
    i = 1
    while i < len(args):
        a = args[i]
        if a == "--warmup":
            opts["warmup"] = int(args[i + 1]); i += 2
        elif a == "--runs":
            opts["runs"] = int(args[i + 1]); i += 2
        elif a == "--passes":
            opts["passes"] = int(args[i + 1]); i += 2
        elif a == "--seed":
            opts["seed"] = int(args[i + 1]); i += 2
        elif a == "--meta":
            i = parse_meta(args, i, opts["meta"])
        else:
            raise SystemExit(f"bench.py run-matrix: unknown argument {a!r}")

    cells = [json.loads(line) for line in open(cells_path) if line.strip()]
    base_seed = opts["seed"] if opts["seed"] is not None else random.SystemRandom().randrange(2**31)
    sys.stderr.write(f"bench.py run-matrix: {len(cells)} cells x {opts['passes']} passes, base seed {base_seed}\n")
    sys.stderr.flush()
    for p in range(1, opts["passes"] + 1):
        order = list(cells)
        # A fresh Random per pass, seeded off base_seed and the pass number: reproducible given
        # --seed, but pass 2's order is never pass 1's order, which is the point (an ordering
        # effect that happened to match a record-mode effect once should not survive a reshuffle).
        random.Random(base_seed + p).shuffle(order)
        sys.stderr.write(f"bench.py run-matrix: pass {p}/{opts['passes']} order: " +
                          ", ".join(f"{c['workload']}/{c['tier']}/{c['record']}" for c in order) + "\n")
        sys.stderr.flush()
        for c in order:
            stats = measure_one(c.get("prepare", ""), c["command"], opts["warmup"], opts["runs"])
            stats.update(c.get("meta", {}))
            stats.update(opts["meta"])
            stats["workload"] = c["workload"]
            stats["tier"] = c["tier"]
            stats["record"] = c["record"]
            stats["pass"] = p
            stats["kind"] = "measured"
            print(json.dumps(stats))
            sys.stdout.flush()


def cmd_skip(args):
    # A skipped tier still gets a row (its reason), never a silently missing one: run.sh calls
    # this the same way it calls "measure", passing every value through argv rather than building
    # JSON in shell, so a reason string with a quote or a "=" in it (doctor's own messages have
    # both) can never produce broken JSON.
    meta = {}
    i = 0
    while i < len(args):
        if args[i] == "--meta":
            k, _, v = args[i + 1].partition("=")
            meta[k] = v; i += 2
        else:
            raise SystemExit(f"bench.py skip: unknown argument {args[i]!r}")
    meta["kind"] = "skipped"
    print(json.dumps(meta))


def pool(rows):
    """Combine one or more measured rows for the same cell (one per pass) into one set of stats,
    pooling their raw per-run times rather than averaging medians — a true combined median/stddev,
    not an average of two already-summary numbers."""
    times = []
    for r in rows:
        times.extend(r.get("times_s") or [r["median_s"]] * r["n"])
    return {
        "median_s": statistics.median(times),
        "stddev_s": statistics.pstdev(times) if len(times) > 1 else 0.0,
        "n": len(times),
    }


def passes_agree(rows):
    """Do independently-shuffled passes of the same cell agree: a cell whose two
    passes disagree by more than their combined spread means the box was too noisy for that cell,
    and the table must say so rather than publish a falsely precise number."""
    if len(rows) < 2:
        return True, ""
    lo = min(rows, key=lambda r: r["median_s"])
    hi = max(rows, key=lambda r: r["median_s"])
    delta_ms = (hi["median_s"] - lo["median_s"]) * 1000.0
    spread_ms = (lo["stddev_s"] + hi["stddev_s"]) * 1000.0
    agree = delta_ms <= spread_ms
    return agree, f"Δ{delta_ms:.1f}ms vs combined spread {spread_ms:.1f}ms over {len(rows)} passes"


def group_by_pass(rows, key):
    g = {}
    for r in rows:
        g.setdefault(key(r), []).append(r)
    return g


def cmd_render(args):
    if len(args) != 1:
        raise SystemExit("bench.py render: one jsonl path required")
    rows = [json.loads(line) for line in open(args[0]) if line.strip()]
    measured = [r for r in rows if r.get("kind") == "measured"]
    skipped = [r for r in rows if r.get("kind") == "skipped"]

    bare_groups = group_by_pass([r for r in measured if r["tier"] == "bare"], lambda r: r["workload"])
    cell_groups = group_by_pass([r for r in measured if r["tier"] != "bare"],
                                 lambda r: (r["workload"], r["tier"], r["record"]))

    def summarize(group_rows):
        agree, detail = passes_agree(group_rows)
        return pool(group_rows), agree, detail

    bare = {w: summarize(g) for w, g in bare_groups.items()}

    # noop is bare-vs-enforced on a binary that does nothing: by construction that delta is the
    # run's fixed per-invocation cost (cgroup, Landlock ruleset, seccomp install, ledger open) with
    # no workload duration to amortize it into. Keyed by (tier, record) so every other workload's
    # own delta can have that fixed term subtracted out, leaving a marginal, per-syscall cost — one
    # percentage otherwise conflates "slow to start" with "slow per syscall it made," which is what
    # makes a short workload's number look worse than a long one even at the same per-syscall cost.
    noop_bare = bare.get("noop")
    fixed_ms = {}
    for (workload, tier, record), grp in cell_groups.items():
        if workload != "noop" or noop_bare is None:
            continue
        stats, agree, _ = summarize(grp)
        if agree and noop_bare[1]:
            fixed_ms[(tier, record)] = (stats["median_s"] - noop_bare[0]["median_s"]) * 1000.0

    header = ("| Workload | Tier | Record | Bare median (spread) | Enforced median (spread) | "
              "Fixed cost | Marginal cost | Total overhead | Runs/pass x passes | Kernel | CPU |\n"
              "|---|---|---|---|---|---|---|---|---|---|---|")
    lines = [header]
    for (workload, tier, record), grp in sorted(cell_groups.items()):
        stats, agree, detail = summarize(grp)
        b = bare.get(workload)
        n_desc = f"{grp[0]['n']}/pass x {len(grp)}"
        kernel, cpu = grp[0].get("kernel", "?"), grp[0].get("cpu", "?")
        if not agree:
            lines.append(
                "| {w} | {t} | {r} | — | NOISY: passes disagree ({d}) | — | — | not published | {n} | {k} | {c} |".format(
                    w=workload, t=tier, r=record, d=detail, n=n_desc, k=kernel, c=cpu))
            continue
        enf = f"{stats['median_s']*1000:.1f} ms (±{stats['stddev_s']*1000:.1f})"
        bare_str, total, fixed, marginal = "n/a (no bare row)", "n/a (no bare row)", "n/a (no noop row)", "n/a (no noop row)"
        if b and b[1]:
            bstats, _, _ = b
            bare_str = f"{bstats['median_s']*1000:.1f} ms (±{bstats['stddev_s']*1000:.1f})"
            delta_ms = (stats["median_s"] - bstats["median_s"]) * 1000.0
            total = f"{delta_ms / (bstats['median_s'] * 1000.0) * 100.0:+.1f}%"
            fx = fixed_ms.get((tier, record))
            if fx is not None:
                fixed = f"{fx:.1f} ms"
                marginal_ms = delta_ms - fx
                marginal = f"{marginal_ms / (bstats['median_s'] * 1000.0) * 100.0:+.1f}%"
        elif b and not b[1]:
            bare_str = total = "NOISY bare (passes disagree)"
        lines.append(
            "| {w} | {t} | {r} | {bare} | {enf} | {fixed} | {marginal} | {total} | {n} | {k} | {c} |".format(
                w=workload, t=tier, r=record, bare=bare_str, enf=enf, fixed=fixed, marginal=marginal,
                total=total, n=n_desc, k=kernel, c=cpu))
    for r in sorted(skipped, key=lambda r: (r["workload"], r["tier"])):
        lines.append("| {workload} | {tier} | — | — | — | — | — | skipped: {reason} | — | {kernel} | {cpu} |".format(
            workload=r["workload"], tier=r["tier"], reason=r["reason"],
            kernel=r.get("kernel", "?"), cpu=r.get("cpu", "?"),
        ))
    print("\n".join(lines))


def main():
    cmds = {
        "measure": cmd_measure, "cell": cmd_cell, "run-matrix": cmd_run_matrix,
        "skip": cmd_skip, "render": cmd_render,
    }
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        raise SystemExit(__doc__)
    cmds[sys.argv[1]](sys.argv[2:])


if __name__ == "__main__":
    main()
