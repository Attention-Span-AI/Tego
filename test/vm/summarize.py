#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# summarize.py — the report at the end of test/vm/root-suites.sh (`make vm-root-test`).
#
# Why it exists: an exit code alone hides the one thing that matters most for a privileged suite,
# which is whether its tests ran at all. A suite whose every test skipped exits 0 exactly like one
# that passed. This reads each suite's `go tool test2json` stream and counts, per suite, the top-level
# tests that ran (pass or fail) against those that skipped, keeps each skip's own reason and each
# failure's decisive lines, prints a table, writes the same as JSON, and exits 1 unless every suite
# ran something and nothing failed. A binary that panics or is killed never prints its own end, which
# is all test2json goes by, so the raw console is read as well: a test that started and never reported
# counts as failed, and each suite's <suite>.list (its top-level tests, read from source by
# root-suites.sh) names the tests that never started at all.
#
# Usage: summarize.py <results.tsv> <summary.json>
#   results.tsv rows: suite, package, tags, status (an exit code | build-failed | not-run | vm-<reason>
#   when the guest itself failed: vm-lost, vm-timeout, vm-no-report, vm-env, vm-usage),
#   test2json path (or -), and a log path or a note.
import json
import re
import sys

LOC = re.compile(r"^\s+\S+\.go:\d+: ")
RESULT = re.compile(r"^(\s*)--- (PASS|FAIL|SKIP): (\S+) \(")
RUN = re.compile(r"^=== (RUN|CONT)\s+(\S+)")


def console_results(path):
    """The results the raw -test.v stream states, the test that was running last, and a panic block.

    test2json only reports a result it has seen the end of; a binary that panics or is killed never
    prints that end, so the raw lines are read too."""
    final, last, panic = {}, None, []
    lines = [l.rstrip("\n") for l in tail(path, 10 ** 7)]
    for i, l in enumerate(lines):
        m = RESULT.match(l)
        if m:
            final[m.group(3)] = m.group(2).lower()
            continue
        m = RUN.match(l)
        if m:
            last = m.group(2)
            continue
        if l.startswith("panic: ") and not panic:
            panic = [x for x in lines[i:i + 40] if x.strip()][:14]
    return final, last, panic


def tail(path, n):
    try:
        with open(path, errors="replace") as f:
            lines = [l.rstrip("\r\n") for l in f]
    except OSError:
        return []
    return lines[-n:]


def events(path):
    out = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("{"):
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


def text_of(lines):
    return [l.rstrip("\n") for l in lines if not l.lstrip().startswith(("=== ", "--- "))]


def summarize_suite(suite, pkg, tags, status, jpath, extra):
    rec = {"suite": suite, "package": pkg, "tags": tags, "ran": 0, "skipped": 0,
           "subtests_ran": 0, "subtests_skipped": 0, "failures": [], "skip_reasons": []}
    if status == "build-failed":
        rec["result"] = "build-failed"
        rec["failures"] = ["build failed: " + " | ".join(tail(extra, 15))]
        return rec
    if status == "not-run":
        rec["result"] = "not-run"
        rec["skip_reasons"] = [extra]
        return rec
    if status == "vm-lost":
        # Something outside the harness ended qemu (kvm-run.sh's GUEST-LOST): no verdict at all, not even on the guest.
        rec["result"] = "guest-lost"
        lines = [l for l in tail(extra, 300) if l.strip()]
        rec["failures"] = ["the guest was lost (qemu ended by a signal from outside) before the suite finished; this is "
                           "not a test result. Last lines: %s" % " | ".join(lines[-4:])]
        return rec
    if status.startswith("vm-"):
        # The guest, not the suite, failed: nothing it printed is a verdict on the code under test.
        rec["result"] = "vm-error"
        lines = [l for l in tail(extra, 300) if re.search(r"tego-vm|panic|Kernel|kvm-run", l)]
        rec["failures"] = ["the guest failed (%s), no suite result: %s" % (status, " | ".join(lines[-8:]))]
        return rec
    code = int(status)
    rec["exit"] = code
    if jpath == "-":  # a plain command (tego doctor): its exit code and its last lines
        rec["result"] = "pass" if code == 0 else "fail"
        rec["ran"] = 1
        lines = [l for l in tail(extra, 400) if l.strip()]
        keep = [l for l in lines if re.search(r"tier|tego doctor:|fix|FAIL|error", l, re.I)]
        rec["output"] = keep[-25:]
        if code != 0:
            rec["failures"] = ["exit %d: %s" % (code, " | ".join(keep[-10:] or lines[-10:]))]
        return rec

    final, output, started = {}, {}, []
    for ev in events(jpath):
        t = ev.get("Test")
        if not t:
            continue
        a = ev.get("Action")
        if a == "run" and t not in started:
            started.append(t)
        if a == "output":
            output.setdefault(t, []).append(ev.get("Output", ""))
        elif a in ("pass", "fail", "skip"):
            final[t] = a
    raw, last, panic = console_results(extra)
    for t, a in raw.items():
        final.setdefault(t, a)
    # A test that started and never reported (a panic, a kill, a timeout) did not pass.
    crashed = [t for t in started if t not in final]
    for t in crashed:
        final[t] = "fail"
        output.setdefault(t, []).append("    (no result: the test binary died while this test ran)\n")
    if panic:
        rec["failures"].append("the test binary panicked in %s: %s" % (last, " | ".join(x.strip() for x in panic)))
    for t, a in sorted(final.items()):
        top = "/" not in t
        if a == "skip":
            rec["skipped" if top else "subtests_skipped"] += 1
            if top:
                why = [l.strip() for l in text_of(output.get(t, [])) if l.strip()]
                rec["skip_reasons"].append("%s: %s" % (t, why[0] if why else "(no reason printed)"))
        else:
            rec["ran" if top else "subtests_ran"] += 1
        if a == "fail":
            lines = []
            for name in sorted(output):
                if name == t or name.startswith(t + "/"):
                    lines += [l.rstrip() for l in text_of(output[name])
                              if LOC.match(l) or "panic" in l or "Error" in l]
            if top or not lines:
                rec["failures"].append("%s: %s" % (t, " | ".join(x.strip() for x in lines[:12]) or "(no message)"))
    failed_tests = sum(1 for t, a in final.items() if a == "fail" and "/" not in t)
    rec["failed"] = failed_tests
    # Tests the build holds that never started: everything after a crash, or a -test.run filter.
    listed = [l.strip() for l in tail(jpath[:-len(".json")] + ".list", 10 ** 6) if l.strip()]
    seen = {t.split("/")[0] for t in final} | {t.split("/")[0] for t in started}
    missing = [t for t in listed if t not in seen]
    rec["not_reached"] = len(missing)
    if missing:
        rec["not_reached_tests"] = missing
    if code != 0 and failed_tests == 0:
        lines = tail(extra, 300)
        why = [l for l in lines if re.search(r"panic|timed out|fatal error|TEGO-VM|kvm-run", l)]
        rec["failures"].append("exit %d with no failing test: %s" % (code, " | ".join((why or lines)[-8:])))
    if code != 0 or failed_tests:
        rec["result"] = "fail"
    elif rec["ran"] == 0:
        rec["result"] = "not-run"
        rec["failures"].append("every test skipped: a suite that ran nothing is not a pass")
    else:
        rec["result"] = "pass"
    return rec


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: summarize.py <results.tsv> <summary.json>")
    recs = []
    with open(sys.argv[1]) as f:
        for row in f:
            row = row.rstrip("\n")
            if row:
                recs.append(summarize_suite(*row.split("\t", 5)))
    with open(sys.argv[2], "w") as f:
        json.dump(recs, f, indent=2)

    print("%-44s %-12s %5s %5s %6s %11s   %s" % ("suite", "result", "ran", "skip", "failed", "not reached",
                                               "subtests ran/skip"))
    for r in recs:
        print("%-44s %-12s %5d %5d %6s %11s   %d/%d" % (r["suite"], r["result"], r["ran"], r["skipped"],
                                                      r.get("failed", "-"), r.get("not_reached", "-"),
                                                      r["subtests_ran"], r["subtests_skipped"]))
    for r in recs:
        if r["failures"] or r["skip_reasons"] or r.get("output"):
            print("\n-- %s (%s)" % (r["suite"], r["result"]))
            for x in r.get("output", []):
                print("   | " + x)
            for x in r["failures"]:
                print("   FAIL " + x)
            for x in r["skip_reasons"]:
                print("   skip " + x)
            if r.get("not_reached_tests"):
                print("   never started: " + " ".join(r["not_reached_tests"]))
    print("\nfull report: " + sys.argv[2])
    sys.exit(0 if all(r["result"] == "pass" for r in recs) else 1)


if __name__ == "__main__":
    main()
