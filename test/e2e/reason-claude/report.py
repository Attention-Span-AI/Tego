# SPDX-License-Identifier: Apache-2.0
#
# report.py reads what the model stub logged (server.py --log-content) and says what the harness in front of it
# delivered: the tool results of each turn, once each, and the hooks' text, as system reminders or as plain feedback.
# It trusts nothing the harness printed. fakeclaude and, in the end-to-end run, the real Claude Code are held to the same
# checks and the same shape files.
#
# Usage:
#   report.py check STUB_LOG [--result RESULT.json] [--bare] [--no-reminders]
#             [--expect-reminder SUB[=N]]... [--forbid-reminder SUB]... [--expect-feedback SUB[=N]]...
#             [--marker SUB]... [--shape GOLDEN]
#   report.py shape STUB_LOG [--marker SUB]...        prints the request shape (see shape())
#   report.py e2e STUB_LOG --ledger EVENTS --scenario a|c|d|e [--golden G [--write-golden]] [--sub VALUE=PH]...
#             [--isolation PATH]...                   tego's reason channel end to end (see SCENARIOS)
#
# A reminder is a text block wrapped in <system-reminder> tags; feedback is any other text block after the first
# request. SUB=N asks for exactly N blocks containing SUB (default 1). A marker picks out the blocks a hook wrote
# (every stand-in hook's text starts "stand-in hook:"); the shape counts only those, so a harness that adds
# reminders of its own (the real Claude Code does) compares equal to one that does not.
# --result is fakeclaude's summary: with it, each turn's tool_use ids must come back as tool_results in the next
# request, once each, with is_error as the call's outcome, and the stub's reply must have agreed with the script.
# A run the summary says a hook ended ("ended": "stopped_by_hook") may lack the request that would have carried its
# last turn's results, and may have sent no request at all when SessionStart ended it; no other turn may.
# Exit 1 when a check fails.
import argparse
import json
import os
import re
import sys

REMINDER_OPEN = "<system-reminder>"


def load_log(path):
    """The log's message entries (those with a turn), in order, and the lines of any other request the stub refused
    (a bad path or body). Entries without the user digest mean the stub was not started with --log-content."""
    out, bad = [], []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if "turn" in e:
                out.append(e)
            elif e.get("status") != 200:
                bad.append(e)
    for e in out:
        if "user" not in e:
            raise SystemExit("report.py: the stub log has no request content; start server.py with --log-content")
    return out, bad


def blocks(entry):
    """What the harness added since the model last spoke: the stub's "tail" (every message after the last assistant
    message, each block with its role) when it logged one, else the last user message."""
    return entry["tail"] if "tail" in entry else entry["user"]


def texts(entry):
    return [b.get("text", "") for b in blocks(entry) if b.get("type") == "text"]


def is_reminder(t):
    return t.lstrip().startswith(REMINDER_OPEN)


def reminders(entry):
    """Text the harness added as a system note, one per hook: a <system-reminder> block, or each hook note of a
    message of role "system" (Claude Code 2.1.310 sends all of a turn's tool-hook notes, and SessionStart's, in one
    system message after the tool results: RESULTS.md, finding R1), its whole text when it holds no note."""
    out = []
    for b in blocks(entry):
        t = b.get("text", "")
        if b.get("type") != "text":
            continue
        if b.get("role") == "system":
            ms = list(NOTE.finditer(t))
            out += [t[m.start():(ms[i + 1].start() if i + 1 < len(ms) else len(t))] for i, m in enumerate(ms)] or [t]
        elif is_reminder(t):
            out.append(t)
    return out


def feedback(entry, first):
    """Plain text blocks. The first request's first text block is the prompt, not feedback."""
    ts = [b.get("text", "") for b in blocks(entry) if b.get("type") == "text" and b.get("role", "user") == "user"
          and not is_reminder(b.get("text", ""))]
    return ts[1:] if first and ts else ts


def tool_results(entry):
    return [b for b in blocks(entry) if b.get("type") == "tool_result"]


def shape(entries, markers):
    """The request shape both harnesses must produce for a scenario: per request, the stub's turn number, the
    is_error flag of each tool_result in order, and how many hook-written reminders and feedback blocks it carried
    (blocks containing a marker). No ids and no text, which differ between harnesses."""
    out = []
    for i, e in enumerate(entries):
        marked = lambda t: any(m in t for m in markers)
        out.append({
            "turn": e["turn"],
            "tool_results": [bool(b.get("is_error")) for b in tool_results(e)],
            "hook_reminders": sum(1 for t in reminders(e) if marked(t)),
            "hook_feedback": sum(1 for t in feedback(e, i == 0) if marked(t)),
        })
    return out


class Report:
    def __init__(self, out=None):
        self.failed = 0
        self.out = out or sys.stdout

    def check(self, ok, what):
        print(("PASS  " if ok else "FAIL  ") + what, file=self.out)
        self.failed += not ok
        return ok


def split_count(spec):
    sub, sep, n = spec.rpartition("=")
    if sep and n.isdigit():
        return sub, int(n)
    return spec, 1


def run_checks(entries, args, rep, result=None, bad=()):
    # A run a hook ended (continue:false, or exit 2 from PostToolBatch) stopped before the request that would have
    # carried the last turn's results, or before the first request when SessionStart said it; the harness says so in
    # the summary's "ended", and only then is that absence expected (see the --result check below).
    stopped = result is not None and result.get("ended") == "stopped_by_hook"
    none_sent = stopped and result["requests"] == []
    rep.check((len(entries) > 0 or none_sent) and all(e.get("status") == 200 for e in entries),
              f"the stub answered every request ({len(entries)}) with 200")
    rep.check(not bad, f"the stub refused no other request ({len(bad)} refused)")
    rep.check(none_sent or [e["turn"] for e in entries[:1]] == [0], "the first request carried no assistant message (turn 0)")

    all_rem = [t for e in entries for t in reminders(e)]
    all_fb = [t for i, e in enumerate(entries) for t in feedback(e, i == 0)]

    if result is not None:
        rep.check(len(entries) == len(result["requests"]),
                  f"the stub logged as many requests ({len(entries)}) as the harness sent ({len(result['requests'])})")
        rep.check(all(r.get("agrees_with_script", True) for r in result["requests"]),
                  "the stub's reply for every turn named the tools the script ran (the two scripts agree)")
        seen = []
        for k, turn in enumerate(result["turns"]):
            want = [c["tool_use_id"] for c in turn["calls"]]
            if k + 1 >= len(entries):
                if stopped and k == len(result["turns"]) - 1:
                    rep.check(True, f"turn {k}: a hook ended the run before request {k + 1}, which would have carried its results")
                else:
                    rep.check(False, f"turn {k}: request {k + 1} exists to carry its results")
                continue
            got = [b.get("tool_use_id") for b in tool_results(entries[k + 1])]
            seen += got
            rep.check(got == want, f"turn {k}: request {k + 1} carries the tool results {want} in call order (got {got})")
            flags = [bool(b.get("is_error")) for b in tool_results(entries[k + 1])]
            rep.check(flags == [not c["ok"] for c in turn["calls"]],
                      f"turn {k}: is_error is the call's failure ({flags})")
        rep.check(len(seen) == len(set(seen)), "every tool result was delivered once")
        if result.get("bare") and not args.bare:
            args.bare = True

    if args.bare or args.no_reminders:
        rep.check(not all_rem, f"no system reminder reached the model (bare mode drops them; {len(all_rem)} did)")
    for spec in args.expect_reminder:
        sub, n = split_count(spec)
        got = sum(1 for t in all_rem if sub in t)
        rep.check(got == n, f"reminders containing {sub!r}: {got}, expected {n}")
    for sub in args.forbid_reminder:
        got = sum(1 for t in all_rem if sub in t)
        rep.check(got == 0, f"no reminder contains {sub!r} ({got} do)")
    for spec in args.expect_feedback:
        sub, n = split_count(spec)
        got = sum(1 for t in all_fb if sub in t)
        rep.check(got == n, f"plain feedback blocks containing {sub!r}: {got}, expected {n}")
    if args.shape:
        with open(args.shape) as f:
            want = json.load(f)
        got = shape(entries, args.marker)
        rep.check(got == want, f"the request shape equals {args.shape}" + ("" if got == want else f"\n   got  {json.dumps(got)}\n   want {json.dumps(want)}"))
    return rep.failed


# ---- end to end: tego's reason channel through a harness ------------------------------------------
#
# A scenario is one `tego run` of the harness under contract.yaml against stub-<name>.json: turn 0 is a warm-up write
# inside the workspace (the request after it carries whatever the harness's start-up made tego refuse), turn 1 is the
# scenario's own, and the request after turn 1 is the "next request". What each scenario must have tego refuse in
# turn 1, by reason code and operation, and whether that refusal may surface in a later request:
SCENARIOS = {
    "a": [("write-outside-contract", "open")],
    "c": [("exec-not-allowed", "exec")],
    "d": [("write-outside-contract", "open"), ("exec-not-allowed", "exec")],
    "e": [],
}
NOTE = re.compile(r"(?:(?<=\n)|^)([A-Za-z]+(?::[A-Za-z_]+)?) hook additional context: ")
TEGO_HEAD = "Tego, this run's access control, refused "
MORE = re.compile(r"^\d+ more not listed\.$")


def ledger_refusals(path):
    """The run's refused lines, in seq order: seq, op, target, reason, rule."""
    out = []
    with open(path) as f:
        for line in f:
            e = json.loads(line)
            if e.get("kind") == "refused":
                out.append({k: e.get(k, "") for k in ("seq", "op", "target", "reason", "rule")})
    return out


def notes(entry):
    """The hook notes of a request: (channel, label, body) for every "<Label> hook additional context: " in a text
    block the harness added. The channel is the block's role, "user-reminder" for a <system-reminder> in a user
    message. A note's body runs to the next note or the end of the block."""
    out = []
    for b in blocks(entry):
        t = b.get("text", "")
        if b.get("type") != "text" or "hook additional context: " not in t:
            continue
        role = b.get("role", "user")
        channel = "user-reminder" if role == "user" and is_reminder(t) else role
        t = t.replace("</system-reminder>", "")
        ms = list(NOTE.finditer(t))
        for i, m in enumerate(ms):
            end = ms[i + 1].start() if i + 1 < len(ms) else len(t)
            out.append((channel, m.group(1), t[m.end():end]))
    return out


def refusal_lines(text):
    """Every line of a text that holds "Tego refused ", whatever its bullet: without a leading "- ", "* " or other
    bullet mark and any "xN " count. Read wide on purpose, so an absence check is not blind to a form the hook does
    not print."""
    return [re.sub(r"^([-*+\u2022]\s*)?(x\d+ )?", "", ln.strip()) for ln in text.splitlines() if "Tego refused " in ln]


def tego_lines(text, norm):
    """Tego's text in a text: each refusal line that is not an isolation refusal, reason.Render's "N more not
    listed." line (the refusals it leaves out cannot be shown to be isolation ones), and tego's heading where no
    refusal line at all follows it (with nothing new an event prints nothing, so a bare heading is tego text)."""
    lines = refusal_lines(text)
    out = [ln for ln in lines if not norm.isolated(ln)]
    out += [ln.strip() for ln in text.splitlines() if MORE.match(ln.strip())]
    if TEGO_HEAD in text and not lines:
        out.append(next(ln.strip() for ln in text.splitlines() if TEGO_HEAD in ln))
    return out


class Norm:
    """Turns a harness's text into the shared golden's: given values become placeholders (longest first), and what
    differs on every run (a temporary file's suffix, a descriptor number, Claude Code's token counter) is masked."""

    def __init__(self, subs, isolation):
        self.subs = sorted(subs, key=lambda kv: len(kv[0]), reverse=True)
        self.isolation = [p.rstrip("/") for p in isolation if p]

    def __call__(self, s):
        for value, ph in self.subs:
            s = s.replace(value, ph)
        s = re.sub(r"\.tmp\.\d+\.[0-9a-f]+", ".tmp.@TMP@", s)
        s = re.sub(r"/proc/self/fd/\d+/", "/proc/self/fd/@FD@/", s)
        s = re.sub(r"<total_tokens>[^<]*</total_tokens>", "", s)
        return s.strip()

    def isolated(self, line):
        """A refusal of the account's own agent configuration (the contract's isolation deny_read), which the real
        Claude Code reads at start and later whatever HOME says; it is not a scenario's and the twin has none."""
        return any(f'"{p}' in line or f"[{p}]" in line for p in self.isolation)


def normalise(entry, norm):
    """The next request in the golden's form: each tool result's flag and text, the channels its hook notes came by
    (a note left with nothing but isolation refusals is dropped), and tego's text in them (tego_lines), sorted. Not the
    notes' labels or their number: which hook claims a refusal depends on when the refusal lands (the real binary's
    Write unlinks its temporary file 0.4 ms after the refused open, inside the reason file's 10 ms window, so the
    PostToolUseFailure hook that starts 4 ms later sees only the open and PostToolBatch or the next call's hook tells
    the unlink: RESULTS.md R7), and each is told once either way."""
    lines, labels = [], []
    for channel, _, body in notes(entry):
        own = tego_lines(body, norm)
        if own or not body.strip().startswith(TEGO_HEAD):
            labels.append(channel)
        lines += own
    return {
        "tool_results": [{"is_error": bool(b.get("is_error")), "content": norm(b.get("content", ""))} for b in tool_results(entry)],
        "notes": sorted(set(labels)),
        "refusals": sorted(norm(ln) for ln in lines),
    }


def tego_text(entry, norm):
    """Tego's text in a request's hook notes (tego_lines of each note's body)."""
    return [ln for _, _, body in notes(entry) for ln in tego_lines(body, norm)]


def block_text(b):
    """A text block's text, or a tool result's content as text (a string, or the text of its content blocks)."""
    if b.get("type") == "text":
        return b.get("text", "")
    if b.get("type") != "tool_result":
        return ""
    c = b.get("content", "")
    return c if isinstance(c, str) else "\n".join(x.get("text", "") for x in c if isinstance(x, dict))


def stray(entry, norm):
    """Tego's text in a request outside a hook note: in a tool result, or in a text block before its first note (a
    note runs to the end of its block), read as tego_lines reads a note. The absence checks read these too, so a
    harness that hands tego's words over without the note marker is not taken to have said nothing."""
    out = []
    for b in blocks(entry):
        t = block_text(b)
        m = NOTE.search(t) if b.get("type") == "text" else None
        out += tego_lines(t[:m.start()] if m else t, norm)
    return out


def told(entry, norm):
    """Every refusal of the run's own a request tells the model, in a hook note or not."""
    return tego_text(entry, norm) + stray(entry, norm)


def run_e2e(args, rep):
    entries, bad = load_log(args.log)
    norm = Norm([tuple(s.split("=", 1)) for s in args.sub], args.isolation)
    want = SCENARIOS[args.scenario]
    if not rep.check(bool(args.ledger) and os.path.isfile(args.ledger), f"the run left a ledger ({args.ledger or 'none found'})"):
        return rep.failed
    refused = ledger_refusals(args.ledger)
    rep.check(len(entries) >= 3 and all(e.get("status") == 200 for e in entries) and not bad,
              f"scenario {args.scenario}: the stub answered every request with 200 ({len(entries)} requests, {len(bad)} refused)")
    nxt = [e for e in entries if e["turn"] == 2]
    if not rep.check(len(nxt) == 1, f"one request carries turn 1's results (turn 2 requests: {len(nxt)})"):
        return rep.failed
    nxt = nxt[0]
    later = [e for e in entries[entries.index(nxt) + 1:]]
    carried = tego_text(nxt, norm)
    own = [r for r in refused if not norm.isolated(f'"{r["target"]}"') and not norm.isolated(f'[{r["rule"]}]')]
    for reason, op in want:
        hits = [r for r in own if r["reason"] == reason and r["op"] == op]
        if not rep.check(bool(hits), f"the ledger has a {op} refused {reason}"):
            continue
        r = hits[0]
        lines = [ln for ln in carried if f'Tego refused {op} "{r["target"]}"' in ln]
        rep.check(bool(lines), f"the next request carries the refusal of {op} {norm(r['target'])} (ledger reason {reason})")
        rep.check(any(f"(rule {r['rule']})" in ln or f'(rule "{r["rule"]}")' in ln for ln in lines),
                  f"... with its rule ({r['rule']})")
        rep.check(not any(f'"{r["target"]}"' in ln for e in later for ln in told(e, norm)),
                  f"... and no later request repeats it (seq {r['seq']})")
    if not want:
        loose = stray(nxt, norm)
        rep.check(not carried and not loose, f"the next request carries no tego text ({len(carried)} refusal lines in "
                  f"hook notes, {len(loose)} outside them)")
        iso = [ln for _, _, body in notes(nxt) for ln in refusal_lines(body) if norm.isolated(ln)]
        if iso:
            print(f"NOTE  it carries {len(iso)} refusal(s) of the account's own agent configuration (isolation)", file=rep.out)
    # Every refusal of the run's own is told once, across all requests (the warm-up's included).
    lines = [norm(ln) for e in entries for ln in told(e, norm)]
    rep.check(len(lines) == len(set(lines)), f"no refusal line is told twice in the run ({len(lines)} told)")
    got = normalise(nxt, norm)
    if args.write_golden:
        try:
            with open(args.golden) as f:
                golden = json.load(f)
        except FileNotFoundError:
            golden = {}
        golden[args.scenario] = got
        with open(args.golden, "w") as f:
            json.dump(golden, f, indent=1, sort_keys=True, ensure_ascii=False)
            f.write("\n")
        print(f"wrote scenario {args.scenario} to {args.golden}", file=rep.out)
    elif args.golden:
        with open(args.golden) as f:
            golden = json.load(f).get(args.scenario)
        rep.check(got == golden, f"the next request, normalised, equals {os.path.basename(args.golden)}[{args.scenario}]"
                  + ("" if got == golden else f"\n   got  {json.dumps(got, ensure_ascii=False)}\n   want {json.dumps(golden, ensure_ascii=False)}"))
    return rep.failed


def main(argv=None):
    ap = argparse.ArgumentParser(prog="report.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e2e = sub.add_parser("e2e")
    e2e.add_argument("log")
    e2e.add_argument("--ledger", required=True)
    e2e.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    e2e.add_argument("--golden")
    e2e.add_argument("--write-golden", action="store_true")
    e2e.add_argument("--sub", action="append", default=[], help="VALUE=PLACEHOLDER")
    e2e.add_argument("--isolation", action="append", default=[])
    for name in ("check", "shape"):
        p = sub.add_parser(name)
        p.add_argument("log")
        p.add_argument("--marker", action="append", default=[])
    c = sub.choices["check"]
    c.add_argument("--result")
    c.add_argument("--bare", action="store_true")
    c.add_argument("--no-reminders", action="store_true")
    c.add_argument("--expect-reminder", action="append", default=[])
    c.add_argument("--forbid-reminder", action="append", default=[])
    c.add_argument("--expect-feedback", action="append", default=[])
    c.add_argument("--shape")
    args = ap.parse_args(argv)
    if args.cmd == "e2e":
        return 1 if run_e2e(args, Report()) else 0
    entries, bad = load_log(args.log)
    if args.cmd == "shape":
        print(json.dumps(shape(entries, args.marker), indent=2))
        return 0
    result = None
    if args.result:
        with open(args.result) as f:
            result = json.load(f)
    return 1 if run_checks(entries, args, Report(), result, bad) else 0


if __name__ == "__main__":
    sys.exit(main())
