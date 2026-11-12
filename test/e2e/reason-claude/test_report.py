# SPDX-License-Identifier: Apache-2.0
#
# report.py's own tests: python3 -I -m unittest   (run in this directory; discovery puts it on sys.path)
import contextlib
import io
import json
import os
import tempfile
import unittest

import report

HOOK = "stand-in hook: fixed"


def rem(text):
    return {"type": "text", "text": f"<system-reminder>\nX hook additional context: {text}\n</system-reminder>"}


def txt(text):
    return {"type": "text", "text": text}


def res(i, err=False):
    return {"type": "tool_result", "tool_use_id": i, "is_error": err, "content": "c"}


def entry(turn, user, status=200):
    return {"n": turn, "path": "/v1/messages", "status": status, "turn": turn, "stream": False,
            "stop_reason": "tool_use", "messages": 2 * turn + 1, "user": user}


def result(turns, bare=False, agrees=True, extra=0, ended="end_turn"):
    return {
        "bare": bare,
        "ended": ended,
        "requests": [{"n": k, "agrees_with_script": agrees} for k in range(len(turns) + 1 + extra)],
        "turns": [{"calls": [{"tool_use_id": i, "ok": ok} for i, ok in t]} for t in turns],
    }


# one successful call, one failing call, a hook reminder for each, and a Stop continuation
GOOD = [
    entry(0, [txt("prompt"), rem(HOOK + " start")]),
    entry(1, [res("a"), rem(HOOK + " post")]),
    entry(2, [res("b", True), rem(HOOK + " failure")]),
    entry(3, [txt("stand-in hook: keep going")]),
]
GOOD_RESULT = result([[("a", True)], [("b", False)]], extra=1)


def run(entries, argv, res_=None, bad=()):
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "stub.log")
        with open(log, "w") as f:
            for e in list(entries) + list(bad):
                f.write(json.dumps(e) + "\n")
        argv = ["check", log] + argv
        if res_ is not None:
            rp = os.path.join(d, "result.json")
            with open(rp, "w") as f:
                json.dump(res_, f)
            argv += ["--result", rp]
        with contextlib.redirect_stdout(out):
            code = report.main(argv)
    return code, out.getvalue()


class ReportTest(unittest.TestCase):
    def test_a_good_run_passes(self):
        code, out = run(GOOD, ["--expect-reminder", HOOK + " post", "--expect-reminder", "stand-in hook=3",
                               "--expect-feedback", "keep going"], GOOD_RESULT)
        self.assertEqual(code, 0, out)
        self.assertNotIn("FAIL", out)

    def test_a_missing_tool_result_fails(self):
        entries = [GOOD[0], entry(1, [rem("x")])] + GOOD[2:]
        code, out = run(entries, [], GOOD_RESULT)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  turn 0", out)

    def test_a_tool_result_delivered_twice_fails(self):
        entries = GOOD[:2] + [entry(2, [res("a"), res("b", True)])] + GOOD[3:]
        code, out = run(entries, [], GOOD_RESULT)
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_is_error_must_be_the_calls_failure(self):
        entries = [GOOD[0], entry(1, [res("a", True)]), GOOD[2], GOOD[3]]
        code, out = run(entries, [], GOOD_RESULT)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  turn 0: is_error", out)

    def test_counts_are_exact(self):
        code, out = run(GOOD, ["--expect-reminder", "stand-in hook=2"], GOOD_RESULT)
        self.assertEqual(code, 1)
        self.assertIn("stand-in hook': 3, expected 2", out.replace('"', "'"))
        code, _ = run(GOOD, ["--forbid-reminder", "failure"], GOOD_RESULT)
        self.assertEqual(code, 1)
        code, _ = run(GOOD, ["--expect-feedback", "keep going=2"], GOOD_RESULT)
        self.assertEqual(code, 1)

    def test_bare_means_no_reminders_and_feedback_still_counts(self):
        bare = [entry(0, [txt("prompt")]), entry(1, [res("a"), txt(HOOK + " stderr")])]
        code, out = run(bare, ["--expect-feedback", "stderr"], result([[("a", True)]], bare=True))
        self.assertEqual(code, 0, out)
        code, out = run(GOOD, ["--bare"], GOOD_RESULT)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  no system reminder", out)
        code, _ = run(GOOD, [], result([[("a", True)], [("b", False)]], bare=True, extra=1))
        self.assertEqual(code, 1, "a result that says bare is held to bare")

    def test_script_disagreement_fails(self):
        code, out = run(GOOD, [], result([[("a", True)], [("b", False)]], agrees=False, extra=1))
        self.assertEqual(code, 1)
        self.assertIn("FAIL  the stub's reply", out)

    def test_a_run_a_hook_ended_lacks_only_the_request_it_never_sent(self):
        # PostToolUse continue:false or PostToolBatch exit 2 after turn 1: requests 0 and 1 exist, request 2 does not
        stopped = result([[("a", True)], [("b", False)]], ended="stopped_by_hook")
        stopped["requests"] = stopped["requests"][:2]
        code, out = run(GOOD[:2], [], stopped)
        self.assertEqual(code, 0, out)
        self.assertIn("PASS  turn 1: a hook ended the run before request 2", out)
        # the same log from a run that says it ended normally is missing a request
        ended = result([[("a", True)], [("b", False)]])
        ended["requests"] = ended["requests"][:2]
        code, out = run(GOOD[:2], [], ended)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  turn 1: request 2 exists", out)

    def test_a_hook_ending_the_run_excuses_only_the_last_turn(self):
        stopped = result([[("a", True)], [("b", False)]], ended="stopped_by_hook")
        stopped["requests"] = stopped["requests"][:1]
        code, out = run(GOOD[:1], [], stopped)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  turn 0: request 1 exists", out)

    def test_a_run_stopped_at_session_start_sent_no_request(self):
        stopped = {"bare": False, "ended": "stopped_by_hook", "requests": [], "turns": []}
        code, out = run([], [], stopped)
        self.assertEqual(code, 0, out)
        # without the summary saying so, an empty log is a failure; a request the stub saw that the summary lacks too
        code, _ = run([], [], dict(stopped, ended="end_turn"))
        self.assertEqual(code, 1)
        code, _ = run(GOOD[:1], [], stopped)
        self.assertEqual(code, 1)

    def test_a_refused_request_or_a_non_200_fails(self):
        code, out = run(GOOD, [], GOOD_RESULT, bad=[{"n": 9, "path": "/x", "status": 404}])
        self.assertEqual(code, 1)
        self.assertIn("FAIL  the stub refused no other request", out)
        code, _ = run(GOOD[:1] + [entry(1, [res("a")], status=500)] + GOOD[2:], [], GOOD_RESULT)
        self.assertEqual(code, 1)

    def test_the_log_must_carry_content(self):
        e = dict(GOOD[0])
        del e["user"]
        with self.assertRaises(SystemExit):
            run([e], [])

    def test_shape_counts_only_marked_hook_blocks(self):
        entries = GOOD + [entry(4, [txt("someone else's note"), rem("the harness's own reminder")])]
        got = report.shape(entries, ["stand-in hook:"])
        self.assertEqual(got, [
            {"turn": 0, "tool_results": [], "hook_reminders": 1, "hook_feedback": 0},
            {"turn": 1, "tool_results": [False], "hook_reminders": 1, "hook_feedback": 0},
            {"turn": 2, "tool_results": [True], "hook_reminders": 1, "hook_feedback": 0},
            {"turn": 3, "tool_results": [], "hook_reminders": 0, "hook_feedback": 1},
            {"turn": 4, "tool_results": [], "hook_reminders": 0, "hook_feedback": 0},
        ])

    def test_shape_golden_comparison(self):
        with tempfile.TemporaryDirectory() as d:
            golden = os.path.join(d, "shape.json")
            with open(golden, "w") as f:
                json.dump(report.shape(GOOD, ["stand-in hook:"]), f)
            code, out = run(GOOD, ["--marker", "stand-in hook:", "--shape", golden])
            self.assertEqual(code, 0, out)
            code, out = run(GOOD[:3], ["--marker", "stand-in hook:", "--shape", golden])
            self.assertEqual(code, 1)
            self.assertIn("FAIL  the request shape", out)


# ---- e2e: a scenario's next request against the ledger --------------------------------------------
W = "/w"
WRITE = f'Tego refused open "{W}/out/x.tmp.12.ab": this run may not write to that path (rule unmatched).'
ISO = 'Tego refused open "/h/.claude/skills": files under that path are not readable in this run (rule fs.deny_read[/h/.claude]).'


def note(*lines, label="PostToolUseFailure:Write"):
    body = "Tego, this run's access control, refused %d actions:\n" % len(lines) + "".join(f"- {ln}\n" for ln in lines)
    return {"type": "text", "role": "system", "text": f"{label} hook additional context: {body}<total_tokens>9 left</total_tokens>"}


def tentry(turn, tail):
    e = entry(turn, [b for b in tail if b.get("role", "user") == "user"])
    e["tail"] = tail
    return e


def run_e2e(entries, refused, scenario="a", golden=None, hooks=None):
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as d:
        log, led = os.path.join(d, "stub.log"), os.path.join(d, "events.jsonl")
        with open(log, "w") as f:
            f.writelines(json.dumps(e) + "\n" for e in entries)
        with open(led, "w") as f:
            f.writelines(json.dumps(dict(kind="refused", **r)) + "\n" for r in refused)
        argv = ["e2e", log, "--ledger", led, "--scenario", scenario, "--sub", f"{W}=@W@", "--isolation", "/h/.claude"]
        if golden is not None:
            gp = os.path.join(d, "golden")
            with open(gp, "w") as f:
                json.dump({scenario: golden}, f)
            argv += ["--golden", gp]
        if hooks is not None:
            rp = os.path.join(d, "result.json")
            with open(rp, "w") as f:
                json.dump({"hooks": hooks}, f)
            argv += ["--result", rp]
        with contextlib.redirect_stdout(out):
            code = report.main(argv)
    return code, out.getvalue()


def hook(event, began, *lines, took=0.004, seen=None):
    """A summary's hook run: tego's hook printing lines (nothing when there are none), began seconds after 12:00:00.
    seen is the reason file's seq the stand-in read just before it began (reason_seq); None leaves the key out."""
    out = ""
    if lines:
        body = "Tego, this run's access control, refused %d actions:\n" % len(lines) + "".join(f"- {ln}\n" for ln in lines)
        out = json.dumps({"hookSpecificOutput": {"hookEventName": event.split(":")[0], "additionalContext": body}})
    h = {"event": event.split(":")[0], "tool": event.partition(":")[2], "began": at(began), "recorded": at(began + took),
         "stdout": out}
    if seen is not None:
        h["reason_seq"] = seen
    return h


def at(sec):
    """A UTC time sec seconds after 2026-11-11T12:00:00Z, with nine fractional digits as the ledger writes them."""
    return "2026-11-11T12:00:%02d.%09dZ" % (int(sec), round((sec - int(sec)) * 1e9))


LEDGER_A = [{"seq": 5, "op": "open", "target": "/h/.claude/skills", "reason": "read-denied", "rule": "fs.deny_read[/h/.claude]"},
            {"seq": 9, "op": "open", "target": f"{W}/out/x.tmp.12.ab", "reason": "write-outside-contract", "rule": "unmatched",
             "ts": at(1.0)}]
TURN0 = tentry(0, [txt("prompt")])
TURN1 = tentry(1, [res("w"), note(ISO, label="PostToolUse:Write")])
ERR = {"type": "tool_result", "tool_use_id": "o", "is_error": True, "content": f"EACCES: open '{W}/out/x.tmp.34.cd'"}


class E2ETest(unittest.TestCase):
    def test_a_delivered_refusal_passes_and_matches_its_golden(self):
        golden = {"notes": ["system"], "refusals": ['Tego refused open "@W@/out/x.tmp.@TMP@": this run may not write to that path (rule unmatched).'],
                  "tool_results": [{"is_error": True, "content": "EACCES: open '@W@/out/x.tmp.@TMP@'"}]}
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR, note(WRITE)]), tentry(3, [txt("done")])], LEDGER_A, golden=golden)
        self.assertEqual(code, 0, out)
        self.assertNotIn("FAIL", out)

    def test_a_missing_refusal_fails(self):
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR]), tentry(3, [txt("done")])], LEDGER_A)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  the next request, or the one after it, carries the refusal of open @W@/out/x.tmp.@TMP@ (ledger reason "
                      "write-outside-contract", out)

    def test_a_refusal_told_one_request_later_passes_and_matches_the_golden(self):
        # Its line landed after the next request's hooks ran: the request after it carries it (the turn after the
        # refused one waits a second), and the golden, which is the next request's, holds it all the same.
        golden = {"notes": ["system"], "refusals": ['Tego refused open "@W@/out/x.tmp.@TMP@": this run may not write to that path (rule unmatched).'],
                  "tool_results": [{"is_error": True, "content": "EACCES: open '@W@/out/x.tmp.@TMP@'"}]}
        late = [TURN0, TURN1, tentry(2, [ERR]), tentry(3, [res("s"), note(WRITE, label="PostToolUse:Bash")]), tentry(4, [txt("done")])]
        code, out = run_e2e(late, LEDGER_A, golden=golden)
        self.assertEqual(code, 0, out)
        self.assertIn("PASS  the next request, or the one after it, carries the refusal of open @W@/out/x.tmp.@TMP@ "
                      "(ledger reason write-outside-contract): the request after it, one hook later", out)
        # Told in neither, it fails, and so does a refusal told only two requests later.
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR]), tentry(3, [res("s")]), tentry(4, [note(WRITE, label="Stop")])], LEDGER_A)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  the next request, or the one after it, carries the refusal", out)
        # Told in both is told twice.
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR, note(WRITE)]), tentry(3, [res("s"), note(WRITE, label="PostToolUse:Bash")])], LEDGER_A)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  ... and no later request repeats it", out)
        self.assertIn("FAIL  no refusal line is told twice in the run", out)

    def test_a_refusal_told_with_the_wrong_rule_or_sentence_fails(self):
        golden = {"notes": ["system"], "refusals": ['Tego refused open "@W@/out/x.tmp.@TMP@": this run may not write to that path (rule unmatched).'],
                  "tool_results": [{"is_error": True, "content": "EACCES: open '@W@/out/x.tmp.@TMP@'"}]}
        wrong_rule = WRITE.replace("(rule unmatched)", "(rule fs.write[./work/])")
        for told_in in (2, 3):
            tails = {2: [ERR], 3: [res("s")]}
            tails[told_in] = tails[told_in] + [note(wrong_rule)]
            code, out = run_e2e([TURN0, TURN1, tentry(2, tails[2]), tentry(3, tails[3])], LEDGER_A, golden=golden)
            self.assertEqual(code, 1, out)
            self.assertIn("FAIL  ... with its rule (unmatched)", out)
        wrong_reason = WRITE.replace("may not write to that path", "may not read that path")
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR]), tentry(3, [res("s"), note(wrong_reason)])], LEDGER_A, golden=golden)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL  the next request, normalised, equals", out)

    def test_hook_runs_hold_a_late_refusal_to_the_first_hook_that_found_it_listed(self):
        late = [TURN0, TURN1, tentry(2, [ERR]), tentry(3, [res("s"), note(WRITE, label="PostToolUse:Bash")]), tentry(4, [txt("done")])]
        # The line (seq 9) landed at 1.0 s. The refused call's hooks began before the reason file listed it (the file's
        # seq was still 5), the Bash's after its one-second wait, with it listed.
        hooks = [hook("SessionStart", 0.1, seen=5), hook("PostToolUseFailure:Write", 0.99, seen=5), hook("PostToolBatch", 1.06, seen=5),
                 hook("PostToolUse:Bash", 2.1, WRITE, seen=9), hook("PostToolBatch", 2.15, seen=9)]
        code, out = run_e2e(late, LEDGER_A, hooks=hooks)
        self.assertEqual(code, 0, out)
        self.assertIn("PASS  ... and no tool hook that ended before the teller began found it in the reason file and left it out", out)
        # A hook that found it listed and left it out failed to tell it, however soon after the line it began: 40 ms
        # here, and one hook of the next request too (a 0.5 s margin let the first pass).
        for k, dropped in enumerate((
                hooks[:2] + [hook("PostToolBatch", 1.04, seen=9)] + hooks[3:],
                hooks[:3] + [hook("PostToolUse:Bash", 2.1, seen=9), hook("PostToolBatch", 2.15, WRITE, seen=9)])):
            code, out = run_e2e(late, LEDGER_A, hooks=dropped)
            self.assertEqual(code, 1, (k, out))
            self.assertIn("FAIL  ... and no tool hook that ended before the teller began found it in the reason file and left it out; "
                          + ("PostToolBatch began" if k == 0 else "PostToolUse began"), out)
        # Hooks of one event start together and one of them claims it: a sibling that found it listed and printed
        # nothing did not run before the teller, and passes.
        siblings = hooks[:3] + [hook("PostToolUse:Bash", 2.1, seen=9, took=0.05), hook("PostToolUse:Bash", 2.1005, WRITE, seen=9)] + hooks[4:]
        code, out = run_e2e(late, LEDGER_A, hooks=siblings)
        self.assertEqual(code, 0, out)
        # A tool hook without the seq it began with cannot be judged, and fails.
        blind = hooks[:2] + [hook("PostToolBatch", 1.06)] + hooks[3:]
        code, out = run_e2e(late, LEDGER_A, hooks=blind)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL  ... every tool hook carries the reason file's seq the stand-in read before it began (1 does not)", out)
        # Two hooks telling it, or a teller that ran before the line landed, fail too.
        twice = hooks[:2] + [hook("PostToolBatch", 1.04, WRITE, seen=9)] + hooks[3:]
        code, out = run_e2e(late, LEDGER_A, hooks=twice)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL  ... told by one hook (2 told it)", out)
        early = hooks[:1] + [hook("PostToolUseFailure:Write", 0.5, WRITE, seen=5)] + hooks[2:3] + [hook("PostToolUse:Bash", 2.1, seen=9)] + hooks[4:]
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR, note(WRITE)]), tentry(3, [res("s")])], LEDGER_A, hooks=early)
        self.assertEqual(code, 1, out)
        self.assertIn("FAIL  ... by a hook that ran after its line landed", out)

    def test_a_refusal_told_again_later_fails(self):
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR, note(WRITE)]), tentry(3, [note(WRITE, label="Stop")])], LEDGER_A)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  ... and no later request repeats it", out)

    def test_no_refusal_means_no_tego_text_but_isolation_is_only_noted(self):
        good = [TURN0, TURN1, tentry(2, [res("n"), note(ISO, label="PostToolUse:Write")]), tentry(3, [txt("done")])]
        code, out = run_e2e(good, LEDGER_A[:1], scenario="e")
        self.assertEqual(code, 0, out)
        self.assertIn("NOTE  it carries 1 refusal(s)", out)
        code, out = run_e2e([TURN0, TURN1, tentry(2, [res("n"), note(WRITE)]), tentry(3, [txt("done")])], LEDGER_A, scenario="e")
        self.assertEqual(code, 1)
        self.assertIn("FAIL  the next request carries no tego text", out)

    def test_tego_text_outside_a_hook_note_counts_too(self):
        # Tego's words reaching the model some other way than a "<Label> hook additional context: " note (a harness
        # that drops the marker, or puts a hook's output into the tool result) are still tego text in the request.
        envelope = "Tego, this run's access control, refused 1 action:\n- " + WRITE + "\n"
        unmarked = [
            {"type": "text", "role": "system", "text": envelope},
            {"type": "text", "role": "user", "text": f"<system-reminder>{envelope}</system-reminder>"},
            {"type": "text", "role": "user", "text": "Tego, this run's access control, refused 1 action:"},
            dict(res("n"), content="ok\n" + WRITE),
        ]
        for block in unmarked:
            tail = [block] if block.get("type") == "tool_result" else [res("n"), block]
            code, out = run_e2e([TURN0, TURN1, tentry(2, tail), tentry(3, [txt("done")])], LEDGER_A[:1], scenario="e")
            self.assertEqual(code, 1, f"{block}\n{out}")
            self.assertIn("FAIL  the next request carries no tego text", out)
        # An unmarked envelope that holds only isolation refusals is the account's own configuration, as in a note.
        iso = {"type": "text", "role": "system", "text": "Tego, this run's access control, refused 1 action:\n- " + ISO + "\n"}
        code, out = run_e2e([TURN0, TURN1, tentry(2, [res("n"), iso]), tentry(3, [txt("done")])], LEDGER_A[:1], scenario="e")
        self.assertEqual(code, 0, out)
        # A refusal told again later outside a note is a repeat, and so is one told twice that way.
        later = {"type": "text", "role": "system", "text": envelope}
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR, note(WRITE)]), tentry(3, [later])], LEDGER_A)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  ... and no later request repeats it", out)
        self.assertIn("FAIL  no refusal line is told twice in the run", out)

    def test_tego_text_in_a_hook_note_counts_in_any_form(self):
        # Inside a note too, tego's text is every line that holds "Tego refused ", whatever its bullet, and tego's
        # heading when no refusal line follows it: with nothing new an event prints nothing (REASON-CHANNEL 3).
        head = "Tego, this run's access control, refused 1 action:"
        marked = [
            head + "\n",
            head + "\n" + WRITE + "\n",
            head + "\n* " + WRITE + "\n",
            WRITE + "\n",
            head + "\n- " + ISO + "\n2 more not listed.\n",  # what reason.Render leaves out may be the scenario's
        ]
        for body in marked:
            block = {"type": "text", "role": "system", "text": f"PostToolUse:Write hook additional context: {body}"}
            code, out = run_e2e([TURN0, TURN1, tentry(2, [res("n"), block]), tentry(3, [txt("done")])], LEDGER_A[:1], scenario="e")
            self.assertEqual(code, 1, f"{body!r}\n{out}")
            self.assertIn("FAIL  the next request carries no tego text", out)
        # A note left with only isolation refusals, in whatever form, is still only noted.
        iso = {"type": "text", "role": "system", "text": f"PostToolUse:Write hook additional context: {head}\n{ISO}\n"}
        code, out = run_e2e([TURN0, TURN1, tentry(2, [res("n"), iso]), tentry(3, [txt("done")])], LEDGER_A[:1], scenario="e")
        self.assertEqual(code, 0, out)
        self.assertIn("NOTE  it carries 1 refusal(s)", out)
        # A later note that repeats the refusal without its dash is a repeat.
        later = {"type": "text", "role": "system", "text": f"Stop hook additional context: {head}\n{WRITE}\n"}
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR, note(WRITE)]), tentry(3, [later])], LEDGER_A)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  ... and no later request repeats it", out)
        self.assertIn("FAIL  no refusal line is told twice in the run", out)

    def test_a_run_that_left_no_ledger_fails_and_says_so(self):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "stub.log")
            with open(log, "w") as f:
                f.write(json.dumps(TURN0) + "\n")
            for led in ("", os.path.join(d, "none.jsonl")):
                with contextlib.redirect_stdout(out):
                    code = report.main(["e2e", log, "--ledger", led, "--scenario", "a"])
                self.assertEqual(code, 1)
        self.assertEqual(out.getvalue().count("FAIL  the run left a ledger"), 2, out.getvalue())

    def test_golden_drift_fails(self):
        golden = {"notes": ["user-reminder"], "refusals": [], "tool_results": []}
        code, out = run_e2e([TURN0, TURN1, tentry(2, [ERR, note(WRITE)]), tentry(3, [txt("done")])], LEDGER_A, golden=golden)
        self.assertEqual(code, 1)
        self.assertIn("FAIL  the next request, normalised, equals", out)


if __name__ == "__main__":
    unittest.main()
