#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact guest evidence assertions and host-safe deliberately wrong controls."""
import argparse
import copy
import json
import os
import re
from pathlib import Path
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_events(path, damaged=False):
    events = []
    for line in Path(path).read_text().splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            require(damaged, "invalid record line without injected record fault")
    return events


def operation(events, ask, verdict):
    selected = [e for e in events if e.get("kind") == "ask" and e.get("ask_id") == ask]
    require(len(selected) == 1, "exact held ask absent or duplicated")
    held = selected[0]
    matches = [e for e in events if e.get("kind") == "fs" and e.get("pid") == held["pid"]
               and e.get("tid") == held["tid"] and e.get("run") == held["run"]
               and e.get("op") == "open" and e.get("path") == held["target"]
               and e.get("seq", -1) > held["seq"]]
    require(len(matches) == 1, "held operation's own completion absent or duplicated")
    effect = matches[0]
    require(effect.get("id") and effect.get("verdict") == verdict, "held operation has wrong verdict/id")
    return dict(ask_id=ask, ask_event_id=held["id"], operation_event_id=effect["id"], operation_seq=effect["seq"],
                pid=held["pid"], tid=held["tid"], target=held["target"], verdict=verdict)


def actor(events, ask, identity, approved=True):
    answers = [e for e in events if e.get("kind") == "answer" and e.get("ask_id") == ask]
    require(len(answers) == 1, "answer absent or duplicated")
    answer = answers[0]
    actual = answer.get("actor", {})
    require(answer.get("approved") is approved, "wrong recorded decision")
    require(actual.get("pid") == identity["pid"] and actual.get("start_boot_ns") == identity["start_boot_ns"],
            "recorded actor differs from captured answerer's PID/start")
    require(actual.get("uid") == 0 and actual.get("role") == "owner"
            and actual.get("source") == "kernel-local-uid"
            and actual.get("user_namespace") == identity["user_namespace"], "wrong actor authority")


def status(path, expected):
    require(Path(path).read_text() == str(expected) + "\n", str(path) + ": wrong exact exit status")


def result(case, expected):
    path = Path(case) / "work/out/result"
    if expected == "absent":
        require(not path.exists(), "dead caller unexpectedly wrote a result")
    else:
        require(path.read_text() == expected + "\n", "wrong exact held caller result")
    effect = Path(case) / "work/held/effect"
    if expected == "0":
        require(effect.read_bytes() == b"ONE-EFFECT\n", "wrong held effect bytes")
    else:
        require(not effect.exists(), "refused held operation produced an effect")


def broker(replies, identity, count):
    replies = [r for r in replies if r.get("peer_pid") == identity["pid"]
               and r.get("peer_uid") == 21001 and r.get("code") == "owner-only"
               and "only root may answer once" in r.get("error", "")]
    require(len(replies) == count, "dashboard lacks exact broker reply count for actual dashboard PID")
    require(all(r.get("packet_pidfd") is True for r in replies), "6.17 row did not use kernel packet pidfds")



def placement(mode, owner, socket_mode, socket_owner):
    require((mode, owner) == (0o755, 0), "diagnostic live run placement differs from explicit 0755 root fixture")
    require((socket_mode, socket_owner) == (0o600, 21001), "product socket placement changed")


# Wire sentinel and launch diagnostics are pinned by the product catalogue/specs.
NOT_PENDING = "tego approve: ask: request is no longer pending [io]"
# The root-drop refusal names the program to run as root: the tego in this helper's own folder (/opt/roles1 in the
# guest, which the guest script makes root-owned and not group-writable first, as the product's path check needs).
GUEST_TEGO = str(Path(__file__).resolve().parent / "tego")


def root_drop_text(program):
    return ("tego run: runtime: root launcher with no unprivileged uid to drop the agent to: "
            "from your login shell, run it as root (sudo " + program + " run), "
            "or as the unprivileged user the agent should run as [run]")


ROOT_DROP = root_drop_text(GUEST_TEGO)
# What the product prints for a program whose path it cannot vouch for (a writable group): a reason and no command.
UNTRUSTED_ROOT_DROP = ("tego run: runtime: root launcher with no unprivileged uid to drop the agent to: from your login shell, "
                       "run it as root (cannot verify that only root or you can change this tego's path, so no command is shown")
ADOPT_FLOOR = ('tego adopt: admission check "local approval floor" during preparation: runtime: invalid adoption: '
               'local root-only approvals do not support adoption [run]')
LOCAL_LAUNCH = ("tego run: runtime: local root-only approvals require initial-namespace root, "
                "a non-root child, enforcement, recording and setuid disabled [run]")


def race_loser(code, text, run):
    ended = "tego approve: " + run + " has ended; nothing waits for an answer [not-running]"
    require((code == 125 and NOT_PENDING in text.splitlines())
            or (code == 1 and ended in text.splitlines()), "wrong race loser status or diagnostic")


def activation_refusal(kind, code, text):
    expected = ROOT_DROP if kind == "root-drop" else LOCAL_LAUNCH
    if kind == "adopt":
        expected = ADOPT_FLOOR
    require(code == 125 and expected in text.splitlines(), "wrong activation status or diagnostic: " + kind)


def fault_cause(pattern, errors, events, run):
    # Shutdown can overtake the broker reply after ledgerFailed saved the cause.
    # A shell trace or another run's error is not evidence of this injected fault.
    matches = [line for text in errors for line in text.splitlines()
               if line.startswith("tego ") and re.search(pattern, line)]
    matches.extend(e["detail"] for e in events
                   if e.get("kind") == "run_end" and e.get("run") == run
                   and e.get("reason") == "error" and re.search(pattern, e.get("detail", "")))
    require(matches, "injected fault cause absent from product diagnostics and this run's error record")
    return matches


def self_check():
    held = dict(kind="ask", ask_id="q-one", run="r-one", pid=42, tid=42, seq=1, id="ask-id", target="/held/one")
    effect = dict(kind="fs", run="r-one", pid=42, tid=42, seq=3, id="op-id", op="open", path="/held/one", verdict="refused")
    identity = dict(pid=61, start_boot_ns=10000000, user_namespace=4026531837)
    answer = dict(kind="answer", ask_id="q-one", approved=True, actor=dict(identity, uid=0, role="owner", source="kernel-local-uid"))
    good = [held, answer, effect]
    operation(good, "q-one", "refused")
    actor(good, "q-one", identity)
    reply = dict(peer_pid=61, peer_uid=21001, code="owner-only", error="only root may answer once", packet_pidfd=True)
    broker([reply, reply], identity, 2)
    race_loser(125, "tego approve: ask: request is no longer pending [io]\n", "r-one")
    ended = "tego approve: r-one has ended; nothing waits for an answer [not-running]"
    race_loser(1, ended + "\n", "r-one")
    activation_refusal("root-drop", 125, ROOT_DROP + "\n")
    for kind in ("record-off", "observe", "setuid", "userns"):
        activation_refusal(kind, 125, LOCAL_LAUNCH + "\n")
    activation_refusal("adopt", 125, ADOPT_FLOOR + "\n")
    fault = dict(kind="run_end", run="r-one", reason="error", detail="ledger: ledger: required approval sync: input/output error")
    cancelled = ["tego approve: ask: unavailable: context canceled [io]"]
    fault_cause("input/output error", cancelled, [fault], "r-one")
    cases = [
        ("fault-cancellation-only", lambda: fault_cause("input/output error", cancelled, [], "r-one")),
        ("fault-other-run", lambda: fault_cause("input/output error", cancelled, [fault], "r-other")),
        ("fault-wrong-record-kind", lambda: fault_cause("input/output error", cancelled, [dict(fault, kind="answer")], "r-one")),
        ("fault-wrong-end-reason", lambda: fault_cause("input/output error", cancelled, [dict(fault, reason="exit")], "r-one")),
        ("fault-wrong-cause", lambda: fault_cause("short write", cancelled, [fault], "r-one")),
        ("fault-shell-trace-only", lambda: fault_cause("input/output error", ["+ grep input/output error"], [], "r-one")),
        ("race-invented-not-pending", lambda: race_loser(125, "tego approve: ask: request is not pending [io]", "r-one")),
        ("race-wrong-status", lambda: race_loser(0, NOT_PENDING, "r-one")),
        ("race-ended-wrong-status", lambda: race_loser(125, ended, "r-one")),
        ("race-ended-other-run", lambda: race_loser(1, ended, "r-other")),
        ("race-unrelated-refusal", lambda: race_loser(125, "permission denied", "r-one")),
        ("root-drop-wrong-role-expectation", lambda: activation_refusal("root-drop", 125, LOCAL_LAUNCH)),
        ("root-drop-wrong-status", lambda: activation_refusal("root-drop", 0, ROOT_DROP)),
        ("root-drop-old-wording", lambda: activation_refusal("root-drop", 125, ROOT_DROP.replace("from your login shell, run it as root (sudo " + GUEST_TEGO + " run)", "run it as `sudo tego run`"))),
        ("root-drop-untrusted-path-no-command", lambda: activation_refusal("root-drop", 125, UNTRUSTED_ROOT_DROP + "\n")),
        ("adopt-without-admission-prefix", lambda: activation_refusal("adopt", 125, ADOPT_FLOOR.replace('admission check "local approval floor" during preparation: ', ""))),
        ("userns-inaccessible-contract", lambda: activation_refusal("userns", 125, "agent.yaml: agent: open agent.yaml: permission denied [io]")),
        ("userns-missing-delegation", lambda: activation_refusal("userns", 125, "agent.yaml: tier landlock pinned but not available [tier-unavailable]")),
        ("activation-timeout", lambda: activation_refusal("setuid", 124, LOCAL_LAUNCH)),
        ("activation-backend-failure", lambda: activation_refusal("setuid", 125, "tier unavailable")),
    ]
    for field, value in (("pid", 99), ("tid", 99), ("run", "r-other"), ("path", "/unrelated"), ("op", "read"), ("verdict", "allow"), ("seq", 0), ("id", "")):
        wrong = copy.deepcopy(good); wrong[-1][field] = value
        cases.append(("operation-" + field, lambda wrong=wrong: operation(wrong, "q-one", "refused")))
    cases.append(("operation-unrelated-refused", lambda: operation([held, answer, dict(effect, path="/other")], "q-one", "refused")))
    cases.append(("operation-missing", lambda: operation([held, answer], "q-one", "refused")))
    cases.append(("operation-wrong-ask", lambda: operation(good, "q-other", "refused")))
    cases.append(("operation-duplicated", lambda: operation(good + [effect], "q-one", "refused")))
    cases.append(("ask-duplicated", lambda: operation(good + [held], "q-one", "refused")))
    cases.append(("answer-duplicated", lambda: actor(good + [answer], "q-one", identity)))
    cases.append(("answer-wrong-decision", lambda: actor([held, dict(answer, approved=False), effect], "q-one", identity)))
    for field, value in (("pid", 99), ("start_boot_ns", 20), ("user_namespace", 99), ("uid", 1), ("role", "agent"), ("source", "claimed")):
        wrong = copy.deepcopy(good); wrong[1]["actor"][field] = value
        cases.append(("actor-" + field, lambda wrong=wrong: actor(wrong, "q-one", identity)))
    for field, value in (("peer_pid", 99), ("peer_uid", 0), ("code", "unavailable"), ("error", "permission denied: only root"), ("packet_pidfd", False)):
        wrong = dict(reply); wrong[field] = value
        cases.append(("broker-" + field, lambda wrong=wrong: broker([wrong, wrong], identity, 2)))
    cases.append(("broker-reply-missing", lambda: broker([reply], identity, 2)))
    # TEGO_ROLES_SCRATCH names a disk-backed parent for the case folders; unset, the system temporary folder is used.
    scratch = os.environ.get("TEGO_ROLES_SCRATCH") or None
    if scratch:
        Path(scratch).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as directory:
        case = Path(directory)
        (case / "work/out").mkdir(parents=True)
        (case / "work/held").mkdir()
        (case / "work/out/result").write_text("2\n")
        result(case, "2")
        wrong_effect = case / "wrong-effect"
        (wrong_effect / "work/out").mkdir(parents=True)
        (wrong_effect / "work/held").mkdir()
        (wrong_effect / "work/out/result").write_text("2\n")
        (wrong_effect / "work/held/effect").write_text("UNEXPECTED\n")
        wrong_success = case / "wrong-success"
        (wrong_success / "work/out").mkdir(parents=True)
        (wrong_success / "work/held").mkdir()
        (wrong_success / "work/out/result").write_text("0\n")
        (wrong_success / "work/held/effect").write_text("WRONG-EFFECT\n")
        (case / "verify.status").write_text("125\n")
        cases.extend([
            ("refused-operation-has-effect", lambda: result(wrong_effect, "2")),
            ("allowed-operation-wrong-effect", lambda: result(wrong_success, "0")),
            ("caller-wrong-result", lambda: result(case, "0")),
            ("caller-missing-result", lambda: result(case / "missing", "2")),
            ("dead-caller-has-result", lambda: result(case, "absent")),
            ("clean-verify-failed", lambda: status(case / "verify.status", 0)),
            ("diagnostic-unreadable-0711", lambda: placement(0o711, 0, 0o600, 21001)),
            ("diagnostic-wrong-owner", lambda: placement(0o755, 21001, 0o600, 21001)),
            ("socket-mode-altered", lambda: placement(0o755, 0, 0o666, 21001)),
            ("socket-owner-altered", lambda: placement(0o755, 0, 0o600, 0)),
        ])
        for name, check in cases:
            try:
                check()
            except (AssertionError, FileNotFoundError):
                print(name + "\tFAIL (expected)")
            else:
                raise AssertionError("self-check accepted wrong outcome: " + name)
    print("ASSERTION-SELF-CHECK-DONE: " + str(len(cases)) + " wrong outcomes rejected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("self-check")
    capture = sub.add_parser("exec")
    capture.add_argument("identity", type=Path)
    capture.add_argument("argv", nargs=argparse.REMAINDER)
    record = sub.add_parser("operation")
    record.add_argument("events"); record.add_argument("ask"); record.add_argument("verdict")
    record = sub.add_parser("actor")
    record.add_argument("events"); record.add_argument("ask"); record.add_argument("identity", type=Path)
    record.add_argument("--deny", action="store_true")
    check = sub.add_parser("result"); check.add_argument("case"); check.add_argument("expected")
    check = sub.add_parser("status"); check.add_argument("path"); check.add_argument("expected", type=int)
    check = sub.add_parser("placement"); check.add_argument("directory", type=Path)
    check = sub.add_parser("broker"); check.add_argument("path"); check.add_argument("identity", type=Path); check.add_argument("count", type=int)
    check = sub.add_parser("race-loser"); check.add_argument("status"); check.add_argument("stderr"); check.add_argument("run")
    check = sub.add_parser("activation-refusal"); check.add_argument("kind"); check.add_argument("status"); check.add_argument("stderr")
    check = sub.add_parser("fault-cause"); check.add_argument("pattern"); check.add_argument("events"); check.add_argument("run"); check.add_argument("stderr", nargs="+")
    args = parser.parse_args()
    if args.command == "self-check":
        self_check()
    elif args.command == "fault-cause":
        print("\n".join(fault_cause(args.pattern, [Path(p).read_text() for p in args.stderr],
                                     read_events(args.events, damaged=True), args.run)))
    elif args.command == "race-loser":
        race_loser(int(Path(args.status).read_text()), Path(args.stderr).read_text(), args.run)
    elif args.command == "activation-refusal":
        activation_refusal(args.kind, int(Path(args.status).read_text()), Path(args.stderr).read_text())
    elif args.command == "exec":
        stat = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        identity = dict(pid=os.getpid(), start_boot_ns=int(stat[19]) * (1000000000 // os.sysconf("SC_CLK_TCK")),
                        user_namespace=os.stat("/proc/self/ns/user").st_ino)
        args.identity.write_text(json.dumps(identity) + "\n")
        os.execvp(args.argv[0], args.argv)
    elif args.command == "operation":
        print(json.dumps(operation(read_events(args.events), args.ask, args.verdict)))
    elif args.command == "actor":
        actor(read_events(args.events), args.ask, json.loads(args.identity.read_text()), not args.deny)
    elif args.command == "result":
        result(args.case, args.expected)
    elif args.command == "status":
        status(args.path, args.expected)
    elif args.command == "placement":
        directory, sock = args.directory.stat(), (args.directory / "ask.sock").stat()
        placement(directory.st_mode & 0o777, directory.st_uid, sock.st_mode & 0o777, sock.st_uid)
    elif args.command == "broker":
        broker(read_events(args.path), json.loads(args.identity.read_text()), args.count)


if __name__ == "__main__":
    main()
