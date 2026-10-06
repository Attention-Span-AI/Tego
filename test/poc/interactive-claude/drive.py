# SPDX-License-Identifier: Apache-2.0
#
# drive.py — plays the person at the keyboard for README.md's session: it starts the REAL interactive Claude Code
# under `tego watch --boundary` on a pseudo-terminal, gets past Claude Code's own first-run dialogs, types prompts,
# answers Claude Code's own permission questions, and, from a separate process, answers tego's approvals
# (`tego ask`, `tego approve --always`). The model is the local stand-in (stub/server.py answering stub-script.json),
# so what Claude Code "decides" to do is fixed by the script; everything after that decision is the real thing: the
# real TUI, the real tool code, the real kernel refusals.
#
# Usage: drive.py <root> [session|reason|probe-nokey|probe-nokey-unseeded]
#        reason: part 1 only (the write inside, the write outside, git push), then /exit: the interactive half of
#        test/e2e/reason-claude (its run.sh reads the model stub's log for the refusal's reason).
#        (run.sh sets <root> up: tego, config, stand-in, workspace). A probe starts Claude Code, says which screen it
#        reached and stops; DRIVE_NO_KEY=1 leaves the dummy key out of the environment.
# It writes screens to <root>/evidence/ and prints a line per action. Exit 0 when every step did what it should.
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyscreen import Session  # noqa: E402

root = os.path.abspath(sys.argv[1])
mode = sys.argv[2] if len(sys.argv) > 2 else "session"
ws, ev = f"{root}/ws", f"{root}/evidence/{mode}"
tego = f"{root}/bin/tego"
os.makedirs(ev, exist_ok=True)

# The agent's environment is built from nothing: tego sees these, and passes the contract's env.pass names on.
# The key is an obvious dummy; the stand-in does not look at it. SSL_CERT_FILE is tego's own (the forwarder's TLS
# client trusts the stand-in's certificate through it); the contract does not pass it, so the agent never has it.
KEY = "sk-ant-api03-OFFLINE-DUMMY-NOT-A-REAL-KEY-" + "0" * 20
# tego's runtime directory is the POC's own (run.sh makes the same one): the launch makes <XDG_RUNTIME_DIR>/tego and
# sweeps the directories the invoking user's crashed runs left there (identity-config.md R27 clause b4); 0700, as tego
# requires. The agent's own XDG_RUNTIME_DIR is the contract's env.set. Not under state/: tego denies the agent its own
# state directory, and the Claude Code settings file a run provisions is in the runtime directory.
runtime_dir = f"{root}/run"
os.makedirs(runtime_dir, exist_ok=True)
os.chmod(runtime_dir, 0o700)
tego_env = {
    "PATH": f"{ws}/bin:" + os.environ.get("PATH", "/usr/bin:/bin"),
    "LANG": os.environ.get("LANG", "C.UTF-8"),
    "HOME": f"{root}/home",
    "TERM": "xterm-256color",
    "COLORTERM": "truecolor",
    "XDG_RUNTIME_DIR": runtime_dir,
    "SSL_CERT_FILE": f"{root}/stub/cert.pem",
    "TEGO_CONFIG": f"{root}/state/config.yaml",
    "TEGO_TEST_CHAIN_ANCHOR": f"{root}/state/chain.log",
    "TEGO_TEST_OWN_LOG_HOME": f"{root}/state/ownlog",
}
if os.environ.get("DRIVE_NO_KEY") != "1":
    tego_env["ANTHROPIC_API_KEY"] = KEY

failures = []
step_no = 0


def check(ok, what):
    print(("PASS  " if ok else "FAIL  ") + what, flush=True)
    if not ok:
        failures.append(what)
    return ok


def snap(s, name, note=""):
    global step_no
    step_no += 1
    path = f"{ev}/{step_no:02d}-{name}.txt"
    with open(path, "w") as f:
        if note:
            f.write(f"# {note}\n")
        f.write(s.screen.text() + "\n")
    s.note(f"screen saved: evidence/{os.path.basename(path)}")


def tego_cmd(*args):
    """A separate tego process, the way a person at a second terminal runs one."""
    p = subprocess.run([tego, *args], env={**tego_env, "ANTHROPIC_API_KEY": ""}, capture_output=True, text=True, timeout=30)
    return p.returncode, (p.stdout + p.stderr)


def newest_run():
    d = f"{root}/state/runs"
    runs = [r for r in os.listdir(d) if r.startswith("r-")] if os.path.isdir(d) else []
    return max(runs, key=lambda r: os.path.getmtime(f"{d}/{r}")) if runs else None


DIALOG = re.compile(r"(Do you want to [^\n]*\?)(.*?)(?:Esc to cancel|$)", re.S)


def answer_claude_dialogs(s, log, deadline_marker=None, timeout=120, extra_loop=None):
    """Until `deadline_marker` is on the screen: say yes to Claude Code's own permission questions (its own
    prompts, not tego's; the contract is the boundary), calling extra_loop(s) every turn."""
    end = time.time() + timeout
    while time.time() < end:
        s.pump(0.3)
        if extra_loop:
            extra_loop(s)
        txt = s.screen.text()
        if deadline_marker and re.search(deadline_marker, txt):
            return True
        m = DIALOG.search(txt)
        if m and re.search(r"1\. Yes", txt):
            q = m.group(1).strip()
            snap(s, "claude-asks", f"Claude Code's own permission question: {q}")
            log.append(q)
            s.note(f"Claude Code asks: {q}  -> choosing 1. Yes")
            s.send("1", 0.4)
            s.send("\r", 0.8)
            # wait for the dialog to go away before looking again
            t2 = time.time() + 10
            while time.time() < t2 and re.search(r"1\. Yes", s.screen.text()):
                s.pump(0.3)
        if not s.alive:
            return False
    return False


def transcript(s, name):
    """Ctrl-O shows Claude Code's transcript view, with the tool results its normal view folds away."""
    s.send("\x0f", 1.5)
    snap(s, name, "Claude Code's transcript view (ctrl+o): the tool results")
    s.send("\x0f", 1.0)
    s.pump(0.5)


def submit(s, prompt):
    s.note(f"typing prompt: {prompt}")
    s.type(prompt)
    s.send("\r", 0.3)


SCREENS = {  # in the order they are tried: the first-run failure screen also says "Welcome to Claude Code"
    "preflight": r"Unable to connect to Anthropic services",
    "trust": r"Yes, I trust this folder",
    "key": r"Detected a custom API key",
    "login": r"Select login method|Choose the text style|Paste code here|Sign in|Welcome to Claude Code",
    "prompt": r"\n\s*❯ ?\s*\n.*(?:auto mode|accept edits|default|shift\+tab|\? for shortcuts)",
}


def first_run(s):
    """Get past Claude Code's first-run dialogs (workspace trust, the dummy-key approval) and return the screen it
    ends on: "prompt" (the prompt box), "login", "preflight", or None."""
    got = None
    for _ in range(8):
        got = s.wait_any(SCREENS, timeout=40)
        if got == "login" and s.wait_for(SCREENS["preflight"], 8):
            got = "preflight"  # the welcome banner is drawn first; the failure follows it a moment later
        s.note(f"first-run screen: {got}")
        if got is None or got in ("login", "preflight", "prompt"):
            break
        snap(s, f"first-run-{got}")
        if got == "trust":
            # the selection starts on "No, exit": move it to "Yes", confirm, and wait for the dialog to go
            s.send("\x1b[B", 0.3)
            s.wait_for(r"❯ Yes, I trust this folder", 10)
            s.send("\r", 0.5)
        elif got == "key":
            # the selection starts on "No (recommended)"
            s.send("\x1b[A", 0.3)
            s.wait_for(r"❯ Yes\b", 10)
            s.send("\r", 0.5)
        t_end = time.time() + 15
        while time.time() < t_end and re.search(SCREENS[got], s.screen.text()):
            s.pump(0.3)
    s.pump(1.5)
    return got


def probe():
    """Start Claude Code and report which screen it reaches."""
    argv = [tego, "watch", "--boundary", f"{root}/contract/agent.yaml", "--offline", "--", "claude", "--permission-mode", "default"]
    s = Session(argv, tego_env, ws, rows=50, cols=140)
    got = first_run(s)
    snap(s, f"probe-{mode}", f"screen reached: {got}")
    print(f"screen reached: {got}")
    if got == "prompt" and mode == "probe-nokey":
        # no key and no login: does the first request go out?
        s.type("hello")
        s.send("\r", 0.3)
        s.pump(15)
        snap(s, f"probe-{mode}-after-a-prompt", "what a prompt does with no key")
    print(s.screen.text())
    rc = s.close()
    print(f"tego watch exited {rc}")


def main():
    argv = [tego, "watch", "--boundary", f"{root}/contract/agent.yaml", "--offline", "--"]
    argv += ["claude", "--permission-mode", "default"]
    s = Session(argv, tego_env, ws, rows=50, cols=140)
    s.note("started: tego watch --boundary contract/agent.yaml -- claude --permission-mode default")

    # ---- first run dialogs (workspace trust, the dummy-key approval), up to the prompt box ------------------------
    got = first_run(s)
    snap(s, "first-run-end", f"first-run result: {got}")
    if not check(got == "prompt", "Claude Code reaches its prompt box with a dummy key and no login screen"):
        s.close()
        return
    time.sleep(1)
    s.pump(1)
    run = None
    for _ in range(20):
        run = newest_run()
        if run:
            break
        time.sleep(0.2)
    s.note(f"run id: {run}")
    open(f"{ev}/run-id.txt", "w").write((run or "") + "\n")

    dialogs = []

    # ---- 1. a write inside the workspace, a write outside, git push ---------------------------------------------
    submit(s, "Please run the first part of the demo.")
    ok = answer_claude_dialogs(s, dialogs, r"STEP-1-DONE", timeout=120)
    snap(s, "part1-done", "after the stand-in's three tool calls: write inside, write outside, git push")
    transcript(s, "part1-transcript")
    check(ok, "part 1 ended: the stand-in's three tool calls were each tried")
    check(os.path.exists(f"{ws}/work/note.txt"), "write inside the workspace: work/note.txt exists")
    check(not os.path.exists(f"{root}/outside/leak.txt"), "write outside the workspace: outside/leak.txt does not exist")

    if mode == "reason":
        finish(s, dialogs, [])
        return

    # ---- 2. the held directory: a person answers from another process ---------------------------------------------
    answers = []
    state = {"approved": set()}

    def person(s_):
        rc, out = tego_cmd("ask", run)
        for line in out.splitlines():
            m = re.match(r"(q-\S+)\s+(.*)", line)
            if m and m.group(1) not in state["approved"]:
                qid = m.group(1)
                state["approved"].add(qid)
                snap(s_, "held-by-tego", f"the agent is held on {line.strip()}")
                s_.note(f"tego holds: {line.strip()}")
                s_.pump(2.0)  # a person reads it for a moment; Claude Code's screen keeps its spinner
                snap(s_, "held-by-tego-2s", "two seconds later, still held")
                # The journal is written in place, so a standing answer to its exact path is worth giving; the Write
                # tool's temporary file has a new random name every time, so "always" there would never match.
                flags = ["--always"] if "journal" in line else []
                rc2, out2 = tego_cmd("approve", run, qid, *flags)
                s_.note(f"person: tego approve {run} {qid} {' '.join(flags)} -> rc={rc2}")
                answers.append((qid, line.strip(), rc2, out2.strip()))

    submit(s, "Now the second part: the held directory.")
    ok = answer_claude_dialogs(s, dialogs, r"STEP-2-DONE", timeout=180, extra_loop=person)
    snap(s, "part2-done", "after the held writes")
    transcript(s, "part2-transcript")
    check(ok, "part 2 ended")
    check(len(answers) >= 1, f"tego held the agent and a person answered ({len(answers)} approval(s) from a second process)")
    finish(s, dialogs, answers)


def finish(s, dialogs, answers):
    """/exit, and the driver's record of the session."""
    submit(s, "/exit")
    s.pump(3)
    rc = s.close()
    s.note(f"tego watch exited {rc}")
    json.dump({"claude_dialogs": dialogs, "answers": answers, "failures": failures}, open(f"{ev}/driver.json", "w"), indent=1)
    open(f"{ev}/screen-final.txt", "w").write(s.screen.everything() + "\n")


if __name__ == "__main__":
    probe() if mode.startswith("probe") else main()
    sys.exit(1 if failures else 0)
