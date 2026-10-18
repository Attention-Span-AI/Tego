# SPDX-License-Identifier: Apache-2.0
#
# drive.py — plays the person at the keyboard for README.md's session: it starts the REAL interactive Codex under
# `tego watch --boundary` on a pseudo-terminal, types the dummy API key into Codex's login screen, types prompts, and,
# from separate processes, answers tego's approvals (`tego ask`, `tego approve [--always]`, `tego deny --always`).
# The model is the local stand-in (test/workloads/model-stub/openai_responses.py answering stub-script.json), so what
# Codex "decides" to do is fixed by the script; everything after that decision is the real thing: the real TUI, the
# real tool code, the shell it starts, the real kernel refusals.
#
# Usage: drive.py <root> <mode>
#        (run.sh sets <root> up: tego, config, stand-in, workspace, contract). Modes:
#          session       the whole scripted session and the checks below
#          probe         start Codex, say which screens it reached, wait DRIVE_WAIT seconds (default 12) at the prompt
#                        box, optionally type one prompt (DRIVE_PROMPT), and stop. DRIVE_ARGS are codex's own flags
#                        (default "--no-daemon"; the empty string starts it with none), DRIVE_NO_LOGIN=1 types no key
#          probe-login   try the login screen's other two ways in, the ChatGPT account ones
#        Other switches: DRIVE_LABEL names the evidence directory; DRIVE_ROUTE=b is the custom-provider route (the key is
#        in the environment and there is no login screen); DRIVE_BOUNDARY=none runs with no contract, recording only.
#        It writes screens to <root>/evidence/<label>/ and prints a line per action. Exit 0 when every step did what it
#        should.
import json
import os
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True  # the shared module is in another directory: leave no __pycache__ there
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "interactive-claude"))
from ptyscreen import Session  # noqa: E402  the one terminal emulator the POC has: shared, not copied

root = os.path.abspath(sys.argv[1])
mode = sys.argv[2] if len(sys.argv) > 2 else "session"
label = os.environ.get("DRIVE_LABEL", mode)
ws, ev = f"{root}/ws", f"{root}/evidence/{label}"
tego = f"{root}/bin/tego"
os.makedirs(ev, exist_ok=True)

# The key is an obvious dummy; the stand-in does not look at it. It is typed into Codex's own login screen ("Provide
# your own API key"), which stores it as auth.json in the run's private CODEX_HOME, because Codex's interactive
# interface reads no API key from the environment. SSL_CERT_FILE is tego's own (the forwarder's TLS client trusts the
# stand-in's certificate through it); the contract does not pass it on, so the agent never has it.
KEY = "sk-offline-DUMMY-not-a-real-key-" + "0" * 16
tego_env = {
    "PATH": f"{ws}/bin:" + os.environ.get("PATH", "/usr/bin:/bin"),
    "LANG": os.environ.get("LANG", "C.UTF-8"),
    "HOME": f"{root}/home",
    "TERM": "xterm-256color",
    "COLORTERM": "truecolor",
    "HISTFILE": "/dev/null",
    # tego puts the run's private CODEX_HOME in $XDG_RUNTIME_DIR/tego/<run>/codex (capture-derive.md R19b)
    "XDG_RUNTIME_DIR": f"{root}/xdg-tego",
    "SSL_CERT_FILE": f"{root}/stub/cert.pem",
    "TEGO_CONFIG": f"{root}/state/config.yaml",
    "TEGO_TEST_CHAIN_ANCHOR": f"{root}/state/chain.log",
    "TEGO_TEST_OWN_LOG_HOME": f"{root}/state/ownlog",
}

# DRIVE_BOUNDARY=none: no contract, tego only records (run.sh, L). Codex then talks to the plain stand-in itself
# (openai_base_url in its own config) and keeps its state in the workspace.
boundary = os.environ.get("DRIVE_BOUNDARY") != "none"
if not boundary:
    tego_env["CODEX_HOME"] = f"{ws}/.codex-state"
    tego_env.pop("SSL_CERT_FILE")
    # The recording keeps the private XDG_RUNTIME_DIR above. A person who runs `tego watch -- codex` has their own
    # (their D-Bus session bus and agent sockets under it), and until 2026-10-24 this mode handed on the caller's so
    # that `learn` saw those sockets; but that launch made the caller's <XDG_RUNTIME_DIR>/tego and removed the
    # directories their crashed runs left there (identity-config.md R27 clause b4). The proposal `learn` makes from this
    # recording names $ROOT/xdg-tego where a person's would name their /run/user/<uid>.

# DRIVE_ROUTE=b: Codex is pointed at the forwarder by a custom provider whose key is read from the environment
# (STAND_IN_API_KEY), so its login screen never appears; route a (default) is the built-in provider, which asks for one.
route = os.environ.get("DRIVE_ROUTE", "a")
if route == "b":
    tego_env["STAND_IN_API_KEY"] = KEY

failures = []
step_no = 0
login_seen = False


def check(ok, what):
    print(("PASS  " if ok else "FAIL  ") + what, flush=True)
    if not ok:
        failures.append(what)
    return ok


def snap(s, name, note="", everything=False):
    global step_no
    step_no += 1
    path = f"{ev}/{step_no:02d}-{name}.txt"
    text = s.screen.everything() if everything else s.screen.text()
    # the splash art is braille: drop its lines, they carry no text
    text = "\n".join(line for line in text.splitlines() if not re.match(r"^[\s⠀-⣿]+$", line) or not line.strip())
    with open(path, "w") as f:
        if note:
            f.write(f"# {note}\n")
        f.write(text.rstrip() + "\n")
    s.note(f"screen saved: evidence/{label}/{os.path.basename(path)}")


def tego_cmd(*args):
    """A separate tego process, the way a person at a second terminal runs one."""
    p = subprocess.run([tego, *args], env=tego_env, capture_output=True, text=True, timeout=30)
    return p.returncode, (p.stdout + p.stderr)


def newest_run():
    d = f"{root}/state/runs"
    runs = [r for r in os.listdir(d) if r.startswith("r-")] if os.path.isdir(d) else []
    return max(runs, key=lambda r: os.path.getmtime(f"{d}/{r}")) if runs else None


def start(extra):
    if boundary:
        argv = [tego, "watch", "--boundary", f"{root}/contract/agent.yaml", "--offline", "--", "codex"] + extra
    else:
        argv = [tego, "watch", "--", "codex"] + extra
    return Session(argv, tego_env, ws, rows=50, cols=140)


SCREENS = {
    "login": r"Provide your own API key",
    "trust": r"Trust and continue",
    "upgrade": r"Try new model",
    "daemon-error": r"app server did not become ready|rerun the same command with --no-daemon",
}
PROMPT = r"› Ask Codex to do anything"


def first_run(s, log_in=True):
    """Get Codex to its prompt box: its login screen (shown on every start, since the run's CODEX_HOME holds no
    auth.json) and, if the contract's config did not pre-trust the folder, its trust question. Returns "prompt",
    or the name of the screen it is stuck on, or None."""
    global login_seen
    first = float(os.environ.get("DRIVE_FIRST_TIMEOUT", "25"))
    got = s.wait_any({**SCREENS, "prompt": PROMPT}, timeout=first)
    if got == "prompt":
        # the prompt box is drawn first and, when Codex holds no credential, the login screen replaces it a moment later
        s.pump(3.0)
        got = s.wait_any(SCREENS, timeout=0.3) or "prompt"
    s.note(f"first screen after {first:.0f} s at most: {got}")
    for _ in range(4):
        if got == "login":
            login_seen = True
            snap(s, "first-run-login", "Codex's login screen: no auth.json exists in the run's CODEX_HOME")
            if not log_in:
                return "login"
            # the selection starts on "Sign in with ChatGPT" (which needs auth.openai.com, refused): move to 3
            s.send("\x1b[B", 0.3)
            s.send("\x1b[B", 0.3)
            s.send("\r", 1.0)
            s.wait_for(r"Paste or type your API key", 10)
            s.type(KEY)
            s.send("\r", 1.5)
        elif got == "trust":
            snap(s, "first-run-trust", "Codex's folder trust question")
            s.send("\r", 1.5)
        else:
            break
        got = s.wait_any({**SCREENS, "prompt": PROMPT}, timeout=25)
        s.note(f"next screen: {got}")
        if got == "prompt":
            break
    s.pump(1.0)
    return got if got in ("prompt", "login", "trust", "upgrade", "daemon-error") else ("prompt" if re.search(PROMPT, s.screen.text()) else got)


def submit(s, prompt):
    s.note(f"typing prompt: {prompt}")
    s.type(prompt)
    s.send("\r", 0.3)


def transcript(s, name, note):
    """Ctrl-T shows Codex's transcript view: every command and its whole output, which the normal view folds."""
    s.send("\x14", 1.5)
    snap(s, name, note)
    s.send("\x14", 1.2)  # the same key closes it; Esc would start Codex's "edit the previous message"
    s.pump(0.5)


def wait_for_marker(s, marker, extra_loop=None, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        s.pump(0.3)
        if extra_loop:
            extra_loop(s)
        if re.search(marker, s.screen.text()):
            return True
        if not s.alive:
            return False
    return False


def probe():
    """Start Codex and report which screens it reaches; optionally type one prompt."""
    args = os.environ.get("DRIVE_ARGS", "--no-daemon").split()
    s = start(args)
    got = first_run(s, log_in=os.environ.get("DRIVE_NO_LOGIN") != "1")
    snap(s, f"probe-{label}", f"screen reached: {got}")
    print(f"screen reached: {got}")
    if got == "prompt":
        s.pump(float(os.environ.get("DRIVE_WAIT", "12")))
        if os.environ.get("DRIVE_PROMPT"):
            submit(s, os.environ["DRIVE_PROMPT"])
            s.pump(float(os.environ.get("DRIVE_WAIT_AFTER", "8")))
            snap(s, f"probe-{label}-after-a-prompt", "after one prompt")
    else:
        s.pump(float(os.environ.get("DRIVE_WAIT", "12")) / 2)
        snap(s, f"probe-{label}-later", "the same, a few seconds later", everything=False)
    print("\n".join(line for line in s.screen.text().splitlines() if line.strip() and not re.match(r"^[\s⠀-⣿]+$", line)))
    run = None
    for _ in range(20):
        run = newest_run()
        if run:
            break
        time.sleep(0.2)
    rc = s.close()
    print(f"tego watch exited {rc}")
    print(f"run: {run}")


def probe_login():
    """The login screen's other two ways in, tried under the contract: "Sign in with ChatGPT" (Codex starts a login server
    on a local port for the browser's redirect) and "Sign in with Device Code" (a request to auth.openai.com)."""
    s = start(["--no-daemon"])
    got = first_run(s, log_in=False)
    print(f"screen reached: {got}")
    snap(s, "login-menu", "the login screen")
    s.send("\r", 4.0)
    snap(s, "login-chatgpt", "option 1, Sign in with ChatGPT, chosen")
    print("-- option 1:", " / ".join(line.strip() for line in s.screen.text().splitlines() if "failed" in line or "error" in line.lower()))
    s.send("\x1b[B", 0.4)
    s.send("\r", 8.0)
    snap(s, "login-device-code", "option 2, Sign in with Device Code, chosen")
    print("-- option 2:", " ".join(line.strip() for line in s.screen.text().splitlines() if "failed" in line or "error" in line.lower() or "openai.com" in line))
    rc = s.close()
    print(f"tego watch exited {rc}")


def main():
    s = start(["--no-daemon"])
    s.note("started: tego watch --boundary contract/agent.yaml -- codex --no-daemon")

    # ---- the first screens: Codex's login screen (the dummy key) and its prompt box ------------------------------------
    got = first_run(s)
    snap(s, "first-run-end", f"first-run result: {got}")
    if not check(got == "prompt", "Codex reaches its prompt box with a dummy key " + ("in its environment" if route == "b" else "typed into its login screen") + " and no network"):
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
    # the credential Codex stored: look while the run is alive (it lives in the run's private CODEX_HOME and goes
    # with the run), and keep what it holds
    auth = f"{root}/xdg-tego/tego/{run}/codex/auth.json" if boundary else f"{ws}/.codex-state/auth.json"
    held_key = open(auth).read() if os.path.exists(auth) else ""
    open(f"{ev}/auth-json-seen.txt", "w").write(held_key)
    if route == "b":
        check(not login_seen and not held_key, "Codex took the dummy key from its environment: no login screen, and it stored no credential (no auth.json)")
    else:
        check(KEY in held_key and "refresh_token" not in held_key and "access_token" not in held_key,
              "the only credential Codex stored is the dummy key (auth.json in its CODEX_HOME, which the run made private)" if boundary
              else "the only credential Codex stored is the dummy key (auth.json in its CODEX_HOME)")

    # ---- part 1: a command in the workspace, a secret read, git push, a connection ---------------------------------------
    submit(s, "Please run the first part of the demo.")
    ok = wait_for_marker(s, r"STEP-1-DONE", timeout=120)
    s.pump(1.0)
    snap(s, "part1-done", "after the stand-in's four tool calls: a command in the workspace, a secret read, git push, a connection")
    transcript(s, "part1-transcript", "Codex's transcript view (ctrl+t): each command and its whole output")
    check(ok, "part 1 ended: the stand-in's four tool calls each ran or were refused")
    check(os.path.exists(f"{ws}/work/note.txt"), "a normal command in the workspace worked: work/note.txt exists")

    # ---- part 2: the held directory; a person answers from other processes -----------------------------------------------
    answers = []
    state = {"seen": set()}

    def person(s_):
        rc, out = tego_cmd("ask", run)
        for line in out.splitlines():
            m = re.match(r"(q-\S+)\s+(.*)", line)
            if m and m.group(1) not in state["seen"]:
                qid = m.group(1)
                state["seen"].add(qid)
                snap(s_, "held-by-tego", f"Codex is held on {line.strip()}")
                s_.note(f"tego holds: {line.strip()}")
                s_.pump(2.0)  # a person reads it for a moment; Codex's screen keeps its spinner
                snap(s_, "held-by-tego-2s", "two seconds later, still held")
                # report.txt: once. journal.txt: always (written in place twice). other.txt: deny, always.
                if "other.txt" in line:
                    cmd = ["deny", run, qid, "--always"]
                elif "journal" in line:
                    cmd = ["approve", run, qid, "--always"]
                else:
                    cmd = ["approve", run, qid]
                rc2, out2 = tego_cmd(*cmd)
                s_.note(f"person: tego {' '.join(cmd)} -> rc={rc2}")
                answers.append((qid, line.strip(), " ".join(cmd[:1] + cmd[3:]), rc2, out2.strip()))

    submit(s, "Now the second part: the held directory.")
    ok = wait_for_marker(s, r"STEP-2-DONE", extra_loop=person, timeout=240)
    s.pump(1.0)
    snap(s, "part2-done", "after the held writes")
    transcript(s, "part2-transcript", "Codex's transcript view (ctrl+t): the held commands and their outputs")
    check(ok, "part 2 ended")
    if boundary:
        check(len(answers) >= 3, f"tego held the agent and a person answered ({len(answers)} answer(s) from a second process)")
    else:
        check(not answers, f"nothing was held: this run had no boundary ({len(answers)} holds)")

    submit(s, "/exit")
    s.pump(3)
    s.alive and s.note("Codex is still running after /exit")
    rc = s.close()
    s.note(f"tego watch exited {rc}")
    json.dump({"answers": answers, "failures": failures, "run": run}, open(f"{ev}/driver.json", "w"), indent=1)
    open(f"{ev}/screen-final.txt", "w").write(s.screen.everything() + "\n")
    check(rc == 0, f"tego watch exited {rc} after /exit")


if __name__ == "__main__":
    {"probe": probe, "probe-login": probe_login}.get(mode, main)()
    sys.exit(1 if failures else 0)
