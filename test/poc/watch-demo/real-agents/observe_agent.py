# SPDX-License-Identifier: Apache-2.0
#
# observe_agent.py <label> <seconds> -- <agent argv...>
#
# Starts a REAL interactive agent (claude, codex, anything with a full-screen terminal interface) under
# 'tego watch' on a pseudo-terminal, in an isolated home directory with no credentials, lets it run for
# <seconds>, ends it with Ctrl-C, and prints what the run recorded: what it started, connected to and opened, and
# what was refused. Nothing is typed into the agent, so it stops at its own first screen (a login or a theme
# choice) and calls no model.
#
# It needs the isolated tego environment that run.sh makes (source <demo>/tego/env.sh first) and TEGO_BIN, a
# tego built with -tags tegotesthooks. WATCH_ARGS adds flags to 'tego watch' (for example
# '--boundary /path/contract.yaml'); WATCH_CWD is the agent's working directory (outside tego's state directory
# and the contract file's directory: tego refuses a boundary that lets the agent write either).
import collections
import fcntl
import json
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time

if len(sys.argv) < 4 or "--" not in sys.argv:
    sys.exit(__doc__ or "usage: observe_agent.py <label> <seconds> -- <agent argv...>")
label, seconds = sys.argv[1], float(sys.argv[2])
agent = sys.argv[sys.argv.index("--") + 1:]
tego = os.environ["TEGO_BIN"]
# Fail closed (identity-config.md R27; tools/isocheck SH-5, SH-6): the environment must carry the test build's
# isolation, and the binary must be a test build, which alone contains the anchor variable's name and honours it. A
# product build would anchor this run in the invoking user's own ~/.tego/chain.log.
for var in ("TEGO_CONFIG", "TEGO_TEST_CHAIN_ANCHOR", "TEGO_TEST_OWN_LOG_HOME", "XDG_RUNTIME_DIR"):
    if not os.environ.get(var):
        sys.exit(f"observe_agent.py: {var} is not set; source the demo's env.sh first")
# The launch makes <XDG_RUNTIME_DIR>/tego and sweeps the directories crashed runs left there (R27 clause b4): the
# login session's is the operator's own, so the demo's env.sh names one of its own.
if os.path.realpath(os.environ["XDG_RUNTIME_DIR"]) == os.path.realpath(f"/run/user/{os.getuid()}"):
    sys.exit("observe_agent.py: XDG_RUNTIME_DIR is the login session's; source the demo's env.sh first")
with open(tego, "rb") as binary:
    if b"TEGO_TEST_CHAIN_ANCHOR" not in binary.read():
        sys.exit(f"observe_agent.py: {tego} is not built with -tags tegotesthooks; it would write the real ~/.tego")
state = os.path.dirname(os.environ["TEGO_CONFIG"])
root = os.environ.get("DEMO_ROOT") or os.path.dirname(state)
home = f"{root}/home-{label}"
os.makedirs(home + "/.claude", exist_ok=True)
os.makedirs(home + "/.codex", exist_ok=True)
cwd = os.environ.get("WATCH_CWD") or os.path.join(root, f"ws-{label}")
os.makedirs(cwd, exist_ok=True)

# The agent's environment: no credentials from the caller, its own home, no shell history (a shell the agent starts
# on this terminal would otherwise append to the operator's own ~/.bash_history; HOME alone does not stop it when the
# agent's shell is started with its own), and the switches that turn off what is not the work itself (updates,
# telemetry).
env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC", "OPENAI", "CLAUDE", "CODEX"))}
env.update({
    "HOME": home, "HISTFILE": "/dev/null", "TERM": "xterm-256color", "COLUMNS": "120", "LINES": "40", "NO_COLOR": "1",
    "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DO_NOT_TRACK": "1",
    "CLAUDE_CONFIG_DIR": home + "/.claude", "CODEX_HOME": home + "/.codex",
})
argv = [tego, "watch"] + os.environ.get("WATCH_ARGS", "").split() + ["--"] + agent
pid, fd = pty.fork()
if pid == 0:
    os.chdir(cwd)
    os.execve(argv[0], argv, env)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
out = b""


def drain(seconds_):
    global out
    end = time.time() + seconds_
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return
            if not data:
                return
            out += data


drain(seconds)
for _ in range(3):  # Ctrl-C twice ends both TUIs; once more for luck
    try:
        os.write(fd, b"\x03")
    except OSError:
        break
    drain(1.5)
drain(3)
try:
    done, _ = os.waitpid(pid, os.WNOHANG)
    if done == 0:
        os.kill(pid, 15)  # the agent ignored Ctrl-C: end the run, which still writes its record
        drain(3)
        os.waitpid(pid, 0)
except ChildProcessError:
    pass
drain(1)

text = out.decode("utf-8", "replace")
text = re.sub(r"\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][A-B0-2]|\x1b[=>]", "", text)
lines = [line.rstrip() for line in text.replace("\r", "").split("\n") if line.strip()]
print("== the agent's last screen:")
print("\n".join(lines[-14:]))

m = re.search(r"recorded as run (r-\S+)", text)
run = m.group(1) if m else None
if not run:  # the run was ended before it could say: take the newest in the ledger
    ledger = next((line.split(":", 1)[1].strip() for line in open(os.environ["TEGO_CONFIG"]) if line.startswith("ledger_root:")), "")
    runs = sorted((d for d in os.listdir(ledger) if d.startswith("r-")), key=lambda d: os.stat(os.path.join(ledger, d)).st_mtime) if ledger and os.path.isdir(ledger) else []
    run = runs[-1] if runs else None
if not run:
    sys.exit("no run was recorded: tego did not start the agent (read the screen above)")
events = [json.loads(line) for line in subprocess.run([tego, "events", run, "--json"], capture_output=True, text=True, env=os.environ).stdout.splitlines() if line.strip()]
print(f"\n== what tego recorded ({run}): {len(events)} events", dict(collections.Counter(e["kind"] for e in events)))
progs = collections.Counter(" ".join(e.get("argv") or [])[:60] for e in events if e["kind"] == "exec")
print(f"-- programs started: {sum(progs.values())} ({len(progs)} distinct); most frequent:")
for p, n in progs.most_common(8):
    print(f"   {n:4d}  {p}")
net = collections.Counter((e.get("proto"), e.get("dst"), e.get("verdict")) for e in events if e["kind"] == "net")
print("-- connections (proto, destination, verdict):")
for (proto, dst, verdict), n in net.most_common(12):
    print(f"   {n:4d}  {proto:5s} {dst}  [{verdict}]")
areas = collections.Counter()
for e in events:
    if e["kind"] == "fs":
        path = e.get("path", "")
        areas["the agent's home" if path.startswith(home) else "/" + path.split("/")[1] if path.count("/") > 1 else path] += 1
print("-- file opens by area:", dict(areas.most_common(8)))
refused = collections.Counter((e["kind"], e.get("reason") or e.get("verdict"), e.get("rule"), e.get("dst") or e.get("path")) for e in events if e["kind"] == "refused" or str(e.get("verdict", "")).startswith("refused"))
print("-- refused:", "none" if not refused else "")
for (kind, reason, rule, target), n in refused.most_common(12):
    print(f"   {n:4d}  {kind:8s} {reason}  {rule}  {target}")
