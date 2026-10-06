# SPDX-License-Identifier: Apache-2.0
#
# interactive_pty.py — proves an interactive program works under 'tego watch': it starts a shell on a real
# pseudo-terminal, types into it, presses Ctrl-C on a running command and checks the terminal size, the way a person
# at a terminal (or Claude Code or Codex in one) would. It needs the isolated environment run.sh set up
# (TEGO_CONFIG and friends) and TEGO_BIN.
import fcntl
import os
import pty
import select
import shutil
import struct
import sys
import tempfile
import termios
import time

tego = os.environ["TEGO_BIN"]
# Fail closed (identity-config.md R27; tools/isocheck SH-5, SH-6): the environment must carry the test build's
# isolation, and the binary must be a test build, which alone contains the anchor variable's name and honours it. A
# product build would anchor this run in the invoking user's own ~/.tego/chain.log.
for var in ("TEGO_CONFIG", "TEGO_TEST_CHAIN_ANCHOR", "TEGO_TEST_OWN_LOG_HOME", "XDG_RUNTIME_DIR"):
    if not os.environ.get(var):
        sys.exit(f"interactive_pty.py: {var} is not set; source the demo's env.sh (run.sh does)")
# The launch makes <XDG_RUNTIME_DIR>/tego and sweeps the directories crashed runs left there (R27 clause b4): the
# login session's is the operator's own, so the demo's env.sh names one of its own.
if os.path.realpath(os.environ["XDG_RUNTIME_DIR"]) == os.path.realpath(f"/run/user/{os.getuid()}"):
    sys.exit("interactive_pty.py: XDG_RUNTIME_DIR is the login session's; source the demo's env.sh (run.sh does)")
with open(tego, "rb") as binary:
    if b"TEGO_TEST_CHAIN_ANCHOR" not in binary.read():
        sys.exit(f"interactive_pty.py: {tego} is not built with -tags tegotesthooks; it would write the real ~/.tego")
# An interactive shell writes its history on exit: give it a home of its own and no history file, so the commands
# typed here never reach the real ~/.bash_history.
home = tempfile.mkdtemp(prefix="tego-pty-home-")
argv = [tego, "watch", "--", "bash", "--noprofile", "--norc", "-i"]
env = dict(os.environ, TERM="xterm-256color", PS1="agent$ ", HOME=home, HISTFILE="/dev/null", HISTSIZE="0")

pid, fd = pty.fork()
if pid == 0:
    os.execve(tego, argv, env)

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
out = b""


def drain(seconds):
    global out
    end = time.time() + seconds
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


def send(text, wait=1.2):
    os.write(fd, text if isinstance(text, bytes) else text.encode())
    drain(wait)


drain(4.0)
send("echo hello-from-the-agent\n")
send("tty; stty size\n")
send("sleep 30\n", 0.8)
send(b"\x03", 1.0)  # Ctrl-C stops the sleep, not the shell
send("echo still-alive-after-ctrl-c\n")
send("exit\n", 3.0)
_, status = os.waitpid(pid, 0)
shutil.rmtree(home, ignore_errors=True)
text = out.decode("utf-8", "replace")

checks = {
    "the agent's output reaches the terminal": "hello-from-the-agent" in text,
    "it runs on a real terminal (a /dev/pts device)": "/dev/pts/" in text,
    "it sees the terminal's size (40 rows, 120 columns)": "40 120" in text,
    "Ctrl-C stops the running command, not the shell": "still-alive-after-ctrl-c" in text,
    "its exit status comes back (0)": os.waitstatus_to_exitcode(status) == 0,
}
failed = 0
for name, ok in checks.items():
    print(("PASS  " if ok else "FAIL  ") + name)
    failed += not ok
sys.exit(1 if failed else 0)
