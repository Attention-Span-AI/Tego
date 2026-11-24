#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run `tego start` in a pseudo-terminal inside a guest and answer its questions.

Usage: drive-start.py TRANSCRIPT [TEGO]

The answers take the shortest path: "Another program" running python3's unittest, on the test project, with the
recommended rules, typing arrow keys into the menus. An agent of that name left by an earlier run keeps its rules. The transcript is the raw terminal
output. The exit status is tego's own, or 124 when it did not end in 150 seconds (it is then ended by its pid).
"""
import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][0-9A-B]")
DOWN, ENTER = b"\x1b[B", b"\r"
# (text that asks, what to type). A terminal always gets the arrow-key menus (TERM only switches the colour off), so a
# menu answer is arrow keys and Enter: a digit is ignored. Each question is answered once: a menu draws its question
# again, marked done, after the answer, and that second drawing is not a new question.
ANSWERS = [
    (b"Which agent do you want to supervise", DOWN + DOWN + ENTER),  # Another program
    (b"What command starts it", b"python3 -m unittest -v" + ENTER),
    (b"Which project should", ENTER),
    (b"Which rules should", ENTER),
    (b"already exists. Replace its rules", ENTER),
]


def main() -> int:
    transcript, tego = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "tego")
    pid, fd = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
        os.environ.update(TERM="xterm-256color", NO_COLOR="1", HISTFILE="/dev/null")
        os.execvp(tego, [tego, "start"])
    out = open(transcript, "wb")
    seen, mark, deadline = b"", 0, time.monotonic() + 150
    status = None
    pending = list(ANSWERS)
    while status is None:
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            out.write(b"\n[drive-start: no end in 150 s, ended by pid]\n")
            return 124
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if data:
                out.write(data)
                out.flush()
                seen += ANSI.sub(b"", data)
                for ask, answer in pending:
                    if seen.find(ask, mark) >= 0:
                        time.sleep(0.4)  # let the question finish drawing
                        os.write(fd, answer)
                        pending.remove((ask, answer))
                        mark = len(seen)
                        break
                continue
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
    out.write(b"\n[drive-start: tego start ended, status %d]\n" % os.waitstatus_to_exitcode(status))
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
