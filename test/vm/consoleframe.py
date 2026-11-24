#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# consoleframe.py - frames a guest's serial console before anything reads a verdict from it.
#
# Why it exists: the guest's test output and the kernel's own printk share one serial line. printk is not
# ordered against the tty buffer, so a kernel message ("[   51.159345] reboot: Power down") can land in the
# middle of a result line: "--- PASS: TestAttachTarg[   51.159345] reboot: Power down" then
# "etsResolve/tego_path_link (0.00s)". Read as it stands, the test started and never reported, and the
# summary said FAIL for a test that passed. This filter moves a kernel record that interrupts a go test
# marker out of the line and puts the two halves back together. A marker it cannot put back together is
# never guessed at: the line becomes "TEGO-CONSOLE-UNKNOWN: <raw bytes>", which the summary reports as
# UNKNOWN, neither a pass nor a failure.
#
# Usage: consoleframe.py < console > framed        (or import frame(lines))
import re
import sys

UNKNOWN = "TEGO-CONSOLE-UNKNOWN: "
# A kernel printk record: "[ seconds.micro] text" up to the end of the line.
PRINTK = re.compile(r"\[\s*\d+\.\d{6}\] ")
# The start of a go test marker, and a whole one (the test name and the "(0.00s)" timing).
MARK_START = re.compile(r"^\s*(--- (PASS|FAIL|SKIP): |=== (RUN|CONT|PAUSE|NAME)\s)")
MARK_FULL = re.compile(r"^\s*(--- (PASS|FAIL|SKIP): \S+ \(\d+(\.\d+)?s\)|=== (RUN|CONT|PAUSE|NAME)\s+\S+)")


def frame(lines):
    """lines (no newlines) -> framed lines."""
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        i += 1
        m = PRINTK.search(line)
        if not m or m.start() == 0 or not MARK_START.match(line):
            out.append(line)
            continue
        head, record = line[:m.start()], line[m.start():]
        if i < len(lines):
            joined = head + lines[i]
            if MARK_FULL.match(joined):
                out.append(record)  # the kernel's line, whole, then the repaired marker
                out.append(joined)
                i += 1
                continue
        out.append(UNKNOWN + line + (" || " + lines[i] if i < len(lines) else ""))
        out.append(record)
        if i < len(lines):
            i += 1
    return out


def main():
    data = sys.stdin.buffer.read().decode("utf-8", "replace")
    for l in frame(data.split("\n") if data else []):
        sys.stdout.write(l + "\n")


if __name__ == "__main__":
    main()
