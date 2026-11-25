#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""drive-start.py answers tego start's first question by reading the list, whatever order the guide draws it in.

No guest and no tego: the program under the pseudo-terminal is a stand-in that draws the first question and counts the
arrow keys it is given before Enter."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

SOURCE = Path(__file__).with_name("drive-start.py")
spec = importlib.util.spec_from_file_location("drive_start", SOURCE)
drive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drive)

DOWN, ENTER = drive.DOWN, drive.ENTER
DEMO_FIRST = [b"Demonstration agent (recommended)", b"Claude Code", b"Codex", b"Another program"]
CLAUDE_READY = [b"Claude Code (recommended)", b"Codex", b"Another program", b"Demonstration agent"]
CODEX_AND_CLAUDE_READY = [b"Claude Code (recommended)", b"Codex", b"Another program", b"Demonstration agent"]


def frame(items):
    return b"Which agent do you want to supervise?\r\n" + b"".join(b"  " + item + b"\r\n" for item in items)


class ToAnotherProgram(unittest.TestCase):
    def test_counts_the_items_drawn_above_it(self):
        self.assertEqual(drive.to_another_program(frame(DEMO_FIRST)), DOWN * 3 + ENTER)
        self.assertEqual(drive.to_another_program(frame(CLAUDE_READY)), DOWN * 2 + ENTER)
        self.assertEqual(drive.to_another_program(frame(CODEX_AND_CLAUDE_READY)), DOWN * 2 + ENTER)

    def test_waits_for_the_list(self):
        self.assertIsNone(drive.to_another_program(b"Which agent do you want to supervise?\r\n  Demonstration agent\r\n"))


STAND_IN = """#!{python}
import os, sys, termios, tty
items = {items!r}
sys.stdout.write("Which agent do you want to supervise?\\r\\n" + "".join("  " + i + "\\r\\n" for i in items))
sys.stdout.flush()
tty.setraw(0)
got = b""
while not got.endswith(b"\\r"):
    got += os.read(0, 1)
downs = got.count(b"\\x1b[B")
sys.stdout.write("\\r\\nresult " + str(downs) + "\\r\\n")
raise SystemExit(0 if downs == {want} else 7)
"""


class Driven(unittest.TestCase):
    def run_driver(self, items, want):
        with tempfile.TemporaryDirectory() as tmp:
            stand_in = Path(tmp) / "tego"
            stand_in.write_text(STAND_IN.format(python=sys.executable, items=[i.decode() for i in items], want=want))
            stand_in.chmod(0o755)
            transcript = Path(tmp) / "transcript"
            code = subprocess.run([sys.executable, str(SOURCE), str(transcript), str(stand_in)], timeout=30,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
            return code, transcript.read_bytes()

    def test_it_types_the_right_number_of_arrow_keys_in_each_order(self):
        for name, items, want in [("no agent ready", DEMO_FIRST, 3), ("one agent ready", CLAUDE_READY, 2)]:
            with self.subTest(name):
                code, transcript = self.run_driver(items, want)
                self.assertEqual(code, 0, transcript)


if __name__ == "__main__":
    unittest.main()
