#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A kernel message that lands in a result line must never turn a pass into a FAIL (vmmatrix C9)."""
import json
import os
import tempfile
import unittest

import consoleframe
import summarize

HERE = os.path.dirname(os.path.abspath(__file__))
SPLIT = os.path.join(HERE, "testdata", "console-split-printk.txt")  # captured from a hosted fedora-7.0 run


def read(path):
    with open(path) as f:
        return f.read().split("\n")[:-1]


class Frame(unittest.TestCase):
    def test_split_line_is_repaired(self):
        out = consoleframe.frame(read(SPLIT))
        self.assertIn("    --- PASS: TestAttachTargetsResolve/tego_path_link (0.00s)", out)
        self.assertIn("[   51.159345] reboot: Power down", out)
        self.assertFalse([l for l in out if l.startswith(consoleframe.UNKNOWN)])

    def test_clean_console_is_unchanged(self):
        clean = [l for l in read(SPLIT) if "TestAttachTarg[" not in l and not l.startswith("etsResolve")]
        self.assertEqual(consoleframe.frame(clean), clean)

    def test_unrepairable_line_is_unknown_with_raw_bytes(self):
        raw = "    --- PASS: TestX[   1.000000] reboot: Power down"
        out = consoleframe.frame([raw, "garbage that is not the rest of a marker"])
        self.assertTrue(out[0].startswith(consoleframe.UNKNOWN + raw))

    def test_cut_at_end_of_console_is_unknown(self):
        raw = "    --- PASS: TestX[   1.000000] reboot: Power down"
        self.assertTrue(consoleframe.frame([raw])[0].startswith(consoleframe.UNKNOWN))


class Summary(unittest.TestCase):
    def suite(self, console_lines, passed):
        d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        con, js = os.path.join(d, "s.console"), os.path.join(d, "s.json")
        with open(con, "w") as f:
            f.write("\n".join(console_lines) + "\n")
        names = ["TestAttachTargetsResolve/tego_path_link", "TestAttachTargetsResolve/tego_path_symlink"]
        with open(js, "w") as f:
            f.write(json.dumps({"Action": "run", "Test": "TestAttachTargetsResolve"}) + "\n")
            for n in names:
                f.write(json.dumps({"Action": "run", "Test": n}) + "\n")
            for n in names[1:]:
                f.write(json.dumps({"Action": "pass", "Test": n}) + "\n")
            if passed:
                f.write(json.dumps({"Action": "pass", "Test": names[0]}) + "\n")
            f.write(json.dumps({"Action": "pass", "Test": "TestAttachTargetsResolve"}) + "\n")
        return summarize.summarize_suite("s", "p", "-", "0", js, con)

    def test_split_pass_line_is_pass(self):
        rec = self.suite(read(SPLIT), passed=False)
        self.assertEqual(rec["result"], "pass", rec["failures"])
        self.assertEqual(rec["failures"], [])

    def test_unframed_line_is_unknown_not_fail(self):
        lines = read(SPLIT)
        lines = [l for l in lines if not l.startswith("etsResolve")]
        rec = self.suite(lines, passed=False)
        self.assertEqual(rec["result"], "unknown")
        self.assertTrue(rec["unknown"])
        self.assertEqual(rec.get("failed", 0), 0)

    def run_with(self, code, lines):
        d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        con, js = os.path.join(d, "s.console"), os.path.join(d, "s.json")
        with open(con, "w") as f:
            f.write("\n".join(lines) + "\n")
        open(js, "w").close()
        return summarize.summarize_suite("test_conformance", "test/conformance", "integration", code, js, con)

    def test_binary_not_found_is_a_harness_fault(self):
        rec = self.run_with("127", ["[    2.8] Initramfs unpacking failed: write error",
                                    "/.vm/cmd: 2: exec: /vm/test_conformance.test: not found"])
        self.assertEqual(rec["result"], "harness-fault")
        self.assertIn("HARNESS FAULT", rec["failures"][0])

    def test_exit_127_after_tests_ran_stays_a_failure(self):
        rec = self.run_with("127", ["=== RUN   TestX", "--- FAIL: TestX (0.00s)", "sh: 1: foo: not found"])
        self.assertEqual(rec["result"], "fail")


if __name__ == "__main__":
    unittest.main()
