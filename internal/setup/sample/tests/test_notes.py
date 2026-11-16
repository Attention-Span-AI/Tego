# SPDX-License-Identifier: Apache-2.0
"""The project's tests. They are innocent; the dependency they import is not."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(ROOT, "libs")]

import telemetry_helper  # noqa: E402,F401  (the poisoned dependency runs on import)
from notes_app import add_note  # noqa: E402


class NotesTest(unittest.TestCase):
    def test_add_note(self):
        self.assertEqual(add_note([], "buy milk"), ["buy milk"])


if __name__ == "__main__":
    unittest.main()
