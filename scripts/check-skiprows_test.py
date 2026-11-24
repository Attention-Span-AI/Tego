# SPDX-License-Identifier: Apache-2.0
"""check-skiprows.py reads every line of a workflow step's run block, including the last one."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("check_skiprows", Path(__file__).with_name("check-skiprows.py"))
skiprows = importlib.util.module_from_spec(spec)
spec.loader.exec_module(skiprows)

HEAD = """name: vm
jobs:
  matrix:
    env:
      KERNEL: ${{ matrix.kernel }}
    strategy:
      matrix:
        kernel:
          - fedora-7.0
        part: [row]
    steps:
"""

# A step that ends in a continued call and is followed at once by the next step: the split on "\n      - " takes the
# newline after the call's last line, which used to leave a lone backslash for shlex.
CONTINUED = """      - name: other
        run: |
          TEGO_VM_ROW="$KERNEL" VM_OUT="$RUNNER_TEMP/x" \\
            test/vm/root-suites.sh '=internal/cli'
      - name: next
        run: echo done
"""

DISPATCH = """      - name: full
        run: |
          TEGO_VM_ROW="$KERNEL" TEGO_VM_LOCKDOWN=none \\
            test/vm/root-suites.sh internal/runtime/enforce/cgroup
"""


class Scheduled(unittest.TestCase):
    def test_continued_call_before_another_step_parses(self):
        wf = HEAD + CONTINUED
        self.assertFalse(skiprows.scheduled(wf, "fedora-7.0", "", "internal/runtime/enforce/cgroup"))
        self.assertTrue(skiprows.scheduled(wf, "fedora-7.0", "", "internal/cli"))

    def test_continued_call_as_the_jobs_last_line_is_read(self):
        wf = HEAD + CONTINUED + DISPATCH + "\n  other:\n    steps: []\n"
        self.assertTrue(skiprows.scheduled(wf, "fedora-7.0", "", "internal/runtime/enforce/cgroup"))

    def test_a_single_line_call_ending_a_step_is_read(self):
        wf = HEAD + "      - name: one\n        run: |\n          TEGO_VM_ROW=\"$KERNEL\" test/vm/root-suites.sh internal/cli\n      - name: two\n        run: echo\n"
        self.assertTrue(skiprows.scheduled(wf, "fedora-7.0", "", "internal/cli"))


if __name__ == "__main__":
    unittest.main()
