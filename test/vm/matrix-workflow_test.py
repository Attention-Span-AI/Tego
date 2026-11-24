#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the hosted suite dispatch without a build, network or guest."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


FULL_ROWS = ("ubuntu-24.04", "ubuntu-25.10", "debian-13", "rhel-9",
             "al2023", "al2023-6.12", "fedora-7.0", "fedora-7.2")
BOOTS = ("lsm-bpf", "default-lsm")
PACKAGES = ("internal/runtime/enforce/cgroup", "internal/bpf", "test/conformance")


def read_workflow():
    return Path(os.environ.get(
        "VM_MATRIX_WORKFLOW", Path(__file__).resolve().parents[2] /
        ".github/workflows/vm-matrix.yml")).read_text()


def tier3_dispatches(workflow):
    dispatches = []
    for step in re.split(r"\n      - ", workflow)[1:]:
        if not step.startswith("name: tier 3 suites"):
            continue
        condition = re.search(r"^        if: (.+)$", step, re.M)
        body = re.search(r"        run: \|\n((?:          .*\n)+)", step)
        if condition is None or body is None:
            raise ValueError("tier 3 dispatch lacks its condition or shell body")
        script = "\n".join(line[10:] for line in body[1].splitlines())
        dispatches.append((condition[1], script))
    return dispatches


def condition_allows(condition, row, part, body):
    values = {"matrix.kernel": row, "matrix.part": part, "steps.body.outputs.body": body}
    alternatives = []
    for alternative in condition.split("||"):
        terms = []
        for term in alternative.split("&&"):
            match = re.fullmatch(r"\s*([\w.]+)\s*(==|!=)\s*'([^']*)'\s*", term)
            if match is None or match[1] not in values:
                raise ValueError("unsupported tier 3 dispatch condition: " + term)
            equal = values[match[1]] == match[3]
            terms.append(equal if match[2] == "==" else not equal)
        alternatives.append(all(terms))
    return any(alternatives)


def selected_dispatches(dispatches, row, part, body):
    return [script for condition, script in dispatches
            if condition_allows(condition, row, part, body)]


def unique_dispatch(dispatches, row, part, body="full"):
    selected = selected_dispatches(dispatches, row, part, body)
    if len(selected) != 1:
        raise ValueError(f"{row}/{part}/{body}: expected one tier 3 dispatch, got {len(selected)}")
    return selected[0]


class MatrixWorkflow(unittest.TestCase):
    def test_capture_invariant_runs_on_every_full_row_including_rhel(self):
        workflow = Path(os.environ.get(
            "VM_MATRIX_WORKFLOW", Path(__file__).resolve().parents[2] /
            ".github/workflows/vm-matrix.yml")).read_text()
        start = workflow.index("      - name: loaded capture stack invariant")
        step = workflow[start:workflow.index("      - name:", start + 1)]
        self.assertIn("if: matrix.part == 'row' && steps.body.outputs.body != 'doctor-only'", step)
        self.assertNotIn("matrix.kernel !=", step)
        self.assertIn('run: test/vm/capture-stack.sh "$KERNEL" "$RUNNER_TEMP/capture-stack"', step)
        self.assertIn("name: capture-stack-${{ matrix.kernel }}", workflow)
        self.assertIn("${{ runner.temp }}/capture-stack/guest.status", workflow)
        self.assertIn("${{ runner.temp }}/capture-stack/guest.console", workflow)

    def test_failed_full_row_jobs_still_upload_their_evidence(self):
        workflow = read_workflow()
        for name, needles in (
            ("tier3-${{ matrix.kernel }}-${{ matrix.part }}",
             ("tier3/results.tsv", "tier3/summary.json", "tier3/logs/")),
            ("peer-${{ matrix.kernel }}", ("peer/results.tsv", "peer/summary.json", "peer/logs/", "adoptskip/logs/")),
            ("diag-${{ matrix.kernel }}-${{ matrix.part }}", ("diag/",)),
        ):
            start = workflow.index("name: " + name)
            step = workflow[workflow.rindex("\n      - ", 0, start):workflow.index("\n      - ", start)]
            self.assertIn("if: always()", step, name)
            for needle in needles:
                self.assertIn(needle, step, name)
        # The copied source tree, initramfs and test binaries are not evidence.
        for big in ("tier3/src", "tier3/prebuilt", "tier3/bin"):
            self.assertNotIn("runner.temp }}/" + big, workflow)

    def test_suite_caps_leave_build_and_fetch_margin(self):
        workflow = read_workflow()
        timeout = re.search(
            r"timeout-minutes:.*matrix.part == 'row' && (\d+) \|\| (\d+)",
            workflow)
        self.assertIsNotNone(timeout, "cannot determine the suite job's timeout")
        job_minutes = int(timeout[2])
        dispatches = tier3_dispatches(workflow)
        with tempfile.TemporaryDirectory() as td:
            stub = Path(td, "test/vm/root-suites.sh")
            stub.parent.mkdir(parents=True)
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$TEGO_VM_ROW" "$VM_BOOTS" "$VM_SUITE_MEM" "$VM_SUITE_TIMEOUT" "$@"\n')
            stub.chmod(0o755)
            for row in FULL_ROWS:
                for boot in BOOTS:
                    with self.subTest(row=row, boot=boot):
                        script = unique_dispatch(dispatches, row, boot)
                        env = dict(os.environ, KERNEL=row, PART=boot, RUNNER_TEMP=td)
                        dispatched = subprocess.check_output(
                            ["bash", "-eo", "pipefail", "-c", script],
                            cwd=td, env=env, text=True).splitlines()
                        self.assertEqual(dispatched[:2], [row, boot])
                        self.assertEqual(dispatched[4:], list(PACKAGES))
                        memory = "3G" if row in ("debian-13", "rhel-9") else "2560M"
                        self.assertEqual(dispatched[2], "internal/runtime/enforce/cgroup=" + memory)
                        default = 1500
                        overrides = {}
                        for word in dispatched[3].split():
                            if "=" in word:
                                key, value = word.split("=", 1)
                                overrides[key] = int(value)
                            else:
                                default = int(word)
                        self.assertEqual(default, 1500)
                        expected = {"internal/runtime/enforce/cgroup": 6000}
                        if row in ("ubuntu-24.04", "fedora-7.2", "al2023-6.12"):
                            expected = {"internal/runtime/enforce/cgroup": 3600,
                                        "internal_runtime_enforce_cgroup.tegobpf": 9000}
                        self.assertEqual(overrides, expected)
                        # Three full packages, each in both builds, then doctor's five-minute cap.
                        seconds = 300
                        for pkg in PACKAGES:
                            for suffix in ("", ".tegobpf"):
                                suite = pkg.replace("/", "_") + suffix
                                seconds += overrides.get(suite, overrides.get(pkg, default))
                        self.assertLessEqual(seconds + 30 * 60, job_minutes * 60,
                                             f"{seconds / 60:g} guest minutes leave too little build/fetch margin")

    def test_tier3_dispatches_exclude_row_part_and_doctor_only(self):
        dispatches = tier3_dispatches(read_workflow())
        for row in FULL_ROWS:
            with self.subTest(row=row, body="full", part="row"):
                self.assertEqual(selected_dispatches(dispatches, row, "row", "full"), [])
        for row in FULL_ROWS + ("ubuntu-22.04",):
            for part in ("row",) + BOOTS:
                with self.subTest(row=row, body="doctor-only", part=part):
                    self.assertEqual(selected_dispatches(dispatches, row, part, "doctor-only"), [])

    def test_dispatch_selection_refuses_a_missing_row(self):
        dispatches = [(condition, script) for condition, script in tier3_dispatches(read_workflow())
                      if not condition_allows(condition, "debian-13", "lsm-bpf", "full")]
        with self.assertRaisesRegex(ValueError, "expected one tier 3 dispatch, got 0"):
            unique_dispatch(dispatches, "debian-13", "lsm-bpf")

    def test_dispatch_selection_refuses_a_duplicate(self):
        dispatches = tier3_dispatches(read_workflow())
        duplicate = next(item for item in dispatches
                         if condition_allows(item[0], "debian-13", "lsm-bpf", "full"))
        with self.assertRaisesRegex(ValueError, "expected one tier 3 dispatch, got 2"):
            unique_dispatch(dispatches + [duplicate], "debian-13", "lsm-bpf")

    def test_dispatch_selection_refuses_an_overlapping_default(self):
        dispatches = tier3_dispatches(read_workflow())
        script = unique_dispatch(dispatches, "debian-13", "lsm-bpf")
        broad = ("matrix.part != 'row' && steps.body.outputs.body != 'doctor-only'", script)
        with self.assertRaisesRegex(ValueError, "expected one tier 3 dispatch, got 2"):
            unique_dispatch(dispatches + [broad], "debian-13", "lsm-bpf")


if __name__ == "__main__":
    unittest.main()
