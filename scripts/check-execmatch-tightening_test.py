#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused tests for the one-off matcher comparison driver; no Go is run."""
import copy
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = Path(os.environ.get("TEGO_MATCHFIX_CHECKER", Path(__file__).with_name("check-execmatch-tightening.py")))
spec = importlib.util.spec_from_file_location("tightening_checker", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
SCRATCH = Path(__file__).resolve().parents[1].parent / "tmp"

# Entries and inputs approved for P1-GO-14, frozen independently of the driver.
EXPECTED = (
    ("0dadb16663192127e58459bed0c9d4ff05d022fd65e2faee86a5e37ee3d031df", "--no-force", False),
    ("3dee8da0c29de4e7096d32db4ce5b67acc5a57b027f408e5f4b744d1db493706", "--no-force=true", True),
    ("6e14da353afa2cb6bba1d113c385e343f7efaaf026195aa608c36227adf73f6b", "--no-f", False),
    ("86d2f09a51e58995962f059b683c0c5eb2dd738a8dd63d0db3bed7e10a20e07a", "--no-f", True),
    ("8d9f8b2536b5ff3b28a89d545533c7b0e4a3d483ac22e2f9fe9bac72c489d4f3", "--no-f=true", True),
    ("a0a2fb350da3d70781f49132eff5739282d3063a3079ed946d1a807a5c988781", "--no-force", True),
    ("f241d7ab6a99b38d0a56ed473b4f3ba163819ad006b03483a0c499e0a957b25f", "--no-force=true", False),
    ("fc16dd3e4437c6fc0b80cf69d8facfd984e5edb042217c6eb96d0ed745395360", "--no-f=true", False),
)


def accepted_records():
    records = []
    for key, option, complete in EXPECTED:
        before = dict(Key=key, Class="14/negated-prefix", CompileValid=False,
                      Outcome=2, List=1, Final=True, Rule="rule-invalid",
                      Facts=dict(Argv=["git", "add", option], ArgvComplete=complete),
                      Patterns=["git add --no-f"])
        after = dict(before, CompileValid=True, Outcome=1, Final=complete,
                     Rule="exec.allow[git add --no-f]")
        records.append((before, after))
    return records


class TighteningComparisonTests(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=SCRATCH, prefix="round3-checker-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture_sources(self, existing_decide=False, baseline_via="ViaArgv0"):
        package = self.root / "pkg/policy/execmatch"
        package.mkdir(parents=True)
        index = "package execmatch\nfunc (ix *Index) Decide(f *Facts) Result {\nif ix.Empty() || !ix.Guarded(f) { return Result{} }; return Result{}\n}\n// firstMatch\n"
        if existing_decide:
            index += "func (ix *Index) decide(f *Facts) Result { return Result{} }\n"
        current = {"index.go": index, "current.go": "package execmatch\n", "rows/current.go": "package rows\n"}
        baseline = {"index.go": index, "retired.go": b"package execmatch\n", "rows/retired.go": b"package rows\n"}
        baseline = {f"pkg/policy/execmatch/{name}": value.encode() if isinstance(value, str) else value for name, value in baseline.items()}
        for name, value in current.items():
            path = package / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(value)
        # Existing audit-only fixture edits must remain on the old side.
        (package / "rows/coreutils_test.go").write_text('{"argv0 lt-rm", execmatch.ViaMulticall}\n')
        (package / "tightening_test.go").write_text("if (full.Outcome == execmatch.OutcomeRefused || !full.Final) {}\n")
        for name in ("normalize.go", "loader.go", "interpret.go", "multicall.go", "pattern.go", "match.go", "autocorrect.go"):
            (package / name).write_text("package execmatch\n")
            baseline[f"pkg/policy/execmatch/{name}"] = b"package execmatch\n"
        def git_output(command, **_):
            if command[1] == "ls-tree":
                self.assertIn("selected-baseline", command)
                return ("\n".join(sorted(baseline)) + "\n").encode()
            if command[1] == "show":
                ref, name = command[2].split(":", 1)
                self.assertEqual(ref, "selected-baseline")
                if name == "pkg/policy/execmatch/rows/coreutils_test.go":
                    return ('{"argv0 lt-rm", execmatch.' + baseline_via + '}\n').encode()
                return baseline[name]
            raise AssertionError(command)
        return package, baseline, git_output

    def test_overlay_covers_all_production_sources(self):
        package, baseline, git_output = self.fixture_sources()
        with mock.patch.object(checker, "ROOT", self.root), mock.patch.object(checker, "PACKAGE", package), mock.patch.object(checker, "BASE", "selected-baseline"), mock.patch.object(checker.subprocess, "check_output", side_effect=git_output):
            checker.check_baseline_sources()
            result = checker.overlay("old", self.root / "old")
        replacements = json.loads(result.read_text())["Replace"]
        self.assertEqual(replacements[str(package / "current.go")], "")
        self.assertEqual(replacements[str(package / "rows/current.go")], "")
        for name, expected in baseline.items():
            if not name.endswith("index.go"):
                self.assertEqual(Path(replacements[str(self.root / name)]).read_bytes(), expected)
        self.assertEqual(replacements[str(package / "tightening_observer.go")], str(package / "testdata/tightening/observer.go.txt"))

    def test_overlay_preserves_existing_unguarded_observer_seam(self):
        package, _, git_output = self.fixture_sources(existing_decide=True)
        with mock.patch.object(checker, "ROOT", self.root), mock.patch.object(checker, "PACKAGE", package), mock.patch.object(checker, "BASE", "selected-baseline"), mock.patch.object(checker.subprocess, "check_output", side_effect=git_output):
            result = checker.overlay("old", self.root / "old")
        replacements = json.loads(result.read_text())["Replace"]
        value = Path(replacements[str(package / "index.go")]).read_text()
        self.assertEqual(value.count("func (ix *Index) decide("), 1)
        self.assertEqual(value.count("func (ix *Index) decideObserved("), 1)

    def test_fixture_provenance_expectation_follows_selected_baseline(self):
        for expected in ("ViaArgv0", "ViaMulticall"):
            with self.subTest(expected=expected):
                if (self.root / "pkg").exists():
                    shutil.rmtree(self.root / "pkg")
                package, _, git_output = self.fixture_sources(baseline_via=expected)
                with mock.patch.object(checker, "ROOT", self.root), mock.patch.object(checker, "PACKAGE", package), mock.patch.object(checker, "BASE", "selected-baseline"), mock.patch.object(checker.subprocess, "check_output", side_effect=git_output):
                    result = checker.overlay("old", self.root / expected)
                replacements = json.loads(result.read_text())["Replace"]
                fixture = Path(replacements[str(package / "rows/coreutils_test.go")]).read_text()
                self.assertIn("execmatch." + expected, fixture)

    def compare(self, records):
        sources = {"old": [], "new": []}
        for side, column in (("old", 0), ("new", 1)):
            directory = self.root / side
            directory.mkdir(exist_ok=True)
            journal = directory / "input.jsonl"
            sources[side] = [str(journal)]
            offset = 0
            lines = []
            with journal.open("wb") as target:
                for pair in records:
                    entry = pair[column]
                    raw = (json.dumps(entry) + "\n").encode()
                    target.write(raw)
                    lines.append(f'{entry["Key"]}\t{checker.go_digest(checker.decision(entry))}\t0:{offset}\n')
                    offset += len(raw)
            (directory / "answers.unique").write_text("".join(sorted(lines)))
        return checker.compare_indexes(self.root, sources)

    def test_release_bar_accepts_exactly_eight_named_allow_keys(self):
        result = self.compare(accepted_records())
        checker.assert_release_bar(result)
        self.assertEqual(result["loosened"], 8)
        self.assertEqual(result["unexpected_loosened"], 0)
        self.assertEqual(len(result["accepted_allow_loosenings"]), 8)

    def test_release_bar_rejects_any_deny_or_ask_loss(self):
        for list_ in (2, 3):
            with self.subTest(list=list_):
                records = accepted_records()
                before = dict(Key="f" * 64, Outcome=2, List=list_, Final=True, Facts={}, Patterns=["git push ---force"])
                after = dict(before, Outcome=0, List=0)
                result = self.compare(records + [(before, after)])
                with self.assertRaisesRegex(RuntimeError, "unexpected"):
                    checker.assert_release_bar(result)

    def test_release_bar_rejects_unknown_allow_loss_and_missing_expected_key(self):
        records = accepted_records()
        before, after = copy.deepcopy(records[0])
        before["Key"] = after["Key"] = "f" * 64
        result = self.compare(records + [(before, after)])
        with self.assertRaisesRegex(RuntimeError, "unexpected"):
            checker.assert_release_bar(result)
        result = self.compare(records[:-1])
        with self.assertRaisesRegex(RuntimeError, "missing expected"):
            checker.assert_release_bar(result)

    def test_release_bar_checks_entry_and_compile_status_for_accepted_key(self):
        for field, value in (("Patterns", ["git add --force"]), ("CompileValid", True), ("List", 2)):
            with self.subTest(field=field):
                records = accepted_records()
                records[0][0][field] = value
                result = self.compare(records)
                with self.assertRaisesRegex(RuntimeError, "unexpected"):
                    checker.assert_release_bar(result)

    def test_cli_accepts_base_argument(self):
        result = subprocess.run(["python3", str(SCRIPT), "--help"], capture_output=True, text=True, check=True)
        self.assertIn("--base", result.stdout)

    def test_go_legs_receive_private_state_paths(self):
        package = self.root / "package"
        package.mkdir()
        output = self.root / "comparison"
        seen = []

        def overlay(side, destination):
            destination.mkdir()
            return destination / "overlay.json"

        def run(command, **kwargs):
            env = kwargs["env"]
            seen.append(env)
            for key in ("TEGO_CONFIG", "TEGO_TEST_CHAIN_ANCHOR", "TEGO_TEST_OWN_LOG_HOME"):
                path = Path(env[key])
                self.assertTrue(path.is_relative_to(self.root), (key, path))
            config = Path(env["TEGO_CONFIG"])
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            ledger = Path(json.loads(config.read_text())["ledger_root"])
            self.assertTrue(ledger.is_relative_to(self.root))
            for directory in (ledger, Path(env["TEGO_TEST_OWN_LOG_HOME"])):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(env["XDG_RUNTIME_DIR"], inherited["XDG_RUNTIME_DIR"])
            return types.SimpleNamespace(returncode=0)

        inherited = dict(TMPDIR=str(self.root), TEGO_CONFIG="/outside/config",
                         TEGO_TEST_CHAIN_ANCHOR="/outside/anchor", TEGO_TEST_OWN_LOG_HOME="/outside/home",
                         XDG_RUNTIME_DIR="/outside/runtime")
        with mock.patch.dict(os.environ, inherited), mock.patch.object(checker, "PACKAGE", package), \
                mock.patch.object(checker, "BASE", "selected-baseline"), \
                mock.patch.object(checker, "check_baseline_sources"), \
                mock.patch.object(checker, "overlay", side_effect=overlay), \
                mock.patch.object(checker.subprocess, "check_output", return_value=b"selected-baseline\n"), \
                mock.patch.object(checker.subprocess, "run", side_effect=run), \
                mock.patch.object(checker, "compact_index", side_effect=RuntimeError("Go legs complete")), \
                mock.patch("sys.argv", ["checker", "--go", "go-wrapper", "--out", str(output)]):
            with self.assertRaisesRegex(RuntimeError, "Go legs complete"):
                checker.main()
        self.assertEqual(len(seen), 4)  # Each side's main corpus and loader supplement.
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[2], seen[3])
        self.assertNotEqual(seen[0]["TEGO_CONFIG"], seen[2]["TEGO_CONFIG"])


if __name__ == "__main__":
    unittest.main()
