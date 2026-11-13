# SPDX-License-Identifier: Apache-2.0
"""Guest JSON checks and shell assertions, without a product process.

Run: TMPDIR=<scratch> python3 -B test/e2e/test_pausecompile_json.py
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
HELPER = Path(os.environ.get("PAUSECOMPILE_JSON_HELPER", HERE / "pausecompile-json.py"))
ORPHAN_SCRIPT = Path(os.environ.get("PAUSECOMPILE_ORPHAN_SCRIPT", HERE / "kt-pause-orphan.sh"))


class PausecompileJSONTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        (self.bin / "python3").symlink_to(sys.executable)
        self.env = {**os.environ, "PATH": str(self.bin)}

    def run_helper(self, *args, text=""):
        return subprocess.run(
            [str(self.bin / "python3"), "-B", str(HELPER), *map(str, args)],
            input=text, text=True, capture_output=True, env=self.env, check=False,
        )

    def good(self, *args, text="", output=None):
        got = self.run_helper(*args, text=text)
        self.assertEqual(got.returncode, 0, got.stderr)
        if output is not None:
            self.assertEqual(got.stdout, output)
        return got

    def bad(self, *args, text=""):
        got = self.run_helper(*args, text=text)
        self.assertNotEqual(got.returncode, 0, got.stdout)
        self.assertEqual(got.stdout, "", "failed input must not print a success-shaped value")
        return got

    def file(self, name, text):
        path = self.work / name
        path.write_text(text)
        return path

    def recipe5_setup(self):
        # Execute the tracked script's dependency setup, without starting its kernel fixture.
        script = ORPHAN_SCRIPT.read_text()
        setup = script.split('. "$repo_root/e2e/lib.sh"\n', 1)[1].split(
            'tego="$(kt_ensure_tego)"', 1
        )[0]
        return """
set -uo pipefail
repo_root="$1"
kt_skip() { echo "SKIP: $*" >&2; exit 77; }
kt_fail() { echo "FAIL: $*" >&2; exit 1; }
kt_need_jq() { command -v jq >/dev/null || kt_skip 'jq is absent'; }
""" + setup

    def test_recipe5_json_setup_without_jq(self):
        command = self.recipe5_setup() + """
pausecompile_json field state <<<'{"state":"lost"}'
"""
        got = subprocess.run(
            ["/bin/bash", "-c", command, "json-setup-test", str(HERE.parent)],
            text=True, capture_output=True, env=self.env, check=False,
        )
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(got.stdout, "lost\n")

    def test_recipe5_status_accepts_finding_and_rejects_command_or_parse_errors(self):
        command = self.recipe5_setup() + """
tego=status_probe
reply="$2"
probe_status="$3"
status_probe() { printf '%s\n' "$reply"; return "$probe_status"; }
status_json r-test | pausecompile_json project state || kt_fail 'status JSON failed'
"""
        for text, status, want in (
            ('{"state":"lost"}', 0, 0),
            ('{"state":"lost"}', 1, 0),
            ('{"state":"lost"}', 125, 1),
            ('{"state":', 1, 1),
            ('false', 1, 1),
            ('', 1, 1),
        ):
            with self.subTest(text=text, status=status):
                got = subprocess.run(
                    ["/bin/bash", "-c", command, "json-status-test", str(HERE.parent), text, str(status)],
                    text=True, capture_output=True, env=self.env, check=False,
                )
                self.assertEqual(got.returncode, want, got.stderr)

    def test_recipe5_final_record_requires_orphaned_reason(self):
        script = ORPHAN_SCRIPT.read_text()
        start = script.index('last="$(tail -1 "$rundir/events.jsonl"')
        end = script.index('grep -q \'"launcher-lost"\'', start)
        assertion = script[start:end]
        # Execute the tracked assertion with the real JSON helper and tail,
        # stopping before the separate gap and product-verification checks.
        (self.bin / "tail").symlink_to("/usr/bin/tail")
        command = """
set -uo pipefail
rundir="$1"
json_py="$2"
kt_fail() { echo "FAIL: $*" >&2; exit 1; }
pausecompile_json() { python3 "$json_py" "$@"; }
""" + assertion
        for final, want in (
            ({"kind": "run_end", "reason": "orphaned"}, 0),
            ({"kind": "run_end", "reason": "done"}, 1),
            ({"kind": "run_end"}, 1),
            ({"kind": "run_end", "reason": True}, 1),
            ({"kind": "gap", "reason": "orphaned"}, 1),
        ):
            with self.subTest(final=final):
                self.file("events.jsonl", json.dumps(final) + "\n")
                got = subprocess.run(
                    ["/bin/bash", "-c", command, "orphan-end-test", str(self.work), str(HELPER)],
                    text=True, capture_output=True, env=self.env, check=False,
                )
                self.assertEqual(got.returncode, want, got.stderr)

    def test_scalar_fields_from_file_and_stdin(self):
        peer = self.file("peer.json", '{"slave":"/dev/pts/4","sid":1234}')
        self.good("field", "slave", peer, output="/dev/pts/4\n")
        self.good("field", "sid", peer, output="1234\n")
        self.good("field", "paused", text='{"paused":true}', output="true\n")
        self.good("field", "exit_reason", text='{"exit_reason":null}', output="null\n")
        self.bad("field", "missing", peer)
        self.bad("field", "nested", text='{"nested":{}}')

    def test_status_projection_and_join_match_recipe_output(self):
        status = '{"state":"lost","paused":true,"launcher_gone":true,"scope_now":"running"}'
        self.good(
            "project", "state,paused,launcher_gone,scope_now,exit_reason", text=status,
            output='{"state":"lost","paused":true,"launcher_gone":true,"scope_now":"running","exit_reason":null}\n',
        )
        self.good("join", "state,launcher_gone,scope_now", text=status, output="lost true running\n")
        self.bad("join", "state,missing", text=status)

    def test_projection_handles_pretty_status_and_jsonl_tail(self):
        self.good("project", "state", text='{\n "state": "lost"\n}\n', output='{"state":"lost"}\n')
        self.good(
            "project", "seq,kind", text='{"seq":1,"kind":"gap"}\n{"seq":2,"kind":"run_end"}\n',
            output='{"seq":1,"kind":"gap"}\n{"seq":2,"kind":"run_end"}\n',
        )
        self.bad("project", "kind", text='{"kind":"gap"}\n{"kind":')

    def test_subset_status_checks_require_json_boolean_and_all_keys(self):
        expected = '{"state":"lost","paused":true,"scope_now":"unknown"}'
        self.good("check", expected, text='{"state":"lost","paused":true,"scope_now":"unknown","extra":1}')
        for paused in (False, 1, "true", None):
            with self.subTest(paused=paused):
                self.bad("check", expected, text=json.dumps({"state": "lost", "paused": paused, "scope_now": "unknown"}))
        self.bad("check", expected, text='{"state":"lost","paused":true}')
        self.bad("check", '{"exit_reason":null}', text='{}')
        self.good("check", '{"kind":"run_end","reason":"orphaned"}', text='{"kind":"run_end","reason":"orphaned","seq":3}')
        self.bad("check", '{"kind":"run_end","reason":"orphaned"}', text='{"kind":"run_end","reason":"done"}')

    def test_run_end_count_zero_is_a_real_parse_result(self):
        events = self.file("events.jsonl", '{"kind":"run_start"}\n{"kind":"gap"}\n')
        self.good("count", "run_end", events, output="0\n")
        self.good("count", "run_end", text="", output="0\n")
        events.write_text(events.read_text() + '{"kind":"run_end"}\n')
        self.good("count", "run_end", events, output="1\n")
        events.write_text('{"kind":"gap"}\n{"kind":')
        self.bad("count", "run_end", events)
        events.write_text('{"kind":"gap"}\nGARBAGE\n{"kind":"run_end"}\n')
        self.bad("count", "run_end", events)
        self.bad("count", "run_end", self.work / "missing.jsonl")

    def test_refused_tty_count_reads_every_tier_file(self):
        refused = '{"rule":"builtin.other_tty","verdict":"refused"}\n'
        ignored = '{"rule":"builtin.other_tty","verdict":"allowed"}\n{"rule":"other","verdict":"refused"}\n'
        paths = [self.file(tier + ".jsonl", refused * 6 + ignored) for tier in ("landlock", "cgroup", "bpflsm")]
        self.good("refused-tty-count", *paths, output="18\n")
        paths[-1].write_text(refused * 6 + '{"rule":')
        self.bad("refused-tty-count", *paths)

    def test_gc_kept_requires_errors_and_no_orphan_or_delete(self):
        self.good("gc-kept", text='{"scanned":1,"orphaned":0,"deleted":0,"errors":["read cgroup.events"]}')
        for text in (
            '{"orphaned":0,"deleted":0,"errors":[]}',
            '{"orphaned":1,"deleted":0,"errors":["x"]}',
            '{"orphaned":0,"deleted":1,"errors":["x"]}',
            '{"orphaned":false,"deleted":0,"errors":["x"]}',
            '{"orphaned":0,"deleted":0,"errors":"x"}',
            '{"orphaned":0,"deleted":0}',
        ):
            with self.subTest(text=text):
                self.bad("gc-kept", text=text)

    def test_gc_deleted_accepts_no_errors_and_rejects_errors_or_false_count(self):
        for text in ('{"deleted":1}', '{"deleted":1,"errors":null}', '{"deleted":1,"errors":[]}'):
            self.good("gc-deleted", text=text)
        for text in ('{"deleted":0}', '{"deleted":true}', '{"deleted":1,"errors":["x"]}', '{"deleted":1,"errors":{}}'):
            with self.subTest(text=text):
                self.bad("gc-deleted", text=text)

    def test_all_commands_reject_malformed_or_nonobject_documents(self):
        for args in (("field", "kind"), ("project", "kind"), ("join", "kind"),
                     ("check", '{"kind":"run_end"}'), ("count", "run_end"),
                     ("refused-tty-count",), ("gc-kept",), ("gc-deleted",)):
            for text in ('{"kind":', 'false\n', '[]\n', '{"kind":NaN}\n', '{"kind":"gap","kind":"run_end"}\n'):
                with self.subTest(args=args, text=text):
                    self.bad(*args, text=text)

    def test_scalar_document_commands_reject_empty_or_multiple_documents(self):
        for args in (("field", "kind"), ("join", "kind"), ("check", '{}'), ("gc-kept",), ("gc-deleted",)):
            for text in ("", '{}\n{}\n'):
                with self.subTest(args=args, text=text):
                    self.bad(*args, text=text)
        self.bad("project", "kind", text="")

    def test_invalid_cli_and_expected_json_fail(self):
        self.bad("unknown")
        self.bad("field")
        self.bad("check", '{"paused":', text='{"paused":true}')
        self.bad("check", 'false', text='{"paused":true}')


if __name__ == "__main__":
    unittest.main()
