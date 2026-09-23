# SPDX-License-Identifier: Apache-2.0
"""A handful of trivial tests plus one that imports and exercises the installed dependency (Flask):
the overhead workload wants pytest's own startup, collection and import cost (every module Flask's
import chain opens), not a slow test body, so every test here is O(1) once the imports resolve."""
import pathlib

import flask


def test_arithmetic():
    assert 1 + 1 == 2


def test_string_reverse():
    assert "tego"[::-1] == "oget"


def test_sees_its_own_file():
    assert pathlib.Path(__file__).exists()


def test_list_sort():
    assert sorted([3, 1, 2]) == [1, 2, 3]


def test_flask_app_responds():
    app = flask.Flask(__name__)

    @app.route("/")
    def index():
        return "ok"

    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.data == b"ok"


def test_markupsafe_native_speedups_load():
    # markupsafe ships a C extension, which Jinja's escaping uses when it loads. Ordinary work loads it: at the tiers
    # a decision plane decides, its PROT_EXEC map needs an exec.allow entry covering the install directory (ADR
    # 0027), and without one markupsafe falls back to pure Python silently, so this is the check that it did not.
    from markupsafe import _speedups  # noqa: F401
