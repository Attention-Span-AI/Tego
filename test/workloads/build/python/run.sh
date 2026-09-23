#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — the overhead benchmark's pip-install-plus-pytest workload (docs/BENCHMARKS.md).
# It is the thing timed, bare and under `tego run`: install requirements.txt into a fresh
# directory, then run the tests against what was installed. That is the open-heavy (every installed
# file, every test module) and exec-heavy (a subprocess per pip and pytest invocation) half of the
# ticket's pair; test/workloads/build/npm is the other half.
#
# Every path pip and pytest would otherwise touch outside the run is pinned by argument so the
# workload's cost is installing and testing, not the network or a warm system cache: --find-links
# points at a wheelhouse the harness populated once (offline, no PyPI on the clock), --target and
# TMPDIR are wiped before every timed iteration by the harness's hyperfine --prepare step so each
# run pays the real install cost, and PYTHONPATH for the install step is the bootstrap pip the
# harness downloaded once (this system's python3 ships no pip module at all).
#
# Usage: run.sh <wheelhouse> <pip-bootstrap-dir> <target-dir> <tmp-dir>
set -euo pipefail

wheelhouse="${1:?wheelhouse dir}"
pip_bootstrap="${2:?pip bootstrap dir}"
target="${3:?install target dir}"
tmp="${4:?tmp dir}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$target" "$tmp"
export TMPDIR="$tmp"
# PYTHONDONTWRITEBYTECODE: this directory tree is read-only under the contract; a .pyc next to
# requirements.txt's importers would be a write-open the tier has to decide on for no reason.
export PYTHONDONTWRITEBYTECODE=1

PYTHONPATH="$pip_bootstrap" python3 -m pip install \
  --no-index --find-links "$wheelhouse" \
  --target "$target" --no-cache-dir --disable-pip-version-check -q \
  -r "$here/requirements.txt"

# no:cacheprovider: pytest's cache plugin would otherwise write .pytest_cache under $here, which
# sits outside the contract's one declared write directory.
PYTHONPATH="$target" python3 -m pytest -q -p no:cacheprovider "$here/tests"
