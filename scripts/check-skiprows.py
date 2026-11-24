#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate scoped skip rows and their hosted full-package obligations, offline."""

import re
import shlex
import subprocess
from pathlib import Path


def scheduled(workflow, row, body, package):
    """Recognize direct root-suite dispatches in vm-matrix's matrix job.

    This deliberately accepts only the workflow's current literal comparisons,
    package selectors and TEGO_VM_ROW assignment. A new dispatch form needs a
    checker update before it can establish a must-pass obligation.
    """
    job = workflow.split("\n  matrix:\n", 1)[1]
    job = re.split(r"\n  [a-zA-Z0-9_-]+:\n", job, maxsplit=1)[0]
    # These forms can remove a row or narrow its tests outside the invocation.
    # Refuse unsupported scheduling controls rather than assuming they run.
    if (re.search(r"^    if:|^        (?:include|exclude):", job, re.M) or
            re.search(r"^\s*(?:VM_RUN|VM_SHARD|VM_PART|TEGO_VM_ROW):", workflow, re.M)):
        return False
    kernels = re.search(r"        kernel:\n((?:          - [^\n]+\n)+)", job)
    parts = re.search(r"        part: \[([^\]]+)\]", job)
    if kernels is None or parts is None:
        return False
    if row not in re.findall(r"          - (\S+)", kernels[1]):
        return False
    job_env = re.search(r"^    env:\n((?:      [^\n]*\n)+)", job, re.M)
    kernel_is_row = job_env is not None and re.search(
        r"^      KERNEL: \$\{\{ matrix.kernel \}\}$", job_env[1], re.M) is not None

    def condition_allows(condition, part):
        values = {"matrix.kernel": row, "matrix.part": part,
                  "steps.body.outputs.body": body}
        # Parse the supported expression grammar, never eval workflow text.
        alternatives = []
        for alternative in condition.split("||"):
            terms = []
            for term in alternative.split("&&"):
                match = re.fullmatch(r"\s*([\w.]+)\s*(==|!=)\s*'([^']*)'\s*", term)
                if match is None or match[1] not in values:
                    return False
                equal = values[match[1]] == match[3]
                terms.append(equal if match[2] == "==" else not equal)
            alternatives.append(all(terms))
        return any(alternatives)

    for step in re.split(r"\n      - ", job)[1:]:
        # The split takes the newline that ends a step's last line when the next step follows at once, and a job's
        # last line has none; without one the run-block pattern below drops that line, and a call whose continuation
        # line was dropped ends in a lone backslash that shlex refuses.
        step += "\n"
        if re.search(r"^        env:", step, re.M):
            continue
        condition = re.search(r"^        if: (.+)$", step, re.M)
        if condition is not None and not any(condition_allows(condition[1], part.strip())
                                             for part in parts[1].split(",")):
            continue
        run = re.search(r"^        run: \|\n((?:          [^\n]*\n|\n)+)", step, re.M)
        if run is None:
            continue
        script = "\n".join(line[10:] for line in run[1].splitlines())
        # Only one direct invocation establishes a proof here. Shell branches,
        # preceding exports and variable selectors need an explicit checker
        # update; guessing at their effect would allow another inert obligation.
        words = shlex.split(script.replace("\\\n", " "), comments=True)
        command = "test/vm/root-suites.sh"
        if command not in words:
            continue
        index = words.index(command)
        assignments = words[:index]
        if not all(re.fullmatch(r"[A-Z_][A-Z0-9_]*=[^;|&]*", a) for a in assignments):
            continue
        env = dict(a.split("=", 1) for a in assignments)
        if env.get("TEGO_VM_ROW") not in ("$KERNEL", "${KERNEL}", row):
            continue
        if "KERNEL" in env or (env.get("TEGO_VM_ROW") != row and not kernel_is_row):
            continue
        if any(env.get(key) for key in ("VM_RUN", "VM_SHARD", "VM_PART")):
            continue
        selectors = words[index + 1:]
        if not all(re.fullmatch(r"=?[a-zA-Z0-9_/.-]+", s) for s in selectors):
            continue
        if not selectors or any(selector == "=" + package or
                                (not selector.startswith("=") and selector in package)
                                for selector in selectors):
            return True
    return False


def main():
    entries = []
    for name in ("test/unit-skips.txt", "test/integration-skips.txt",
                 "test/vm/root-skips.txt", "test/vm/root-must-pass.txt"):
        for number, line in enumerate(Path(name).read_text().splitlines(), 1):
            words = line.split("#", 1)[0].split()
            if len(words) == 3 and words[2].startswith("row="):
                entries.append((name, number, *words))
    if not entries:
        return 0
    listing = subprocess.check_output(["python3", "test/vm/fetch-kernel.py", "--list"], text=True)
    rows = {words[0]: words[3] for line in listing.splitlines()
            if len(words := line.split()) >= 4}
    workflow = Path(".github/workflows/vm-matrix.yml").read_text()
    failed = False
    module = re.search(r"^module (\S+)", Path("go.mod").read_text(), re.M)[1]
    for name, number, package, test, scope in entries:
        package = package.removeprefix(module + "/")
        row = scope.removeprefix("row=")
        message = None
        if row not in rows:
            message = "unknown matrix row " + row
        elif name == "test/vm/root-must-pass.txt" and not scheduled(workflow, row, rows[row], package):
            message = f"{package} {test}: no scheduled full package run on row={row}"
        if message:
            print(f"check-skiplists: {name}:{number}: {message}")
            failed = True
    return int(failed)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, IndexError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"check-skiplists: cannot verify scoped rows: {error}") from error
