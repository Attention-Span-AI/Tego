#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""model_script.py -- what the stand-in "model" says, as the JSON script that test/workloads/model-stub/server.py serves.

The stub answers turn N of a conversation (N = the assistant messages the request already carries) with entry N of the
script, and with a plain "done" once the script is spent; agent.py reads that as "the task is over" and starts the next.

    model_script.py task          one coding task: run the tests, search, read, fix, run the tests, note it (9 steps)
    model_script.py loop [N]      a model that never gets anywhere: the same tool call N times (default 60)

Prints the JSON on stdout.
"""
import json
import sys


def call(tool):
    return [{"type": "tool_use", "name": tool, "input": {}}]


TASK = ["run_tests", "list_files", "read_file", "list_files", "edit_file", "list_files", "run_tests", "list_files",
        "append_notes"]


def main():
    profile = sys.argv[1] if len(sys.argv) > 1 else "task"
    if profile == "task":
        script = [call(t) for t in TASK]
    elif profile == "loop":
        script = [call("run_tests") for _ in range(int(sys.argv[2]) if len(sys.argv) > 2 else 60)]
    else:
        sys.exit("usage: model_script.py task | loop [N]")
    json.dump(script, sys.stdout)
    print()


if __name__ == "__main__":
    main()
