#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Print what the model was told by Tego, from the model stub's --log-content log (demo.sh reason-hook).

Every line of the log is one request the stand-in Claude Code sent to the model stub. This prints, once
each and in order, the lines of those requests that Tego's PostToolUse hook wrote: the refusal, its
target and the rule, as the model reads them.
"""
import json, sys

seen = set()

def walk(o):
    if isinstance(o, str):
        for line in o.split("\n"):
            line = line.strip()
            if "Tego" in line and line not in seen:
                seen.add(line)
                print("  model read: " + line)
    elif isinstance(o, dict):
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for v in o:
            walk(v)

with open(sys.argv[1], encoding="utf-8") as fh:
    for ln in fh:
        if ln.strip():
            walk(json.loads(ln))
if not seen:
    print("  the model was told nothing by Tego")
    sys.exit(1)
