#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""JSON assertions for the pausecompile guest recipes; Python standard library only.

field KEY [FILE] and join KEYS [FILE] print scalar values (KEYS is comma-separated).
project KEYS [FILE] prints compact object projections from JSON or JSONL.
check EXPECTED [FILE] requires an object subset with strict JSON value types.
count KIND [FILES...] and refused-tty-count [FILES...] scan every JSONL row.
gc-kept [FILE] and gc-deleted [FILE] assert the recipe 4 GC results.
Omitted FILE means stdin. A false assertion or invalid input exits nonzero.
"""

import argparse
import json
import sys


def invalid_constant(value):
    raise ValueError("invalid JSON constant: " + value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


DECODER = json.JSONDecoder(parse_constant=invalid_constant, object_pairs_hook=unique_object)


def read(path):
    if path is None:
        return sys.stdin.read()
    with open(path, encoding="utf-8") as source:
        return source.read()


def object_value(value):
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def document(text):
    return object_value(DECODER.decode(text))


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def scalar(value):
    if isinstance(value, (dict, list)):
        raise ValueError("expected a scalar JSON field")
    return value if isinstance(value, str) else compact(value)


def subset(actual, expected):
    # Python considers True == 1: the guest assertions must retain JSON's distinction.
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return all(key in actual and subset(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(subset(a, e) for a, e in zip(actual, expected))
    return actual == expected


def rows(paths):
    for path in paths or [None]:
        for line in read(path).splitlines():
            if line.strip():
                yield document(line)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("field", "project", "join", "check"):
        command = commands.add_parser(name)
        command.add_argument("query")
        command.add_argument("file", nargs="?")
    for name in ("count", "refused-tty-count"):
        command = commands.add_parser(name)
        if name == "count":
            command.add_argument("kind")
        command.add_argument("files", nargs="*")
    for name in ("gc-kept", "gc-deleted"):
        commands.add_parser(name).add_argument("file", nargs="?")
    args = parser.parse_args()

    if args.command in ("count", "refused-tty-count"):
        if args.command == "count":
            total = sum(row.get("kind") == args.kind for row in rows(args.files))
        else:
            total = sum(row.get("rule") == "builtin.other_tty" and row.get("verdict") == "refused"
                        for row in rows(args.files))
        print(total)
        return 0

    text = read(args.file)
    if args.command == "project":
        # Status JSON may be indented; a ledger tail contains several compact JSON objects.
        output = []
        rest = text.strip()
        while rest:
            value, end = DECODER.raw_decode(rest)
            value = object_value(value)
            output.append(compact({key: value.get(key) for key in args.query.split(",")}))
            rest = rest[end:].lstrip()
        if not output:
            raise ValueError("expected at least one JSON object")
        print("\n".join(output))
        return 0

    value = document(text)
    if args.command == "field":
        print(scalar(value[args.query]))
    elif args.command == "join":
        print(" ".join(scalar(value[key]) for key in args.query.split(",")))
    elif args.command == "check":
        return 0 if subset(value, document(args.query)) else 1
    elif args.command == "gc-kept":
        return 0 if (subset(value, {"orphaned": 0, "deleted": 0})
                     and isinstance(value.get("errors"), list) and value["errors"]) else 1
    elif args.command == "gc-deleted":
        return 0 if subset(value, {"deleted": 1}) and value.get("errors") in (None, []) else 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, UnicodeError) as error:
        print("pausecompile-json: " + str(error), file=sys.stderr)
        sys.exit(1)
