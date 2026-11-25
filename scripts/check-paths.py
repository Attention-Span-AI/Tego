#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check-paths.py: no tracked path may be one a Windows checkout, or a common tool, cannot hold.

    scripts/check-paths.py              the tree's own files (scripts/tree-files.sh: tracked and new, not ignored)
    scripts/check-paths.py --list -     NUL-separated paths on standard input
    scripts/check-paths.py --root DIR   every file under DIR (tools/oss/public_build.py checks the cut tree this way)

A clone of the repository on Windows stops at the first path it cannot create (git: "invalid path"), so one such
file keeps every Windows user from the installer and from building tego.exe. This lists every path that has one of:
  - a character Windows forbids in a name: backslash, colon, asterisk, question mark, double quote, less-than,
    greater-than, vertical bar, or a control character;
  - a name (any folder of the path) that ends in a dot or a space;
  - a reserved device name, in any case, with or without an extension: CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9;
  - a second path that differs from another only in letter case (a clone on a case-insensitive filesystem keeps one;
    names that differ only in Unicode normalisation count too);
  - a length over 240 characters (Windows' MAX_PATH is 260 and the clone's own folder takes some of it).
With no argument it also checks line endings: a tracked script (a .sh, .bash or .py file, or any file with the executable
bit) must have text=auto (or text) and eol=lf from the repository's .gitattributes and no CR in its committed bytes.
Git for Windows writes CRLF into every text file without such an attribute, and a script with CRLF does not run under
WSL (bad interpreter, a carriage return in every command).
Exit 0 when none, 1 when any path has one (each is printed with the reason), 2 when the list could not be read or is
empty: a check that read nothing would pass vacuously.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Iterable, Sequence

FORBIDDEN = set('\\:*?"<>|') | {chr(c) for c in range(32)} | {chr(127)}
DEVICES = {"CON", "PRN", "AUX", "NUL"} | {f"COM{n}" for n in range(1, 10)} | {f"LPT{n}" for n in range(1, 10)}
MAX_LENGTH = 240


def fold(text: str) -> str:
    return unicodedata.normalize("NFC", unicodedata.normalize("NFD", text)).casefold()


def problems(paths: Iterable[str]) -> list[str]:
    """One message per defect, in path order."""
    paths = sorted(set(paths))
    found: list[str] = []
    for path in paths:
        bad = sorted({c for c in path if c in FORBIDDEN})
        if bad:
            shown = " ".join(f"U+{ord(c):04X}" if ord(c) < 32 or ord(c) == 127 else c for c in bad)
            found.append(f"{path!r}: a character Windows cannot have in a name ({shown})")
        for part in path.split("/"):
            if part.endswith((".", " ")):
                found.append(f"{path!r}: the name {part!r} ends in a dot or a space")
            stem = part.split(".", 1)[0].rstrip(" ")
            if stem.upper() in DEVICES:
                found.append(f"{path!r}: the name {part!r} is a reserved device name")
        if len(path) > MAX_LENGTH:
            found.append(f"{path!r}: {len(path)} characters, over {MAX_LENGTH}")
    # Case: every folder prefix and every path, so two folders that differ only in case are found even when no file
    # name repeats.
    seen: dict[str, str] = {}
    for path in paths:
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            key = fold(prefix)
            if key in seen and seen[key] != prefix:
                found.append(f"{prefix!r}: differs only in case or normalisation from {seen[key]!r}")
            else:
                seen.setdefault(key, prefix)
    return found


SCRIPT_SUFFIXES = (".sh", ".bash", ".py")


def eol_problems(listing: bytes) -> list[str]:
    """One message per tracked script a Windows checkout would give CRLF. `listing` is `git ls-files -s --eol -z`."""
    found: list[str] = []
    for item in listing.split(b"\0"):
        if not item:
            continue
        meta, info, path = item.decode("utf-8", "surrogateescape").split("\t", 2)
        if not (path.endswith(SCRIPT_SUFFIXES) or meta.startswith("100755")):
            continue
        index, attr = info.split()[0], info.split("attr/", 1)[1].strip()
        words = attr.split()
        if index in ("i/crlf", "i/mixed"):
            found.append(f"{path!r}: the committed bytes hold CR ({index[2:]})")
        elif "eol=lf" not in words or not ({"text", "text=auto"} & set(words)):
            found.append(f"{path!r}: .gitattributes gives it {attr!r}; a script needs text=auto and eol=lf")
    return found


def read_list(data: bytes) -> list[str]:
    return [item.decode("utf-8", "surrogateescape") for item in data.split(b"\0") if item]


def tree_list(root: Path) -> list[str]:
    out = []
    for folder, _, names in os.walk(root):
        for name in names:
            out.append(Path(folder, name).relative_to(root).as_posix())
    return out


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--list", metavar="FILE", help="NUL-separated paths in FILE, or - for standard input")
    group.add_argument("--root", metavar="DIR", help="check every file under DIR")
    args = ap.parse_args(argv)
    here = Path(__file__).resolve().parent
    try:
        if args.root:
            paths = tree_list(Path(args.root))
        elif args.list == "-":
            paths = read_list(sys.stdin.buffer.read())
        elif args.list:
            paths = read_list(Path(args.list).read_bytes())
        else:
            done = subprocess.run([str(here / "tree-files.sh")], cwd=here.parent, capture_output=True, check=True)
            paths = read_list(done.stdout)
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"check-paths: the path list could not be read: {e}", file=sys.stderr)
        return 2
    if not paths:
        print("check-paths: the path list is empty; nothing was checked", file=sys.stderr)
        return 2
    found = problems(paths)
    if not (args.root or args.list):
        try:
            listing = subprocess.run(["git", "ls-files", "-s", "--eol", "-z"], cwd=here.parent, capture_output=True,
                                     check=True).stdout
        except (OSError, subprocess.CalledProcessError) as e:
            print(f"check-paths: the line-ending listing could not be read: {e}", file=sys.stderr)
            return 2
        found += eol_problems(listing)
    for line in found:
        print(f"check-paths: {line}")
    if found:
        print(f"check-paths: {len(found)} problem(s) in {len(set(paths))} paths", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
