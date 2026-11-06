#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage checksummed release assets by their published names, without executing them.

    stage-release-assets.py CHECKSUMS DESTINATION

Run from the checkout root, after goreleaser. release.yml's release job hands DESTINATION to the signing job, which has
no checkout and signs what it receives. goreleaser leaves several checksummed files outside dist/'s top level: a raw
binary (archive format `binary`) is published as tego_<version>_linux_amd64 while its bytes stay at
dist/tego_linux_amd64_v1/tego, and checksum.extra_files are hashed where they are in the checkout. So each name in
CHECKSUMS is found in goreleaser's own record of what it made, dist/artifacts.json beside CHECKSUMS, or in the files
.goreleaser.yaml's checksum.extra_files globs match. There is no list of names here: an extra file added to
.goreleaser.yaml is staged with no change to this script.

It stops before DESTINATION exists on: a malformed or empty CHECKSUMS, or a name in it twice or named as CHECKSUMS is;
a name with no file behind it, or with two different files (two spellings of one path are one file); a file outside the
checkout or not a regular file; bytes that differ from CHECKSUMS; an extra_files entry it cannot read as goreleaser
does (a name_template, a {{ template }}, ** or {a,b}, a path outside the checkout), a glob that matches no file, two
globs that give one name, and an extra file CHECKSUMS does not list. The copies are hashed again as they are written,
into a fresh directory that becomes DESTINATION only when every file is in it.
"""

import glob
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

try:
    import yaml
except ImportError:
    yaml = None

CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)")
# The glob syntax Python's glob reads as goreleaser's fileglob does: literal path segments, `*` and `?`, neither of
# which crosses a slash, and both of which match a leading dot (include_hidden below). fileglob also reads ** and
# {a,b}, which Python's glob does not; a glob using them is refused rather than read differently.
SUPPORTED_GLOB = re.compile(r"[A-Za-z0-9._/*?-]+")


def checksum_extra_files(root: Path, config: Path) -> dict:
    """The name and path goreleaser checksums for each file checksum.extra_files matches, as its extrafiles.Find does."""
    if yaml is None:
        raise ValueError("PyYAML is needed to read .goreleaser.yaml (python3-yaml)")
    data = yaml.safe_load(config.read_text())
    checksum = data.get("checksum") if isinstance(data, dict) else None
    if not isinstance(checksum, dict):
        raise ValueError(f"{config.name} has no checksum section")
    if checksum.get("split"):
        raise ValueError("checksum.split writes one file per asset, which this staging does not read")
    entries = checksum.get("extra_files") or []
    if not isinstance(entries, list):
        raise ValueError("checksum.extra_files is not a list")
    found = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"glob"} or not isinstance(entry["glob"], str):
            raise ValueError(f"checksum.extra_files entry {entry!r}: only a plain glob is supported")
        pattern = entry["glob"]
        if not SUPPORTED_GLOB.fullmatch(pattern) or "**" in pattern:
            raise ValueError(f"checksum.extra_files glob {pattern!r}: syntax this staging cannot read as goreleaser does")
        if pattern.startswith("/") or ".." in Path(pattern).parts:
            raise ValueError(f"checksum.extra_files glob {pattern!r} is outside the checkout")
        matches = sorted(glob.glob(pattern, root_dir=root, include_hidden=True))
        if not matches:
            raise ValueError(f"checksum.extra_files glob {pattern!r} matches no file")
        for match in matches:
            if (root / match).is_dir():
                raise ValueError(f"checksum.extra_files glob {pattern!r} matches the directory {match}")
            # goreleaser names an extra file by its base name, and a second file of that name silently replaces the
            # first; here it is two candidates for one asset.
            name = Path(match).name
            if name in found:
                raise ValueError(f"checksum.extra_files: {found[name]} and {match} are both named {name}")
            found[name] = match
    return found


def read_checksums(sums: Path, manifest: bytes) -> list:
    text = manifest.decode("ascii")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines:
        raise ValueError("empty checksums file")
    entries = []
    seen = set()
    for line in lines:
        match = CHECKSUM_LINE.fullmatch(line)
        if not match:
            raise ValueError("malformed checksum entry")
        digest, name = match.groups()
        if name in seen or name == sums.name:
            raise ValueError(f"duplicate or reserved asset name: {name}")
        seen.add(name)
        entries.append((digest, name))
    return entries


def stage(sums: Path, destination: Path) -> None:
    root = Path.cwd().resolve()
    metadata = json.loads((sums.parent / "artifacts.json").read_text())
    if not isinstance(metadata, list):
        raise ValueError("artifacts.json is not a list of artifacts")
    paths = {}
    for artifact in metadata:
        paths.setdefault(artifact["name"], set()).add(artifact["path"])
    # checksum.extra_files are hashed from the source tree. A snapshot records nothing about them in artifacts.json; a
    # tag run lists release.extra_files there too, under another spelling of the same path.
    extras = checksum_extra_files(root, root / ".goreleaser.yaml")
    for name, source in extras.items():
        paths.setdefault(name, set()).add(source)

    manifest = sums.read_bytes()
    listed = read_checksums(sums, manifest)
    unlisted = sorted(set(extras) - {name for _, name in listed})
    if unlisted:
        raise ValueError(f"checksum.extra_files that {sums.name} does not list: {', '.join(unlisted)}")
    entries = []
    for digest, name in listed:
        candidates = set()
        for path in paths.get(name, set()):
            try:
                candidates.add((root / path).resolve(strict=True))
            except FileNotFoundError:
                raise ValueError(f"{name}: {path} does not exist") from None
        if len(candidates) != 1:
            raise ValueError(f"{name}: expected exactly one artifact path, found {len(candidates)}")
        source = candidates.pop()
        if not source.is_relative_to(root) or not source.is_file():
            raise ValueError(f"{name}: artifact is outside the checkout or not a regular file")
        with source.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != digest:
            raise ValueError(f"{name}: checksum mismatch")
        entries.append((name, source, digest))

    if destination.exists() or destination.is_symlink():
        raise ValueError(f"{destination} already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".stage-", dir=destination.parent))
    try:
        work.chmod(0o755)
        (work / sums.name).write_bytes(manifest)
        for name, source, digest in entries:
            # Verify the actual copied bytes too: a source changed after preflight must not be handed off.
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(f"{name}: changed while staging")
            with open(work / name, "xb") as out:
                out.write(data)
            print(f"  {name} <- {source.relative_to(root)}")
        os.rename(work, destination)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    print(f"staged {len(entries)} verified assets and {sums.name}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: stage-release-assets.py CHECKSUMS DESTINATION")
    errors = (OSError, ValueError, KeyError, TypeError) + ((yaml.YAMLError,) if yaml else ())
    try:
        stage(Path(sys.argv[1]), Path(sys.argv[2]))
    except errors as error:
        sys.exit(f"stage-release-assets: {error}")
