#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-off release audit of the execmatch corpus and deterministic generator.

Uses two source overlays, not a second implementation. No tracked file changes.
All Go invocations use the Go wrapper the caller names in TEGO_MATCHFIX_GO.
Set TMPDIR to that wrapper's task temporary root for fixture-name normalization.
Artifacts, including every changed input, stay in the caller's scratch directory.
Each Go leg gets private test-hook state under TMPDIR, removed after that leg.
The default baseline is the released matcher; --base selects another commit.
Use --run to compare named test corpora when the machine is loaded. The exact
release acceptance bar needs TestRound2ComparisonCorpus included in the selection.
That bar stays fixed when --base changes: a baseline that already accepts the
formerly invalid allow inputs fails it because the eight expected release changes are absent.
The observer seam and fixture adaptations deliberately target this audit corpus;
review them before using this driver for a later release.
"""
import argparse
import collections
from contextlib import contextmanager
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

BASE = "70a9e8c560de62d52924bc54a5169b8dae400806"
ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "pkg/policy/execmatch"

# Exactly these formerly invalid allow inputs are accepted. Keep the entry and
# input beside every digest so the exception remains reviewable.
ACCEPTED_P1_GO_14_ALLOW = {
    "0dadb16663192127e58459bed0c9d4ff05d022fd65e2faee86a5e37ee3d031df": ("git add --no-f", "--no-force", False),
    "3dee8da0c29de4e7096d32db4ce5b67acc5a57b027f408e5f4b744d1db493706": ("git add --no-f", "--no-force=true", True),
    "6e14da353afa2cb6bba1d113c385e343f7efaaf026195aa608c36227adf73f6b": ("git add --no-f", "--no-f", False),
    "86d2f09a51e58995962f059b683c0c5eb2dd738a8dd63d0db3bed7e10a20e07a": ("git add --no-f", "--no-f", True),
    "8d9f8b2536b5ff3b28a89d545533c7b0e4a3d483ac22e2f9fe9bac72c489d4f3": ("git add --no-f", "--no-f=true", True),
    "a0a2fb350da3d70781f49132eff5739282d3063a3079ed946d1a807a5c988781": ("git add --no-f", "--no-force", True),
    "f241d7ab6a99b38d0a56ed473b4f3ba163819ad006b03483a0c499e0a957b25f": ("git add --no-f", "--no-force=true", False),
    "fc16dd3e4437c6fc0b80cf69d8facfd984e5edb042217c6eb96d0ed745395360": ("git add --no-f", "--no-f=true", False),
}


def check_baseline_sources():
    """Inventory every production source, including sources added or removed."""
    prefix = "pkg/policy/execmatch/"
    listed = subprocess.check_output(["/usr/bin/git", "ls-tree", "-r", "--name-only", BASE, "--", prefix], cwd=ROOT).decode().splitlines()
    baseline = {Path(name) for name in listed if name.endswith(".go") and not name.endswith("_test.go") and "testdata" not in Path(name).parts}
    current = {path.relative_to(ROOT) for path in PACKAGE.rglob("*.go") if not path.name.endswith("_test.go") and "testdata" not in path.relative_to(PACKAGE).parts}
    index = Path(prefix + "index.go")
    if index not in baseline or index not in current:
        raise RuntimeError("selected baseline and current matcher both need index.go for the observer seam")
    return baseline, current


def observe_index(value, side):
    declaration = "func (ix *Index) Decide("
    if value.count(declaration) != 1:
        raise RuntimeError("Decide observer seam needs review")
    if side == "old" and "func (ix *Index) decide(" not in value:
        # The released matcher has no separate unguarded method. Copy its whole
        # decision and remove only its early guard, as the original audit did.
        start = value.index(declaration)
        end = value.index("// firstMatch", start)
        full = value[start:end]
        guard = "ix.Empty() || !ix.Guarded(f)"
        if full.count(guard) != 1:
            raise RuntimeError("baseline unguarded decision seam needs review")
        full = full.replace(declaration, "func (ix *Index) decide(", 1).replace(guard, "ix.Empty()", 1)
        value += "\n" + full
    if "func (ix *Index) decide(" not in value:
        raise RuntimeError("unguarded decision observer seam needs review")
    return value.replace(declaration, "func (ix *Index) decideObserved(", 1)


def overlay(side, dest):
    dest.mkdir()
    replace = {}
    baseline, current = check_baseline_sources()
    for name in sorted(baseline | current):
        source = ROOT / name
        if side == "old" and name not in baseline:
            # Go's empty overlay target hides a current-only production source.
            replace[str(source)] = ""
            continue
        if side == "new" and name not in current:
            continue
        value = (subprocess.check_output(["/usr/bin/git", "show", f"{BASE}:{name}"], cwd=ROOT)
                 if side == "old" else source.read_bytes())
        if name == Path("pkg/policy/execmatch/index.go"):
            value = observe_index(value.decode(), side).encode()
        target = dest / name.relative_to("pkg/policy/execmatch")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        replace[str(source)] = str(target)
    if side == "old":
        # This regression exercises private retained-reader state absent from the
        # released package. Its source-overlay red proof is separate; the selected
        # comparison corpora still run unchanged on both sides.
        replace[str(PACKAGE / "security_floor_test.go")] = ""
        # The input is identical on both sides; only its expected diagnostic is
        # old-specific. The observer still compares argv0 versus multicall.
        source = PACKAGE / "rows/coreutils_test.go"
        lines = source.read_text().splitlines(keepends=True)
        baseline_fixture = subprocess.check_output(["/usr/bin/git", "show", f"{BASE}:pkg/policy/execmatch/rows/coreutils_test.go"], cwd=ROOT).decode().splitlines()
        baseline_lines = [line for line in baseline_fixture if '{"argv0 lt-rm",' in line]
        if len(baseline_lines) != 1:
            raise RuntimeError("baseline stripped-applet fixture was not found exactly once")
        baseline_via = re.findall(r"execmatch\.Via\w+", baseline_lines[0])
        if len(baseline_via) != 1:
            raise RuntimeError("baseline stripped-applet fixture expectation needs review")
        found = 0
        for i, line in enumerate(lines):
            if '{"argv0 lt-rm",' in line:
                if len(re.findall(r"execmatch\.Via\w+", line)) != 1:
                    raise RuntimeError("stripped-applet fixture expectation needs review")
                lines[i] = re.sub(r"execmatch\.Via\w+", baseline_via[0], line)
                found += 1
        if found != 1:
            raise RuntimeError("stripped-applet fixture was not found exactly once")
        target = dest / "coreutils_test.go"
        target.write_text("".join(lines))
        replace[str(source)] = str(target)
        source = PACKAGE / "tightening_test.go"
        value = source.read_text().replace('if (full.Outcome == execmatch.OutcomeRefused || !full.Final)', 'if false && (full.Outcome == execmatch.OutcomeRefused || !full.Final)')
        target = dest / source.name
        target.write_text(value)
        replace[str(source)] = str(target)
    replace[str(PACKAGE / "tightening_observer.go")] = str(PACKAGE / "testdata/tightening/observer.go.txt")
    path = dest / "overlay.json"
    path.write_text(json.dumps({"Replace": replace}))
    return path


def stable_temporary_names(value):
    if isinstance(value, str):
        # testing.T.TempDir adds a random decimal suffix, with the same /001,
        # /002 children for the same test. Normalize that suffix only. Actual
        # argument text outside the test temp root stays byte-for-byte data.
        root = os.environ["TMPDIR"] + "/"
        stable = re.sub(re.escape(root) + r"(Test[^/]*?)[0-9]+/", root + r"\1$TEMP/", value)
        # holdNodeLines creates one os.MkdirTemp(base, "n") fixture for each
        # native Node vector. Preserve its relative module/URL spelling while
        # removing that second random allocation name, in this test only.
        return re.sub(re.escape(root) + r"(TestNodeRowModulesDifferential\$TEMP/[0-9]{3})/n[0-9]+/", root + r"\1/n$TEMP/", stable)
    if isinstance(value, list):
        return [stable_temporary_names(v) for v in value]
    if isinstance(value, dict):
        return {k: stable_temporary_names(v) for k, v in value.items()}
    return value


def key_facts(entry):
    if entry.get("RawKeyFacts") is not None:
        return entry["RawKeyFacts"]
    facts = json.loads(json.dumps(entry["Facts"]))
    for name in ("Argv", "Interp"):
        if facts[name] is None:
            facts[name] = []
    loaded = facts.get("Loaded")
    if loaded:
        if loaded["Argv"] is None:
            loaded["Argv"] = []
        argv = facts["Argv"]
        empty = any(w == "--argv0=" or w == "--argv0" and i + 1 < len(argv) and argv[i + 1] == "" for i, w in enumerate(argv[1:], 1))
        if empty and loaded["Argv"]:
            loaded["Argv"][0] = loaded["Path"]
    return facts


def go_digest(value):
    # Match encoding/json's map order, UTF-8 and HTML escaping. Keys being
    # recovered below are verified against the original SHA-256 before use.
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    for char, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        raw = raw.replace(char, escaped)
    return hashlib.sha256(raw.encode()).hexdigest()


def compact_index(out, side, files, sources, signatures, append):
    directory = out / side
    temporary = directory / "sort-tmp"
    temporary.mkdir(exist_ok=True)
    sorted_path = directory / "answers.sorted"
    unique_path = directory / "answers.unique"
    command = ["/usr/bin/sort", "--parallel=1", "-S", "64M", "-T", str(temporary), "-t", "\t", "-k1,1", "-k2,2", "-u"]
    if append:
        command.append(str(unique_path))
    command.append("-")
    calls = normalized = recovered = 0
    transient_prefix = os.environ["TMPDIR"].encode() + b"/Test"
    with sorted_path.open("wb") as target:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=target)
        try:
            for path in files:
                path = path.resolve()
                if str(path) in sources:
                    raise RuntimeError(f"journal was already compared: {path}")
                file_index = len(sources)
                sources.append(str(path))
                offset = 0
                with path.open("rb") as journal:
                    for line in journal:
                        entry = json.loads(line)
                        calls += 1
                        key = entry["Key"]
                        if not re.fullmatch(r"[0-9a-f]{64}", key):
                            raise RuntimeError("invalid journal key")
                        projection = decision(entry)
                        if transient_prefix in line:
                            pattern_key = json.dumps(entry["Patterns"])
                            sig = entry.get("IndexSignature")
                            if sig:
                                signatures.setdefault(pattern_key, set()).add(sig)
                            facts = key_facts(entry)
                            stable = stable_temporary_names(facts)
                            if facts != stable:
                                if not sig:
                                    matches = [candidate for candidate in signatures.get(pattern_key, ()) if go_digest([candidate, facts]) == key]
                                    if len(matches) != 1:
                                        raise RuntimeError(f"cannot verify original index signature for {key}")
                                    sig = matches[0]
                                    recovered += 1
                                if go_digest([sig, facts]) != key:
                                    raise RuntimeError(f"journal key verification failed for {key}")
                                key = go_digest([sig, stable])
                                normalized += 1
                            projection = stable_temporary_names(projection)
                        encoded = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
                        digest = hashlib.sha256(encoded).hexdigest()
                        process.stdin.write(f"{key}\t{digest}\t{file_index}:{offset}\n".encode())
                        offset += len(line)
                        if calls % 1000000 == 0:
                            print(f"{side}: compacted {calls} calls", flush=True)
            process.stdin.close()
            if process.wait() != 0:
                raise RuntimeError("external sort failed")
        except BaseException:
            process.stdin.close()
            process.terminate()
            process.wait()
            raise
    previous = None
    replacement = directory / "answers.unique.next"
    with sorted_path.open("rb") as source, replacement.open("wb") as target:
        for line in source:
            fields = line.rstrip(b"\n").split(b"\t")
            if len(fields) != 3:
                raise RuntimeError("malformed sorted answer")
            key, digest, _ = fields
            if previous and previous[0] == key:
                # sort -u removed identical (key,digest) pairs. A second digest
                # for a key is a non-deterministic result, never a chosen winner.
                raise RuntimeError(f"non-deterministic result for {key.decode()}")
            previous = key, digest
            target.write(line)
    replacement.replace(unique_path)
    sorted_path.unlink()
    print(f"{side}: indexed {calls} calls", flush=True)
    return calls, normalized, recovered


def accepted_allow_loosening(before, after):
    expected = ACCEPTED_P1_GO_14_ALLOW.get(before["Key"])
    if expected is None or after["Key"] != before["Key"]:
        return False
    entry, option, complete = expected
    return (before.get("Class") == after.get("Class") == "14/negated-prefix" and
            before.get("CompileValid") is False and after.get("CompileValid") is True and
            before.get("List") == after.get("List") == 1 and
            before.get("Patterns") == after.get("Patterns") == [entry] and
            before.get("Facts") == after.get("Facts") and
            before["Facts"].get("Argv") == ["git", "add", option] and
            before["Facts"].get("ArgvComplete") is complete and
            before["Outcome"] == 2 and after["Outcome"] == 1)


def assert_release_bar(result):
    """No lost deny/ask refusal; exactly the eight named allow exceptions."""
    errors = []
    if result["missing"] or result["added"]:
        errors.append(f'input coverage differs: missing={result["missing"]}, added={result["added"]}')
    if result["loosened"] != len(ACCEPTED_P1_GO_14_ALLOW):
        errors.append(f'expected exactly {len(ACCEPTED_P1_GO_14_ALLOW)} allow loosenings, got {result["loosened"]}')
    if result["unexpected_loosened"]:
        errors.append(f'{result["unexpected_loosened"]} unexpected loosenings')
    missing = set(ACCEPTED_P1_GO_14_ALLOW) - set(result["accepted_allow_loosenings"])
    if missing:
        errors.append("missing expected P1-GO-14 allow loosenings: " + ", ".join(sorted(missing)))
    if errors:
        raise RuntimeError("; ".join(errors))


def compare_indexes(out, sources):
    files = {}
    def entry(side, fields):
        file_index, offset = map(int, fields[2].split(b":"))
        path = sources[side][file_index]
        if path not in files:
            files[path] = open(path, "rb")
        source = files[path]
        source.seek(offset)
        return json.loads(source.readline())
    def read(source):
        line = source.readline()
        return line.rstrip(b"\n").split(b"\t") if line else None
    missing = added = unique = changed = loosened = 0
    classes = collections.Counter()
    accepted = {}
    unexpected = 0
    with (out / "old/answers.unique").open("rb") as old, (out / "new/answers.unique").open("rb") as new, (out / "changed.jsonl").open("w") as changes, (out / "loosened.jsonl").open("w") as loose:
        a, b = read(old), read(new)
        while a or b:
            if b is None or a is not None and a[0] < b[0]:
                missing += 1
                a = read(old)
                continue
            if a is None or b[0] < a[0]:
                added += 1
                b = read(new)
                continue
            unique += 1
            if a[1] != b[1]:
                before, after = entry("old", a), entry("new", b)
                record = json.dumps({"old": before, "new": after}) + "\n"
                if ((before["Outcome"] == 2 and after["Outcome"] != 2) or
                        (not before["Final"] and after["Final"] and after["Outcome"] != 2) or
                        (before["Outcome"] == 2 and before["List"] == 2 and after["List"] == 3)):
                    loosened += 1
                    if accepted_allow_loosening(before, after):
                        accepted[before["Key"]] = dict(entry=before["Patterns"][0], argv=before["Facts"]["Argv"], complete=before["Facts"]["ArgvComplete"])
                    else:
                        unexpected += 1
                    loose.write(record)
                changed += 1
                changes.write(record)
                classes[f'{before["Outcome"]}/{before["List"]}/{before["Final"]} -> {after["Outcome"]}/{after["List"]}/{after["Final"]}'] += 1
            a, b = read(old), read(new)
    for source in files.values():
        source.close()
    return dict(unique=unique, missing=missing, added=added, changed=changed, loosened=loosened, unexpected_loosened=unexpected, accepted_allow_loosenings=accepted, classes=dict(classes))


def decision(entry):
    return {k: v for k, v in entry.items() if k not in ("Key", "IndexSignature", "RawKeyFacts", "Facts", "Patterns")}


@contextmanager
def comparison_environment(dest, side):
    # HOME alone cannot isolate test-hook state. Preserve the caller's runtime
    # directory so its Go wrapper can reach the user manager; these packages do
    # not start Tego runs, and their tests own any private runtime they need.
    with tempfile.TemporaryDirectory(prefix="em-", dir=os.environ["TMPDIR"]) as name:
        state = Path(name)
        home, ledger = (state / part for part in ("home", "runs"))
        for directory in (home, ledger):
            directory.mkdir(mode=0o700)
        config = state / "config.json"
        config.write_text(json.dumps({"ledger_root": str(ledger)}) + "\n")
        config.chmod(0o600)
        yield dict(os.environ, TEGO_EXECMATCH_JOURNAL=str(dest / "journal"), TEGO_EXECMATCH_SIDE=side,
                   TEGO_CONFIG=str(config), TEGO_TEST_CHAIN_ANCHOR=str(state / "chain.log"),
                   TEGO_TEST_OWN_LOG_HOME=str(home))


def main():
    global BASE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=BASE, help="matcher baseline commit (default: released matcher)")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compare-only", action="store_true")
    parser.add_argument("--additional-old", type=Path, action="append")
    parser.add_argument("--additional-new", type=Path, action="append")
    parser.add_argument("--run", help="Go -run selector for a targeted corpus; omits the full-corpus loader supplement")
    parser.add_argument("--go", default=os.environ.get("TEGO_MATCHFIX_GO"), required="TEGO_MATCHFIX_GO" not in os.environ)
    args = parser.parse_args()
    try:
        BASE = subprocess.check_output(["/usr/bin/git", "rev-parse", "--verify", "--end-of-options", args.base + "^{commit}"], cwd=ROOT, stderr=subprocess.PIPE).decode().strip()
    except subprocess.CalledProcessError:
        parser.error("--base must name an existing commit")
    check_baseline_sources()
    if not os.environ.get("TMPDIR"):
        parser.error("set TMPDIR to the task temporary root used by the Go wrapper")
    out = args.out.resolve()
    out.mkdir(exist_ok=args.compare_only)
    # New regression tests have a separate red/green proof. Run the exact same
    # pre-existing corpus, all fuzz seeds, and generated inputs on both sides.
    regressions = {"CorrectedBuiltinAliases", "GuardArgv0Fallback", "LoaderExplicitEmptyArgv0", "LoaderEmptyArgv0KeepsOperandReading", "DerivedSubcommandsResolveAliases", "DerivedRowTargets", "GuardInterpretationBound"}
    # The fixed assertions have separate overlay red/green proofs. Compare their
    # inputs through the before/after corpus instead, so the old matcher can run.
    # Discover later regression names without excluding their observation corpora.
    for source in PACKAGE.glob("*_test.go"):
        regressions.update(name for name in re.findall(r"^func Test(Round[23]\w+)\(t \*testing\.T\)", source.read_text(), re.M) if not name.endswith("ComparisonCorpus"))
    skip = "^Test(" + "|".join(sorted(regressions)) + ")$"
    for side in (() if args.compare_only else ("old", "new")):
        dest = out / side
        ov = overlay(side, dest)
        journal = dest / "journal"
        journal.mkdir()
        with comparison_environment(dest, side) as env:
            package = "./pkg/policy/execmatch" if args.run is not None else "./pkg/policy/execmatch/..."
            command = [args.go, "test", "-p", "1", "-count=1", "-overlay", str(ov), package, "-skip", skip]
            if args.run is not None:
                command.extend(["-run", args.run])
            with (dest / "test.log").open("w") as log:
                run = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
            print(f"{side}: exit={run.returncode}; log={dest / 'test.log'}", flush=True)
            if run.returncode:
                raise SystemExit(run.returncode)
            if args.run is None:
                supplement = [args.go, "test", "-p", "1", "-count=1", "-overlay", str(ov), "./pkg/policy/execmatch", "-run", "^TestDerivedSubcommandsResolveAliases$/^(loader-corpus|rule-corpus)$"]
                with (dest / "loader-corpus.log").open("w") as log:
                    run = subprocess.run(supplement, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
                if run.returncode:
                    raise SystemExit(run.returncode)
    append = bool(args.additional_old or args.additional_new)
    if append and (not args.compare_only or not args.additional_old or not args.additional_new):
        parser.error("additional journals require --compare-only and journals for both sides")
    previous = json.loads((out / "summary.json").read_text()) if append else {}
    sources_path = out / "sources.json"
    sources = json.loads(sources_path.read_text()) if append else {"old": [], "new": []}
    signatures = {}
    new_calls, new_normalized, _ = compact_index(out, "new", args.additional_new or sorted((out / "new/journal").glob("*.jsonl")), sources["new"], signatures, append)
    old_calls, old_normalized, old_recovered = compact_index(out, "old", args.additional_old or sorted((out / "old/journal").glob("*.jsonl")), sources["old"], signatures, append)
    sources_path.write_text(json.dumps(sources, indent=2) + "\n")
    result = compare_indexes(out, sources)
    index_key = previous.get("index_key", "journal-recorded-signatures") if args.compare_only else "raw-pattern-inputs"
    summary = dict(base=BASE, run=args.run, index_key=index_key, old_calls=old_calls + previous.get("old_calls", 0), new_calls=new_calls + previous.get("new_calls", 0), old_temp_normalized=old_normalized + previous.get("old_temp_normalized", 0), new_temp_normalized=new_normalized + previous.get("new_temp_normalized", 0), old_signatures_verified=old_recovered + previous.get("old_signatures_verified", 0), **result)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    assert_release_bar(result)


if __name__ == "__main__":
    main()
