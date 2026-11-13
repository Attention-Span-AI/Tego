# Combined released-matcher comparison

The release comparison checks both matcher fix families against private released
commit `70a9e8c56`. The 20 production files under `internal/baseline` differ only
in their import prefix. Verify every source byte with:

```sh
python3 test/execmatchdiff/prepare.py --verify
```

Run ordinary tests with your Go command. `GO_CHECK` stands for it below; it may
name a wrapper that runs Go under the host's memory and CPU limits:

```sh
"$GO_CHECK" test -p 1 -count=1 -v ./test/execmatchdiff
```

The bounded separator matrix visits every named command and alias, plain and
constrained entries, direct/argv0/loader/interpreter routes and open prefixes.
The value matrix keeps one required option per command scenario plus the named
npm and AWS regressions. `TestReconciliationReleasedComparison` keeps the eight
released-invalid allow keys, corrected aliases/external helpers and a seeded
slice of the other matcher generator. The original source-contract corpus also
checks its compilation outcomes directly against the frozen matcher, including
invalid entries. Ordinary matcher tests retain bounded slices of the correction
and prefix sweeps. Assertions and dedicated defect regressions still run.

The policy bar permits zero lost deny/ask refusals, zero deny-to-ask transitions
and zero premature final admissions. Allow gains are restricted to:

- The eight named keys for the formerly invalid `git add --no-f` entry: four
  documented negative-option spellings, complete and incomplete.
There is no invocation-marker exception. An allow entry does not admit its command
when the command line puts `--` before the subcommand; write the command without it.

Typed npm value changes, pattern-separator corrections, commandless vectors and
browser unions cannot remove a released refusal. The product decision retains a
conservative compatibility reader for that purpose. Parser-only oracle functions
remain tested as evidence of source semantics; their broader correction classes
are not permissions in the combined release comparison. Parser-only marker oracles remain semantic controls and cannot authorize a release gain.

The long runner requires an explicit scratch directory and runs all heavy steps
serially with GOMAXPROCS=2, GOMEMLIMIT=2GiB and `go test -p 1`. It runs Go through
`GO_CHECK` when that is set and through the `go` on PATH otherwise:

```sh
EXECMATCH_SCRATCH="$COMPARE_SCRATCH" test/execmatchdiff/long.sh
```

It enables `TEGO_EXECMATCH_LONG=1` only for the full matrices/generators/sweeps:

1. Extended separator, complete value and reconciliation matrices, plus the
   ordinary inventory and exception controls.
2. Actual matcher and row package tests and stored fuzz seeds under a disposable
   observer overlay, with ordinary bounded defaults.
3. Both original generators: the matcher-reconciliation seed and command-marker
   boundary-position seed, including raw source-contract cases.
4. Complete correction sweep and prefix pair/triple sweeps.

Each phase has its own log and elapsed seconds in `logs/summary`. The long
matrices also print paired calls per side and aligned source keys. Keys contain
the entry actually parsed, list, supplied facts and candidate input, never a
normalized result. Counts have separate test/phase namespaces; compile refusals
and the eight restored keys are accounted for separately. Set
`TEGO_EXECMATCH_KEYS=1` to retain these counts in a bounded run too. The observer
reconstructs the same public grammar, patterns, identities, loader facts, implicit
grants and candidate inventories in the released types. Private indices are
rebuilt; new grammar metadata is absent from the frozen types. No product parser
is replaced, and every actual Decide call is observed. All original compiled
package tests still run. No guest, private gate or fuzz loop is started.

The older journal driver `scripts/check-execmatch-tightening.py` remains as the
standalone spelling-fix audit and keeps its own checker tests. Its fixed eight-key
exception set alone intentionally does not permit separator gains. The combined
runner reads its original generator and source corpus through the shared observer
rather than silently widening that standalone audit's acceptance bar.

The ordinary inventory reads contracts from examples, presets, conformance,
documentation, shell heredocs and `test/fixtures` without executing scripts or
expanding their words. `TEGO_EXECMATCH_ORDINARY` and `TEGO_EXECMATCH_INVENTORY` retain
its per-entry vectors and sources. The combined tree additionally includes the
formerly invalid negated-prefix entry documented by the other matcher fix.
Released-invalid entries have no released admitted invocations and are accounted
for separately; only the named exception is eligible for restoration.

On a host where product executables are forbidden, prepare the conformance
in-process CLI overlay and use its testhook tags:

```sh
python3 test/execmatchdiff/conformance.py "$CONFORMANCE_SCRATCH"
"$GO_CHECK" test -p 1 -race -count=1 -tags tegobpf,tegotesthooks \
  -overlay "$CONFORMANCE_SCRATCH/overlay.json" ./test/conformance
```

This retains fixture materialization, oracle expectations, compile output readers,
machine hooks and isolated configuration, anchor and own-log environment. It does
not start a Tego executable. Host agreement is not kernel enforcement evidence;
all final-commit guest and record checks remain owed.

The exhaustive correction inventory and prefix matrices run in eight serial
partitions apiece under Go's existing package deadline. Correction partitions
select disjoint named targets. Prefix partitions generate every vector in order
before selecting rows, preserving both original RNG streams and all assertions.
The shard variable is rejected unless exhaustive mode is enabled.
