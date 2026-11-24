# Pre-baseline writer fixtures

The fixtures were produced by the launch and adoption record writers at commit
`2910acb2b`, before the baseline slices, in a scratch checkout made with
`git archive 2910acb2b | tar -x -C <fix1>/prebaseline`.

Copy only `internal/runtime/baseline_compat_test.go` into that checkout. Create
`internal/runtime/testdata/prebaseline`, then run from that checkout:

```
TEGO_WRITE_COMPAT=1 <fix1>/check go test -tags tegotesthooks -p 2 -count=1 ./internal/runtime -run '^TestBaselineLegacyWriterStreams$'
```

Copy the resulting two JSONL files here. The current writer test compares the
entire streams, byte for byte, after the same masks. Both streams emit exactly
`run_start` and `run_end`. This proves those two kinds at these writer seams.
It does not prove other event kinds, action producers, kernel behavior, or complete
running-process launch/adoption streams.

The clocks, build identity, run identity, command, cwd, launcher start, labels and
environment are fixed. Adoption reads a synthetic proc cwd. Masks replace exactly
`id`, `prev`, `pid`, `tid`, `launcher_pid` and `launcher_uid` values with key-named
markers. Masks remove exactly the optional `launcher_user`, `host`, `sudo_uid`
and `sudo_user` members. The two chain fields depend on masked host values.
No other fields are masked. The same test source is used on both trees.

## Re-pinned 2026-11-20 (ADR 0157, record minor 41)

Every launch and adoption now writes revision 41 from run_start on, so both fixtures' `record_minor` moved from 31 to 41.
That is the only byte that changed in either file (checked by rewriting the 31 in the old files and comparing); every other
field is still what the pre-baseline writer wrote. The run has no home in these fixtures (the test's machine config has none),
so run_start carries no `home`.
