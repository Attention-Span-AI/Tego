# Test data: where each file comes from

All from one governed run on 2026-11-10: run `r-5cd05e60-0dmrm463r69xq-kpyavw`, an Ubuntu 24.04 guest (kernel 6.8.0-147), tier `landlock`, tego `v0.1.1-rc.1-pub.c9186ce`. The source guest logs were retained outside this repository.

| File | Provenance | Real? |
|---|---|---|
| `events.jsonl` | The output of `tego events <run> --json` ("the stored lines byte for byte", internal/cli/events.go:51) | **Real**, as printed by tego in the guest |
| `run_start.json` | Line 1 of `events.jsonl` | **Real** |
| `doctor.json` | `tego doctor --json` | **Real** |
| `compile.txt` | `tego compile <contract>` | **Real** |
| `contract.yaml` | The run's input contract | **Real** input |
| `receipt.json` | Computed on this host on 2026-11-10 by `receipt.Compute` + `Receipt.JSON` (internal/check/receipt) (public code reference: main 691106e), over a copy of `events.jsonl`, through a scratch test added with `go test -overlay` (no repo file changed, no tego binary run). The same pass's text layout equals the guest's `tego receipt --verify` output except the time zone of the refusal times and the `Chain:` line. | **Reconstructed** by tego's own code; the guest did not print `receipt --json` |
| `verify.json` | Same scratch test: `ledger.VerifyRunDir` over the copy, against an anchor file holding `<run> <run_end id>`, constructed in the shape of internal/cli/verify.go:25-36. The guest's text line said "verified 74 lines, run_start to run_end, head a48c6844922d, anchored in /home/tego/.tego/chain.log". | **Reconstructed**; the anchor line was constructed |
| `compile.json` | Built by hand (a Python parse of `compile.txt`) in the shape of internal/cli/compile.go:779-940. Only the fields the renderer and check-writes.sh read are filled. | **Hand-made**; replace with a real `tego compile --json` in TEST-PLAN T1 |

`check.json` is a constructed binding-1 CLI success response used by fake-tego to test control flow.
Its explicit `binding_v:1` models the supported seven-check minimum.
It is not a comparison of these historical, unbound receipt bytes. The fresh-check path must be measured
with an actual compatible release on GitHub. summary.md and comment.md are deterministic display samples;
doctor-summary.md is a constructed refusal display. All three carry a visible sample notice.

`bindings/v1` and `bindings/v2` contain deterministic receipt and check JSON
produced by `TestWorkflowBindingFixtures` from this directory's `events.jsonl`,
using a fixed synthetic producer build and image hash. Refresh with
`TEGO_UPDATE_ACTION_BINDINGS=1 go test ./internal/check/receipt -run '^TestWorkflowBindingFixtures$'`.
They test product format compatibility, not a real release or hosted execution.
The offline verifier tests run both through collection and fresh verification.
