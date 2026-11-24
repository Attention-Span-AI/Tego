# Historical binding-1 comparison fixture

These synthetic receipt/record bytes were captured with the receipt package at
commit `75cbde47473dc50a0d39a6e1135c221bf3f93095`, through a Go test overlay that
restored every changed receipt source/test file from that commit. The capture
used the original `boundRun`, `testBy`, `Compute` and `Receipt.JSON` implementations.
It did not run a product executable or a governed workload. This fixed fixture
holds the new reader to the old writer independently of `BindVersion:1`.

The capture command and overlay are retained privately.
