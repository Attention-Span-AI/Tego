// SPDX-License-Identifier: Apache-2.0

//go:build integration && !cgo

package launch

// testBinaryUsesCgo is false in a test binary built without cgo, as the shipped tego always is: the Go
// runtime starts its threads with clone(2), which a clone3 filter leaves alone.
const testBinaryUsesCgo = false
