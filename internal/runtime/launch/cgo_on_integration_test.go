// SPDX-License-Identifier: Apache-2.0

//go:build integration && cgo

package launch

// testBinaryUsesCgo is true in a test binary built with cgo, as `go test` builds one wherever a C compiler is
// present (the race detector needs it): its OS threads are started by glibc's pthread_create, which uses
// clone3 and aborts on EPERM rather than falling back to clone(2).
const testBinaryUsesCgo = true
