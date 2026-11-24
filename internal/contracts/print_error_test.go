// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"errors"
	"testing"
)

func TestContractsListPreservesFirstWriteError(t *testing.T) {
	failure := errors.New("first output write failed")
	w := &failOnceWriter{failure: failure}
	c := Catalog{Contracts: []Entry{{Name: "fixture", Path: "/contract.yaml", State: "missing"}}}
	if err := PrintList(w, c, false); !errors.Is(err, failure) {
		t.Fatalf("first output error was lost: %v", err)
	}
}

// Later writes succeed, so a successful table header cannot hide an earlier
// output failure. A writer that fails every write would miss that regression.
type failOnceWriter struct {
	failure error
	failed  bool
}

func (w *failOnceWriter) Write(p []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return 0, w.failure
	}
	return len(p), nil
}
