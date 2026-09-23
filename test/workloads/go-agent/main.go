// SPDX-License-Identifier: Apache-2.0

// Command go-agent is an enforce-only workload: Go's crypto/tls has no OpenSSL, so a run shows a capture gap.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	out := os.Getenv("TEGO_TEST_OUT")
	if out == "" {
		out = "/tmp/tego-out"
	}
	_ = os.MkdirAll(out, 0o755)
	if err := os.WriteFile(filepath.Join(out, "go.txt"), []byte("ok\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("HOME"), ".netrc.tego-test"), []byte("no\n"), 0o644); err != nil {
		fmt.Println("refused as expected:", err)
	} else {
		fmt.Fprintln(os.Stderr, "UNEXPECTED: write outside contract succeeded")
	}
}
