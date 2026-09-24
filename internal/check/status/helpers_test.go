// SPDX-License-Identifier: Apache-2.0

package status

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// osReadFile, osWriteFile and osMkdir keep the test bodies free of permission constants.
func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }

func osWriteFile(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }

func osMkdir(p string) error { return os.Mkdir(p, 0o700) }

// splitLines splits a ledger into its lines, terminators kept.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

// TestMain keeps this package's temporary directories under one parent instead of scattering
// hundreds of short-lived entries directly in the system temp directory: a sibling appearing or
// vanishing there while another package's test enumerates it is a race between test binaries,
// which `go test ./...` runs in parallel (seen against internal/runtime/enforce/landlock's
// sibling-enumeration tests). The parent is created once and removed when the package is done.
func TestMain(m *testing.M) {
	parent, err := os.MkdirTemp("", "tego-status-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("TMPDIR", parent); err != nil {
		fmt.Fprintf(os.Stderr, "set TMPDIR: %v\n", err)
		os.Exit(1)
	}
	code := testutil.LeakCheckMain(m)
	_ = os.RemoveAll(parent)
	os.Exit(code)
}
