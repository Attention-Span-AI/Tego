// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package cli

import (
	"flag"
	"io"
	"testing"
)

func TestProductionRunHasNoGeneralSelector(t *testing.T) {
	cmd := cmdRun()
	for _, selector := range []string{"general", "managed"} {
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		cmd.Flags(fs)
		if fs.Lookup(selector) != nil {
			t.Fatalf("production exposes --%s before general enforcement closure", selector)
		}
		if err := fs.Parse([]string{"--" + selector}); err == nil {
			t.Fatalf("production accepts --%s", selector)
		}
	}
}
