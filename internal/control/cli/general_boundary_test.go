// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package cli

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Control parses flags inside each command's Run, so callback substitution proves
// registry lookup and verbatim dispatch only. It never starts a service or reads
// account policy. The engine's production source certificate guards these command
// bodies separately. Names includes registrations omitted from help.
func TestProductionGeneralControlDispatch(t *testing.T) {
	names := Names()
	if len(names) == 0 || len(names) != len(commands) {
		t.Fatal("incomplete production command registry")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			original := commands[name]
			registered, ok := Lookup(name)
			if !ok || registered.Name != name {
				t.Fatalf("registered command %q cannot be looked up", name)
			}
			t.Cleanup(func() { commands[name] = original })
			for _, args := range [][]string{nil, {"--general"}, {"--managed", "example"}} {
				called := 0
				cmd := registered
				cmd.Run = func(_ context.Context, got []string, _, _ io.Writer) int {
					called++
					if !slices.Equal(got, args) {
						t.Errorf("dispatch arguments %q, want %q", got, args)
					}
					return identity.ExitOK
				}
				commands[name] = func() Command { return cmd }
				var out, errs bytes.Buffer
				argv := append([]string{handoff.Name, name}, args...)
				code := mainWith(t.Context(), argv, &out, &errs, privilege{euid: 1000})
				if called != 1 || code != identity.ExitOK || out.Len() != 0 || errs.Len() != 0 {
					t.Fatalf("dispatch %q: called %d, exit %d, stdout %q, stderr %q", args, called, code, &out, &errs)
				}
			}
		})
	}
}
