// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

type compilationResolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f compilationResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

// TestCompilationInterruptCancelsDNS exercises the signal context at both CLI entry
// points during lookup, after their pre-compile context checks (R29).
func TestCompilationInterruptCancelsDNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("version: 0\nname: interrupted\ncommand: [/usr/bin/true]\nnet:\n  allow: [interrupted.example:443]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, run := range []bool{false, true} {
		t.Run(map[bool]string{false: "compile", true: "run"}[run], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			queries := make(chan string, 1)
			resolver := compilationResolverFunc(func(dctx context.Context, network, host string) ([]netip.Addr, error) {
				queries <- network + ":" + host
				cancel()
				<-dctx.Done()
				return nil, dctx.Err()
			})
			var errs bytes.Buffer
			var code int
			if run {
				_, _, _, code = compileForRun(ctx, runOptions{contract: path, resolver: resolver}, config.Builtin(), &errs)
			} else {
				code = runCompile(ctx, path, compileRequest{resolver: resolver}, io.Discard, &errs)
			}
			select {
			case query := <-queries:
				if query != "ip:interrupted.example" {
					t.Fatalf("lookup %q, want the contract's named endpoint", query)
				}
			default:
				t.Fatal("compilation never entered DNS lookup")
			}
			if code != identity.ExitError || !strings.Contains(errs.String(), "interrupted") || strings.Contains(errs.String(), "host-unresolvable") {
				t.Fatalf("exit=%d stderr=%q, want interruption rather than hostname failure", code, errs.String())
			}
		})
	}
}
