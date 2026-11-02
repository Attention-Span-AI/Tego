// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAskMutationRefusesNameMatchedFile is ADR 0043's interface 2 (supervisor R15f) for an fs.ask mutation (ADR
// 0047): the approved mutation is made by this process, outside any plane, so at tiers cgroup and bpflsm a file made,
// removed or moved at a name an entry covers (a temporary file renamed to .env.local, a symlink or a link made there,
// an unlink of one) is refused before any person is asked, named by the entry, and nothing changes. A directory of
// that name is no name entry's (D1) and a name the entry excepts is not covered: both are asked and made. At tier
// landlock no name entry decides (D7), and the person is asked.
func TestAskMutationRefusesNameMatchedFile(t *testing.T) {
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	type tc struct {
		name  string
		act   func(scope string) error
		asked bool
		check func(t *testing.T, scope string)
	}
	cases := func(tier backend.Tier) []tc {
		named := tier != backend.TierLandlock
		return []tc{
			{"rename onto .env.local", func(s string) error {
				return unix.Renameat(unix.AT_FDCWD, filepath.Join(s, "tmp"), unix.AT_FDCWD, filepath.Join(s, ".env.local"))
			}, !named, func(t *testing.T, s string) {
				if exists(filepath.Join(s, ".env.local")) == named || exists(filepath.Join(s, "tmp")) != named {
					t.Fatalf("rename moved=%v, want %v", exists(filepath.Join(s, ".env.local")), !named)
				}
			}},
			{"symlink at .env.local", func(s string) error {
				return unix.Symlinkat("tmp", unix.AT_FDCWD, filepath.Join(s, ".env.local"))
			}, !named, func(t *testing.T, s string) {
				if exists(filepath.Join(s, ".env.local")) == named {
					t.Fatalf("symlink made=%v, want %v", !named, !named)
				}
			}},
			{"link at .env.local", func(s string) error {
				return unix.Linkat(unix.AT_FDCWD, filepath.Join(s, "tmp"), unix.AT_FDCWD, filepath.Join(s, ".env.local"), 0)
			}, !named, func(t *testing.T, s string) {
				if exists(filepath.Join(s, ".env.local")) == named {
					t.Fatalf("link made=%v, want %v", named, !named)
				}
			}},
			{"unlink .env.prod", func(s string) error {
				return unix.Unlinkat(unix.AT_FDCWD, filepath.Join(s, ".env.prod"), 0)
			}, !named, func(t *testing.T, s string) {
				if exists(filepath.Join(s, ".env.prod")) != named {
					t.Fatalf("unlink removed=%v, want %v", !named, !named)
				}
			}},
			{"mkdir .env.d", func(s string) error {
				return unix.Mkdirat(unix.AT_FDCWD, filepath.Join(s, ".env.d"), 0o755)
			}, true, func(t *testing.T, s string) {
				if !exists(filepath.Join(s, ".env.d")) {
					t.Fatal("the approved directory was not made")
				}
			}},
			{"rename onto the excepted .env.example", func(s string) error {
				return unix.Renameat(unix.AT_FDCWD, filepath.Join(s, "tmp"), unix.AT_FDCWD, filepath.Join(s, ".env.example"))
			}, true, func(t *testing.T, s string) {
				if !exists(filepath.Join(s, ".env.example")) {
					t.Fatal("the approved rename was not made")
				}
			}},
		}
	}
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM, backend.TierLandlock} {
		for _, c := range cases(tier) {
			t.Run(string(tier)+" "+c.name, func(t *testing.T) {
				scope := filepath.Join(t.TempDir(), "scope")
				mustWrite(t, filepath.Join(scope, "tmp"), "x")
				mustWrite(t, filepath.Join(scope, ".env.prod"), "SECRET=1")
				pol := askScopePolicy(scope)
				pol.Rules.Tier = tier
				pol.Rules.NameDeny = []agent.NameDenyRule{{Literal: ".env.", Prefix: true, Except: []string{".env.example"}, BuiltIn: true,
					Scopes: []agent.NameScope{{Canonical: scope, Spelling: scope}}}}
				asked, sink, err := heldMutations(t, mutationNRs, pol, func() error { return c.act(scope) }, nil, func(ask.Summary) bool { return true })
				if (len(asked) != 0) != c.asked {
					t.Fatalf("asks %+v, want asked=%v", asked, c.asked)
				}
				c.check(t, scope)
				if c.asked {
					if err != nil {
						t.Fatalf("approved mutation: %v", err)
					}
					return
				}
				if !errors.Is(err, unix.EACCES) {
					t.Fatalf("refused mutation returned %v, want EACCES", err)
				}
				if ev := sink.one(t); ev.Verdict != record.VerdictRefused || !strings.HasSuffix(ev.Rule, "/**/.env.*]") {
					t.Fatalf("line %+v, want refused and named by the .env.* entry", ev)
				}
			})
		}
	}
}
