// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"github.com/attention-span-ai/tego/internal/platform/tomoyo"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenLabelTOMOYO(t *testing.T) {
	t.Cleanup(tomoyo.SetLoaderOmissionForTest(func() string { return "" }))
	const neverUpdated = "Policy update:                                 0"
	// A counter an unprivileged process moved, and a root-readable profile with nothing enforcing in it, or one that
	// enforces (SEC08b): the admission or the refusal is TOMOYO's own, and another LSM's check still runs after it.
	moved := fmt.Sprintf("Policy %-30s %10d (Last: 2026/11/19 12:00:00)", "update:", 3)
	const quiet = "PROFILE_VERSION=20150505\n0-COMMENT=x\n0-CONFIG={ mode=disabled grant_log=no reject_log=yes }\n"
	const loud = quiet + "1-CONFIG={ mode=enforcing grant_log=no reject_log=yes }\n"
	for _, syscallList := range []bool{false, true} {
		for _, tc := range []struct {
			name, domain, stat, missing, want, profile string
			differs                                    bool
			level, opener                              string
		}{
			{name: "Debian stock", domain: "<kernel>", stat: neverUpdated},
			{name: "label terminators", domain: "<kernel>\n\x00", stat: neverUpdated},
			{name: "another domain", domain: "<kernel> /usr/bin/tego", stat: neverUpdated, want: "TOMOYO observed domain"},
			{name: "empty domain", stat: neverUpdated, want: "TOMOYO self_domain"},
			{name: "oversized domain", domain: strings.Repeat("x", 64*1024+1), stat: neverUpdated, want: "TOMOYO self_domain"},
			{name: "unreadable domain", missing: "/sys/kernel/security/tomoyo/self_domain", stat: neverUpdated, want: "tomoyo/self_domain"},
			{name: "counter changed", domain: "<kernel>", stat: "Policy update:                                 1", want: "TOMOYO's policy has been updated since boot"},
			{name: "counter changed, profile proves nothing enforces", domain: "<kernel> /usr/bin/tego", stat: moved, profile: quiet},
			{name: "counter changed, profile enforces", domain: "<kernel>", stat: moved, profile: loud, want: "enforces"},
			{name: "counter changed, profile proof does not mask AppArmor", domain: "<kernel>", stat: moved, profile: quiet,
				opener: "different (enforce)\n", want: "apparmor /attr/", differs: true},
			{name: "AppArmor still checks depth", domain: "<kernel>", stat: neverUpdated, level: "1\n", want: "AppArmor complete stack visibility"},
			{name: "AppArmor still compares labels", domain: "<kernel>", stat: neverUpdated, opener: "different (enforce)\n", want: "apparmor /attr/", differs: true},
			{name: "prefix missing", domain: "<kernel>", stat: "Policy violation: 0", want: "TOMOYO stat"},
			{name: "unreadable stat", domain: "<kernel>", missing: "/sys/kernel/security/tomoyo/stat", want: "tomoyo/stat"},
		} {
			t.Run(fmt.Sprintf("syscall=%t/%s", syscallList, tc.name), func(t *testing.T) {
				read := func(path string) ([]byte, error) {
					if path == tc.missing {
						return nil, unix.EACCES
					}
					switch path {
					case "/sys/kernel/security/lsm":
						return []byte("lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm"), nil
					case "/sys/kernel/security/tomoyo/self_domain":
						return []byte(tc.domain), nil
					case "/sys/kernel/security/tomoyo/profile":
						if tc.profile != "" {
							return []byte(tc.profile), nil
						}
					case "/sys/kernel/security/tomoyo/stat":
						return []byte(tc.stat + "\nPolicy violation in enforcing mode: 0\n"), nil
					case "/sys/kernel/security/apparmor/.ns_level":
						if tc.level != "" {
							return []byte(tc.level), nil
						}
						return []byte("0\n"), nil
					case "/proc/456/attr/apparmor/current":
						if tc.opener != "" {
							return []byte(tc.opener), nil
						}
						return []byte("unconfined\n"), nil
					case "/proc/123/attr/apparmor/current":
						return []byte("unconfined\n"), nil
					}
					return nil, fmt.Errorf("unexpected fact %s", path)
				}
				var modules func() ([]uint64, error)
				if syscallList {
					modules = func() ([]uint64, error) { return []uint64{108, 100, 110, 105, 104, 103, 109, 113, 111, 112}, nil }
				}
				err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, read, modules, nil, false)
				if tc.want == "" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, errOpenLabelDiffers) != tc.differs {
					t.Fatalf("got %v, want fact failure %q", err, tc.want)
				}
			})
		}
	}
}
