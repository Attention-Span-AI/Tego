// SPDX-License-Identifier: Apache-2.0

package tomoyo

import (
	"errors"
	"fmt"
	"github.com/attention-span-ai/tego/internal/platform/kernelconfig"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Captured as uid 1001 in a Debian 13 guest.
const stockLine = "Policy update:                                 0\n"
const updatedMessage = "TOMOYO's policy has been updated since boot; held file opens are refused on this machine until TOMOYO is unused again after a restart"

func TestNeverUpdatedBytes(t *testing.T) {
	if got := fmt.Sprintf("Policy %-30s %10d\n", "update:", uint32(0)); got != stockLine || len(got) != 49 {
		t.Fatalf("kernel format = %q (%d bytes), want captured %q", got, len(got), stockLine)
	}
}

func TestCheckFacts(t *testing.T) {
	for _, tc := range []struct{ name, domain, line, missing, dataError, source, want string }{
		{name: "stock", domain: "<kernel>", line: stockLine},
		{name: "domain terminators", domain: "<kernel>\n\x00", line: stockLine},
		{name: "later stat lines", domain: "<kernel>", line: stockLine + "Policy violation in enforcing mode: 0\n"},
		{name: "other domain", domain: "<kernel> /usr/bin/tego", line: stockLine, want: `TOMOYO observed domain "<kernel> /usr/bin/tego" prevents held file opens`},
		{name: "empty domain", line: stockLine, want: "TOMOYO self_domain"},
		{name: "embedded newline", domain: "<kernel>\nx", line: stockLine, want: "TOMOYO self_domain"},
		{name: "embedded NUL", domain: "<kernel>\x00x", line: stockLine, want: "TOMOYO self_domain"},
		{name: "oversized domain", domain: strings.Repeat("x", limit+1), line: stockLine, want: "TOMOYO self_domain"},
		{name: "unreadable domain", line: stockLine, missing: selfDomain, want: "tomoyo/self_domain"},
		{name: "domain data plus error", domain: "<kernel>", line: stockLine, dataError: selfDomain, want: "tomoyo/self_domain"},
		{name: "unreadable stat", domain: "<kernel>", missing: stat, want: "tomoyo/stat"},
		{name: "stat data plus error", domain: "<kernel>", line: stockLine, dataError: stat, want: "tomoyo/stat"},
		{name: "nonzero without stamp", domain: "<kernel>", line: fmt.Sprintf("Policy %-30s %10d\n", "update:", 1), want: updatedMessage},
		{name: "nonzero with stamp", domain: "<kernel>", line: fmt.Sprintf("Policy %-30s %10d (Last: 2026/11/17 12:00:00)\n", "update:", 1), want: updatedMessage},
		{name: "zero with stamp", domain: "<kernel>", line: strings.TrimSuffix(stockLine, "\n") + " (Last: 2026/11/17 12:00:00)\n", want: updatedMessage},
		{name: "empty stat", domain: "<kernel>", want: "TOMOYO stat"},
		{name: "oversized stat", domain: "<kernel>", line: stockLine + strings.Repeat("x", limit), want: "TOMOYO stat"},
		{name: "missing prefix", domain: "<kernel>", line: "Policy violation: 0\n", want: "TOMOYO stat"},
		{name: "missing newline", domain: "<kernel>", line: strings.TrimSuffix(stockLine, "\n"), want: "TOMOYO stat"},
		{name: "no padding", domain: "<kernel>", line: "Policy update:0\n", want: "TOMOYO stat"},
		{name: "short padding", domain: "<kernel>", line: "Policy update: 0\n", want: "TOMOYO stat"},
		{name: "extra padding", domain: "<kernel>", line: strings.Replace(stockLine, ":", ": ", 1), want: "TOMOYO stat"},
		{name: "CR", domain: "<kernel>", line: strings.TrimSuffix(stockLine, "\n") + "\r\n", want: "TOMOYO stat"},
		{name: "Unicode space", domain: "<kernel>", line: strings.Replace(stockLine, ": ", ":\u00a0", 1), want: "TOMOYO stat"},
		{name: "tab", domain: "<kernel>", line: strings.Replace(stockLine, ": ", ":\t", 1), want: "TOMOYO stat"},
		{name: "bad counter", domain: "<kernel>", line: "Policy update: bad\n", want: "TOMOYO stat"},
		{name: "bad stamp", domain: "<kernel>", line: strings.TrimSuffix(stockLine, "\n") + " (Last: bad)\n", want: "TOMOYO stat"},
		{name: "loader omitted", domain: "<kernel>", line: stockLine, source: "/boot/config-test", want: "CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if path == tc.missing {
					return nil, os.ErrPermission
				}
				data := tc.line
				if path == selfDomain {
					data = tc.domain
				}
				if path == tc.dataError {
					return []byte(data), os.ErrPermission
				}
				return []byte(data), nil
			}
			err := check(read, tc.source)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if (tc.missing != "" || tc.dataError != "") && !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckStateless(t *testing.T) {
	domain, line := "<kernel>", stockLine
	reads := map[string]int{}
	read := func(path string) ([]byte, error) {
		reads[path]++
		if path == selfDomain {
			return []byte(domain), nil
		}
		return []byte(line), nil
	}
	for i, wantPass := range []bool{true, false, false, true, false, true} {
		switch i {
		case 1:
			line = "Policy update:                                 1\n"
		case 2:
			line = stockLine
			domain = "<kernel> /usr/bin/tego"
		case 3:
			domain = "<kernel>"
		case 4:
			line = "Policy update:0"
		case 5:
			line = stockLine
		}
		if err := check(read, ""); (err == nil) != wantPass {
			t.Fatalf("check %d = %v, want pass %t", i, err, wantPass)
		}
	}
	if reads[selfDomain] != 6 || reads[stat] != 6 {
		t.Fatalf("facts cached: %v", reads)
	}
}

func TestReadFileRejectsOversizedFact(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fact")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", limit+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(p); err == nil {
		t.Fatal("oversized fact accepted")
	}
}

func TestLoaderOmission(t *testing.T) {
	t.Cleanup(SetLoaderOmissionForTest(func() string { return "" }))
	stock := func(path string) ([]byte, error) {
		if path == selfDomain {
			return []byte("<kernel>"), nil
		}
		return []byte(stockLine), nil
	}

	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"enabled", "CONFIG_SECURITY_TOMOYO=y\nCONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y\n", true},
		{"disabled", "CONFIG_SECURITY_TOMOYO=y\n# CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER is not set\n", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config")
			if err := os.WriteFile(p, []byte(tc.text), 0o600); err != nil {
				t.Fatal(err)
			}
			got, _ := loaderOmission([]string{p + "-missing", p}, kernelconfig.Read)
			if (got == p) != tc.want {
				t.Fatalf("source=%q, want enabled=%t", got, tc.want)
			}
			omittedLoader = func() string {
				source, _ := loaderOmission([]string{p + "-missing", p}, kernelconfig.Read)
				return source
			}
			err := Check(stock)
			if (err != nil) != tc.want {
				t.Fatalf("held-open decision: %v, want refusal=%t", err, tc.want)
			}
			if tc.want && (!strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y")) {
				t.Fatal(err)
			}

		})
	}
	missing := filepath.Join(t.TempDir(), "missing")
	omittedLoader = func() string { source, _ := loaderOmission([]string{missing}, kernelconfig.Read); return source }
	if got := omittedLoader(); got != "" {
		t.Fatal(got)
	}
	if err := Check(stock); err != nil {
		t.Fatalf("unreadable configuration changed the decision: %v", err)
	}

}

func TestLoaderOmissionCache(t *testing.T) {
	for _, tc := range []struct {
		name       string
		readableAt int
		enabled    bool
		unameFails bool
		wantReads  int
		wantRefuse []bool
	}{
		{"unreadable then enabled", 2, true, false, 6, []bool{false, true, true}},
		{"unreadable twice", 0, false, false, 6, []bool{false, false}},
		{"readable without option", 1, false, false, 3, []bool{false, false}},
		{"uname fails proc readable", 1, true, true, 1, []bool{true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, round := 0, 0
			load := newLoaderOmission(func(u *unix.Utsname) error {
				if tc.unameFails {
					return errors.New("uname failed")
				}
				copy(u.Release[:], "test")
				return nil
			}, func(path string) (map[string]bool, bool) {
				reads++
				if tc.unameFails && path != "/proc/config.gz" {
					t.Fatalf("uname failure tried release-dependent path %s", path)
				}
				if tc.readableAt == 0 || round < tc.readableAt {
					return nil, false
				}
				// The last candidate proves all candidates are retried after an unreadable result.
				if !tc.unameFails && path != "/lib/modules/test/config" {
					return nil, false
				}
				return map[string]bool{"CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER": tc.enabled}, true
			})
			t.Cleanup(SetLoaderOmissionForTest(load))
			for i, want := range tc.wantRefuse {
				round = i + 1
				err := Check(func(path string) ([]byte, error) {
					if path == selfDomain {
						return []byte("<kernel>"), nil
					}
					return []byte(stockLine), nil
				})
				if (err != nil) != want {
					t.Errorf("check %d: %v, want refusal %t", round, err, want)
				}
			}
			if reads != tc.wantReads {
				t.Errorf("configuration reads = %d, want %d", reads, tc.wantReads)
			}
		})
	}
}
