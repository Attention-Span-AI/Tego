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
				if path == profile {
					return nil, os.ErrPermission // the unprivileged thread: no profile proof (the rows below it are tier landlock's)
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
			_, err := check(read, tc.source)
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
		if path == profile {
			return nil, os.ErrPermission
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
		if _, err := check(read, ""); (err == nil) != wantPass {
			t.Fatalf("check %d = %v, want pass %t", i, err, wantPass)
		}
	}
	// Each check reads its facts afresh: the update line and the domain once each, and the profile once for each moved counter.
	if reads[selfDomain] != 6 || reads[stat] != 6 || reads[profile] != 1 {
		t.Fatalf("facts cached: %v", reads)
	}
}

func TestReadFileRejectsOversizedFact(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fact")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", limit+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(p, false); err == nil {
		t.Fatal("oversized fact accepted")
	}
}

func TestLoaderOmission(t *testing.T) {
	t.Cleanup(SetLoaderOmissionForTest(func() string { return "" }))
	stock := func(path string) ([]byte, error) {
		if path == selfDomain {
			return []byte("<kernel>"), nil
		}
		if path == profile {
			return nil, os.ErrPermission
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
					if path == profile {
						return nil, os.ErrPermission
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

// SEC08b: the profile proof. A counter an unprivileged process moved (a program started as /sbin/modprobe in a mount
// namespace of its own makes a domain) refuses every held open on the machine at the stateless check; a thread that can
// read TOMOYO's profile (root in the initial user namespace: the root tiers) admits one when the whole profile between two
// reads of the update line has nothing enforcing.
var (
	movedLine = fmt.Sprintf("Policy %-30s %10d (Last: 2026/11/19 12:00:00)\n", "update:", 3)
)

const (
	// The kernel's own text for the stock policy: one namespace, profiles 0 and 1.
	stockProfile = "PROFILE_VERSION=20150505\n" +
		"0-COMMENT=-----Disabled Mode-----\n" +
		"0-PREFERENCE={ max_audit_log=1024 max_learning_entry=2048 }\n" +
		"0-CONFIG={ mode=disabled grant_log=no reject_log=yes }\n" +
		"1-COMMENT=-----Learning Mode-----\n" +
		"1-PREFERENCE={ max_audit_log=1024 max_learning_entry=2048 }\n" +
		"1-CONFIG={ mode=learning grant_log=no reject_log=yes }\n" +
		"1-CONFIG::file::execute={ mode=permissive grant_log=yes reject_log=no }\n"
)

// profileRead is a read hook of a machine whose first update line is stat1 and whose later ones are stat2, whose
// profile is prof (profileErr when set, with prof's bytes too), and whose domain is "<kernel>". reads counts each path.
func profileRead(stat1, stat2, prof string, profileErr error, reads map[string]int) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		reads[path]++
		switch path {
		case selfDomain:
			return []byte("<kernel>"), nil
		case profile:
			return []byte(prof), profileErr
		case stat:
			if reads[stat] == 1 {
				return []byte(stat1), nil
			}
			return []byte(stat2), nil
		}
		return nil, os.ErrNotExist
	}
}

// TestProfileProofAdmitsNothingEnforced: a moved counter with a profile that enforces nothing is admitted, with the
// profile read once, between two reads of the update line, and the domain never read. Before the proof every one of
// these refused. A never-updated line with the loader omitted from the build is admitted the same way.
func TestProfileProofAdmitsNothingEnforced(t *testing.T) {
	for _, tc := range []struct{ name, prof, stat, source string }{
		{"empty policy", "PROFILE_VERSION=0\n", movedLine, ""},
		{"disabled, learning and permissive", stockProfile, movedLine, ""},
		{"two namespaces", "<kernel> PROFILE_VERSION=20150505\n<kernel> 0-CONFIG={ mode=disabled grant_log=no reject_log=yes }\n" +
			"<ns2> PROFILE_VERSION=20150505\n<ns2> 3-CONFIG::file={ mode=learning grant_log=no reject_log=no }\n", movedLine, ""},
		{"a comment that names the enforcing mode", "PROFILE_VERSION=20150505\n0-COMMENT=0-CONFIG={\\040mode=enforcing\\040}\n" +
			"0-COMMENT=mode=enforcing\n0-CONFIG={ mode=permissive grant_log=no reject_log=no }\n", movedLine, ""},
		{"the loader omitted, never updated", stockProfile, stockLine, "/boot/config-test"},
		{"the loader omitted, moved", stockProfile, movedLine, "/boot/config-test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := map[string]int{}
			via, err := check(profileRead(tc.stat, tc.stat, tc.prof, nil, reads), tc.source)
			if err != nil || !via {
				t.Fatalf("check = %v, %v; want admitted by the profile proof", via, err)
			}
			if reads[stat] != 2 || reads[profile] != 1 || reads[selfDomain] != 0 {
				t.Errorf("reads %v, want the update line twice around one read of the profile and no domain", reads)
			}
		})
	}
	// The exported Check and CheckVia say the same.
	if via, err := CheckVia(profileRead(movedLine, movedLine, stockProfile, nil, map[string]int{})); err != nil || !via {
		t.Errorf("CheckVia = %v, %v", via, err)
	}
	if err := Check(profileRead(movedLine, movedLine, stockProfile, nil, map[string]int{})); err != nil {
		t.Errorf("Check = %v", err)
	}
	// A never-updated machine is the stateless proof, and says so.
	if via, err := check(profileRead(stockLine, stockLine, stockProfile, nil, map[string]int{}), ""); err != nil || via {
		t.Errorf("the never-updated line: %v, %v; want the stateless proof, not the profile's", via, err)
	}
}

// TestProfileProofRefusesEnforcing: the mode enforcing anywhere in the profile refuses: the default config, a category, an
// operation, and a second namespace's, however the lines around it read.
func TestProfileProofRefusesEnforcing(t *testing.T) {
	enforcing := "mode=enforcing grant_log=no reject_log=yes"
	for name, prof := range map[string]string{
		"default config":   stockProfile + "2-CONFIG={ " + enforcing + " }\n",
		"category":         stockProfile + "1-CONFIG::file={ " + enforcing + " }\n",
		"operation":        stockProfile + "1-CONFIG::file::open={ " + enforcing + " }\n",
		"second namespace": "<kernel> PROFILE_VERSION=20150505\n<kernel> 0-CONFIG={ mode=disabled grant_log=no reject_log=yes }\n<ns2> PROFILE_VERSION=20150505\n<ns2> 0-CONFIG::network::inet_stream_connect={ " + enforcing + " }\n",
		"after a comment":  "PROFILE_VERSION=20150505\n0-COMMENT=x\n" + "0-CONFIG={ " + enforcing + " }\n",
		"the first line":   "PROFILE_VERSION=20150505\n0-CONFIG={ " + enforcing + " }\n" + stockProfile[len("PROFILE_VERSION=20150505\n"):],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := check(profileRead(movedLine, movedLine, prof, nil, map[string]int{}), "")
			if err == nil || !strings.Contains(err.Error(), "enforces") || !strings.Contains(err.Error(), "refused on this machine") {
				t.Fatalf("check = %v, want a refusal naming the enforcing profile", err)
			}
		})
	}
}

// TestProfileProofStrictGrammar: a profile this check does not fully parse refuses, whatever it says: unknown keys and
// modes, a carriage return or other control byte, a missing closing brace, a line with no text of the kernel's printed
// forms, a missing trailing line break or version line, an oversized profile, and data that came with an error.
func TestProfileProofStrictGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, prof string
		err        error
	}{
		{name: "unknown key", prof: stockProfile + "1-CONFIG={ mode=learning grant_log=no reject_log=yes extra=1 }\n"},
		{name: "unknown mode", prof: stockProfile + "1-CONFIG={ mode=ignoring grant_log=no reject_log=yes }\n"},
		{name: "upper-case mode", prof: stockProfile + "1-CONFIG={ mode=Enforcing grant_log=no reject_log=yes }\n"},
		{name: "CR", prof: stockProfile + "1-COMMENT=x\r\n"},
		{name: "NUL", prof: stockProfile + "1-COMMENT=x\x00y\n"},
		{name: "tab", prof: stockProfile + "1-COMMENT=x\ty\n"},
		{name: "non-ASCII", prof: stockProfile + "1-COMMENT=é\n"},
		{name: "missing closing brace", prof: stockProfile + "1-CONFIG={ mode=learning grant_log=no reject_log=yes\n"},
		{name: "missing opening brace", prof: stockProfile + "1-CONFIG= mode=learning grant_log=no reject_log=yes }\n"},
		{name: "unknown line", prof: stockProfile + "NOT-A-LINE\n"},
		{name: "blank line", prof: stockProfile + "\n"},
		{name: "text after the brace", prof: stockProfile + "1-CONFIG={ mode=learning grant_log=no reject_log=yes } x\n"},
		{name: "spaces between the tokens", prof: stockProfile + "1-CONFIG={ mode=learning  grant_log=no reject_log=yes }\n"},
		{name: "a namespace with no line", prof: stockProfile + "<ns2>\n"},
		{name: "a bad namespace", prof: stockProfile + "<ns2 0-COMMENT=x\n"},
		{name: "missing line break", prof: strings.TrimSuffix(stockProfile, "\n")},
		{name: "no version line", prof: "0-COMMENT=x\n"},
		{name: "empty", prof: ""},
		{name: "oversized", prof: stockProfile + strings.Repeat("x", limit)},
		{name: "data with an error", prof: stockProfile, err: errors.New("short read")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			via, err := check(profileRead(movedLine, movedLine, tc.prof, tc.err, map[string]int{}), "")
			if err == nil || via {
				t.Fatalf("check = %v, %v; want a refusal", via, err)
			}
		})
	}
}

// statSeqRead is a read hook whose n-th read of the update line is stats[n-1] (the last one for every later read), whose
// profile is stockProfile, and whose domain is "<kernel>". reads counts each path.
func statSeqRead(stats []string, reads map[string]int) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		reads[path]++
		switch path {
		case selfDomain:
			return []byte("<kernel>"), nil
		case profile:
			return []byte(stockProfile), nil
		case stat:
			n := reads[stat]
			if n > len(stats) {
				n = len(stats)
			}
			return []byte(stats[n-1]), nil
		}
		return nil, os.ErrNotExist
	}
}

func movingLine(n int) string {
	return fmt.Sprintf("Policy %-30s %10d (Last: 2026/11/19 12:00:%02d)\n", "update:", 3+n, n%60)
}

// TestProfileProofBracket: the update line is read again after the profile and must be byte-equal to the first, its
// (Last:) stamp included: a profile written between the two reads moves it. The whole proof is then tried again, from a
// fresh first read, up to three times, and the open is refused when no attempt was clean.
func TestProfileProofBracket(t *testing.T) {
	old := retryPause
	t.Cleanup(func() { retryPause = old })
	retryPause = 0
	moving := make([]string, 12)
	stamp := make([]string, 12)
	for i := range moving {
		moving[i] = movingLine(i)
		stamp[i] = fmt.Sprintf("Policy %-30s %10d (Last: 2026/11/19 12:00:%02d)\n", "update:", 3, i) // only the stamp moves
	}
	for name, tc := range map[string]struct {
		stats []string
		src   string
	}{
		"the counter moves on every read": {moving, ""},
		"only the stamp moves":            {stamp, ""},
		"never updated, then moving":      {append([]string{stockLine}, moving...), "/boot/config-test"}, // the loader omission is what makes a never-updated line need the proof
	} {
		t.Run(name, func(t *testing.T) {
			reads := map[string]int{}
			_, err := check(statSeqRead(tc.stats, reads), tc.src)
			if err == nil || !strings.Contains(err.Error(), "changed while its profile was read") || !strings.Contains(err.Error(), "in each of 3 attempts") {
				t.Fatalf("check = %v, want the bracket's refusal after 3 attempts", err)
			}
			if reads[stat] != 6 || reads[profile] != 3 {
				t.Errorf("reads %v, want three whole proofs (6 update lines, 3 profiles)", reads)
			}
		})
	}
	// A line that stops being a line is refused too: the retry reads it first and finds no update line.
	_, err := check(statSeqRead([]string{movedLine, strings.TrimSuffix(movedLine, "\n")}, map[string]int{}), "")
	if err == nil || !strings.Contains(err.Error(), "missing or malformed Policy update: line") {
		t.Fatalf("an unterminated second line: %v", err)
	}
	// An error on the second read refuses too, with no second attempt.
	reads := map[string]int{}
	read := profileRead(movedLine, movedLine, stockProfile, nil, reads)
	_, err = check(func(path string) ([]byte, error) {
		if path == stat && reads[stat] >= 1 {
			reads[stat]++
			return nil, os.ErrPermission
		}
		return read(path)
	}, "")
	if err == nil || !strings.Contains(err.Error(), "tomoyo/stat") || reads[profile] != 1 {
		t.Fatalf("an unreadable second update line: %v (reads %v)", err, reads)
	}
}

// TestProfileProofRetriesAMovedBracket: a counted update between the two reads of the update line (a learning-mode
// machine counts every ACL entry it learns) costs one attempt, not the open: the next whole proof, from a fresh first
// read, admits it, on the second or the third try, with each attempt's reads counted. Before, one miss refused.
func TestProfileProofRetriesAMovedBracket(t *testing.T) {
	old := retryPause
	t.Cleanup(func() { retryPause = old })
	retryPause = 0
	a, b, c, d := movingLine(1), movingLine(2), movingLine(3), movingLine(4)
	for name, tc := range map[string]struct {
		stats    []string
		attempts int
	}{
		"clean at once":   {[]string{a, a}, 1},
		"clean at second": {[]string{a, b, b}, 2},
		"clean at third":  {[]string{a, b, c, d, d}, 3},
	} {
		t.Run(name, func(t *testing.T) {
			reads := map[string]int{}
			via, err := check(statSeqRead(tc.stats, reads), "")
			if err != nil || !via {
				t.Fatalf("check = %v, %v; want the proof to admit", via, err)
			}
			if reads[profile] != tc.attempts {
				t.Errorf("reads %v, want %d whole proofs", reads, tc.attempts)
			}
		})
	}
}

// TestReadFileNeedsSecurityfs: every TOMOYO fact is read from a descriptor that sits on securityfs, so a file shown at
// the same path by a mount namespace of its own is refused, and one on securityfs is not.
func TestReadFileNeedsSecurityfs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "profile")
	if err := os.WriteFile(p, []byte("PROFILE_VERSION=20150505\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(p); err == nil || !strings.Contains(err.Error(), "is not on securityfs") {
		t.Fatalf("a file that is not on securityfs: %v", err)
	}
	if b, err := readBounded(p, false); err != nil || len(b) == 0 {
		t.Fatalf("the bounded reader without the check: %q, %v", b, err)
	}
	// A reader that serves other modules' files too holds only TOMOYO's to securityfs.
	tmp, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tmp.Close() }()
	if err := CheckFact("/sys/kernel/security/tomoyo/profile", tmp); err == nil || !strings.Contains(err.Error(), "is not on securityfs") {
		t.Errorf("a TOMOYO fact on another filesystem: %v", err)
	}
	for _, other := range []string{"/proc/self/attr/current", "/sys/kernel/security/lsm", "/sys/kernel/security/apparmor/.ns_level"} {
		if err := CheckFact(other, tmp); err != nil {
			t.Errorf("%s is not a TOMOYO fact: %v", other, err)
		}
	}
	f, err := os.Open("/sys/kernel/security/lsm")
	if err != nil {
		t.Skipf("no securityfs to hold the control against: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := CheckSecurityfs(f); err != nil {
		t.Errorf("a securityfs file: %v", err)
	}
	if _, err := ReadFile("/sys/kernel/security/lsm"); err != nil {
		t.Errorf("ReadFile of a securityfs file: %v", err)
	}
}

// TestProfileUnreadableKeepsRefusal: a thread that cannot read the profile (tier landlock, the invoking user) keeps the
// counter's refusal, today's words with the sentence that says what a root tier can do; any other failure to read it adds
// the cause. Neither changes the answer a machine with a moved counter always gave, and the domain is read as before.
func TestProfileUnreadableKeepsRefusal(t *testing.T) {
	reads := map[string]int{}
	_, err := check(profileRead(movedLine, movedLine, "", os.ErrPermission, reads), "")
	if err == nil || !strings.Contains(err.Error(), updatedMessage) ||
		!strings.Contains(err.Error(), "a root tier can prove nothing is enforced, and this tier cannot read TOMOYO's profile") {
		t.Fatalf("EACCES: %v", err)
	}
	if reads[selfDomain] != 1 {
		t.Errorf("reads %v: the refusal reads the domain as before", reads)
	}
	_, err = check(profileRead(movedLine, movedLine, "", errors.New("input/output error"), map[string]int{}), "")
	if err == nil || !strings.Contains(err.Error(), updatedMessage) || !strings.Contains(err.Error(), "its profile could not be read (TOMOYO /sys/kernel/security/tomoyo/profile: input/output error)") {
		t.Fatalf("EIO: %v", err)
	}
	// The loader omission's message keeps its words and gains the sentence.
	_, err = check(profileRead(stockLine, stockLine, "", os.ErrPermission, map[string]int{}), "/boot/config-test")
	if err == nil || !strings.Contains(err.Error(), "CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER=y") || !strings.Contains(err.Error(), "this tier cannot read TOMOYO's profile") {
		t.Fatalf("loader omission, unreadable profile: %v", err)
	}
	// A bad domain keeps its place in the order: it is the first thing a thread that cannot prove anything is told.
	_, err = check(func(path string) ([]byte, error) {
		if path == selfDomain {
			return []byte("<kernel> /usr/bin/tego"), nil
		}
		return profileRead(movedLine, movedLine, "", os.ErrPermission, map[string]int{})(path)
	}, "")
	if err == nil || !strings.Contains(err.Error(), `TOMOYO observed domain "<kernel> /usr/bin/tego"`) {
		t.Fatalf("a changed domain: %v", err)
	}
}
