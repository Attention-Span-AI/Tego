// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/watch/sig"
)

func statFixture(pid, ppid int, start uint64, tty int64, comm string) []byte {
	fields := []string{"S", fmt.Sprint(ppid), "0", "0", fmt.Sprint(tty)}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, fmt.Sprint(start))
	return []byte(fmt.Sprintf("%d (%s) %s\n", pid, comm, strings.Join(fields, " ")))
}

func statusFixture(uid uint32) []byte {
	return []byte(fmt.Sprintf("Name:\tMARKER_SECRET\nUid:\t%d\t%d\t%d\t%d\nNSpid:\t10\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n", uid, uid, uid, uid))
}

func TestParseStatus(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		ok   bool
		ns   int
		caps uint64
	}{
		{"selected fields", statusFixture(123), true, 1, 0},
		{"child namespace", bytes.ReplaceAll(statusFixture(123), []byte("NSpid:\t10"), []byte("NSpid:\t10\t2")), true, 2, 0},
		{"capability", bytes.Replace(statusFixture(123), []byte("CapEff:\t0000000000000000"), []byte("CapEff:\t0000000000000001"), 1), true, 1, 1},
		{"missing uid", []byte("Name:\tsecret\n"), false, 0, 0},
		{"duplicate uid", append(statusFixture(123), []byte("Uid: 1 1 1 1\n")...), false, 0, 0},
		{"short uid", []byte("Uid: 1 1 1\n"), false, 0, 0},
		{"negative uid", []byte("Uid: -1 1 1 1\n"), false, 0, 0},
		{"overflow uid", []byte("Uid: 4294967295 1 1 1\n"), false, 0, 0},
		{"truncated line", []byte("Uid: 1 1 1 1\nNSpid"), false, 0, 0},
		{"bad utf8", append(statusFixture(123), 255), false, 0, 0},
		{"oversized", bytes.Repeat([]byte{'a'}, maxProcText+1), false, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, e := parseStatus(tc.b)
			if (e == nil) != tc.ok {
				t.Fatalf("ok=%v error=%v", tc.ok, e)
			}
			if tc.ok && (v.uids != [4]uint32{123, 123, 123, 123} || v.nspids != tc.ns || v.caps != tc.caps || v.capsSeen != 4) {
				t.Fatalf("selected fields: %+v", v)
			}
		})
	}
}

func TestParseStat(t *testing.T) {
	valid := statFixture(10, 2, 123, -7, "name ) with ( spaces")
	cases := []struct {
		name string
		b    []byte
		ok   bool
	}{
		{"comm delimiters", valid, true},
		{"empty", nil, false},
		{"truncated", []byte("10 (x) S 1"), false},
		{"bad pid", bytes.Replace(valid, []byte("10 ("), []byte("-1 ("), 1), false},
		{"overflow start", bytes.Replace(valid, []byte(" 123\n"), []byte(" 18446744073709551616\n"), 1), false},
		{"bad terminal", bytes.Replace(valid, []byte("-7"), []byte("x"), 1), false},
		{"invalid utf8", append(valid, 255), false},
		{"too large", bytes.Repeat([]byte{'x'}, maxProcText+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, e := parseStat(tc.b)
			if (e == nil) != tc.ok {
				t.Fatalf("ok=%v error=%v", tc.ok, e)
			}
			if tc.ok && (v.pid != 10 || v.ppid != 2 || v.start != 123 || v.tty != -7 || v.comm != "name ) with ( spaces") {
				t.Fatalf("identity: %+v", v)
			}
		})
	}
}

func TestParseArgv(t *testing.T) {
	cases := []struct {
		name   string
		b      []byte
		ok     bool
		tokens int
	}{
		{"empty", nil, true, 0},
		{"wrapper with secrets", []byte("node\x00--key=MARKER_SECRET\x00/lib/@openai/codex/bin/codex.js\x00"), true, 3},
		{"empty token", []byte("x\x00\x00"), true, 2},
		{"partial token", []byte("claude"), false, 0},
		{"invalid utf8", []byte{'x', 0, 255, 0}, false, 0},
		{"token bound", append(bytes.Repeat([]byte{'x'}, maxProcText+1), 0), false, 0},
		{"token count", bytes.Repeat([]byte{'x', 0}, maxArgvTokens+1), false, 0},
		{"byte bound", bytes.Repeat([]byte{0}, maxArgvBytes+1), false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, e := parseArgv(tc.b)
			if (e == nil) != tc.ok || len(v) != tc.tokens {
				t.Fatalf("ok=%v tokens=%d error=%v", tc.ok, len(v), e)
			}
		})
	}
}

func TestParseCgroup(t *testing.T) {
	run := "r-0123abcd-0000000000000-abcdef"
	cases := []struct {
		name, input string
		ok          bool
		run         string
		unit        bool
	}{
		{"outside", "0::/user.slice\n", true, "", false},
		{"run", "0::/tego.slice/tego-agent.slice/run-" + run + ".scope/child\n", true, run, false},
		{"forged env irrelevant", "0::/app.slice/run-" + run + ".scope\n", true, "", false},
		{"unit", "0::/user.slice/user-123.slice/user@123.service/app.slice/test.service\n", true, "", true},
		{"other uid unit", "0::/user.slice/user-456.slice/user@456.service/app.slice/test.service\n", true, "", false},
		{"no unified", "1:cpu:/\n", false, "", false},
		{"malformed", "0:/secret", false, "", false},
		{"duplicate", "0::/\n0::/", false, "", false},
		{"relative", "0::relative", false, "", false},
		{"unclean", "0::/x/../tego.slice", false, "", false},
		{"controls", "0::/secret\r", false, "", false},
		{"oversize", "0::/" + strings.Repeat("x", maxProcText), false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, e := parseCgroup([]byte(tc.input), 123)
			if (e == nil) != tc.ok {
				t.Fatalf("ok=%v error=%v", tc.ok, e)
			}
			if tc.ok && (v.run != tc.run || v.userUnit != tc.unit) {
				t.Fatalf("membership: %+v", v)
			}
		})
	}
}

func FuzzScanStatus(f *testing.F) {
	f.Add(statusFixture(123))
	f.Add([]byte("Uid: -1 1 1 1\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseStatus(b) })
}
func FuzzScanStat(f *testing.F) {
	f.Add(statFixture(10, 2, 123, 0, "comm ) x"))
	f.Add([]byte("1 (x) S"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseStat(b) })
}
func FuzzScanCgroup(f *testing.F) {
	f.Add([]byte("0::/\n"))
	f.Add([]byte("0::/user.slice\n0::/"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseCgroup(b, 123) })
}
func FuzzScanArgvEvidence(f *testing.F) {
	f.Add([]byte("node\x00--key=MARKER_SECRET\x00/lib/@openai/codex/bin/codex.js\x00"))
	f.Add([]byte("claude"))
	f.Fuzz(func(t *testing.T, b []byte) {
		argv, e := parseArgv(b)
		if e != nil {
			return
		}
		facts := sig.Facts{Argv: argv}
		for _, r := range sig.Default() {
			fact, hit := r.Evidence(facts)
			if hit != r.Match(facts) {
				t.Fatal("selection differs")
			}
			switch fact {
			case "", sig.FactExeName, sig.FactArgv0Name, sig.FactCommName, sig.FactArgvPattern, sig.FactPath, sig.FactFileID:
			default:
				t.Fatal("input escaped fact code")
			}
		}
	})
}
