// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// statLine builds a stat line with comm and the field-22 starttime a test wants; the filler fields
// are the shape proc(5) documents, so the field offsets are exercised for real.
func statLine(pid int, comm string, ppid int, threads int, start uint64) string {
	tail := make([]string, 0, 50)
	add := func(vs ...string) { tail = append(tail, vs...) }
	add("S", itoa(ppid), "10", "10", "0", "-1", "4194304") // 3..9
	add("100", "0", "0", "0", "5", "6", "0", "0")          // 10..17
	add("20", "0", itoa(threads), "0", utoa(start))        // 18..22
	for i := 23; i <= 52; i++ {
		add("0")
	}
	return itoa(pid) + " (" + comm + ") " + strings.Join(tail, " ") + "\n"
}

func itoa(n int) string    { return strconv.Itoa(n) }
func utoa(n uint64) string { return strconv.FormatUint(n, 10) }

func TestParseStat(t *testing.T) {
	cases := []struct {
		name string
		line string
		want Stat
		err  bool
	}{
		{"plain", statLine(42, "python3", 7, 3, 1234), Stat{PID: 42, Comm: "python3", State: 'S', PPID: 7, Pgrp: 10, StartTicks: 1234, NumThreads: 3, Flags: 4194304}, false},
		{"comm with spaces and parens", statLine(9, "my (odd) name", 1, 1, 5), Stat{PID: 9, Comm: "my (odd) name", State: 'S', PPID: 1, Pgrp: 10, StartTicks: 5, NumThreads: 1, Flags: 4194304}, false},
		{"comm with a close paren last", statLine(9, "a)b", 1, 1, 5), Stat{PID: 9, Comm: "a)b", State: 'S', PPID: 1, Pgrp: 10, StartTicks: 5, NumThreads: 1, Flags: 4194304}, false},
		{"exiting: PF_EXITING in the flags", strings.Replace(statLine(9, "a", 1, 1, 5), " 4194304 ", " 4194308 ", 1), Stat{PID: 9, Comm: "a", State: 'S', PPID: 1, Pgrp: 10, StartTicks: 5, NumThreads: 1, Flags: 4194308}, false},
		{"non-numeric flags", strings.Replace(statLine(9, "a", 1, 1, 5), " 4194304 ", " x ", 1), Stat{}, true},
		{"no parens", "42 python3 S 1\n", Stat{}, true},
		{"unclosed comm", "42 (python3 S 1\n", Stat{}, true},
		{"non-numeric pid", "x (a) S 1 2 3\n", Stat{}, true},
		{"negative pid", statLine(-1, "a", 1, 1, 5), Stat{}, true},
		{"truncated tail", "42 (a) S 1\n", Stat{}, true},
		{"empty", "", Stat{}, true},
		{"only a paren", ")", Stat{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseStat([]byte(tc.line))
			if tc.err {
				if err == nil {
					t.Fatalf("ParseStat(%q) = %+v, want an error", tc.line, got)
				}
				if !errors.Is(err, ErrStat) {
					t.Fatalf("error %v does not wrap ErrStat", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStat(%q): %v", tc.line, err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestStartBootNSAndSameProcess(t *testing.T) {
	s := Stat{StartTicks: 7}
	if got := s.StartBootNS(); got != 7*NanosPerTick {
		t.Errorf("StartBootNS = %d", got)
	}
	cases := []struct {
		name string
		a, b uint64
		want bool
	}{
		{"identical", 100, 100, true},
		{"within one tick", 0, NanosPerTick - 1, true},
		{"within one tick reversed", NanosPerTick - 1, 0, true},
		{"exactly one tick apart", 0, NanosPerTick, false},
		{"pid reuse seconds later", 1_000_000_000, 5_000_000_000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SameProcess(tc.a, tc.b); got != tc.want {
				t.Errorf("SameProcess(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestParseCgroup(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"unified", "0::/user.slice/user-1000.slice/session-2.scope\n", "/user.slice/user-1000.slice/session-2.scope"},
		{"unified after v1 lines", "12:pids:/user.slice\n1:name=systemd:/user.slice\n0::/tego/run-1\n", "/tego/run-1"},
		{"path with a colon", "0::/a:b/c\n", "/a:b/c"},
		{"v1 only", "12:pids:/user.slice\n1:name=systemd:/x\n", ""},
		{"controllers set on hierarchy 0", "0:pids:/x\n", ""},
		{"no newline at end", "0::/x", "/x"},
		{"garbage", "not a cgroup file", ""},
		{"empty", "", ""},
		{"single colon", "0:\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseCgroup([]byte(tc.in)); got != tc.want {
				t.Errorf("ParseCgroup(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseArgv(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"three args", "python3\x00-m\x00pytest\x00", []string{"python3", "-m", "pytest"}},
		{"no trailing NUL", "python3\x00-m", []string{"python3", "-m"}},
		{"single", "sh\x00", []string{"sh"}},
		{"empty blob", "", nil},
		{"all NULs", "\x00\x00", []string{"", ""}},
		{"empty trailing arguments", "a\x00\x00\x00", []string{"a", "", ""}},
		{"empty middle argument", "a\x00\x00b\x00", []string{"a", "", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseArgv([]byte(tc.in)); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseArgv(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseMaps(t *testing.T) {
	in := strings.Join([]string{
		"55d0d9c00000-55d0d9c21000 r--p 00000000 fd:01 1310724                    /usr/bin/python3.12",
		"7f0a1c000000-7f0a1c021000 rw-p 00000000 00:00 0 ",
		"7f0a1d000000-7f0a1d200000 r-xp 00000000 fd:01 1311000                    /usr/lib/x86_64-linux-gnu/libssl.so.3",
		"7f0a1e000000-7f0a1e200000 r-xp 00000000 fd:01 1311000                    /usr/lib/x86_64-linux-gnu/libssl.so.3",
		"7f0a1f000000-7f0a1f200000 r-xp 00000000 fd:01 9                          /tmp/gone.so (deleted)",
		"7ffd0f000000-7ffd0f021000 rw-p 00000000 00:00 0                          [stack]",
		"7f0a20000000-7f0a20200000 r-xp 00000000 fd:01 10                         /opt/a b/lib.so",
		"truncated",
	}, "\n")
	want := []string{"/opt/a b/lib.so", "/usr/bin/python3.12", "/usr/lib/x86_64-linux-gnu/libssl.so.3"}
	if got := ParseMaps([]byte(in)); !reflect.DeepEqual(got, want) {
		t.Errorf("ParseMaps = %q, want %q", got, want)
	}
	if got := ParseMaps(nil); len(got) != 0 {
		t.Errorf("ParseMaps(nil) = %q", got)
	}
}

func FuzzParseStat(f *testing.F) {
	f.Add(statLine(1, "systemd", 0, 1, 12))
	f.Add("1 (a) S 0 0 0 0 0")
	f.Add(")(")
	f.Add(statLine(1, "x", 0, 1, 18446744073709551615))
	f.Fuzz(func(t *testing.T, line string) {
		s, err := ParseStat([]byte(line))
		if err != nil {
			if !errors.Is(err, ErrStat) {
				t.Fatalf("ParseStat(%q) = %v, which is not ErrStat", line, err)
			}
			return
		}
		if s.PID < 0 || s.PPID < 0 || s.NumThreads < 0 {
			t.Fatalf("negative pid, ppid or thread count from %q: %+v", line, s)
		}
		// StartBootNS multiplied without a bound, so a starttime past 2^64/1e7 ticks wrapped to a small time and read as
		// another process's start.
		if s.StartBootNS()/NanosPerTick != s.StartTicks {
			t.Fatalf("starttime %d ticks wraps to %d ns", s.StartTicks, s.StartBootNS())
		}
	})
}

// FuzzParseCgroup: the unified path is one line's own, the rest of a "0::" line, and reads back as itself.
func FuzzParseCgroup(f *testing.F) {
	f.Add("0::/x\n")
	f.Add("0:")
	f.Add("12:pids:/a\n0::/user.slice/a:b\n")
	f.Fuzz(func(t *testing.T, in string) {
		p := ParseCgroup([]byte(in))
		if p == "" {
			return
		}
		if strings.Contains(p, "\n") || !strings.Contains(in, "0::"+p) {
			t.Fatalf("ParseCgroup(%q) = %q, which is not the rest of one 0:: line", in, p)
		}
		if again := ParseCgroup([]byte("0::" + p + "\n")); again != p {
			t.Fatalf("ParseCgroup(%q) = %q, but that path alone reads as %q", in, p, again)
		}
	})
}

// FuzzParseArgv: the arguments hold no NUL and, joined by NULs, are the blob without its final terminator.
func FuzzParseArgv(f *testing.F) {
	f.Add("a\x00b\x00")
	f.Add("\x00\x00")
	f.Add("unterminated")
	f.Fuzz(func(t *testing.T, in string) {
		argv := ParseArgv([]byte(in))
		if in == "" {
			if argv != nil {
				t.Fatalf("an empty blob gave %q, want nil", argv)
			}
			return
		}
		for _, a := range argv {
			if strings.Contains(a, "\x00") {
				t.Fatalf("ParseArgv(%q) holds an argument with a NUL: %q", in, argv)
			}
		}
		if got, want := strings.Join(argv, "\x00"), strings.TrimSuffix(in, "\x00"); got != want {
			t.Fatalf("ParseArgv(%q) = %q, which joins back to %q", in, argv, got)
		}
	})
}

// FuzzParseMaps: the paths are sorted, distinct, absolute, not deleted, one line's rest each, and a maps blob
// written from them reads back as the same paths.
func FuzzParseMaps(f *testing.F) {
	f.Add("55d0-55d1 r--p 0 fd:01 1 /usr/bin/x\n")
	f.Add("1-2 r--p 0 0:0 0 /a b (deleted)\n1-2 r--p 0 0:0 0\t/with\ttabs\n1-2 r--p 0 0:0 0 [heap]\n")
	f.Fuzz(func(t *testing.T, in string) {
		paths := ParseMaps([]byte(in))
		var blob strings.Builder
		for i, p := range paths {
			if p == "" || p[0] != '/' || strings.Contains(p, "\n") || strings.HasSuffix(p, " (deleted)") ||
				(i > 0 && paths[i-1] >= p) || !strings.Contains(in, p) {
				t.Fatalf("ParseMaps(%q) = %q: %q is not a sorted, distinct, live mapping path of the blob", in, paths, p)
			}
			blob.WriteString("1-2 r--p 0 00:00 0 " + p + "\n")
		}
		if again := ParseMaps([]byte(blob.String())); !reflect.DeepEqual(again, paths) {
			t.Fatalf("ParseMaps(%q) = %q, but those paths written out read as %q", in, paths, again)
		}
	})
}
