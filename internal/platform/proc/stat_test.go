// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"fmt"
	"io/fs"
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

// releasedStatLine is the line fs/proc/array.c's do_task_stat writes for a task released (release_task) after the
// read took a reference to it and before the read took its sighand lock (torvalds/linux 1d4ee94a51bd,
// fs/proc/array.c:474-475 and 518-541): __exit_signal set task->sighand to NULL, so lock_task_sighand fails and
// ppid 0, pgid -1, sid -1, tty_nr 0, tty_pgrp -1 and num_threads 0 keep the values they were declared with. The
// state was read before the lock (array.c:491), so it is whatever the task was then. The mm is gone (exit_mm), so
// vsize, rss and the code and data addresses are 0, rsslim 0, and the signal masks are empty. Fields as
// array.c:588-662 prints them, 52 in all.
func releasedStatLine(pid int, comm string, state byte, start uint64) string {
	tail := []string{
		string(state), "0", "-1", "-1", "0", "-1", "4194308", // 3..9: state ppid pgrp session tty_nr tpgid flags
		"120", "0", "0", "0", "3", "1", "0", "0", // 10..17: faults and times
		"20", "0", "0", "0", utoa(start), // 18..22: priority nice num_threads itrealvalue starttime
		"0", "0", "0", "0", "0", "0", "0", "0", // 23..30: vsize rss rsslim code stack esp eip
		"0", "0", "0", "0", "0", "0", "0", // 31..37: signal masks, wchan, nswap, cnswap
		"17", "3", "0", "0", "0", "0", "0", // 38..44: exit_signal cpu rt_priority policy blkio gtime cgtime
		"0", "0", "0", "0", "0", "0", "0", "0", // 45..52: data, brk, arg, env, exit_code
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
		{"plain", statLine(42, "python3", 7, 3, 1234), Stat{PID: 42, Comm: "python3", State: 'S', PPID: 7, Pgrp: 10, Session: 10, StartTicks: 1234, NumThreads: 3, Flags: 4194304}, false},
		{"comm with spaces and parens", statLine(9, "my (odd) name", 1, 1, 5), Stat{PID: 9, Comm: "my (odd) name", State: 'S', PPID: 1, Pgrp: 10, Session: 10, StartTicks: 5, NumThreads: 1, Flags: 4194304}, false},
		{"comm with a close paren last", statLine(9, "a)b", 1, 1, 5), Stat{PID: 9, Comm: "a)b", State: 'S', PPID: 1, Pgrp: 10, Session: 10, StartTicks: 5, NumThreads: 1, Flags: 4194304}, false},
		{"exiting: PF_EXITING in the flags", strings.Replace(statLine(9, "a", 1, 1, 5), " 4194304 ", " 4194308 ", 1), Stat{PID: 9, Comm: "a", State: 'S', PPID: 1, Pgrp: 10, Session: 10, StartTicks: 5, NumThreads: 1, Flags: 4194308}, false},
		{"non-numeric flags", strings.Replace(statLine(9, "a", 1, 1, 5), " 4194304 ", " x ", 1), Stat{}, true},
		{"no parens", "42 python3 S 1\n", Stat{}, true},
		{"unclosed comm", "42 (python3 S 1\n", Stat{}, true},
		{"non-numeric pid", "x (a) S 1 2 3\n", Stat{}, true},
		{"negative pid", statLine(-1, "a", 1, 1, 5), Stat{}, true},
		{"pid zero", statLine(0, "a", 1, 1, 5), Stat{}, true},
		{"process group -1 of a live task", strings.Replace(statLine(9, "a", 1, 1, 5), " 1 10 10 ", " 1 -1 10 ", 1), Stat{}, true},
		{"session -1 of a live task", strings.Replace(statLine(9, "a", 1, 1, 5), " 1 10 10 ", " 1 10 -1 ", 1), Stat{}, true},
		{"session -2", strings.Replace(statLine(9, "a", 1, 1, 5), " 1 10 10 ", " 1 10 -2 ", 1), Stat{}, true},
		{"non-numeric session", strings.Replace(statLine(9, "a", 1, 1, 5), " 1 10 10 ", " 1 10 x ", 1), Stat{}, true},
		{"non-numeric tty", strings.Replace(statLine(9, "a", 1, 1, 5), " 10 10 0 -1 ", " 10 10 x -1 ", 1), Stat{}, true},
		{"process group -2", strings.Replace(releasedStatLine(9, "a", 'X', 5), " -1 -1 0 -1 ", " -2 -1 0 -1 ", 1), Stat{}, true},
		{"reaped shape with a thread", strings.Replace(releasedStatLine(9, "a", 'X', 5), " 0 0 5 ", " 1 0 5 ", 1), Stat{}, true},
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

// deThreadStatLine is a line a reader on kernel 6.17 caught for a LIVE process: a thread other than the leader
// of pid 842314 ran execve in a loop, and de_thread released the old leader while the read held it. It has the
// released shape (releasedStatLine), state Z and exit_signal (field 38) -1. The process ran on under the same pid
// and start time, and no read of it got ENOENT (measured in review on 2026-11-11 with a pread loop).
const deThreadStatLine = "842314 (exe) Z 0 -1 -1 0 -1 4228108 40251 0 0 0 4 27 0 0 20 0 0 0 82606841 0 0 0 0 0 0 0 " +
	"0 0 0 0 0 1 0 0 -1 6 0 0 0 0 0 0 0 0 0 0 0 0 0\n"

// TestParseStatOfAReleasedTask: a task released while its stat was read is printed with process group -1
// (releasedStatLine). One line cannot say whether the process is gone: the kernel writes it for a process reaped
// during the read and for a live one whose old leader an execve released (deThreadStatLine). ParseStat answers
// ErrStat and ErrReleased, never ErrGone, so a caller that does not read again fails closed.
func TestParseStatOfAReleasedTask(t *testing.T) {
	lines := []string{deThreadStatLine}
	for _, state := range []byte{'X', 'Z', 'R', 'S'} {
		lines = append(lines, releasedStatLine(4242, "a (b) c", state, 900))
	}
	for _, line := range lines {
		if n := len(strings.Fields(line[strings.LastIndexByte(line, ')')+1:])); n != 50 {
			t.Fatalf("%q has %d fields after the comm, want 50 (fields 3..52)", line, n)
		}
		s, err := ParseStat([]byte(line))
		if !errors.Is(err, ErrStat) || !errors.Is(err, ErrReleased) || errors.Is(err, ErrGone) {
			t.Fatalf("ParseStat(%q) = %+v, %v; want ErrStat and ErrReleased, not ErrGone", line, s, err)
		}
	}
}

// reads is a stat file that answers each read with the next of its results, and the last one after that.
type reads struct {
	lines []string
	errs  []error
	n     int
}

func (r *reads) read() ([]byte, error) {
	i := min(r.n, len(r.lines)-1)
	r.n++
	if r.errs[i] != nil {
		return nil, r.errs[i]
	}
	return []byte(r.lines[i]), nil
}

// TestReadStatReadsAReleasedLineAgain: ReadStat decides a released line by the next read. A process that is gone
// is read's own error (ENOENT here, which FS.Stat answers ErrGone); a live process mid-exec is its next line; a
// line that stays released through every read is returned, and ParseStat refuses it (ErrStat).
func TestReadStatReadsAReleasedLineAgain(t *testing.T) {
	released := releasedStatLine(842314, "exe", 'Z', 82606841)
	live := statLine(842314, "exe", 842312, 1, 82606841)
	enoent := fmt.Errorf("open /proc/842314/stat: %w", fs.ErrNotExist)
	for _, c := range []struct {
		name  string
		lines []string
		errs  []error
		want  string
		err   error
		reads int
	}{
		{"live", []string{live}, []error{nil}, live, nil, 1},
		{"reaped", []string{released, ""}, []error{nil, enoent}, "", enoent, 2},
		{"a live process mid-exec", []string{deThreadStatLine, live}, []error{nil, nil}, live, nil, 2},
		{"released on every read", []string{released}, []error{nil}, released, nil, statReads},
		{"gone at once", []string{""}, []error{enoent}, "", enoent, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &reads{lines: c.lines, errs: c.errs}
			b, err := ReadStat(r.read)
			if string(b) != c.want || !errors.Is(err, c.err) || (c.err == nil) != (err == nil) || r.n != c.reads {
				t.Fatalf("ReadStat = %q, %v after %d reads; want %q, %v after %d", b, err, r.n, c.want, c.err, c.reads)
			}
		})
	}
}

// TestParseStatReadsSessionAndTTY: fields 6 and 7, the session and the controlling terminal (tty_nr, 0 for none),
// which the supervisor's tty class reads (heldTTY).
func TestParseStatReadsSessionAndTTY(t *testing.T) {
	line := strings.Replace(statLine(9, "a", 1, 1, 5), " 1 10 10 0 -1 ", " 1 10 9 34817 10 ", 1)
	s, err := ParseStat([]byte(line))
	if err != nil || s.Session != 9 || s.TTY != 34817 {
		t.Fatalf("ParseStat(%q) = %+v, %v; want session 9 and tty 34817", line, s, err)
	}
}

// TestReadParsedStat: ReadParsedStat is ReadStat and then ParseStat. A released line read again is the live line
// that follows it; one that stays released is ErrStat and ErrReleased; read's own error comes back unchanged.
func TestReadParsedStat(t *testing.T) {
	released := releasedStatLine(842314, "exe", 'Z', 82606841)
	live := statLine(842314, "exe", 842312, 1, 82606841)
	enoent := fmt.Errorf("open /proc/842314/stat: %w", fs.ErrNotExist)
	s, err := ReadParsedStat((&reads{lines: []string{deThreadStatLine, live}, errs: []error{nil, nil}}).read)
	if err != nil || s.PPID != 842312 || s.StartTicks != 82606841 {
		t.Fatalf("mid-exec: ReadParsedStat = %+v, %v; want the live line", s, err)
	}
	if _, err := ReadParsedStat((&reads{lines: []string{released}, errs: []error{nil}}).read); !errors.Is(err, ErrStat) || !errors.Is(err, ErrReleased) {
		t.Fatalf("released on every read: ReadParsedStat = %v; want ErrStat and ErrReleased", err)
	}
	if _, err := ReadParsedStat((&reads{lines: []string{released, ""}, errs: []error{nil, enoent}}).read); !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrStat) {
		t.Fatalf("reaped: ReadParsedStat = %v; want read's ENOENT", err)
	}
}

// TestStatOfAReleasedTask: FS.Stat, and so every FS reader built on it, reads a released line again. A file that
// keeps it is ErrStat, never ErrGone: no read said the process is gone.
func TestStatOfAReleasedTask(t *testing.T) {
	f := fakeProc(t, 4242, map[string]string{"stat": releasedStatLine(4242, "agent", 'X', 900)}, nil)
	if _, err := f.Stat(4242); !errors.Is(err, ErrStat) || errors.Is(err, ErrGone) {
		t.Fatalf("Stat(released) = %v, want ErrStat and not ErrGone", err)
	}
	if _, err := f.Identity(4242); !errors.Is(err, ErrStat) || errors.Is(err, ErrGone) {
		t.Fatalf("Identity(released) = %v, want ErrStat and not ErrGone", err)
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
	f.Add(releasedStatLine(7, "a", 'X', 3))
	f.Add(deThreadStatLine)
	f.Fuzz(func(t *testing.T, line string) {
		s, err := ParseStat([]byte(line))
		if err != nil {
			// Every error is ErrStat, the line of a task released while it was read too: one line cannot say the
			// process is gone, so no line is ErrGone. ErrReleased marks only a line whose process group is -1.
			if !errors.Is(err, ErrStat) || errors.Is(err, ErrGone) {
				t.Fatalf("ParseStat(%q) = %v, which is not ErrStat, or is ErrGone", line, err)
			}
			if errors.Is(err, ErrReleased) {
				tail := strings.Fields(line[strings.LastIndexByte(line, ')')+1:])
				if len(tail) < 3 || tail[2] != "-1" {
					t.Fatalf("ParseStat(%q) = %v, from a line whose process group is not -1", line, err)
				}
			}
			return
		}
		if s.PID <= 0 || s.PPID < 0 || s.Pgrp < 0 || s.Session < 0 || s.NumThreads < 0 {
			t.Fatalf("a pid of 0 or below, or a negative ppid, process group, session or thread count from %q: %+v", line, s)
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
