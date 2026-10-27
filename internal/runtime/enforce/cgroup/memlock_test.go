// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFdinfoMemlockTellsAReportedZeroFromNone is ADR 0022 (8)'s memlock_unreported: an fdinfo whose "memlock:" line
// says 0 (an empty LPM trie on 6.x: tego_net_cidr, tego_net_ingress, tego_unix_names) reports 0, and only an fdinfo
// with no such line, or one that holds no number, leaves the object's memlock unreported.
func TestFdinfoMemlockTellsAReportedZeroFromNone(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		fdinfo   string
		n        uint64
		reported bool
	}{
		{"pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1063\nmap_type:\t11\nkey_size:\t20\nvalue_size:\t4\n" +
			"max_entries:\t1024\nmap_flags:\t0x1\nmap_extra:\t0x0\nmemlock:\t0\nmap_id:\t40\nfrozen:\t0\n", 0, true},
		{"pos:\t0\nmap_type:\t1\nmemlock:\t4096\nmap_id:\t41\n", 4096, true},
		{"prog_type:\t8\nprog_jited:\t1\nprog_tag:\tabc\nmemlock:\t8192\nprog_id:\t7\n", 8192, true},
		{"pos:\t0\nmap_type:\t11\nmap_id:\t42\n", 0, false},
		{"memlock:\tmany\n", 0, false},
		{"", 0, false},
	} {
		n, reported := fdinfoMemlock(strings.NewReader(c.fdinfo))
		if n != c.n || reported != c.reported {
			t.Errorf("fdinfoMemlock(%q) = %d, %v; want %d, %v", c.fdinfo, n, reported, c.n, c.reported)
		}
	}
}

// TestReadFdinfoReadsTheLentNumbersOwnFdinfo is the lend rule mapObject and programObject keep (ADR 0023): procfs
// looks a number up in the descriptor table each time its fdinfo is read, not when the fdinfo is opened, so the whole
// read must run while the number is lent. The test lends a pipe's write end, then puts a read-only /dev/null at its
// number (dup2), as a reuse after the lend would. An fdinfo opened before the reuse and read after it, as an earlier
// fix
// read the memlock, describes /dev/null: that is the premise, and the test fails if procfs ever resolves the
// number at open. readFdinfo has read the fdinfo before it returns, and what it read is the write end's O_WRONLY.
func TestReadFdinfoReadsTheLentNumbersOwnFdinfo(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	w := p[1]
	defer func() { _ = unix.Close(p[0]); _ = unix.Close(w) }()
	opened, err := os.Open(fdinfoDir + strconv.Itoa(w))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	inside := -1
	if err := readFdinfo(w, func(r io.Reader) { inside = fdinfoAccess(t, r) }); err != nil {
		t.Fatalf("readFdinfo: %v", err)
	}
	if inside < 0 {
		t.Fatal("readFdinfo returned without having handed the fdinfo to its reader")
	}
	null, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.Dup2(null, w)
	_ = unix.Close(null)
	if err != nil {
		t.Fatal(err)
	}
	if after := fdinfoAccess(t, opened); after != unix.O_RDONLY {
		t.Fatalf("premise: an fdinfo opened before its number was reused and read after says access mode %#o, not the "+
			"new file's O_RDONLY, so procfs resolved the number at open", after)
	}
	if inside != unix.O_WRONLY {
		t.Errorf("readFdinfo read access mode %#o for the lent write end, not O_WRONLY", inside)
	}
}

// fdinfoAccess is the access mode (O_ACCMODE) of an fdinfo's "flags:" line, an octal number.
func fdinfoAccess(t *testing.T, r io.Reader) int {
	t.Helper()
	s := bufio.NewScanner(r)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "flags:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 8, 32)
			if err != nil {
				t.Fatalf("the fdinfo's flags line %q: %v", v, err)
			}
			return int(n) & unix.O_ACCMODE
		}
	}
	t.Fatalf("the fdinfo has no flags line (%v)", s.Err())
	return 0
}
