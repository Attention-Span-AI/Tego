// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"os"
	"slices"
	"testing"
)

// TestParseStatusCreds reads the four lines RunAs is decided by, and refuses a status file that lacks one
// or garbles one rather than reading its ids as zero, which is root.
func TestParseStatusCreds(t *testing.T) {
	const status = "Name:\tpython3\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\n" +
		"Uid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\n" +
		"FDSize:\t64\nGroups:\t27 4 1000 \nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n" +
		"CapEff:\t0000000000000400\nCapBnd:\t000001ffffffffff\n"
	got, err := ParseStatusCreds([]byte(status))
	if err != nil {
		t.Fatal(err)
	}
	want := TaskCreds{EUID: 1001, FSUID: 1003, EGID: 2001, FSGID: 2003, Groups: []uint32{4, 27, 1000}, CapEff: 0x400}
	if !got.Equal(want) {
		t.Errorf("parsed %+v, want %+v", got, want)
	}
	empty, err := ParseStatusCreds([]byte("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapEff:\t0\n"))
	if err != nil || len(empty.Groups) != 0 {
		t.Errorf("no supplementary groups: %+v, %v", empty, err)
	}
	for name, bad := range map[string]string{
		"no Uid line":     "Gid:\t0\t0\t0\t0\nGroups:\t\nCapEff:\t0\n",
		"no CapEff line":  "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\n",
		"no Groups line":  "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0\n",
		"a short Uid":     "Uid:\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapEff:\t0\n",
		"a garbled Gid":   "Uid:\t0\t0\t0\t0\nGid:\t0\tx\t0\t0\nGroups:\t\nCapEff:\t0\n",
		"a garbled group": "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t1 -2\nCapEff:\t0\n",
		"a garbled cap":   "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapEff:\tzz\n",
	} {
		if _, err := ParseStatusCreds([]byte(bad)); !errors.Is(err, ErrCredentials) {
			t.Errorf("%s: err = %v, want ErrCredentials", name, err)
		}
	}
}

// TestRunAsOwnCredentialsRunsInline: the common tier-1 case, where the task is the same user as this
// process, changes nothing and needs no thread of its own.
func TestRunAsOwnCredentialsRunsInline(t *testing.T) {
	own, err := ReadTaskCreds(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	if err := RunAs(own, func() { ran = true }); err != nil || !ran {
		t.Fatalf("RunAs(own credentials) = %v, ran %v", err, ran)
	}
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Errorf("recovered %v, want fn's own panic re-raised on the caller", p)
			}
		}()
		_ = RunAs(own, func() { panic("boom") })
	}()
}

// TestRunAsRefusesWhatItCannotTake: without CAP_SETUID a thread cannot take another user's ids, and fn
// must then never run — the caller's fallback is a refusal, not a connect made as this process.
func TestRunAsRefusesWhatItCannotTake(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can take any ids; the refusal is the unprivileged path")
	}
	own, err := ReadTaskCreds(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	other := own
	other.EUID, other.FSUID = own.EUID+1, own.FSUID+1
	ran := false
	if err := RunAs(other, func() { ran = true }); !errors.Is(err, ErrCredentials) || ran {
		t.Errorf("RunAs(another uid) = %v, ran %v; want ErrCredentials and fn not run", err, ran)
	}
	odd := own
	odd.FSUID = own.EUID + 1 // an fsuid apart from the euid is not reproduced
	if err := RunAs(odd, func() { ran = true }); !errors.Is(err, ErrCredentials) || ran {
		t.Errorf("RunAs(fsuid != euid) = %v, ran %v; want ErrCredentials and fn not run", err, ran)
	}
	// This process is untouched either way: the thread that failed is gone, not returned to the pool.
	after, err := ReadTaskCreds(os.Getpid())
	if err != nil || !after.Equal(own) || !slices.Equal(after.Groups, own.Groups) {
		t.Errorf("process credentials after a failed RunAs = %+v (%v), want %+v", after, err, own)
	}
}
