// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
)

// uidStatus is a status file with the four uids given: real, effective, saved, filesystem.
func uidStatus(real, effective, saved, fsuid uint32) []byte {
	return []byte(fmt.Sprintf("Name:\tMARKER_SECRET\nUid:\t%d\t%d\t%d\t%d\nNSpid:\t10\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n", real, effective, saved, fsuid))
}

// basicProcesses reads a one-process fake /proc as the basic scan would, with proc's owner (the effective uid) and the
// contents given, and the names of every file it read.
func basicProcesses(t *testing.T, owner uint32, status []byte, statusErr error) (processSnapshot, []string) {
	t.Helper()
	return basicProcessesAs(t, uint32(os.Getuid()), owner, status, statusErr)
}

// basicProcessesAs is basicProcesses for a caller of the given uid.
func basicProcessesAs(t *testing.T, caller, owner uint32, status []byte, statusErr error) (processSnapshot, []string) {
	t.Helper()
	root := t.TempDir()
	processFixture(t, root, 10, 1, 100, "/bin/claude", []byte("claude\x00"), 0)
	writeProcFile(t, root, "10/status", status)
	fs, e := openProc(root)
	if e != nil {
		t.Fatal(e)
	}
	defer fs.close()
	var read []string
	spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{},
		ownerHook: func(int, uint32, error) (uint32, error) { return owner, nil },
		hook: func(_ int, name string, _ int, b []byte, e error) ([]byte, error) {
			read = append(read, name)
			if name == "status" && statusErr != nil {
				return nil, statusErr
			}
			return b, e
		}}
	return readProcesses(context.Background(), spy, root, caller, catalog.Rows()), read
}

// A process of another user is skipped after its uid line alone: no stat, cmdline, exe, cgroup or cwd.
func TestOtherUIDOwnerReadsOnlyTheUIDLine(t *testing.T) {
	other := uint32(os.Getuid() + 1)
	got, read := basicProcesses(t, other, uidStatus(other, other, other, other), nil)
	if got.Unknown || got.OtherUID != 1 || got.Read != 0 || len(got.UnreadablePIDs) != 0 || len(got.Processes) != 0 {
		t.Fatalf("other owner: %+v", got)
	}
	if len(read) != 1 || read[0] != "status" {
		t.Fatalf("other owner's process content read: %v", read)
	}
}

// A process the scan cannot attribute to one uid is uncertainty, whoever owns its proc directory. Before this, an
// owner that was neither the caller nor root made the process "other uid" without a look at its real uid, so a
// setuid program run by the caller (real uid the caller's, proc owner the file's owner) was silently absent.
func TestMixedUIDProcessIsUncertain(t *testing.T) {
	me, other, third := uint32(os.Getuid()), uint32(os.Getuid()+1), uint32(os.Getuid()+2)
	for _, tc := range []struct {
		name    string
		owner   uint32
		uids    [4]uint32
		wantOne string // "other" (skipped as another user's), "uncertain", or "own"
	}{
		{"setuid copy: real mine, effective, saved and fs another's", other, [4]uint32{me, other, other, other}, "uncertain"},
		{"proc owner another's while every uid is mine", other, [4]uint32{me, me, me, me}, "uncertain"},
		{"real another's, effective mine", me, [4]uint32{other, me, me, me}, "uncertain"},
		{"saved uid mine only", other, [4]uint32{other, other, me, other}, "uncertain"},
		{"fs uid mine only", other, [4]uint32{other, other, other, me}, "uncertain"},
		{"saved uid differs, owner mine", me, [4]uint32{me, me, other, me}, "uncertain"},
		{"two other users, none mine", third, [4]uint32{other, third, third, other}, "other"},
		{"all another's", other, [4]uint32{other, other, other, other}, "other"},
		{"all mine", me, [4]uint32{me, me, me, me}, "own"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := basicProcesses(t, tc.owner, uidStatus(tc.uids[0], tc.uids[1], tc.uids[2], tc.uids[3]), nil)
			switch tc.wantOne {
			case "uncertain":
				found := false
				for _, s := range got.Sources {
					found = found || s.State == "not-read" && s.Reason == "owner" && s.Critical
				}
				if !got.Unknown || got.OtherUID != 0 || !found {
					t.Fatalf("mixed uid not counted as uncertainty: unknown %v other %d sources %+v", got.Unknown, got.OtherUID, got.Sources)
				}
			case "other":
				if got.Unknown || got.OtherUID != 1 {
					t.Fatalf("another user's process: %+v", got)
				}
			case "own":
				if got.Unknown || got.OtherUID != 0 || got.Read != 1 {
					t.Fatalf("own process: %+v", got)
				}
			}
		})
	}
}

// A directory of another user whose uid line cannot be read cannot be attributed either (hidepid=1 denies it).
func TestForeignOwnerWithUnreadableUIDLineIsUncertain(t *testing.T) {
	other := uint32(os.Getuid() + 1)
	got, _ := basicProcesses(t, other, uidStatus(other, other, other, other), syscall.EACCES)
	if !got.Unknown || got.OtherUID != 0 {
		t.Fatalf("unreadable foreign status counted absent: %+v", got)
	}
}

// The check's exit: a scan that cannot attribute one process answers 125 ("unknown"), also when unrelated own
// processes would make it 3, since unknown outranks the unreadable-program answer.
func TestMixedUIDProcessMakesTheCheck125(t *testing.T) {
	me, other := uint32(os.Getuid()), uint32(os.Getuid()+1)
	for _, tc := range []struct {
		name string
		uids [4]uint32
		want int
	}{{"attributable", [4]uint32{me, me, me, me}, 0}, {"mixed", [4]uint32{other, me, me, me}, 125}} {
		t.Run(tc.name, func(t *testing.T) {
			o := commandOptions(t)
			o.Check = true
			for _, outside := range []string{"20", "30"} {
				if err := os.RemoveAll(fmt.Sprintf("%s/%s", o.ProcRoot, outside)); err != nil {
					t.Fatal(err)
				}
			}
			processFixture(t, o.ProcRoot, 40, 1, 400, "/bin/sleep", []byte("sleep\x00"), 0)
			writeProcFile(t, o.ProcRoot, "40/status", uidStatus(tc.uids[0], tc.uids[1], tc.uids[2], tc.uids[3]))
			s := Collect(t.Context(), o).Snapshot
			if s.ExitCode() != tc.want {
				t.Fatalf("exit %d check %s", s.ExitCode(), s.Check)
			}
		})
	}
}

// Root reads every process, so a process root can attribute only by its effective uid is judged like any other. This
// is sudo itself (a setuid-root program: real uid the login's, effective root, proc owner root) and su: the parent of
// every `sudo tego scan`. Counting it uncertain made every ordinary root scan end at exit 125.
func TestRootCallerJudgesAMixedProcessItCanRead(t *testing.T) {
	login := uint32(1000)
	for _, tc := range []struct {
		name  string
		owner uint32
		uids  [4]uint32
		want  string // "own" (judged), "uncertain"
	}{
		{"sudo: real the login's, effective, saved and fs root, proc owner root", 0, [4]uint32{login, 0, 0, 0}, "own"},
		{"saved uid the login's, proc owner root", 0, [4]uint32{0, 0, login, 0}, "own"},
		{"real root, effective the login's: proc owner the login's, not judged", login, [4]uint32{0, login, login, login}, "uncertain"},
		{"saved root only, proc owner the login's", login, [4]uint32{login, login, 0, login}, "uncertain"},
		{"all the login's", login, [4]uint32{login, login, login, login}, "other"},
		{"all root", 0, [4]uint32{0, 0, 0, 0}, "own"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := basicProcessesAs(t, 0, tc.owner, uidStatus(tc.uids[0], tc.uids[1], tc.uids[2], tc.uids[3]), nil)
			switch tc.want {
			case "uncertain":
				if !got.Unknown || got.OtherUID != 0 {
					t.Fatalf("unjudgeable process not uncertain: %+v", got)
				}
			case "other":
				if got.Unknown || got.OtherUID != 1 {
					t.Fatalf("another user's process: %+v", got)
				}
			case "own":
				if got.Unknown || got.OtherUID != 0 || got.Read != 1 {
					t.Fatalf("root's own process not judged: %+v", got)
				}
			}
		})
	}
}

// A mixed process root can read is judged by its program: one that is an agent is listed, not dropped.
func TestRootCallerListsAMixedAgentProcess(t *testing.T) {
	got, _ := basicProcessesAs(t, 0, 0, uidStatus(1000, 0, 0, 0), nil)
	if got.Unknown || got.Read != 1 {
		t.Fatalf("%+v", got)
	}
	if len(got.Processes) != 1 {
		t.Fatalf("the agent program of a mixed process was dropped: %+v", got)
	}
}

// For a caller that is not root, a mixed process whose proc owner and effective uid are both root is root's process:
// a setuid-root program (sudo, su) run from the login runs that program's code, not the login's. Basic scope skips
// root's processes as another user's, and so does it here. A mixed process whose effective uid is another non-root
// user's stays uncertain (the setuid copy), and so does one root's effective uid does not explain.
func TestNonRootCallerSkipsMixedProcessRootOwns(t *testing.T) {
	me, other := uint32(os.Getuid()), uint32(os.Getuid()+1)
	if me == 0 {
		t.Skip("the caller of this case is not root")
	}
	for _, tc := range []struct {
		name  string
		owner uint32
		uids  [4]uint32
		want  string // "other" (root's, skipped), "uncertain", "own"
	}{
		{"sudo: real mine, effective, saved and fs root, proc owner root", 0, [4]uint32{me, 0, 0, 0}, "other"},
		{"effective and saved root, fs uid mine, proc owner root", 0, [4]uint32{me, 0, 0, me}, "other"},
		{"effective root with the saved uid still mine", 0, [4]uint32{me, 0, me, 0}, "other"},
		{"effective root, real another user's, owner root", 0, [4]uint32{other, 0, 0, 0}, "other"},
		{"setuid copy: real mine, effective another non-root user's, owner theirs", other, [4]uint32{me, other, other, other}, "uncertain"},
		{"effective another non-root user's although owner root", 0, [4]uint32{me, other, other, other}, "uncertain"},
		{"effective root but proc owner another user's", other, [4]uint32{me, 0, 0, 0}, "uncertain"},
		{"effective mine, proc owner root", 0, [4]uint32{me, me, me, me}, "uncertain"},
		{"real root, effective mine, owner mine", me, [4]uint32{0, me, me, me}, "uncertain"},
		{"all root", 0, [4]uint32{0, 0, 0, 0}, "other"},
		{"all mine", me, [4]uint32{me, me, me, me}, "own"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, read := basicProcesses(t, tc.owner, uidStatus(tc.uids[0], tc.uids[1], tc.uids[2], tc.uids[3]), nil)
			switch tc.want {
			case "uncertain":
				if !got.Unknown || got.OtherUID != 0 {
					t.Fatalf("unattributable process not uncertain: %+v", got)
				}
			case "other":
				if got.Unknown || got.OtherUID != 1 || got.Read != 0 || len(got.UnreadablePIDs) != 0 || len(got.Processes) != 0 {
					t.Fatalf("root's process not counted as another user's: %+v", got)
				}
				if len(read) != 1 || read[0] != "status" {
					t.Fatalf("root's process content read beyond the uid line: %v", read)
				}
			case "own":
				if got.Unknown || got.OtherUID != 0 || got.Read != 1 {
					t.Fatalf("own process: %+v", got)
				}
			}
		})
	}
}
