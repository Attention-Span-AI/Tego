// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestParseLockInfo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want LockInfo
		ok   bool
	}{
		{"round trip", "4321 990000000\n", LockInfo{PID: 4321, StartBootNS: 990000000}, true},
		{"no terminator", "7 8", LockInfo{PID: 7, StartBootNS: 8}, true},
		{"extra spaces", "  7   8  \n", LockInfo{PID: 7, StartBootNS: 8}, true},
		{"empty", "", LockInfo{}, false},
		{"torn", "4321 99", LockInfo{PID: 4321, StartBootNS: 99}, true},
		{"truncated to one field", "4321", LockInfo{}, false},
		{"three fields", "1 2 3", LockInfo{PID: 1, StartBootNS: 2, PIDNS: 3}, true},
		{"four fields", "1 2 3 4", LockInfo{}, false},
		{"bad namespace", "1 2 x", LockInfo{}, false},
		{"zero pid", "0 1", LockInfo{}, false},
		{"negative pid", "-1 1", LockInfo{}, false},
		{"not a number", "x y", LockInfo{}, false},
		{"overflowing start", "1 99999999999999999999999", LockInfo{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseLockInfo([]byte(tc.in))
			if tc.ok != (err == nil) {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
			if tc.ok && got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if !tc.ok && !errors.Is(err, ErrLockInfo) {
				t.Fatalf("error %v does not wrap ErrLockInfo", err)
			}
		})
	}
}

// Also pins runtime-launch.md E21: the lock file's format is frozen, so either binary's stop reads either
// run's lock.
func TestLockInfoStringRoundTrip(t *testing.T) {
	want := LockInfo{PID: 12345, StartBootNS: 987654321000}
	got, err := ParseLockInfo([]byte(want.String()))
	if err != nil || got != want {
		t.Fatalf("round trip got %+v err %v, want %+v", got, err, want)
	}
}

func FuzzParseLockInfo(f *testing.F) {
	for _, s := range []string{"1 2\n", "", "  ", "1", "1 2 3", "9999999999999999999999 1", "\x00\x00"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := ParseLockInfo(b)
		if err == nil && info.PID <= 0 {
			t.Fatalf("accepted pid %d", info.PID)
		}
	})
}

func TestParseStartBootNSRealProcess(t *testing.T) {
	ns, err := StartBootNS(os.Getpid())
	if err != nil {
		t.Fatalf("StartBootNS: %v", err)
	}
	if ns == 0 {
		t.Fatal("this process started at boot nanosecond 0")
	}
	if _, err := StartBootNS(-1); err == nil {
		t.Fatal("a negative pid has no /proc entry")
	}
}

func openRun(t *testing.T, root, id string) *ledger.Writer {
	t.Helper()
	dir := filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "tester"},
		ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	return w
}

// nopAnchor keeps tests out of the host-wide chain.log.
type nopAnchor struct{}

func (nopAnchor) Append(string, string) error       { return nil }
func (nopAnchor) Head(string) (string, bool, error) { return "", false, nil }

// Also pins runtime-launch.md I1: "live" is defined only as the lock being held.
func TestProbeLockHeldAndFree(t *testing.T) {
	root := t.TempDir()
	id := "r-00000000-000000000000a-aaaaaa"
	w := openRun(t, root, id)
	dir := filepath.Join(root, id)
	if err := writeLockInfo(w, LockInfo{PID: os.Getpid(), StartBootNS: 7}); err != nil {
		t.Fatalf("write lock info: %v", err)
	}
	// R1/R12: the probe blocks against the holder even inside the holder's own process, because
	// flock is per open file description — the sweep needs no self-exclusion.
	held, info, err := ProbeLock(dir)
	if err != nil || !held {
		t.Fatalf("held=%v err=%v, want held", held, err)
	}
	if info.PID != os.Getpid() || info.StartBootNS != 7 {
		t.Fatalf("info %+v", info)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("close: %v", err)
	}
	held, info, err = ProbeLock(dir)
	if err != nil || held {
		t.Fatalf("held=%v err=%v, want free", held, err)
	}
	if info.PID != os.Getpid() {
		t.Fatalf("the lock file keeps its content after release: %+v", info)
	}
}

func TestProbeLockMissingFile(t *testing.T) {
	held, info, err := ProbeLock(t.TempDir())
	if err != nil || held || info != (LockInfo{}) {
		t.Fatalf("held=%v info=%+v err=%v, want a free, empty probe", held, info, err)
	}
}

func TestStopMarker(t *testing.T) {
	dir := t.TempDir()
	if StopRequested(dir) {
		t.Fatal("a fresh run has no stop marker")
	}
	if err := RequestStop(dir); err != nil {
		t.Fatalf("RequestStop: %v", err)
	}
	if !StopRequested(dir) {
		t.Fatal("the marker is the signal")
	}
	if err := RequestStop(dir); !errors.Is(err, ErrStopRequested) {
		t.Fatalf("second RequestStop: %v, want ErrStopRequested", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != "."+StopRequestFile+".lock" || entries[1].Name() != StopRequestFile {
		t.Fatalf("only the marker and persistent publication lock should remain: %v", entries)
	}
}

// A user who owns the ledger root can plant <run>/lock, flock it and write another process's pid and start time
// there (both are world-readable). A privileged stop must not signal that process: it does not hold the lock.
func TestOpenStopTargetRefusesAPidThatDoesNotHoldTheLock(t *testing.T) {
	victim := exec.Command("/bin/sleep", "30")
	if err := victim.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	t.Cleanup(func() { _ = victim.Process.Kill(); _ = victim.Wait() })
	vstart, err := StartBootNS(victim.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f, err := os.OpenFile(lockPath(dir), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenStopTarget(dir, victim.Process.Pid, vstart); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("the victim named in a planted lock line: %v, want ErrNotLockHolder", err)
	}
	if _, err := OpenStopTarget(dir, victim.Process.Pid, 0); !errors.Is(err, ErrStale) {
		t.Fatalf("a lock line with start time 0: %v, want ErrStale", err)
	}

	// The real holder (this process) is accepted.
	self, err := StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	target, err := OpenStopTarget(dir, os.Getpid(), self)
	if err != nil {
		t.Fatalf("the process holding the lock: %v", err)
	}
	_ = target.Close()
}

// caller's names a pid this process cannot interpret; it is ErrNotLockHolder, never ErrStale (which stop
// reads as "not running" and the sweep as a dead launcher).
func TestOpenStopTargetForRefusesAnotherPidNamespace(t *testing.T) {
	own := ownPIDNS()
	if own == 0 {
		t.Skip("no /proc/self/ns/pid")
	}
	// A pid no process has here and a start time nothing matches: only the namespace can make this not stale.
	info := LockInfo{PID: 4194000, StartBootNS: 1, PIDNS: own + 1}
	if _, err := OpenStopTargetFor(t.TempDir(), info); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("foreign pid namespace: %v, want ErrNotLockHolder", err)
	}
	info.PIDNS = own
	if _, err := OpenStopTargetFor(t.TempDir(), info); !errors.Is(err, ErrStale) {
		t.Fatalf("same namespace, gone pid: %v, want ErrStale", err)
	}
	if got := (LockInfo{PID: 1, StartBootNS: 2, PIDNS: 3}).String(); got != "1 2 3\n" {
		t.Fatalf("String %q", got)
	}
}
