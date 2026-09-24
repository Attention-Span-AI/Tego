// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails this package's tests when one leaves behind a goroutine the runtime can prove is leaked
// (testutil.LeakCheckMain): the recorder's ring drain must end with the run that started it. Started with
// leaderExitsEnv set, the test binary is instead the helper process of TestIntegrationExitIsTheThreadGroups.
// The binary fails, too, when anything in the invoking user's real ~/.tego or ~/.bash_history changed while the tests
// ran (testutil.GuardedLeakCheckMain, tools/isocheck GO-4): its tests import internal/runtime, which can start a run,
// a sweep or a gc in-process.
func TestMain(m *testing.M) {
	if marker := os.Getenv(leaderExitsEnv); marker != "" {
		leaderExitsFirst(marker)
	}
	if d, err := time.ParseDuration(os.Getenv(sleepEnv)); err == nil {
		time.Sleep(d) // TestIntegrationRelativeExecIsResolved's program: alive while the recorder reads its cwd
		os.Exit(0)
	}
	os.Exit(testutil.GuardedLeakCheckMain(m))
}

// leaderExitsEnv names the file the helper process reads once its thread-group leader has exited.
const leaderExitsEnv = "TEGO_OBSERVE_LEADER_EXITS_FIRST"

// sleepEnv makes the test binary a process that sleeps this long and exits.
const sleepEnv = "TEGO_OBSERVE_SLEEP"

// init locks the main goroutine to the thread it runs on, the process's first thread, its thread-group leader,
// when this binary is the helper: an init function runs there, and the lock is what lets leaderExitsFirst end
// that thread and no other.
func init() {
	if os.Getenv(leaderExitsEnv) != "" {
		runtime.LockOSThread()
	}
}

// leaderExitsFirst is a process whose thread-group leader exits while another thread goes on: the leader
// thread ends with exit(2), which ends one thread, and a goroutine on another thread reads marker 300 ms later
// and then ends the process with exit_group(2). The helper runs with GOGC=off, so no collection waits on the
// leader's goroutine, which the runtime still counts as running.
func leaderExitsFirst(marker string) {
	started := make(chan struct{})
	go func() {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = os.ReadFile(marker)
		os.Exit(0)
	}()
	<-started // the goroutine runs on another thread: this one is locked to the main goroutine
	_, _, _ = unix.RawSyscall(unix.SYS_EXIT, 0, 0, 0)
}
