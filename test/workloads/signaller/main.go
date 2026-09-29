// SPDX-License-Identifier: Apache-2.0

// Command signaller is a workload for the signal scope below Landlock ABI 6 (supervisor R33): it starts its
// first argument with "30", kills it through os.Process.Kill (pidfd_send_signal when the runtime's pidfd
// probe succeeds, kill(2) when it does not), spins long enough for the Go runtime to preempt it with tgkill,
// and prints "ok" when the child died of the signal.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

func main() {
	cmd := exec.Command(os.Args[1], "30")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr // no /dev/null: it is not writable here
	if err := cmd.Start(); err != nil {
		fmt.Println("start:", err)
		os.Exit(1)
	}
	if err := cmd.Process.Kill(); err != nil {
		fmt.Println("kill:", err)
		os.Exit(1)
	}
	err := cmd.Wait()
	done := make(chan struct{})
	go func() {
		for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
		}
		close(done)
	}()
	runtime.Gosched()
	<-done
	if ee, ok := err.(*exec.ExitError); ok && !ee.Exited() {
		fmt.Println("ok")
		return
	}
	fmt.Println("wait:", err)
}
