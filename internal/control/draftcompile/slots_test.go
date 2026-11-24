// SPDX-License-Identifier: Apache-2.0
package draftcompile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// A child must keep its reservation after the spawning helper drops its copy.
// New helper images then see the same two-child bound until those children exit: a governed program's check does;
// a person's own check is admitted on the one slot kept for it.
func TestCompilerReservationsSurviveParentRelease(t *testing.T) {
	ctx := WithPool(context.Background(), fmt.Sprintf("test-%d-%s", os.Getpid(), t.Name()))
	var stop []func()
	for range 2 {
		lease, err := compilerLease(WithGoverned(ctx), time.Now().Add(AdmissionWait)) // the shared slots
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/proc/self/exe", Argument)
		cmd.Stdin = bytes.NewBufferString(`{"Text":"c3RhbGw="}`)
		cmd.Stderr = lease
		err = cmd.Start()
		_ = lease.Close()
		if err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		cleanup := func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) }
		stop = append(stop, cleanup)
		t.Cleanup(cleanup)
	}
	_, err := Check(WithGoverned(ctx), Request{})
	if err == nil || !strings.Contains(err.Error(), "busy, try again") {
		t.Fatalf("inherited reservations did not bound a fresh governed check: %v", err)
	}
	if _, err = Check(ctx, Request{}); err == nil || !strings.Contains(err.Error(), "no machine config") {
		t.Fatalf("a person's check was not admitted on the reserved slot while the shared ones were held: %v", err)
	}
	for _, cleanup := range stop {
		cleanup()
	}
	_, err = Check(WithGoverned(ctx), Request{})
	if err == nil || !strings.Contains(err.Error(), "no machine config") {
		t.Fatalf("reaped reservation did not recover: %v", err)
	}
}
