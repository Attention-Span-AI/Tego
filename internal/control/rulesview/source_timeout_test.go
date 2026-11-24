// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
)

// The helper uses an actual descriptor read which cannot return.
// Metadata for the selected regular source still answers. Copies use the real
// reader. This models the source read boundary without a host FUSE mount.
func blockSourceRead(path string) ([]byte, os.FileInfo, error) {
	exe, _ := os.Executable()
	source, err := os.ReadFile(exe + ".source-block/source")
	if err != nil || path != string(source) {
		return readRegularNoFollow(path)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	defer w.Close()
	if err := os.WriteFile(exe+".read", nil, 0600); err != nil {
		return nil, nil, err
	}
	go endWithCaller()
	b, err := io.ReadAll(r)
	return b, st, err
}

// endWithCaller ends this test worker once its caller has closed the request
// pipe. The read above never returns, and the caller neither waits for the
// worker nor kills it. Nothing else would end the process, and each worker
// left behind holds one of the uid's helper reservations on the machine that
// ran the tests.
func endWithCaller() {
	fds := []unix.PollFd{{Fd: 0, Events: unix.POLLHUP}}
	for {
		_, err := unix.Poll(fds, -1)
		if err != nil && !errors.Is(err, unix.EINTR) {
			os.Exit(125)
		}
		if err == nil && fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			os.Exit(0)
		}
	}
}

func TestInForceSourceTransportTimeoutKeepsRecordedRules(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000020-blockx")
	const secret = "timeout-copy-private-canary"
	f.startFrom(t, sourceText+"\nenv:\n  set:\n    TOKEN: "+secret+"\n", nil)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.source, []byte(sourceText), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := exe + ".source-block"
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(marker, "source"), []byte(f.source), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(marker); os.Remove(exe + ".read") })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	v := InForce(ctx, f.root, f.run, Options{Machine: f.m})
	if time.Since(started) > 4*time.Second {
		t.Fatal("transport exceeded budget")
	}
	if _, err := os.Stat(exe + ".read"); err != nil {
		t.Fatalf("source read never blocked: %v", err)
	}
	if v.Err != "" || v.Contract.Text == "" || v.Contract.Table != "" || v.View.Compiled || !strings.Contains(v.View.Text(), "Can run git") || v.Positions != PositionsCopy {
		t.Fatalf("lost recorded rules: %+v", v)
	}
	if strings.Contains(v.Contract.Text, secret) || strings.Contains(v.View.Text(), secret) || !strings.Contains(v.Contract.Text, Hidden) {
		t.Fatal("recorded fallback leaked or lost env redaction")
	}
	assertSourceUnavailable(t, v)
	if !strings.Contains(v.PositionsWhy, pathcheck.Unavailable) || v.Pending != nil {
		t.Fatalf("unsafe source trust: %+v", v)
	}
	entries, err := os.ReadDir(marker)
	if err != nil {
		t.Fatal(err)
	}
	var launchers, workers int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "launcher-") {
			launchers++
		}
		if strings.HasPrefix(e.Name(), "worker-") {
			workers++
		}
	}
	if launchers != 1 || workers != 1 {
		t.Fatalf("starts launcher=%d worker=%d", launchers, workers)
	}
	// One left behind would keep a helper reservation of this uid until someone killed it.
	if left := helperWorkersLeft(10 * time.Second); len(left) != 0 {
		t.Fatalf("test workers outlived their caller: pids %v", left)
	}
}

// helperWorkersLeft lists the helper processes of this test image that are
// still alive, after waiting up to wait for them to end. A process that has
// exited and waits to be reaped has ended: its image link no longer reads.
func helperWorkersLeft(wait time.Duration) []int {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	deadline := time.Now().Add(wait)
	for {
		var left []int
		dirs, _ := filepath.Glob("/proc/[0-9]*")
		for _, dir := range dirs {
			pid, _ := strconv.Atoi(filepath.Base(dir))
			if image, err := os.Readlink(dir + "/exe"); err != nil || image != exe || pid == os.Getpid() {
				continue
			}
			args, _ := os.ReadFile(dir + "/cmdline")
			if words := strings.Split(string(args), "\x00"); len(words) > 1 && words[1] == contracts.HelperCommand {
				left = append(left, pid)
			}
		}
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRecordedProjectionKeepsInvalidYAMLDiagnostic(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000021-badraw")
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "contract.yaml"), []byte("[broken"), 0600); err != nil {
		t.Fatal(err)
	}
	reply, err := viewCall(context.Background(), "inforce-copy", f.root, f.run, "", "", Options{Machine: f.m})
	if err != nil {
		t.Fatal(err)
	}
	if reply.InForce == nil || !strings.Contains(strings.Join(reply.InForce.View.Notes, " "), "not valid YAML") {
		t.Fatalf("lost invalid YAML diagnostic: %+v", reply.InForce)
	}
}
