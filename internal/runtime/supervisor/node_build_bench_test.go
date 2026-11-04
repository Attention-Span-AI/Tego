// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// These benchmarks require the exact inventoried Node 22 executable. Setup
// stays outside the timer. The cache persists across benchmark repetitions, so
// the first ExecImage sample includes a cold hash and later samples reuse it.
func nodeBenchPath(b *testing.B) string {
	b.Helper()
	p := os.Getenv("TEGO_NODE22_BIN")
	if p == "" {
		b.Skip("set TEGO_NODE22_BIN to the pinned Node 22 executable")
	}
	return p
}

func BenchmarkNodeExecImage(b *testing.B) {
	p := nodeBenchPath(b)
	q := pathQuery{tid: os.Getpid(), dirfd: atFDCWD, path: p, head: true}
	b.ReportAllocs()
	for b.Loop() {
		img, err := (sysKernel{}).ExecImage(q)
		if err != nil || img.nodeVersion != "22.21.1" {
			b.Fatalf("version=%q err=%v", img.nodeVersion, err)
		}
	}
}

// nodePoolKernel replaces only the notification transport and target bookkeeping.
// The real four-worker Loop.Run pool dispatches execve, walks the real Node fd,
// reads this process's argv with process_vm_readv, matches and records the exec.
// This excludes seccomp ioctl latency and launching Node/JavaScript itself.
type nodePoolKernel struct {
	selfKernel
	in   chan sysNotif
	out  chan sysResp
	next sysNotif // receive holds recvMu across Wait and Recv
}

func (k *nodePoolKernel) Wait(_, timeoutMS int) (waitState, error) {
	select {
	case k.next = <-k.in:
		return waitReady, nil
	case <-time.After(time.Duration(timeoutMS) * time.Millisecond):
		return waitTimeout, nil
	}
}

func (k *nodePoolKernel) Recv(n *sysNotif) error { *n = k.next; return nil }
func (k *nodePoolKernel) Send(r *sysResp) error  { k.out <- *r; return nil }
func (k *nodePoolKernel) ExecImage(q pathQuery) (execImage, error) {
	q.tid = os.Getpid() // the four synthetic target tids share this real address space/root
	return k.sys.ExecImage(q)
}

// An op is a batch of four simultaneous exec notifications, including all four
// responses. Batch size stays four even when GOMAXPROCS or b.N changes.
func BenchmarkNodeSupervisorPool4(b *testing.B) {
	p := nodeBenchPath(b)
	k := &nodePoolKernel{selfKernel: selfKernel{fakeKernel: newFake()}, in: make(chan sysNotif, 4), out: make(chan sysResp, 4)}
	l, err := New(testListener(), commandPolicy(b, "deny: b.js"), discardSink{}, Options{kernel: k, Workers: 4})
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	<-l.Armed()
	b.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			b.Error(err)
		}
	})
	e := newLiveExec(p, []string{"node", "a.js"})
	n := e.notif(nrFor(b, "execve"))
	b.ReportAllocs()
	for b.Loop() {
		for i := range 4 {
			k.in <- sysNotif{ID: uint64(i + 1), Pid: uint32(n.pid + i), Data: sysData(n.nr, n.args[:]...)}
		}
		for range 4 {
			r := <-k.out
			if r.Error != 0 || r.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE {
				b.Fatalf("exec response: %+v (want %s)", r, record.VerdictAllow)
			}
		}
	}
	runtime.KeepAlive(e)
}
