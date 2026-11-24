// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

var lifecycleTestCommand func() (int, bool)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperCommand {
		if executable, err := os.Executable(); err == nil {
			if _, err := os.Stat(executable + ".traced"); err == nil {
				locationTimeout = hangGuard // a worker traced system call by system call (traceRecordedPath)
			}
		}
		if tracedByATest() { // the tracer reads /proc/<pid>/cwd and fd/N of what it follows; see tracedByATest
			makeUndumpable = func() error { return nil }
		}
		if os.Getenv(helperProbeEnv) != "" { // the real HelperMain, and what it left of the dumpable flag
			code := HelperMain([]string{"probe"})
			dumpable, err := sys.Dumpable()
			fmt.Printf("dumpable=%v err=%v code=%d\n", dumpable, err, code)
			os.Exit(code)
		}
		os.Exit(HelperMain(os.Args[2:]))
	}
	if lifecycleTestCommand != nil {
		if code, ok := lifecycleTestCommand(); ok {
			os.Exit(code)
		}
	}
	os.Exit(m.Run())
}

// tracedByATest says this process is a tracee of the test that follows its pathname system calls
// (traceRecordedPath). That tracer resolves a relative name against /proc/<pid>/cwd and /proc/<pid>/fd/<dirfd>, which
// the kernel hides from every reader without CAP_SYS_PTRACE once the process is undumpable (ptrace's own access check
// has no exception for a tracer), so the helpers it follows are the one place a test keeps them dumpable. The
// undumpable property of the real HelperMain is proved by TestContractsHelperIsUndumpable, which is not traced.
func tracedByATest() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(rest))
			return err == nil && pid != 0
		}
	}
	return false
}

func TestHelperFrameBounds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wire    []byte
		limit   uint64
		want    []byte
		wantErr bool
	}{
		{name: "empty", wire: framed(nil), limit: 0, want: []byte{}},
		{name: "at bound", wire: framed([]byte("abc")), limit: 3, want: []byte("abc")},
		{name: "over bound", wire: framed([]byte("abc")), limit: 2, wantErr: true},
		{name: "truncated header", wire: []byte{0, 0}, limit: 10, wantErr: true},
		{name: "truncated body", wire: framed([]byte("abc"))[:9], limit: 3, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readFrame(bytes.NewReader(tc.wire), tc.limit)
			if (err != nil) != tc.wantErr || (!tc.wantErr && !bytes.Equal(got, tc.want)) {
				t.Fatalf("body %q, error %v", got, err)
			}
		})
	}
	// A hostile size is refused before reading or allocating the body.
	var huge [8]byte
	binary.BigEndian.PutUint64(huge[:], ^uint64(0))
	if _, err := readFrame(bytes.NewReader(huge[:]), maxExchangeBytes); err == nil {
		t.Fatal("unbounded helper response accepted")
	}
}

func TestHelperFrameReadRequiresWholeResponse(t *testing.T) {
	_, err := readFrame(bytes.NewReader(framed([]byte("abc"))[:9]), 3)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated response error: %v", err)
	}
}

func framed(body []byte) []byte {
	var b bytes.Buffer
	if err := writeFrame(&b, body); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func TestHelperFrameShortWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		shortAt int
	}{{"header", 1}, {"body", 2}} {
		t.Run(tc.name, func(t *testing.T) {
			w := &shortFrameWriter{shortAt: tc.shortAt}
			if err := writeFrame(w, []byte("abc")); !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write error: %v", err)
			}
		})
	}
}

type shortFrameWriter struct {
	calls, shortAt int
}

func (w *shortFrameWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.shortAt {
		return len(p) - 1, nil
	}
	return len(p), nil
}

const helperStatusFixture = `Name: check
Uid: 1000 1000 1000 1000
Gid: 1000 1000 1000 1000
Groups: 1000 27
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000000000000000
CapAmb: 0000000000000000
NoNewPrivs: 0
Seccomp: 0
`

func TestHelperAuthorityRequiresCompleteStatus(t *testing.T) {
	for _, key := range []string{"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"} {
		t.Run(key, func(t *testing.T) {
			lines := strings.Split(helperStatusFixture, "\n")
			for i, line := range lines {
				if strings.HasPrefix(line, key+":") {
					lines = append(lines[:i], lines[i+1:]...)
					break
				}
			}
			if _, err := parseHelperCredentials([]byte(strings.Join(lines, "\n"))); !errors.Is(err, sys.ErrCredentials) {
				t.Fatalf("missing %s error: %v", key, err)
			}
		})
	}
	for _, tc := range []struct{ name, status string }{
		{"invalid ambient", strings.Replace(helperStatusFixture, "CapAmb: 0000000000000000", "CapAmb: nope", 1)},
		{"negative no new privs", strings.Replace(helperStatusFixture, "NoNewPrivs: 0", "NoNewPrivs: -1", 1)},
		{"multiple seccomp values", strings.Replace(helperStatusFixture, "Seccomp: 0", "Seccomp: 1 2", 1)},
		{"duplicate permitted", helperStatusFixture + "CapPrm: 0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseHelperCredentials([]byte(tc.status)); !errors.Is(err, sys.ErrCredentials) {
				t.Fatalf("malformed or duplicate status error: %v", err)
			}
		})
	}
}

func TestHelperAuthorityRejectsAdditionalPrivilege(t *testing.T) {
	baseline, err := parseHelperCredentials([]byte(helperStatusFixture))
	if err != nil {
		t.Fatal(err)
	}
	if !baseline.equal(baseline) {
		t.Fatal("identical credentials differ")
	}
	for _, tc := range []struct {
		name   string
		change func(*helperAuthority)
	}{
		{"real uid", func(c *helperAuthority) { c.UIDs[0] = 0 }},
		{"saved uid", func(c *helperAuthority) { c.UIDs[2] = 0 }},
		{"real gid", func(c *helperAuthority) { c.GIDs[0] = 0 }},
		{"saved gid", func(c *helperAuthority) { c.GIDs[2] = 0 }},
		{"inheritable capability", func(c *helperAuthority) { c.Caps[0] = 1 }},
		{"permitted capability", func(c *helperAuthority) { c.Caps[1] = 1 }},
		{"bounding capability", func(c *helperAuthority) { c.Caps[3] = 1 }},
		{"ambient capability", func(c *helperAuthority) { c.Caps[4] = 1 }},
		{"no new privs", func(c *helperAuthority) { c.NoNewPrivs = 1 }},
		{"seccomp", func(c *helperAuthority) { c.Seccomp = 2 }},
		{"securebits", func(c *helperAuthority) { c.Securebits = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := baseline
			tc.change(&changed.Full)
			if !baseline.Creds.Equal(changed.Creds) {
				t.Fatal("fixture changed TaskCreds instead of additional authority")
			}
			if baseline.equal(changed) {
				t.Fatal("changed authority accepted")
			}
		})
	}
}

func TestHelperReservationSurvivesListenerClose(t *testing.T) {
	// A pid-specific synthetic uid avoids the product caller's reservation names.
	uid := uint32(os.Getpid()) | 0x80000000
	var listeners []*net.UnixConn
	var leases []*os.File
	t.Cleanup(func() {
		for _, listener := range listeners {
			closeReservation(listener)
		}
		for _, lease := range leases {
			closePipe(lease)
		}
	})
	for range cap(processWorkers) {
		listener, lease, err := reserveHelper(admissionCtx(t), uid, false)
		if err != nil {
			t.Fatal(err)
		}
		listeners, leases = append(listeners, listener), append(leases, lease)
		// This is the invoking command closing its net.Conn after spawn. The
		// inherited duplicate alone must keep its slot bound in the kernel.
		closeReservation(listener)
	}
	if listener, lease, err := reserveHelper(admissionCtx(t), uid, false); err == nil {
		closeReservation(listener)
		closePipe(lease)
		t.Fatal("excess helper reservation accepted after listener close")
	} else if !strings.Contains(err.Error(), fmt.Sprintf("%d filesystem helpers", cap(processWorkers))) {
		t.Fatalf("reservation refusal: %v", err)
	}
	closePipe(leases[0])
	listener, lease, err := reserveHelper(admissionCtx(t), uid, false)
	if err != nil {
		t.Fatalf("reservation did not recover after last fd close: %v", err)
	}
	listeners, leases = append(listeners, listener), append(leases, lease)
}

// Linux permits 65536 supplementary groups. Serialize that list once so a
// valid caller fits the startup header bound even with ten-digit group IDs.
func TestHelperMaxGroupsHeaderFits(t *testing.T) {
	groups := make([]string, 65536)
	for i := range groups {
		groups[i] = strconv.FormatUint(uint64(0xfffeffff)+uint64(i), 10)
	}
	status := strings.Replace(helperStatusFixture, "Groups: 1000 27", "Groups: "+strings.Join(groups, " "), 1)
	credentials, err := parseHelperCredentials([]byte(status))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(bytes.NewReader(framed(encoded)), 1<<20); err != nil {
		t.Fatalf("valid maximum-group caller refused: %d header bytes: %v", len(encoded), err)
	}
}

func TestHelperSessionReusesWorker(t *testing.T) {
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	session := ctx.Value(helperSessionKey{}).(*helperSession)
	var worker *helperWorker
	for i := range 20 {
		path := fmt.Sprintf("/session-check-%d.yaml", i)
		got, err := PlacePath(ctx, path)
		if err != nil || got != path {
			t.Fatalf("exchange %d: %q %v", i, got, err)
		}
		if session.worker == nil {
			t.Fatal("successful exchange did not retain a worker")
		}
		if worker != nil && session.worker != worker {
			t.Fatal("sequential check started another worker")
		}
		worker = session.worker
		if i == 10 {
			if _, err := exchange(ctx, []byte("invalid request frame payload")); err == nil {
				t.Fatal("malformed operation accepted")
			}
			if session.worker != worker {
				t.Fatal("an ordinary operation error discarded a healthy worker")
			}
		}
	}
	closeSession()
	if session.worker != nil {
		t.Fatal("closed session retained worker")
	}
}

func TestHelperSixteenConcurrentHealthySessions(t *testing.T) {
	// Keep every helper alive until all sixteen have answered. A four-slot
	// shared budget refused healthy commands even though no mount was stuck.
	var ready sync.WaitGroup
	ready.Add(16)
	release := make(chan struct{})
	errs := make(chan error, 16)
	for i := range 16 {
		go func(i int) {
			ctx, closeSession := WithHelperSession(context.Background())
			defer closeSession()
			_, err := PlacePath(ctx, fmt.Sprintf("/healthy-%d.yaml", i))
			errs <- err
			ready.Done()
			<-release
		}(i)
	}
	ready.Wait()
	close(release)
	for range 16 {
		if err := <-errs; err != nil {
			t.Errorf("healthy session refused: %v", err)
		}
	}
}

func TestHelperReservationFailureRefuses(t *testing.T) {
	listener, lease, err := reserveHelperWith(context.Background(), 1000, false, func(string, *net.UnixAddr) (*net.UnixConn, error) {
		return nil, unix.EMFILE
	})
	if listener != nil || lease != nil || !errors.Is(err, unix.EMFILE) || !strings.Contains(err.Error(), "reserve filesystem helper") {
		t.Fatalf("reservation failure: listener=%v lease=%v error=%v", listener, lease, err)
	}
}

func TestHelperChangedAuthorityRefusesBeforeRequest(t *testing.T) {
	as, err := parseHelperCredentials([]byte(helperStatusFixture))
	if err != nil {
		t.Fatal(err)
	}
	changed := as
	changed.Full.Caps[1] ^= 1
	header, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	input, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer send.Close()
	receive, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer receive.Close()
	defer output.Close()
	done := make(chan error, 1)
	go func() {
		if err := writeFrame(output, header); err != nil {
			done <- err
			return
		}
		done <- writeFrame(output, []byte{0})
	}()
	worker := &helperWorker{send: send, receive: receive, started: true}
	result := worker.transact(context.Background(), as, []byte("a path request must not be sent"), nil)
	if !errors.Is(result.err, sys.ErrCredentials) {
		t.Fatalf("changed authority accepted: %v", result.err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// A zero-time poll proves the credential refusal sent no request bytes.
	fds := []unix.PollFd{{Fd: int32(input.Fd()), Events: unix.POLLIN}}
	if n, err := unix.Poll(fds, 0); err != nil || n != 0 {
		t.Fatalf("request reached changed-authority worker: n=%d err=%v revents=%v", n, err, fds)
	}
}

func init() {
	RegisterHelperOperation("test-wait-operation-cancel", func(ctx context.Context, payload []byte) ([]byte, error) {
		if err := os.WriteFile(string(payload)+".ready", nil, 0o600); err != nil {
			return nil, err
		}
		<-ctx.Done()
		// Publish complete bytes: a reader can see WriteFile's created file
		// before its write, mistaking an empty marker for cancellation's result.
		path := string(payload) + ".canceled"
		if err := os.WriteFile(path+".tmp", []byte(ctx.Err().Error()), 0o600); err != nil {
			return nil, err
		}
		return nil, os.Rename(path+".tmp", path)
	})
	RegisterHelperOperation("test-operation-context", func(ctx context.Context, _ []byte) ([]byte, error) {
		return nil, ctx.Err()
	})
	RegisterHelperOperation("test-environment-isolation", func(context.Context, []byte) ([]byte, error) {
		previous := os.Getenv("SUDO_UID") + ":" + os.Getenv("PATH")
		if err := os.Setenv("PATH", "/previous-helper-operation"); err != nil {
			return nil, err
		}
		return []byte(previous), nil
	})
}

func TestHelperSessionEnvironmentIsolation(t *testing.T) {
	t.Setenv("SUDO_UID", "424242")
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	first, err := HelperExchange(ctx, "test-environment-isolation", nil)
	if err != nil || string(first) != ":" {
		t.Fatalf("first environment: %q %v", first, err)
	}
	session := ctx.Value(helperSessionKey{}).(*helperSession)
	worker := session.worker
	if err := os.Unsetenv("SUDO_UID"); err != nil {
		t.Fatal(err)
	}
	second, err := HelperExchange(ctx, "test-environment-isolation", nil)
	if err != nil || string(second) != ":" {
		t.Fatalf("previous request environment leaked: %q %v", second, err)
	}
	if session.worker != worker {
		t.Fatal("environment isolation restarted helper")
	}
}

func TestHelperUnplaceablePathCannotTell(t *testing.T) {
	path, err := PlacePath(context.Background(), "relative/contract.yaml")
	if path != "" || err == nil || !strings.Contains(err.Error(), UnavailableLocation) {
		t.Fatalf("unplaceable path: %q %v", path, err)
	}
}

func TestHelperAbandonReleasesExchangeGoroutine(t *testing.T) {
	input, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer send.Close()
	receive, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer receive.Close()
	defer output.Close()
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	session := ctx.Value(helperSessionKey{}).(*helperSession)
	processWorkers <- struct{}{}
	session.worker = &helperWorker{send: send, receive: receive, started: true}
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancel()
	begin := time.Now()
	if _, err := exchange(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hang result: %v", err)
	}
	if time.Since(begin) > time.Second {
		t.Fatal("exchange did not return within bound")
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	after := runtime.NumGoroutine()
	if after > before {
		stack := make([]byte, 32<<10)
		n := runtime.Stack(stack, true)
		t.Fatalf("abandoned exchange retained goroutines: before=%d after=%d\n%s", before, after, stack[:n])
	}
	t.Logf("abandoned exchange goroutines: before=%d after=%d", before, after)
}

func TestHelperSessionCloseWaitsForActiveOwner(t *testing.T) {
	input, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer send.Close()
	receive, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer receive.Close()
	defer output.Close()
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	session := ctx.Value(helperSessionKey{}).(*helperSession)
	processWorkers <- struct{}{}
	session.worker = &helperWorker{send: send, receive: receive, started: true}
	// Hold the owner's final critical section, after it checked its context.
	// Close must not skip the worker when the gate is temporarily busy.
	<-session.gate
	closed := make(chan struct{})
	go func() { closeSession(); close(closed) }()
	<-ctx.Done()
	early := false
	select {
	case <-closed:
		early = true
	case <-time.After(25 * time.Millisecond):
	}
	session.gate <- struct{}{}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited after active owner released its gate")
	}
	if early || session.worker != nil {
		t.Fatal("Close skipped the active owner's worker")
	}
}

func TestHelperPipeEOFCancelsOperation(t *testing.T) {
	input, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer send.Close()
	ctx, cancel := helperRequestContext(input)
	defer cancel()
	body := []byte("watcher must not consume this framed request")
	if err := writeFrame(send, body); err != nil {
		t.Fatal(err)
	}
	received, err := readFrame(input, maxExchangeBytes)
	if err != nil || !bytes.Equal(received, body) {
		t.Fatalf("request framing: %q %v", received, err)
	}
	if err := send.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("pipe EOF: %v", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("helper operation context survived caller pipe EOF")
	}
}

func TestHelperDeadlineChecksPipeEOFSynchronously(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested=%t", nested), func(t *testing.T) {
			input, send, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer send.Close()
			base, cancelBase := context.WithCancel(context.Background())
			defer cancelBase()
			// Intentionally omit the watcher: a pre-write Err check must observe
			// pipe HUP even when that goroutine has not been scheduled yet.
			lifetime := &helperLifetime{Context: base, cancel: cancelBase, input: input}
			parent := context.WithValue(lifetime, helperLifetimeKey{}, lifetime)
			ctx, cancel := WithHelperDeadline(parent, time.Now().Add(time.Minute))
			defer cancel()
			if nested {
				var cancelNested context.CancelFunc
				ctx, cancelNested = WithHelperDeadline(ctx, time.Now().Add(time.Minute))
				defer cancelNested()
			}
			if err := ctx.Err(); err != nil {
				t.Fatalf("connected caller: %v", err)
			}
			if err := send.Close(); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("pre-write check missed caller pipe EOF before watcher ran")
			}
			select {
			case <-ctx.Done():
			default:
				t.Fatal("Err returned cancellation before closing Done")
			}
		})
	}
}

func TestHelperOperationUsesCallerContext(t *testing.T) {
	request, err := encodeCheck(checkRequest{Caller: CallerContext(context.Background()), Operation: "test-operation-context"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := handleRequestContext(ctx, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("operation ignored caller cancellation: %v", err)
	}
}

func TestHelperPipeWatcherStopsOnCancel(t *testing.T) {
	input, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer send.Close()
	count := func() int {
		stack := make([]byte, 64<<10)
		n := runtime.Stack(stack, true)
		return bytes.Count(stack[:n], []byte("contracts.helperRequestContext.func"))
	}
	before := count()
	_, cancel := helperRequestContext(input)
	cancel()
	deadline := time.Now().Add(time.Second)
	for count() > before && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if after := count(); after > before {
		t.Fatalf("idle worker retained its pipe watcher: before=%d after=%d", before, after)
	}
}

func TestHelperLifetimeHonorsFileCloseBeforeDescriptorRelease(t *testing.T) {
	input, send, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer send.Close()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	lifetime := &helperLifetime{Context: base, cancel: cancel, input: input}
	if err := lifetime.Err(); err != nil {
		t.Fatalf("connected pipe: %v", err)
	}
	// Hold an existing standard-library lease while Close marks the File closed.
	// Its number still names a connected pipe until this lease returns. A cached
	// number misses the close, and can later follow an unrelated reused number.
	leased, release := make(chan struct{}), make(chan struct{})
	leaseDone := make(chan error, 1)
	leaseRead := false
	var closed chan error
	defer func() {
		close(release)
		if !leaseRead {
			select {
			case err := <-leaseDone:
				if err != nil {
					t.Errorf("held lease: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("held lease did not return")
			}
		}
		if closed != nil {
			select {
			case err := <-closed:
				if err != nil {
					t.Errorf("file close: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("file close waited after lease returned")
			}
		}
	}()
	go func() {
		leaseDone <- sys.FileDo(input, func(int) error {
			close(leased)
			<-release
			return nil
		})
	}()
	select {
	case <-leased:
	case err := <-leaseDone:
		leaseRead = true
		t.Fatalf("lease failed before callback: %v", err)
	case <-time.After(time.Second):
		t.Fatal("lease did not start")
	}
	closed = make(chan error, 1)
	go func() { closed <- input.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		err := sys.FileDo(input, func(int) error { return nil })
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("File close did not become visible before releasing its descriptor: %v", err)
		}
		runtime.Gosched()
	}
	if !errors.Is(lifetime.Err(), context.Canceled) {
		t.Fatal("closed File kept its operation alive through a cached descriptor")
	}
	select {
	case <-lifetime.Done():
	default:
		t.Fatal("closed File did not close its operation's Done")
	}
}

func TestHelperSessionCannotRestartAfterClose(t *testing.T) {
	ctx, closeSession := WithHelperSession(context.Background())
	session := ctx.Value(helperSessionKey{}).(*helperSession)
	closeSession()
	// A removal overlay starts a real worker. Close only that owned worker even
	// after the assertion fails; the session's original owner has already left.
	t.Cleanup(func() {
		<-session.gate
		if session.worker != nil {
			session.worker.close()
			session.worker = nil
		}
		session.gate <- struct{}{}
	})
	path, err := PlacePath(context.WithoutCancel(ctx), "/closed-session.yaml")
	if path != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("closed session restarted: path=%q error=%v", path, err)
	}
	if session.worker != nil {
		t.Fatal("closed session retained a new worker")
	}
}

func TestHelperWorkerPipeEOFCancelsRegisteredOperation(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "worker")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := HelperExchange(ctx, "test-wait-operation-cancel", []byte(marker))
		done <- err
	}()
	waitFile := func(path string, bound time.Duration) ([]byte, error) {
		deadline := time.Now().Add(bound)
		for {
			data, err := os.ReadFile(path)
			if err == nil || !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
				return data, err
			}
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := waitFile(marker+".ready", CheckTimeout); err != nil {
		cancel()
		<-done
		t.Fatalf("helper operation did not start: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("caller cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller waited for canceled helper operation")
	}
	data, err := waitFile(marker+".canceled", time.Second)
	if err != nil || string(data) != context.Canceled.Error() {
		// A negative overlay gives this worker only its five-second deadline.
		// Let that finite worker finish before removing its marker directory.
		_, _ = waitFile(marker+".canceled", CheckTimeout)
		t.Fatalf("worker did not inherit request-pipe cancellation: %q %v", data, err)
	}
}

// A healthy worker keeps its kernel lease until actual exit, even after its
// request closes. A full scan can race that exit; the next check must wait for
// capacity within its own deadline instead of refusing a healthy location.
func TestHelperReservationWaitsForRetiringWorker(t *testing.T) {
	uid := uint32(os.Getpid()) | 0x80000000
	attempts := 0
	listener, lease, err := reserveHelperWith(t.Context(), uid, false, func(network string, address *net.UnixAddr) (*net.UnixConn, error) {
		attempts++
		if attempts <= cap(processWorkers) {
			return nil, unix.EADDRINUSE
		}
		return net.ListenUnixgram(network, address)
	})
	if err != nil {
		t.Fatalf("a retiring worker caused a healthy check to refuse: %v", err)
	}
	defer closeReservation(listener)
	defer closePipe(lease)
}
