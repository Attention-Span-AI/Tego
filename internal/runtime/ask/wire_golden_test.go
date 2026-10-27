// SPDX-License-Identifier: Apache-2.0

package ask_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// The ask wire golden: every frame the broker and its client exchange, recorded from the base build
// e47e1ba4 before the client moved out of internal/runtime/ask, by an in-process tap between the two. The test runs
// the same exchanges now and requires the same bytes, frame by frame, and the same results at the client, but for the
// two exchanges the ask hardening changed, an http_request's list and detail, which wireDelta holds. Only the
// values a run draws afresh are normalised: the hello nonce, ask ids (numbered in order of first appearance), the
// answerer's uid and pid, the hold's elapsed seconds, the alternate's directory and its device and inode. This file
// uses the package's exported API only, so it compiled unchanged against e47e1ba4 to record the fixture
// (TEGO_ASK_WIRE_RECORD=<path>). One amendment since, by hand: the list-truncated phase's listed request, whose rule
// is cut at askproto.MaxSummaryRule, carries "rule_truncated":true after "target_truncated" (G11, 2026-10-26); every
// other frame is as recorded.

const wireFixture = "testdata/wire-e47e1ba4.json"

// wireFrame is one packet: dir "s2c" (broker to client) or "c2s", data its normalised bytes.
type wireFrame struct {
	Dir  string `json:"dir"`
	Data string `json:"data"`
}

// wirePhase is one exchange: the frames on the wire and what the client returned.
type wirePhase struct {
	Name   string      `json:"name"`
	Frames []wireFrame `json:"frames"`
	Result string      `json:"result,omitempty"`
	Err    string      `json:"err,omitempty"`
}

// wireClient is the client under test: the ask package's exported calls, or another client of the same socket.
type wireClient struct {
	list      func(ctx context.Context, dir string, pid int) (any, error)
	detail    func(ctx context.Context, dir string, pid int, id string) (any, error)
	answer    func(ctx context.Context, dir string, pid int, id string, approve, always bool) (any, error)
	alternate func(ctx context.Context, dir string, pid int, id string, alt *ask.AlternateFile, always bool) (any, error)
}

var askPackageClient = wireClient{
	list: func(ctx context.Context, dir string, pid int) (any, error) { return ask.ListFor(ctx, dir, pid) },
	detail: func(ctx context.Context, dir string, pid int, id string) (any, error) {
		return ask.DetailFor(ctx, dir, pid, id)
	},
	answer: func(ctx context.Context, dir string, pid int, id string, approve, always bool) (any, error) {
		return ask.AnswerFor(ctx, dir, pid, id, approve, always)
	},
	alternate: func(ctx context.Context, dir string, pid int, id string, alt *ask.AlternateFile, always bool) (any, error) {
		return ask.AlternateFor(ctx, dir, pid, id, alt, always)
	},
}

// wireTap listens where a client dials (<dir>/ask.sock) and relays every packet to the broker's socket, recording
// it under the current phase. The tap runs in the test's process, so the client's SO_PEERCRED check and the broker's
// per-packet credentials both see the test's pid, as they would see the launcher's and the person's.
type wireTap struct {
	dir    string
	server string
	mu     sync.Mutex
	phase  *wirePhase
	mutate func([]byte) []byte
	ln     *net.UnixListener
}

func newWireTap(t *testing.T, serverDir string) *wireTap {
	t.Helper()
	tap := &wireTap{dir: t.TempDir(), server: serverDir}
	fd, err := unix.Open(tap.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	// Bound under /proc/self/fd, as the broker binds, so a long temporary directory still fits sun_path.
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: fmt.Sprintf("/proc/self/fd/%d/%s", fd, ask.SocketName), Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	tap.ln = ln
	go tap.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return tap
}

func (tap *wireTap) serve() {
	for {
		c, err := tap.ln.AcceptUnix()
		if err != nil {
			return
		}
		go tap.relay(c)
	}
}

func (tap *wireTap) relay(client *net.UnixConn) {
	defer func() { _ = client.Close() }()
	fd, err := unix.Open(tap.server, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(fd) }()
	conn, err := net.Dial("unixpacket", fmt.Sprintf("/proc/self/fd/%d/%s", fd, ask.SocketName))
	if err != nil {
		return
	}
	server := conn.(*net.UnixConn)
	defer func() { _ = server.Close() }()
	done := make(chan struct{}, 2)
	pump := func(from, to *net.UnixConn, dir string) {
		defer func() { done <- struct{}{} }()
		buf, oob := make([]byte, 256<<10), make([]byte, 1024)
		for {
			n, on, _, _, err := from.ReadMsgUnix(buf, oob)
			if err != nil || n == 0 {
				_ = to.CloseWrite()
				return
			}
			data := append([]byte(nil), buf[:n]...)
			var rights []int
			if msgs, e := unix.ParseSocketControlMessage(oob[:on]); e == nil {
				for i := range msgs {
					if fds, e := unix.ParseUnixRights(&msgs[i]); e == nil {
						rights = append(rights, fds...)
					}
				}
			}
			tap.mu.Lock()
			if dir == "c2s" && tap.mutate != nil {
				data = tap.mutate(data)
			}
			if tap.phase != nil {
				tap.phase.Frames = append(tap.phase.Frames, wireFrame{Dir: dir, Data: string(data)})
			}
			tap.mu.Unlock()
			var cmsg []byte
			if len(rights) > 0 {
				cmsg = unix.UnixRights(rights...)
			}
			_, _, err = to.WriteMsgUnix(data, cmsg, nil)
			for _, r := range rights {
				_ = unix.Close(r)
			}
			if err != nil {
				return
			}
		}
	}
	go pump(server, client, "s2c")
	go pump(client, server, "c2s")
	<-done
	<-done
}

// record runs one exchange under name and keeps what crossed the tap.
func (tap *wireTap) record(phases *[]wirePhase, name string, mutate func([]byte) []byte, call func() (any, error)) {
	p := &wirePhase{Name: name}
	tap.mu.Lock()
	tap.phase, tap.mutate = p, mutate
	tap.mu.Unlock()
	result, err := call()
	// The broker closes its end after its reply; the tap has relayed every frame by the time the client returned.
	tap.mu.Lock()
	tap.phase, tap.mutate = nil, nil
	tap.mu.Unlock()
	if err != nil {
		p.Err = err.Error()
	} else {
		b, merr := json.Marshal(result)
		if merr != nil {
			p.Err = "marshal: " + merr.Error()
		}
		p.Result = string(b)
	}
	*phases = append(*phases, *p)
}

// wireBroker is a broker for the golden, at its own directory, with its own tap.
type wireBroker struct {
	b   *ask.Broker
	dir string
	tap *wireTap
}

func newWireBroker(t *testing.T, mutate func(*ask.Options)) *wireBroker {
	t.Helper()
	dir := t.TempDir()
	opts := ask.Options{UID: uint32(os.Getuid()), Timeout: 30 * time.Second, Authorize: func(ask.Peer) error { return nil }, Emit: func(ask.Event) error { return nil }}
	if mutate != nil {
		mutate(&opts)
	}
	b, err := ask.New(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return &wireBroker{b: b, dir: dir, tap: newWireTap(t, dir)}
}

// hold publishes req and returns its ask id once it is listed, and the channel its decision arrives on.
func (w *wireBroker) hold(t *testing.T, req ask.Request) (string, <-chan ask.Decision) {
	t.Helper()
	before := map[string]bool{}
	items, err := ask.ListFor(context.Background(), w.dir, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range items {
		before[s.AskID] = true
	}
	ch := make(chan ask.Decision, 1)
	go func() {
		d, _ := w.b.Request(context.Background(), req)
		d.CloseAlternate()
		ch <- d
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		items, err := ask.ListFor(context.Background(), w.dir, os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range items {
			if !before[s.AskID] {
				return s.AskID, ch
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("request not published")
	return "", nil
}

func settle(t *testing.T, ch <-chan ask.Decision) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("the held request did not end")
	}
}

func connectReq(target string) ask.Request {
	return ask.Request{Op: "connect", Target: target, Rule: "net.ask[0]", Hold: "connect", PID: 4242, TID: 4243}
}

func openReq(check func(*ask.AlternateFile) (string, error)) ask.Request {
	return ask.Request{Op: "open", Target: "/srv/data/report.csv", Rule: "fs.ask[0]", Hold: ask.HoldOpen, PID: 4242, TID: 4243,
		Alternates: ask.NewAlternateCheck(check)}
}

// runWireGolden runs every exchange through c and returns them, normalised.
func runWireGolden(t *testing.T, c wireClient) []wirePhase {
	ctx := context.Background()
	pid := os.Getpid()
	var phases []wirePhase
	altDir := t.TempDir()
	altPath := filepath.Join(altDir, "alternate.txt")
	if err := os.WriteFile(altPath, []byte("alternate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openAlt := func() *ask.AlternateFile {
		a, err := ask.OpenAlternateFile(altPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		return a
	}
	named := func(a *ask.AlternateFile) (string, error) { return a.Named, nil }

	w := newWireBroker(t, nil)
	rec := func(name string, call func() (any, error)) { w.tap.record(&phases, name, nil, call) }
	td := w.tap.dir
	rec("list-empty", func() (any, error) { return c.list(ctx, td, pid) })

	a, aDone := w.hold(t, connectReq("127.0.0.1:443"))
	rec("list-one", func() (any, error) { return c.list(ctx, td, pid) })
	rec("detail", func() (any, error) { return c.detail(ctx, td, pid, a) })
	rec("answer-approve", func() (any, error) { return c.answer(ctx, td, pid, a, true, false) })
	settle(t, aDone)

	score := 87
	httpReq := ask.Request{Op: "http_request", Target: "api.example.com POST /v1/messages?key=" + strings.Repeat("k", 150) + "&é=1",
		Rule: "net.ask[" + strings.Repeat("r", 70) + "]", Hold: "request", PID: 4242, TID: 4243, Score: &score, GateRule: "gate.rules[2]"}
	b, bDone := w.hold(t, httpReq)
	rec("list-truncated", func() (any, error) { return c.list(ctx, td, pid) })
	rec("detail-full", func() (any, error) { return c.detail(ctx, td, pid, b) })
	rec("answer-always-not-rememberable", func() (any, error) { return c.answer(ctx, td, pid, b, true, true) })
	rec("answer-deny", func() (any, error) { return c.answer(ctx, td, pid, b, false, false) })
	settle(t, bDone)

	gone := "q-" + strings.Repeat("0", 32)
	rec("detail-not-pending", func() (any, error) { return c.detail(ctx, td, pid, gone) })
	rec("answer-not-pending", func() (any, error) { return c.answer(ctx, td, pid, gone, true, false) })

	cID, cDone := w.hold(t, connectReq("10.0.0.1:443"))
	rec("answer-always", func() (any, error) { return c.answer(ctx, td, pid, cID, true, true) })
	settle(t, cDone)

	e, eDone := w.hold(t, connectReq("10.0.0.2:443"))
	rec("alternate-no-alternate", func() (any, error) { return c.alternate(ctx, td, pid, e, openAlt(), false) })
	rec("answer-deny-always", func() (any, error) { return c.answer(ctx, td, pid, e, false, true) })
	settle(t, eDone)

	d, dDone := w.hold(t, openReq(named))
	rec("alternate", func() (any, error) { return c.alternate(ctx, td, pid, d, openAlt(), false) })
	settle(t, dDone)

	f, fDone := w.hold(t, openReq(func(*ask.AlternateFile) (string, error) { return "", errors.New("it is tego's own state") }))
	rec("alternate-bad", func() (any, error) { return c.alternate(ctx, td, pid, f, openAlt(), false) })
	if _, err := ask.AnswerFor(ctx, w.dir, pid, f, false, false); err != nil {
		t.Fatal(err)
	}
	settle(t, fDone)

	g, gDone := w.hold(t, openReq(named))
	rec("alternate-always", func() (any, error) { return c.alternate(ctx, td, pid, g, openAlt(), true) })
	settle(t, gDone)

	// The broker refuses a command it cannot read: the tap adds a key no command has.
	w.tap.record(&phases, "protocol", func(b []byte) []byte {
		return bytes.Replace(b, []byte(`{"action"`), []byte(`{"extra":1,"action"`), 1)
	}, func() (any, error) { return c.list(ctx, td, pid) })

	// Fill the run's standing answers, then one more "always" is refused.
	for i := 3; i < ask.MaxStanding; i++ {
		id, done := w.hold(t, connectReq(fmt.Sprintf("10.1.%d.%d:443", i/256, i%256)))
		if _, err := ask.AnswerFor(ctx, w.dir, pid, id, true, true); err != nil {
			t.Fatalf("standing answer %d: %v", i, err)
		}
		settle(t, done)
	}
	full, fullDone := w.hold(t, connectReq("10.2.0.1:443"))
	rec("answer-always-standing-full", func() (any, error) { return c.answer(ctx, td, pid, full, true, true) })
	if _, err := ask.AnswerFor(ctx, w.dir, pid, full, false, false); err != nil {
		t.Fatal(err)
	}
	settle(t, fullDone)

	// Two "always" answers for one key: the second, while the first is recorded, is refused.
	release, blocked := make(chan struct{}), make(chan struct{})
	var once sync.Once
	busy := newWireBroker(t, func(o *ask.Options) {
		o.Emit = func(ev ask.Event) error {
			if ev.Kind == "answer" && strings.HasSuffix(ev.Decision.By, " always") {
				once.Do(func() { close(blocked) })
				<-release
			}
			return nil
		}
	})
	one, oneDone := busy.hold(t, connectReq("127.0.0.1:443"))
	two, twoDone := busy.hold(t, connectReq("127.0.0.1:443"))
	go func() { _, _ = ask.AnswerFor(ctx, busy.dir, pid, one, true, true) }()
	<-blocked
	busy.tap.record(&phases, "answer-always-standing-busy", nil, func() (any, error) { return c.answer(ctx, busy.tap.dir, pid, two, false, true) })
	close(release)
	settle(t, oneDone)
	settle(t, twoDone)

	// The ledger refuses the answer's line.
	refusing := newWireBroker(t, func(o *ask.Options) {
		o.Emit = func(ev ask.Event) error {
			if ev.Kind == "answer" {
				return errors.New("the ledger refused the line")
			}
			return nil
		}
	})
	u, uDone := refusing.hold(t, connectReq("127.0.0.1:443"))
	refusing.tap.record(&phases, "answer-unavailable", nil, func() (any, error) { return c.answer(ctx, refusing.tap.dir, pid, u, true, false) })
	settle(t, uDone)

	// A peer the run's own check refuses.
	closed := newWireBroker(t, func(o *ask.Options) { o.Authorize = func(ask.Peer) error { return errors.New("in the run's cgroup") } })
	closed.tap.record(&phases, "list-unauthorized", nil, func() (any, error) { return c.list(ctx, closed.tap.dir, pid) })

	return normaliseWire(phases, altDir)
}

var (
	wireNonce  = regexp.MustCompile(`"(ready|nonce)":"[0-9a-f]{32}"`)
	wireAskID  = regexp.MustCompile(`q-[0-9a-f]{32}`)
	wireBy     = regexp.MustCompile(`uid:[0-9]+ pid:[0-9]+`)
	wireAfter  = regexp.MustCompile(`"after_s":[-+.eE0-9]+`)
	wireDevIno = regexp.MustCompile(`"alternate_(dev|ino)":[0-9]+`)
)

// normaliseWire replaces the values a run draws afresh, and nothing else.
func normaliseWire(phases []wirePhase, altDir string) []wirePhase {
	ids := map[string]string{}
	norm := func(s string) string {
		s = strings.ReplaceAll(s, altDir, "/ALT")
		s = wireNonce.ReplaceAllString(s, `"$1":"NONCE"`)
		s = wireAskID.ReplaceAllStringFunc(s, func(id string) string {
			if _, ok := ids[id]; !ok {
				ids[id] = fmt.Sprintf("q-%032d", len(ids)+1)
			}
			return ids[id]
		})
		s = wireBy.ReplaceAllString(s, "uid:U pid:P")
		s = wireAfter.ReplaceAllString(s, `"after_s":0`)
		return wireDevIno.ReplaceAllString(s, `"alternate_$1":1`)
	}
	for i := range phases {
		for j := range phases[i].Frames {
			phases[i].Frames[j].Data = norm(phases[i].Frames[j].Data)
		}
		phases[i].Result, phases[i].Err = norm(phases[i].Result), norm(phases[i].Err)
	}
	return phases
}

func TestAskWireGolden(t *testing.T) {
	got := runWireGolden(t, askPackageClient)
	if path := os.Getenv("TEGO_ASK_WIRE_RECORD"); path != "" {
		b, err := json.MarshalIndent(got, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	compareWireGolden(t, "ask package", got)
}

// wireDelta holds the exchanges the ask hardening changed, recorded after it with TEGO_ASK_WIRE_RECORD: the broker's
// list and detail show a target in its ledger form (askclient.LedgerTarget), so the two exchanges that hold an
// http_request differ from e47e1ba4's in that target alone (TestWireDeltaIsTheTargetAlone). Every other exchange is
// still e47e1ba4's, byte for byte.
const wireDelta = "testdata/wire-ask-harden.json"

// readPhases reads a fixture of exchanges.
func readPhases(t *testing.T, path string) []wirePhase {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var phases []wirePhase
	if err := json.Unmarshal(b, &phases); err != nil {
		t.Fatal(err)
	}
	return phases
}

// wantWire is the recording at e47e1ba4 with wireDelta's exchanges in place of its own of the same name.
func wantWire(t *testing.T) []wirePhase {
	t.Helper()
	want := readPhases(t, wireFixture)
	for _, d := range readPhases(t, wireDelta) {
		found := false
		for i := range want {
			if want[i].Name == d.Name {
				want[i], found = d, true
			}
		}
		if !found {
			t.Fatalf("%s holds exchange %q, which %s does not", wireDelta, d.Name, wireFixture)
		}
	}
	return want
}

// TestWireDeltaIsTheTargetAlone holds wireDelta to what the ask hardening changed and nothing else: it names the two
// exchanges that list and detail an http_request, each differs from e47e1ba4's in the request's target (and the list's
// target_truncated, which the shorter target no longer needs) alone, and that target is the ledger form of the raw
// one e47e1ba4's detail served, with no byte of its query.
func TestWireDeltaIsTheTargetAlone(t *testing.T) {
	base := map[string]wirePhase{}
	for _, p := range readPhases(t, wireFixture) {
		base[p.Name] = p
	}
	delta := readPhases(t, wireDelta)
	if len(delta) != 2 || delta[0].Name != "list-truncated" || delta[1].Name != "detail-full" {
		t.Fatalf("%s holds %d exchanges; want list-truncated and detail-full", wireDelta, len(delta))
	}
	var raw struct {
		Request askproto.Request `json:"request"`
	}
	if err := json.Unmarshal([]byte(base["detail-full"].Frames[2].Data), &raw); err != nil {
		t.Fatal(err)
	}
	ledger := askclient.LedgerTarget(raw.Request.Op, raw.Request.Target)
	if raw.Request.Op != "http_request" || ledger == raw.Request.Target || strings.Contains(ledger, "key=") {
		t.Fatalf("e47e1ba4's detail served %q, whose ledger form is %q", raw.Request.Target, ledger)
	}
	// strip drops every target and target_truncated key of a decoded frame or result; on the delta's side (check) it
	// first requires each target to be the ledger form.
	var strip func(v any, check bool) any
	strip = func(v any, check bool) any {
		switch x := v.(type) {
		case map[string]any:
			if tg, ok := x["target"]; ok && check && tg != ledger {
				t.Errorf("a target in %s is %q; want the ledger form %q", wireDelta, tg, ledger)
			}
			out := map[string]any{}
			for k, e := range x {
				if k != "target" && k != "target_truncated" {
					out[k] = strip(e, check)
				}
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, e := range x {
				out[i] = strip(e, check)
			}
			return out
		}
		return v
	}
	same := func(delta, base string) bool {
		var dv, bv any
		if json.Unmarshal([]byte(delta), &dv) != nil || json.Unmarshal([]byte(base), &bv) != nil {
			return delta == base
		}
		ds, _ := json.Marshal(strip(dv, true))
		bs, _ := json.Marshal(strip(bv, false))
		return bytes.Equal(ds, bs)
	}
	for _, d := range delta {
		b := base[d.Name]
		if len(d.Frames) != len(b.Frames) || d.Err != b.Err || !same(d.Result, b.Result) {
			t.Fatalf("%s: %d frames, result %s / %q; e47e1ba4's %d, %s / %q", d.Name, len(d.Frames), d.Result, d.Err, len(b.Frames), b.Result, b.Err)
		}
		for i := range d.Frames {
			if d.Frames[i].Dir != b.Frames[i].Dir || !same(d.Frames[i].Data, b.Frames[i].Data) {
				t.Errorf("%s frame %d differs from e47e1ba4's in more than the target:\n got %s\nwant %s", d.Name, i, d.Frames[i].Data, b.Frames[i].Data)
			}
		}
	}
}

func compareWireGolden(t *testing.T, client string, got []wirePhase) {
	t.Helper()
	want := wantWire(t)
	if len(got) != len(want) {
		t.Fatalf("%s: %d exchanges, the fixture has %d", client, len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Name != w.Name {
			t.Fatalf("%s: exchange %d is %q, the fixture's %q", client, i, g.Name, w.Name)
		}
		if len(g.Frames) != len(w.Frames) {
			t.Errorf("%s %s: %d frames %+v, the fixture has %d %+v", client, w.Name, len(g.Frames), g.Frames, len(w.Frames), w.Frames)
			continue
		}
		for j := range w.Frames {
			if g.Frames[j] != w.Frames[j] {
				t.Errorf("%s %s frame %d:\n got %s %s\nwant %s %s", client, w.Name, j, g.Frames[j].Dir, g.Frames[j].Data, w.Frames[j].Dir, w.Frames[j].Data)
			}
		}
		if g.Result != w.Result || g.Err != w.Err {
			t.Errorf("%s %s: the client returned %s / %q, the fixture %s / %q", client, w.Name, g.Result, g.Err, w.Result, w.Err)
		}
	}
}
