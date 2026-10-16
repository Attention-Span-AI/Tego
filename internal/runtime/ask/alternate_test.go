// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readRequest is a held fs.ask_read open whose alternate check records the files it was asked about (by the path
// the person's command named) and refuses the ones refuse names. It reports the named path as the resolved one.
func readRequest(checked *[]string, mu *sync.Mutex, refuse map[string]error) Request {
	r := Request{Op: OpRead, Target: "/home/u/.aws/credentials", Rule: "fs.ask_read[~/.aws/credentials]", Hold: HoldOpen, PID: os.Getpid(), TID: os.Getpid()}
	r.Alternates = NewAlternateCheck(func(a *AlternateFile) (string, error) {
		mu.Lock()
		*checked = append(*checked, a.Named)
		mu.Unlock()
		return a.Named, refuse[a.Named]
	})
	return r
}

// standIn writes a file holding content under t's directory and returns its path.
func standIn(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// named opens p as `tego alternate` does, closed at the end of the test.
func named(t *testing.T, p string) *AlternateFile {
	t.Helper()
	a, err := OpenAlternateFile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// contentOf reads the file a decision's descriptor names, through /proc/self/fd as the supervisor reopens it.
func contentOf(t *testing.T, a *AlternateFile) string {
	t.Helper()
	var got []byte
	err := a.Control(func(fd int) error {
		f, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil {
			return err
		}
		defer f.Close()
		got, err = io.ReadAll(f)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

// A person's alternate answers a held file open: the decision names the file and its identity, approves nothing and
// refuses nothing, carries a descriptor of the very file, the check saw it before the answer was chosen, and the
// answer line carries it.
func TestAlternateAnswersAHeldOpenWithTheNamedFile(t *testing.T) {
	rec := &recorder{}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	var mu sync.Mutex
	var checked []string
	held := requestAsync(b, readRequest(&checked, &mu, nil))
	id := waitAsk(t, dir).AskID
	fake := standIn(t, "fake-credentials", "not a secret")
	alt := named(t, fake)
	var st unix.Stat_t
	if err := unix.Stat(fake, &st); err != nil {
		t.Fatal(err)
	}
	d, err := AlternateFor(context.Background(), dir, os.Getpid(), id, alt, false)
	if err != nil || d.Alternate != fake || d.Approved || d.Reason != "" || d.Always || !strings.HasPrefix(d.By, "uid:") || d.AlternateIno != st.Ino || d.AlternateDev != uint64(st.Dev) || d.File != nil { //nolint:unconvert
		t.Fatalf("the alternate answer = %+v, %v", d, err)
	}
	got := decisionWithin(t, held, 2*time.Second)
	if got.Alternate != fake || got.Approved || got.Reason != "" || got.File == nil || got.AlternateIno != st.Ino {
		t.Fatalf("the held request's decision = %+v", got)
	}
	if c := contentOf(t, got.File); c != "not a secret" {
		t.Fatalf("the decision's descriptor reads %q", c)
	}
	got.CloseAlternate()
	mu.Lock()
	if len(checked) != 1 || checked[0] != fake {
		t.Fatalf("the check saw %v", checked)
	}
	mu.Unlock()
	ev := rec.snapshot()
	if len(ev) != 2 || ev[1].Kind != "answer" || ev[1].Decision.Alternate != fake || ev[1].Decision.AlternateIno != st.Ino || ev[1].Request.Target != "/home/u/.aws/credentials" {
		t.Fatalf("ledger events = %+v: the ask names the target, the answer the alternate", ev)
	}
}

// ADR 0057 D2, the confused deputy: the file delivered is the one the person's command opened when they named it,
// never what the path names later. After the command opened it, the agent replaces the path with another file
// and then with a symbolic link to a secret: the check, the decision's descriptor and the answer line all keep the
// first file's identity and bytes.
func TestAlternateIsTheFileThePersonNamedNotWhatThePathNamesLater(t *testing.T) {
	rec := &recorder{}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	work := t.TempDir()
	secret := standIn(t, "secret", "the secret")
	p := filepath.Join(work, "stand-in")
	if err := os.WriteFile(p, []byte("the stand-in"), 0o600); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	var seenIno []uint64
	req := Request{Op: OpRead, Target: "/home/u/.aws/credentials", Rule: "fs.ask_read[~/.aws]", Hold: HoldOpen, PID: os.Getpid(), TID: os.Getpid()}
	req.Alternates = NewAlternateCheck(func(a *AlternateFile) (string, error) {
		var fst unix.Stat_t
		if err := a.Control(func(fd int) error { return unix.Fstat(fd, &fst) }); err != nil {
			return "", err
		}
		seenIno = append(seenIno, fst.Ino)
		return a.Named, nil
	})
	held := requestAsync(b, req)
	id := waitAsk(t, dir).AskID
	alt := named(t, p) // the person names it: its identity is fixed here
	// The agent swaps the path: first another file renamed over it, then a symbolic link to the secret.
	other := filepath.Join(work, "other")
	if err := os.WriteFile(other, []byte("the agent's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, p); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, p); err != nil {
		t.Fatal(err)
	}
	if _, err := AlternateFor(context.Background(), dir, os.Getpid(), id, alt, false); err != nil {
		t.Fatal(err)
	}
	got := decisionWithin(t, held, 2*time.Second)
	defer got.CloseAlternate()
	if len(seenIno) != 1 || seenIno[0] != st.Ino || got.AlternateIno != st.Ino {
		t.Fatalf("the check saw inode %v and the decision names %d; want the named file's %d", seenIno, got.AlternateIno, st.Ino)
	}
	if c := contentOf(t, got.File); c != "the stand-in" {
		t.Fatalf("the descriptor delivered reads %q; want the file the person named", c)
	}
}

// The command's open follows no symbolic link anywhere on the way and no magic link, so the person names a file by
// the path it has: a link is refused with the path it resolves to, for the person to check and name.
func TestOpenAlternateFileFollowsNoLink(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	links := t.TempDir()
	if err := os.Symlink(real, filepath.Join(links, "dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "f"), filepath.Join(links, "file")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(links, "dir", "f"), filepath.Join(links, "file")} {
		_, err := OpenAlternateFile(p)
		if !errors.Is(err, ErrAlternateSymlink) {
			t.Errorf("%s: %v; want ErrAlternateSymlink", p, err)
		}
	}
	if _, err := OpenAlternateFile(filepath.Join(links, "dir", "f")); err == nil || !strings.Contains(err.Error(), filepath.Join(real, "f")) {
		t.Errorf("the refusal does not name the resolved path: %v", err)
	}
	f, err := os.Open(filepath.Join(real, "f"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = OpenAlternateFile("/proc/self/fd/" + strconv.Itoa(int(f.Fd()))); err == nil {
		t.Error("a magic link was followed")
	}
	if _, err = OpenAlternateFile(real); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	// A relative path is the command's own directory's.
	t.Chdir(real)
	a, err := OpenAlternateFile("f")
	if err != nil || a.Named != filepath.Join(real, "f") {
		t.Fatalf("a relative path = %+v, %v", a, err)
	}
	_ = a.Close()
}

// The race the descriptor closes: while the agent flips a directory on the way between a real directory and a
// symbolic link to a secret directory, every open the person's command makes is either refused or the real file,
// never the secret.
func TestOpenAlternateFileRaceNeverReachesTheSwappedTarget(t *testing.T) {
	work := t.TempDir()
	secretDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(secretDir, "f"), []byte("the secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var secret unix.Stat_t
	if err := unix.Stat(filepath.Join(secretDir, "f"), &secret); err != nil {
		t.Fatal(err)
	}
	realDir, linkDir, d := filepath.Join(work, "real"), filepath.Join(work, "link"), filepath.Join(work, "d")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "f"), []byte("the stand-in"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secretDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(realDir, d); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; !stop.Load(); i++ {
			// Swap d between the real directory and the link, by rename(2) as an agent in the tree would.
			if i%2 == 0 {
				_ = os.Rename(d, realDir)
				_ = os.Rename(linkDir, d)
			} else {
				_ = os.Rename(d, linkDir)
				_ = os.Rename(realDir, d)
			}
		}
	}()
	opened, refused := 0, 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && opened+refused < 20000 {
		a, err := OpenAlternateFile(filepath.Join(d, "f"))
		if err != nil {
			refused++
			continue
		}
		opened++
		if a.Ino == secret.Ino && a.Dev == uint64(secret.Dev) { //nolint:unconvert
			stop.Store(true)
			<-done
			t.Fatalf("after %d opens the command's open reached the secret through the swapped link", opened)
		}
		_ = a.Close()
	}
	stop.Store(true)
	<-done
	if opened == 0 {
		t.Fatalf("no open succeeded in %d tries; the race was not exercised", refused)
	}
	t.Logf("%d opens of the stand-in, %d refused, none reached the secret", opened, refused)
}

// A request that takes no alternate (a connect, an open the supervisor gave no check), and an alternate the open's
// own check refuses, leave the request pending: the person can answer it another way.
func TestAlternateRefusedLeavesTheRequestPending(t *testing.T) {
	b, dir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
	x := named(t, standIn(t, "x", "x"))
	connect := requestAsync(b, testRequest())
	id := waitAsk(t, dir).AskID
	if _, err := AlternateFor(context.Background(), dir, os.Getpid(), id, x, false); !errors.Is(err, ErrNoAlternate) {
		t.Fatalf("an alternate for a connect: %v", err)
	}
	if pendingCount(t, dir) != 1 {
		t.Fatal("the connect stopped being pending")
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, false, false); err != nil {
		t.Fatal(err)
	}
	if got := decisionWithin(t, connect, 2*time.Second); got.Approved || got.Alternate != "" || got.Reason != ReasonDenied {
		t.Fatalf("the connect = %+v", got)
	}

	open := Request{Op: "open", Target: "/w/a", Rule: "fs.ask[/w]", Hold: HoldOpen, PID: os.Getpid(), TID: os.Getpid()}
	held := requestAsync(b, open)
	id = waitAsk(t, dir).AskID
	if _, err := AlternateFor(context.Background(), dir, os.Getpid(), id, x, false); !errors.Is(err, ErrNoAlternate) {
		t.Fatalf("an alternate for an open with no check: %v", err)
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), id, false, false); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, held, 2*time.Second)

	var mu sync.Mutex
	var checked []string
	chain := named(t, standIn(t, "chain.log", "anchor"))
	refusal := errors.New(chain.Named + " lies inside tego's own state")
	read := requestAsync(b, readRequest(&checked, &mu, map[string]error{chain.Named: refusal}))
	id = waitAsk(t, dir).AskID
	_, err := AlternateFor(context.Background(), dir, os.Getpid(), id, chain, false)
	if !errors.Is(err, ErrBadAlternate) || !strings.Contains(err.Error(), "tego's own state") {
		t.Fatalf("a refused alternate: %v; want ErrBadAlternate with the check's reason", err)
	}
	if pendingCount(t, dir) != 1 {
		t.Fatal("the read stopped being pending after a refused alternate")
	}
	fake := named(t, standIn(t, "fake", "fake"))
	if d, err := AlternateFor(context.Background(), dir, os.Getpid(), id, fake, false); err != nil || d.Alternate != fake.Named {
		t.Fatalf("a second, good alternate = %+v, %v", d, err)
	}
	if got := decisionWithin(t, read, 2*time.Second); got.Alternate != fake.Named {
		t.Fatalf("the read = %+v", got)
	} else {
		got.CloseAlternate()
	}
}

// An alternate path is absolute, clean, bounded and free of control characters, at the client and at the broker
// alike; it is never an approval of the target; and an answer with an alternate passes exactly one descriptor while
// every other packet passes none.
func TestAlternateProtocolBounds(t *testing.T) {
	for _, p := range []string{"", "/", "relative/file", "./x", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\nb", "/a\x1b[31mb", "/a\x7f", "/a\u0085b", "/" + strings.Repeat("a", MaxAlternate)} {
		if ValidAlternate(p) {
			t.Errorf("ValidAlternate(%q) = true", p)
		}
	}
	for _, p := range []string{"/tmp/fake", "/home/u/stand in/credentials", "/ünïcode/fïle"} {
		if !ValidAlternate(p) {
			t.Errorf("ValidAlternate(%q) = false", p)
		}
	}
	nonce := strings.Repeat("a", 32)
	id := "q-" + strings.Repeat("0", 32)
	for name, raw := range map[string]string{
		"an approval with an alternate":  `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"alternate":"/tmp/x"}`,
		"a relative alternate":           `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":false,"alternate":"tmp/x"}`,
		"an unclean alternate":           `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":false,"alternate":"/tmp/../etc/x"}`,
		"a control character":            `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":false,"alternate":"/tmp/a\nb"}`,
		"an alternate that is no string": `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":false,"alternate":7}`,
		"an alternate on a list":         `{"action":"list","nonce":"` + nonce + `","alternate":"/tmp/x"}`,
		"an alternate on a detail":       `{"action":"detail","nonce":"` + nonce + `","ask_id":"` + id + `","alternate":"/tmp/x"}`,
	} {
		if _, err := decodeCommand([]byte(raw)); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: decode accepted it (%v)", name, err)
		}
	}
	good := `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":false,"alternate":"/tmp/x","remember":true}`
	if c, err := decodeCommand([]byte(good)); err != nil || c.Alternate == nil || *c.Alternate != "/tmp/x" || c.Remember == nil || !*c.Remember {
		t.Fatalf("a well-formed alternate: %+v %v", c, err)
	}
	b, dir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
	x := named(t, standIn(t, "x", "x"))
	if _, err := b.answer(context.Background(), id, true, false, x, Peer{PID: 1}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("the broker took an approval with an alternate: %v", err)
	}
	if _, err := AlternateFor(context.Background(), t.TempDir(), os.Getpid(), id, &AlternateFile{Named: "tmp/x"}, false); !errors.Is(err, ErrProtocol) {
		t.Fatalf("the client sent a relative alternate: %v", err)
	}
	if _, err := AlternateFor(context.Background(), t.TempDir(), os.Getpid(), id, nil, false); !errors.Is(err, ErrProtocol) {
		t.Fatalf("the client sent an alternate with no file: %v", err)
	}
	if validRequest(Request{Op: "connect", Target: "1.2.3.4:443", Hold: "connect", PID: 1, TID: 1, Alternates: NewAlternateCheck(func(*AlternateFile) (string, error) { return "", nil })}) {
		t.Fatal("a connect carried an alternate check")
	}
	// The descriptor rule, on the wire: an alternate with no descriptor, and a list with one, are protocol errors,
	// and the request stays pending.
	var mu sync.Mutex
	var checked []string
	held := requestAsync(b, readRequest(&checked, &mu, nil))
	qid := waitAsk(t, dir).AskID
	no, path := false, x.Named
	if _, err := call(context.Background(), dir, os.Getpid(), command{Action: "answer", AskID: qid, Approve: &no, Alternate: &path}, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("an alternate with no descriptor: %v", err)
	}
	if _, err := call(context.Background(), dir, os.Getpid(), command{Action: "list"}, x); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a list with a descriptor: %v", err)
	}
	if _, err := call(context.Background(), dir, os.Getpid(), command{Action: "answer", AskID: qid, Approve: &no}, x); !errors.Is(err, ErrProtocol) {
		t.Fatalf("a denial with a descriptor: %v", err)
	}
	if pendingCount(t, dir) != 1 || len(checked) != 0 {
		t.Fatalf("a malformed packet reached the request (checked %v)", checked)
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), qid, false, false); err != nil {
		t.Fatal(err)
	}
	decisionWithin(t, held, 2*time.Second)
}

// --always with an alternate stands like an approval or a denial: the same operation, rule and exact target, and
// no other, is answered with the same file (the descriptor the person's command passed), each answer its own
// recorded pair naming the answer behind it; a request with another target is held anew. Each standing answer line
// repeats the first answer's alternate path and identity (ADR 0057 D1): the path is the one recorded when the person
// named the file, the file is the one alternate_dev/alternate_ino name, and the fs line names the path at delivery.
func TestAlwaysAlternateDeliversTheSameFileForTheSameKeyOnly(t *testing.T) {
	rec := &recorder{}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	var mu sync.Mutex
	var checked []string
	req := readRequest(&checked, &mu, nil)
	first := requestAsync(b, req)
	id := waitAsk(t, dir).AskID
	fakePath := standIn(t, "fake", "the stand-in")
	fake := named(t, fakePath)
	d, err := AlternateFor(context.Background(), dir, os.Getpid(), id, fake, true)
	if err != nil || d.Alternate != fakePath || !d.Always || !strings.HasSuffix(d.By, " always") {
		t.Fatalf("the always alternate = %+v, %v", d, err)
	}
	f := decisionWithin(t, first, 2*time.Second)
	f.CloseAlternate()
	// The person's command has exited and the path now names another file: the standing answer still delivers
	// the file the person named.
	_ = fake.Close()
	if err := os.Remove(fakePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakePath, []byte("swapped in later"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := b.Request(context.Background(), req)
	if err != nil || again.Alternate != fakePath || again.Approved || again.Reason != "" || again.By != "standing:"+id || !again.Always || again.File == nil {
		t.Fatalf("the identical request = %+v, %v; want the same alternate by standing:%s", again, err, id)
	}
	if c := contentOf(t, again.File); c != "the stand-in" {
		t.Fatalf("the standing alternate delivers %q; want the file the person named", c)
	}
	again.CloseAlternate()
	ev := rec.snapshot()
	if len(ev) != 4 || ev[3].Decision.Alternate != fakePath || ev[3].Decision.By != "standing:"+id || ev[3].Decision.AlternateIno != d.AlternateIno {
		t.Fatalf("ledger events = %+v", ev)
	}
	other := req
	other.Target = "/home/u/.aws/config"
	held := requestAsync(b, other)
	oid := waitAsk(t, dir).AskID
	if oid == id {
		t.Fatal("the other target reused the ask id")
	}
	if _, err := AnswerFor(context.Background(), dir, os.Getpid(), oid, false, false); err != nil {
		t.Fatal(err)
	}
	if got := decisionWithin(t, held, 2*time.Second); got.Alternate != "" || got.Reason != ReasonDenied {
		t.Fatalf("another target took the standing alternate: %+v", got)
	}
	// A scored request is never remembered, an alternate included.
	score := 60
	scored := req
	scored.Score, scored.Target = &score, "/home/u/.aws/other"
	sheld := requestAsync(b, scored)
	sid := waitAsk(t, dir).AskID
	x := named(t, standIn(t, "x", "x"))
	if _, err := AlternateFor(context.Background(), dir, os.Getpid(), sid, x, true); !errors.Is(err, ErrNotRememberable) {
		t.Fatalf("an always alternate for a scored request: %v", err)
	}
	if _, err := AlternateFor(context.Background(), dir, os.Getpid(), sid, x, false); err != nil {
		t.Fatal(err)
	}
	if got := decisionWithin(t, sheld, 2*time.Second); got.Alternate != x.Named || got.Always {
		t.Fatalf("the scored request = %+v", got)
	} else {
		got.CloseAlternate()
	}
	// The broker's close closes the standing descriptor: a later decision from it cannot be made, and is refused.
	s := b.standing[standingKey{req.Op, req.Rule, req.Target, req.Target2}]
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if got := s.decision("q-y"); got.Alternate != "" || got.Reason != ReasonUnavailable || got.File != nil {
		t.Fatalf("a standing alternate after the broker closed = %+v", got)
	}
}

// An alternate whose answer line the ledger refuses delivers nothing and stands for nothing; nor does one the
// broker's shutdown overtakes; nor a standing alternate whose own answer line is refused.
func TestUnrecordedAlternateDeliversNothing(t *testing.T) {
	refuseAnswers := errors.New("ledger refused the line")
	var mu sync.Mutex
	failing := false
	rec := &recorder{fail: func(e Event) error {
		mu.Lock()
		defer mu.Unlock()
		if failing && e.Kind == "answer" {
			return refuseAnswers
		}
		return nil
	}}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	var cmu sync.Mutex
	var checked []string
	req := readRequest(&checked, &cmu, nil)
	fake := named(t, standIn(t, "fake", "fake"))
	mu.Lock()
	failing = true
	mu.Unlock()
	held := requestAsync(b, req)
	id := waitAsk(t, dir).AskID
	// The person is told the answer could not be kept: an error, no decision.
	if d, err := AlternateFor(context.Background(), dir, os.Getpid(), id, fake, true); err == nil || d.Alternate != "" || d.Always {
		t.Fatalf("the unrecorded alternate's answer = %+v, %v", d, err)
	}
	if got := decisionWithin(t, held, 2*time.Second); got.Alternate != "" || got.Reason != ReasonUnavailable || got.File != nil {
		t.Fatalf("an unrecorded alternate reached the requester: %+v", got)
	}
	mu.Lock()
	failing = false
	mu.Unlock()
	// Nothing stood: the next identical request is held.
	next := requestAsync(b, req)
	nid := waitAsk(t, dir).AskID
	if _, err := AlternateFor(context.Background(), dir, os.Getpid(), nid, fake, true); err != nil {
		t.Fatal(err)
	}
	n := decisionWithin(t, next, 2*time.Second)
	n.CloseAlternate()
	// Now one stands; its own answer line refused, the repeat delivers nothing.
	mu.Lock()
	failing = true
	mu.Unlock()
	if got, err := b.Request(context.Background(), req); err == nil || got.Alternate != "" || got.Reason != ReasonUnavailable || got.File != nil {
		t.Fatalf("a standing alternate with an unrecorded answer line = %+v, %v", got, err)
	}
	mu.Lock()
	failing = false
	mu.Unlock()
	// A shutdown that overtakes the answer clears it too.
	cb, cdir := testBroker(t, func(o *Options) { o.Timeout = 30 * time.Second })
	other := requestAsync(cb, req)
	waitAsk(t, cdir)
	if err := cb.Close(); err != nil {
		t.Fatal(err)
	}
	if got := decisionWithin(t, other, 2*time.Second); got.Alternate != "" || got.Approved {
		t.Fatalf("after shutdown = %+v", got)
	}
	dup, err := fake.Dup()
	if err != nil {
		t.Fatal(err)
	}
	if s := (standing{askID: "q-x", alternate: "/tmp/fake", file: dup}).decision("q-y"); s.Reason != "" || s.Approved || s.Alternate != "/tmp/fake" || s.File == nil {
		t.Fatalf("a standing alternate's decision = %+v", s)
	} else {
		s.CloseAlternate()
	}
	_ = dup.Close()
	file, err := fake.Dup()
	if err != nil {
		t.Fatal(err)
	}
	if r := refused(Decision{Approved: true, Always: true, Alternate: "/tmp/fake", AlternateIno: 7, File: file}, ReasonUnavailable); r.Approved || r.Always || r.Alternate != "" || r.AlternateIno != 0 || r.File != nil || r.Reason != ReasonUnavailable {
		t.Fatalf("refused kept a grant: %+v", r)
	}
	if err := file.Control(func(int) error { return nil }); err == nil {
		t.Fatal("refused left the alternate's descriptor open")
	}
}

// An always alternate whose own request is cancelled just after its answer line is written still stands, and stands
// with the file the person named (ADR 0057 D1): the cancellation closes the cancelled request's
// descriptor, never the one the standing answer keeps, so the next identical request is delivered that very file
// after the person's command has exited and the path names another.
func TestAnAlwaysAlternateCancelledAfterItsLineStandsWithTheNamedFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := &recorder{}
	rec.fail = func(e Event) error {
		if e.Kind == "answer" && strings.HasSuffix(e.Decision.By, " always") {
			cancel() // the held open's thread dies while the answer line is being written
		}
		return nil
	}
	b, dir := testBroker(t, func(o *Options) { o.Emit = rec.emit; o.Timeout = 30 * time.Second })
	var mu sync.Mutex
	var checked []string
	req := readRequest(&checked, &mu, nil)
	first := make(chan Decision, 1)
	go func() { d, _ := b.Request(ctx, req); first <- d }()
	id := waitAsk(t, dir).AskID
	fakePath := standIn(t, "fake", "the stand-in")
	fake := named(t, fakePath)
	got, err := AlternateFor(context.Background(), dir, os.Getpid(), id, fake, true)
	if err != nil || !got.Always {
		t.Fatalf("a cancelled always alternate = %+v, %v; want the answer standing", got, err)
	}
	if d := decisionWithin(t, first, 2*time.Second); d.Alternate != "" || d.File != nil || d.Approved {
		t.Fatalf("the cancelled request was delivered something: %+v", d)
	}
	_ = fake.Close()
	if err := os.Remove(fakePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakePath, []byte("swapped in later"), 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := b.Request(context.Background(), req)
	if err != nil || again.Alternate != fakePath || again.By != "standing:"+id || again.File == nil {
		t.Fatalf("the next identical request = %+v, %v; want the standing alternate by standing:%s", again, err, id)
	}
	if c := contentOf(t, again.File); c != "the stand-in" {
		t.Fatalf("the standing alternate delivers %q; want the file the person named", c)
	}
	again.CloseAlternate()
}
