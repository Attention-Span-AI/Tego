// SPDX-License-Identifier: Apache-2.0

//go:build integration

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// otherUID is the second real user of TestPeerUIDRefusesAnotherRealUser: nobody's uid, and its gid.
const otherUID = 65534

// peerClientEnv makes this test binary, re-executed as another uid, that user's client of a dashboard: its value is
// a JSON peerClientJob, and the process prints its peerClientReport as JSON and exits before any test runs.
const peerClientEnv = "TEGO_WEB_TEST_PEER_CLIENT"

func init() {
	if job := os.Getenv(peerClientEnv); job != "" {
		os.Exit(peerClientMain(job))
	}
}

// peerClientJob is the GETs a client makes of the dashboard at Base, in order, on one keep-alive connection.
type peerClientJob struct {
	Base     string
	Requests []peerClientRequest
}

// peerClientRequest is one GET: its path and query, and the Cookie header it carries ("" for none).
type peerClientRequest struct {
	Path, Cookie string
}

// peerClientReport is what a client saw: the ids it ran with, and each request's answer in order.
type peerClientReport struct {
	EUID, EGID int
	Replies    []peerClientReply
}

// peerClientReply is one answer, with the client's own end of the connection it came on (the request's RemoteAddr
// at the server) and whether that connection had carried an earlier request.
type peerClientReply struct {
	Local     string
	Reused    bool
	Status    int
	SetCookie []string
	Body      string
}

// peerClient makes job's requests and returns what it saw, as this process's uid.
func peerClient(job peerClientJob) (peerClientReport, error) {
	tr := &http.Transport{MaxConnsPerHost: 1}
	defer tr.CloseIdleConnections()
	c := &http.Client{Timeout: 10 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rep := peerClientReport{EUID: os.Geteuid(), EGID: os.Getegid()}
	for _, q := range job.Requests {
		var got peerClientReply
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			got.Local, got.Reused = info.Conn.LocalAddr().String(), info.Reused
		}}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet,
			job.Base+q.Path, nil)
		if err != nil {
			return rep, err
		}
		if q.Cookie != "" {
			req.Header.Set("Cookie", q.Cookie)
		}
		resp, err := c.Do(req)
		if err != nil {
			return rep, err
		}
		body, err := io.ReadAll(resp.Body) // all of it, so the next request can go on the same connection
		_ = resp.Body.Close()
		if err != nil {
			return rep, fmt.Errorf("%s: %w", q.Path, err)
		}
		got.Status, got.SetCookie, got.Body = resp.StatusCode, resp.Header.Values("Set-Cookie"), string(body)
		rep.Replies = append(rep.Replies, got)
	}
	return rep, nil
}

// peerClientMain is the re-executed client: it runs the job peerClientEnv holds and prints the report, or says on
// stderr why it could not and returns 2.
func peerClientMain(job string) int {
	var j peerClientJob
	if err := json.Unmarshal([]byte(job), &j); err != nil {
		fmt.Fprintln(os.Stderr, "peer client: the job:", err)
		return 2
	}
	rep, err := peerClient(j)
	if err != nil {
		fmt.Fprintln(os.Stderr, "peer client:", err)
		return 2
	}
	if err := json.NewEncoder(os.Stdout).Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, "peer client:", err)
		return 2
	}
	return 0
}

// peerClientAs runs job in a copy of this test binary that every uid can execute, started as uid (with gid uid and no
// supplementary groups), and returns its report.
func peerClientAs(t *testing.T, job peerClientJob, uid uint32) peerClientReport {
	t.Helper()
	b, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, testutil.ExecutableForAnyUID(t), "-test.run=^$")
	cmd.Env = append(os.Environ(), peerClientEnv+"="+string(b))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("the uid %d client: %v: %s", uid, err, exit.Stderr)
		}
		t.Fatalf("the uid %d client: %v", uid, err)
	}
	var rep peerClientReport
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("the uid %d client's report %q: %v", uid, out, err)
	}
	return rep
}

// TestPeerUIDRefusesAnotherRealUser is TestPeerUIDRefusesOtherUser on the kernel's own tcp table instead of a fake
// one (F21). The dashboard is served with the real peer check, and two clients make the same two requests, each on a
// keep-alive connection of its own: a sign-in with the right token, then /status.json with the session's cookie.
// The serving user's own client goes first and gets the session and the status. Then a client of a second real uid,
// this test binary re-executed as nobody, gets the 403 page and no cookie for both: each page names that client's
// own socket and uid 65534, so the check found the socket's row and read the uid the kernel gave it (a missed row
// says "no socket", which fails closed too but proves nothing). The second refusal came on the same connection as
// the first, so a refused connection is not let in by its next request (peerOnce keeps a pass only), and the pass
// kept on the serving user's connection reached no other connection.
//
// It needs root to start a process as another uid: test/vm/root-suites.sh runs it in a KVM guest, and CI's
// root-suites job under sudo. The dashboard then serves uid 0, which tego-control never does (it refuses root,
// ADR 0100 (1b)); the check only compares the socket's uid with the serving one, and holds no uid apart.
func TestPeerUIDRefusesAnotherRealUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the other user's client is started as uid 65534 (test/vm/root-suites.sh runs it)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := New(Config{Ledger: t.TempDir(), Port: port, Token: "tok123"})
	if err != nil {
		t.Fatal(err)
	}
	// The peer check stays New's, over the kernel's tables. The governed check (governed_test.go) is let pass, so
	// the serving user's sign-in shows the peer check's verdict alone; it is never asked for the other user, whose
	// requests the peer check answers first.
	s.governed = func(*http.Request) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, s) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	job := peerClientJob{Base: fmt.Sprintf("http://127.0.0.1:%d", port), Requests: []peerClientRequest{
		{Path: "/?t=tok123"},
		{Path: "/status.json", Cookie: s.cookie + "=" + s.session},
	}}

	own, err := peerClient(job)
	if err != nil {
		t.Fatalf("the serving user's own client: %v", err)
	}
	if r := own.Replies; len(r) != 2 || r[0].Status != http.StatusSeeOther || len(r[0].SetCookie) == 0 ||
		r[1].Status != http.StatusOK {
		t.Fatalf("the serving user's own client: %+v, want the sign-in's 303 with the session cookie, then 200", r)
	}

	other := peerClientAs(t, job, otherUID)
	if other.EUID != otherUID || other.EGID != otherUID {
		t.Fatalf("the other user's client ran as uid %d gid %d, want %d", other.EUID, other.EGID, otherUID)
	}
	if len(other.Replies) != len(job.Requests) {
		t.Fatalf("the other user's client: %d answers for %d requests: %+v", len(other.Replies), len(job.Requests), other.Replies)
	}
	for i, r := range other.Replies {
		if r.Status != http.StatusForbidden || len(r.SetCookie) != 0 {
			t.Errorf("%s from uid %d: %d with cookies %q, want 403 and none: %s", job.Requests[i].Path, otherUID, r.Status,
				r.SetCookie, r.Body)
		}
		for _, want := range []string{"serves only the user who started it", fmt.Sprintf(
			"the connection from %s belongs to uid %d, and this dashboard serves uid %d", r.Local, otherUID, os.Geteuid())} {
			if !strings.Contains(r.Body, want) {
				t.Errorf("%s from uid %d: the 403 page lacks %q:\n%s", job.Requests[i].Path, otherUID, want, r.Body)
			}
		}
	}
	if r := other.Replies; !r[1].Reused || r[1].Local != r[0].Local {
		t.Errorf("the other user's second request came on another connection (%s after %s, reused %v): "+
			"a refused connection's next request went unchecked", r[1].Local, r[0].Local, r[1].Reused)
	}
}
