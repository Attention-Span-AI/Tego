// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/relaymux"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRelayScope is the Linux end's in-run decision: the rule's answer first; past its answer that it cannot tell, for a
// private cgroup namespace (WSL's), only a process whose path is no run's and whose socket the dashboard's own
// governed check admits.
func TestRelayScope(t *testing.T) {
	const scope = "0::/user.slice/user-26743.slice/user@26743.service/app.slice/run-u7.scope\n"
	const inRun = "0::/user.slice/user-26743.slice/user@26743.service/tego.slice/tego-bot.slice/run-r-1.scope\n"
	// What the rule answers for a process in WSL's private cgroup namespace: it cannot tell.
	unknown := answertest.Recorded(runscope.CauseWSLLauncherUnproven, 0)
	admitted := func() error { return nil }
	governed := func() error { return errors.New("403: a governed agent cannot change its own governance (run r-1)") }
	cases := []struct {
		name   string
		answer runscope.Answer
		cgroup string
		readEr error
		prove  func() error
		ok     bool
	}{
		{name: "outside, initial namespace", answer: answertest.Outside(), prove: governed, ok: true},
		{name: "inside a run", answer: answertest.Inside(runscope.CauseGoverned), prove: admitted},
		{name: "private namespace, the dashboard admits it", answer: unknown, cgroup: scope, prove: admitted, ok: true},
		{name: "private namespace, the dashboard refuses it", answer: unknown, cgroup: scope, prove: governed},
		{name: "private namespace, inside a run", answer: unknown, cgroup: inRun, prove: admitted},
		{name: "private namespace, above its root", answer: unknown, cgroup: "0::/../x\n", prove: admitted},
		{name: "private namespace, cgroup unreadable", answer: unknown, readEr: errors.New("EIO"), prove: admitted},
		{name: "private namespace, two cgroup paths", answer: unknown, cgroup: scope + "0::/x\n", prove: admitted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proved := false
			s := relayScope{
				answer:     func() runscope.Answer { return c.answer },
				selfCgroup: func() ([]byte, error) { return []byte(c.cgroup), c.readEr },
			}
			err := s.outsideRuns(func() error { proved = true; return c.prove() })
			if (err == nil) != c.ok {
				t.Fatalf("outsideRuns: %v, want allowed %v", err, c.ok)
			}
			if proved && c.answer.Outside() {
				t.Fatal("asked the dashboard when the rule had decided")
			}
			if proved && !runscope.CouldNotTell(c.answer) {
				t.Fatal("asked the dashboard about a process the rule showed inside a run")
			}
		})
	}
}

// TestRelayRefusesInsideARun: the command refuses before reading anything when it is inside a run.
func TestRelayRefusesInsideARun(t *testing.T) {
	onFixture(t, "fresh")
	old := selfAnswer
	t.Cleanup(func() { selfAnswer = old })
	selfAnswer = func() runscope.Answer { return answertest.Inside(runscope.CauseGoverned) }
	for _, mode := range []string{"serve", "open"} {
		code, out, errs := run(t, "dashboard-relay", mode)
		if code != identity.ExitError || out != "" || !strings.Contains(errs, "inside a tego run") {
			t.Fatalf("%s inside a run: exit %d stdout %q stderr %q", mode, code, out, errs)
		}
	}
	if code, _, _ := run(t, "dashboard-relay", "connect"); code != identity.ExitUsage {
		t.Fatalf("an unknown mode: exit %d, want usage", code)
	}
}

// TestRelayTargetIsTheDashboard: the relay dials only the address the dashboard's own log names on 127.0.0.1, and
// only once that dashboard proved its token; nothing else is a target.
func TestRelayTargetIsTheDashboard(t *testing.T) {
	proof := func(string, string) (string, error) { return "", nil }
	for name, link := range map[string]string{
		"not running":     "",
		"another address": "http://10.0.0.5:8484/?t=" + strings.Repeat("a", 32),
		"no port":         "http://127.0.0.1/?t=" + strings.Repeat("a", 32),
		"no token":        "http://127.0.0.1:8484/",
		"short token":     "http://127.0.0.1:8484/?t=abc",
	} {
		if _, err := findRelayTarget("/h", func(string) (string, bool) { return link, true }, proof); err == nil {
			t.Errorf("%s: %q accepted as the relay's target", name, link)
		}
	}
	tok := strings.Repeat("b", 32)
	got, err := findRelayTarget("/h", func(string) (string, bool) { return "http://127.0.0.1:8484/?t=" + tok, false }, proof)
	if err != nil || got.port != 8484 || got.token != tok {
		t.Fatalf("the dashboard's link: %+v %v", got, err)
	}
}

// fakeDashboard is a loopback HTTP server standing in for the dashboard: it answers every request with the remote
// address it saw, and mints open codes for the bearer token.
func fakeDashboard(t *testing.T, token string) (*httptest.Server, int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_tego/open-code" {
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "an open code needs the dashboard's sign-in token", http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, strings.Repeat("c", 32)+"\n")
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "dashboard saw "+r.Method+" "+r.URL.Path+" "+string(body))
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return srv, port
}

// relayPair starts a serve-mode Linux end over kernel pipes and returns the Windows end's session.
func relayPair(t *testing.T, r *relayServer) (*relaymux.Session, chan int) {
	t.Helper()
	ar, aw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	br, bw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	code := make(chan int, 1)
	go func() { code <- r.serve(context.Background(), br, aw, io.Discard) }()
	win, err := relaymux.Start(ar, bw, relaymux.Options{Opener: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = win.Close() })
	return win, code
}

func httpThrough(t *testing.T, win *relaymux.Session, req string) (string, error) {
	t.Helper()
	st, err := win.Open()
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()
	if _, err := io.WriteString(st, req); err != nil {
		return "", err
	}
	_ = st.CloseWrite()
	b, err := io.ReadAll(st)
	return string(b), err
}

// TestRelayCarriesToTheDashboard: a stream reaches the dashboard's port through a connection the Linux end made,
// whatever the Windows end asks for; the Windows end learns the port from HELLO.
func TestRelayCarriesToTheDashboard(t *testing.T) {
	tok := strings.Repeat("d", 32)
	_, port := fakeDashboard(t, tok)
	target := relayTarget{port: port, token: tok}
	r := &relayServer{target: target, find: func(string) (relayTarget, error) { return target, nil }, dial: dialDashboard}
	win, _ := relayPair(t, r)
	if int(win.PeerPort()) != port {
		t.Fatalf("HELLO port %d, want %d", win.PeerPort(), port)
	}
	got, err := httpThrough(t, win, "POST /approve HTTP/1.0\r\nHost: [::1]:"+strconv.Itoa(port)+"\r\nContent-Length: 2\r\n\r\nok")
	if err != nil || !strings.Contains(got, "200 OK") || !strings.Contains(got, "dashboard saw POST /approve ok") {
		t.Fatalf("through the relay: %v\n%s", err, got)
	}
}

// TestRelayEndsWhenTheDashboardGoes: a dashboard that stopped, or answers on another port, ends the relay with a
// GOAWAY that says so, at the next stream after the recheck interval.
func TestRelayEndsWhenTheDashboardGoes(t *testing.T) {
	tok := strings.Repeat("e", 32)
	_, port := fakeDashboard(t, tok)
	for name, c := range map[string]struct {
		find func(string) (relayTarget, error)
		want string
	}{
		"stopped": {func(string) (relayTarget, error) { return relayTarget{}, errors.New("the dashboard is not running") }, "the dashboard stopped"},
		"moved":   {func(string) (relayTarget, error) { return relayTarget{port: port + 1, token: tok}, nil }, "moved to port"},
	} {
		t.Run(name, func(t *testing.T) {
			r := &relayServer{target: relayTarget{port: port, token: tok}, find: c.find, dial: dialDashboard}
			win, code := relayPair(t, r)
			for range relayMisses {
				r.mu.Lock()
				r.checked = time.Now().Add(-2 * relayRecheck)
				r.mu.Unlock()
				_, _ = httpThrough(t, win, "GET / HTTP/1.0\r\n\r\n")
				if name == "moved" {
					break // another port ends the relay at once
				}
			}
			select {
			case <-win.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the relay outlived its dashboard")
			}
			if err := win.Err(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ended with %v, want %q", err, c.want)
			}
			if got := <-code; got != identity.ExitOK {
				t.Fatalf("serve exit %d", got)
			}
		})
	}
}

// TestRelayMissRefusesOnlyThatStream: one identity check the dashboard does not answer refuses that stream and
// keeps the relay; the next good check carries streams again.
func TestRelayMissRefusesOnlyThatStream(t *testing.T) {
	tok := strings.Repeat("e", 32)
	_, port := fakeDashboard(t, tok)
	good := relayTarget{port: port, token: tok}
	answers := []error{errors.New("no proof within 3s"), nil}
	r := &relayServer{target: good, dial: dialDashboard, find: func(string) (relayTarget, error) {
		err := answers[0]
		answers = answers[1:]
		return good, err
	}}
	win, _ := relayPair(t, r)
	for i, want := range []string{"did not prove itself", "dashboard saw GET /"} {
		r.mu.Lock()
		r.checked = time.Now().Add(-2 * relayRecheck)
		r.mu.Unlock()
		got, err := httpThrough(t, win, "GET / HTTP/1.0\r\n\r\n")
		if err != nil {
			got = err.Error()
		}
		if !strings.Contains(got, want) {
			t.Fatalf("stream %d: %q, want %q", i, got, want)
		}
	}
	select {
	case <-win.Done():
		t.Fatalf("one miss ended the relay: %v", win.Err())
	default:
	}
}

// TestRelayDialFailureAbortsTheStream: a dashboard that cannot be reached aborts that stream with the reason.
func TestRelayDialFailureAbortsTheStream(t *testing.T) {
	target := relayTarget{port: 1, token: strings.Repeat("f", 32)}
	r := &relayServer{target: target, find: func(string) (relayTarget, error) { return target, nil },
		dial: func(context.Context, int) (net.Conn, error) { return nil, errors.New("connection refused") }}
	win, _ := relayPair(t, r)
	_, err := httpThrough(t, win, "GET / HTTP/1.0\r\n\r\n")
	if err == nil || !strings.Contains(err.Error(), "the dashboard could not be reached: connection refused") {
		t.Fatalf("read: %v", err)
	}
}

// TestRelayOpenLine: open mode prints the one line the Windows command parses, with the code the dashboard minted
// for the token and the proof for a fresh challenge; a dashboard that refuses the token gives no line.
func TestRelayOpenLine(t *testing.T) {
	tok := strings.Repeat("a", 32)
	_, port := fakeDashboard(t, tok)
	var challenged string
	proof := func(token, challenge string) (string, error) {
		challenged = challenge
		return strings.Repeat("9", 64), nil
	}
	var out, errs bytes.Buffer
	if code := relayOpen(context.Background(), relayTarget{port: port, token: tok, proof: proof}, "", &out, &errs); code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	want := relayOpenLine + " port=" + strconv.Itoa(port) + " code=" + strings.Repeat("c", 32) + " challenge=" + challenged +
		" proof=" + strings.Repeat("9", 64) + "\n"
	if out.String() != want || len(challenged) != 64 || strings.Contains(out.String(), tok) {
		t.Fatalf("open line %q, want %q, never the token", out.String(), want)
	}
	out.Reset()
	if code := relayOpen(context.Background(), relayTarget{port: port, token: strings.Repeat("b", 32), proof: proof}, "", &out, &errs); code == identity.ExitOK || out.Len() != 0 {
		t.Fatalf("a refused token: exit %d, stdout %q", code, out.String())
	}
}
