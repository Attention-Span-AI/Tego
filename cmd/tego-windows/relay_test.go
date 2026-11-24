// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/relaymux"
)

var (
	okCode      = strings.Repeat("a", 32)
	okChallenge = strings.Repeat("b", 64)
	okProof     = strings.Repeat("c", 64)
	okLine      = "TEGO_DASHBOARD_OPEN port=8484 code=" + okCode + " challenge=" + okChallenge + " proof=" + okProof + "\n"
)

func TestParseOpenLine(t *testing.T) {
	o, err := parseOpenLine(okLine)
	if err != nil || o.port != 8484 || o.code != okCode || o.challenge != okChallenge || o.proof != okProof {
		t.Fatalf("%+v %v", o, err)
	}
}

// TestParseOpenLineRefuses: the relay opens nothing on a line it does not fully understand, a WSL warning before
// or after the line included.
func TestParseOpenLineRefuses(t *testing.T) {
	for name, s := range map[string]string{
		"empty":             "",
		"no newline":        strings.TrimSuffix(okLine, "\n"),
		"warning first":     "wsl: Failed to start the systemd user session\n" + okLine,
		"warning after":     okLine + "more\n",
		"carriage return":   strings.Replace(okLine, "\n", "\r\n", 1),
		"port zero":         strings.Replace(okLine, "port=8484", "port=0", 1),
		"port too big":      strings.Replace(okLine, "port=8484", "port=65536", 1),
		"port padded":       strings.Replace(okLine, "port=8484", "port=08484", 1),
		"short code":        strings.Replace(okLine, okCode, "abc", 1),
		"upper-case code":   strings.Replace(okLine, okCode, strings.ToUpper(okCode), 1),
		"swapped fields":    strings.Replace(okLine, "port=8484 code="+okCode, "code="+okCode+" port=8484", 1),
		"extra field":       strings.Replace(okLine, "\n", " token="+okCode+"\n", 1),
		"another line kind": strings.Replace(okLine, "TEGO_DASHBOARD_OPEN", "TEGO_DASHBOARD_LINK", 1),
	} {
		if _, err := parseOpenLine(s); err == nil {
			t.Errorf("%s: accepted %q", name, s)
		}
	}
}

func TestParseRelayState(t *testing.T) {
	s, err := parseRelayState([]byte(`{"pid":42,"start":133000000000000000,"port":8484,"exe":"C:\\Users\\p\\AppData\\Local\\Tego\\bin\\tego.exe"}`))
	if err != nil || s.PID != 42 || s.Port != 8484 {
		t.Fatalf("%+v %v", s, err)
	}
	for _, b := range []string{``, `{}`, `{"pid":42,"start":1,"port":0,"exe":"x"}`, `{"pid":42,"port":1,"exe":"x"}`, `not json`} {
		if _, err := parseRelayState([]byte(b)); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

// TestJudgeRelay is the reuse rule: a recorded relay is reused only when it is alive with its recorded creation
// time, runs this program as this user and is the only listener on [::1] at the dashboard's port; any other
// listener means the port is taken and nothing is shared.
func TestJudgeRelay(t *testing.T) {
	const exe = `C:\Users\p\AppData\Local\Tego\bin\tego.exe`
	const sid = "S-1-5-21-1-2-3-1001"
	rec := &relayState{PID: 42, Start: 99, Port: 8484, Exe: exe}
	alive := processFacts{open: true, start: 99, exe: exe, sid: sid}
	mine := []listenerFacts{{addr: "::1", pid: 42}}
	cases := []struct {
		name      string
		rec       *relayState
		proc      processFacts
		port      int
		listeners []listenerFacts
		want      relayVerdict
	}{
		{"nothing recorded, port free", nil, processFacts{}, 8484, nil, relayStart},
		{"nothing recorded, port held", nil, processFacts{}, 8484, []listenerFacts{{addr: "::1", pid: 7}}, relayTaken},
		{"ours", rec, alive, 8484, mine, relayCheck},
		{"ours, path case differs", rec, processFacts{open: true, start: 99, exe: strings.ToUpper(exe), sid: sid}, 8484, mine, relayCheck},
		{"ours, for another port", rec, alive, 9000, nil, relayReplace},
		{"pid reused by another program", rec, processFacts{open: true, start: 100, exe: exe, sid: sid}, 8484, mine, relayTaken},
		{"pid reused, port free", rec, processFacts{open: true, start: 100, exe: `C:\x.exe`, sid: sid}, 8484, nil, relayStart},
		{"another user's tego.exe", rec, processFacts{open: true, start: 99, exe: exe, sid: "S-1-5-21-1-2-3-1002"}, 8484, mine, relayTaken},
		{"recorded pid gone, port free", rec, processFacts{}, 8484, nil, relayStart},
		{"ours, plus a wildcard listener", rec, alive, 8484, append([]listenerFacts{{addr: "::", pid: 6288}}, mine...), relayTaken},
		{"ours, but WSL holds [::1]", rec, alive, 8484, []listenerFacts{{addr: "::1", pid: 6288}}, relayTaken},
		{"listeners unknown", rec, alive, 8484, []listenerFacts{{addr: "unknown"}}, relayTaken},
		{"own user unknown", rec, processFacts{open: true, start: 99, exe: exe, sid: ""}, 8484, mine, relayTaken},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := sid
			if c.name == "own user unknown" {
				s = ""
			}
			if got := judgeRelay(c.rec, c.proc, c.port, c.listeners, exe, s); got != c.want {
				t.Fatalf("got %d, want %d", got, c.want)
			}
		})
	}
}

// TestRelayWords: every failure is one line naming what is missing and the one command to run (R7).
func TestRelayWords(t *testing.T) {
	for _, w := range []string{
		portTakenWords(8484, "nginx.exe (pid 7)"),
		portTakenWords(8484, ""),
		relayFailedWords("Tego's Linux did not answer:\n  EOF"),
		notYourDashboardWords(8484),
		portReservedWords(8484),
	} {
		if strings.Contains(w, "\n") || !strings.Contains(w, "run: tego ") || !strings.HasPrefix(w, "tego: ") {
			t.Errorf("%q", w)
		}
	}
	if w := portReservedWords(8484); !strings.Contains(w, "mirrored networking") || !strings.Contains(w, `%USERPROFILE%\.wslconfig`) {
		t.Errorf("%q", w)
	}
	if !strings.Contains(portTakenWords(8484, ""), "another program") {
		t.Error("an unnamed owner is not called another program")
	}
}

func TestOpensDashboard(t *testing.T) {
	for _, c := range []struct {
		args []string
		want bool
	}{
		{[]string{"dashboard"}, true},
		{[]string{"serve", "--open"}, true},
		{[]string{"dashboard", "--stop"}, false},
		{[]string{"serve"}, false},
		{[]string{"session", "list"}, false},
		{nil, false},
	} {
		if got := opensDashboard(c.args); got != c.want {
			t.Errorf("%v: %v", c.args, got)
		}
	}
}

// relayRig is a relay listener on 127.0.0.1 with its session to an in-process Linux end that echoes every stream
// it accepts and counts them.
func relayRig(t *testing.T, owner func(net.Conn) (uint32, error)) (addr string, streams *atomic.Int32, logs func() string) {
	t.Helper()
	ar, aw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	br, bw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	streams = &atomic.Int32{}
	go func() {
		lin, err := relaymux.Start(br, aw, relaymux.Options{Port: 8484})
		if err != nil {
			return
		}
		for {
			st, err := lin.Accept()
			if err != nil {
				return
			}
			streams.Add(1)
			go func() { _, _ = io.Copy(st, st); _ = st.CloseWrite() }()
		}
	}()
	win, err := relaymux.Start(ar, bw, relaymux.Options{Opener: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := helloPort(win.PeerPort(), 8484); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = win.Close() })
	var b strings.Builder
	var mu sync.Mutex
	go serveRelay(ln, win, owner, func(f string, a ...any) { mu.Lock(); fmt.Fprintf(&b, f+"\n", a...); mu.Unlock() })
	return ln.Addr().String(), streams, func() string { mu.Lock(); defer mu.Unlock(); return b.String() }
}

// TestRelayRefusesBeforeForwarding: a connection whose owner is refused is closed with nothing read from it and
// nothing forwarded, and no stream reaches Linux; an admitted one is carried both ways.
func TestRelayRefusesBeforeForwarding(t *testing.T) {
	refuse := func(net.Conn) (uint32, error) { return 77, errors.New("pid 77 runs as S-1-5-21-1-2-3-1002") }
	addr, streams, logs := relayRig(t, refuse)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: [::1]:8484\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 64))
	_ = c.Close()
	if n != 0 || err == nil {
		t.Fatalf("a refused connection got %d bytes back (%v)", n, err)
	}
	time.Sleep(100 * time.Millisecond)
	if streams.Load() != 0 {
		t.Fatalf("a refused connection reached Linux as %d streams", streams.Load())
	}

	admit := func(net.Conn) (uint32, error) { return 42, nil }
	addr, streams, logs2 := relayRig(t, admit)
	c, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("ping"))
	_ = c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || string(got) != "ping" || streams.Load() != 1 {
		t.Fatalf("admitted connection: %q %v, %d streams", got, err, streams.Load())
	}
	if !strings.Contains(logs(), "refused") || !strings.Contains(logs2(), "admitted") {
		t.Fatalf("logs %q / %q", logs(), logs2())
	}
}

// TestHelloPort: a Linux end that serves another port than the relay was started for is refused.
func TestHelloPort(t *testing.T) {
	if err := helloPort(8484, 8484); err != nil {
		t.Fatal(err)
	}
	if err := helloPort(9000, 8484); err == nil || !strings.Contains(err.Error(), "serves port 9000, not 8484") {
		t.Fatalf("%v", err)
	}
}
