// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/relaymux"
)

// The Windows dashboard relay (docs/adr/0123-dashboard-threat-model.md, "A browser on Windows"). `tego dashboard`
// starts or reuses one hidden `tego.exe __relay <port>`: it listens on [::1]:<port> only, the dashboard's own port,
// with SO_EXCLUSIVEADDRUSE, admits a connection only when its client end belongs to a process of this Windows user
// (internal/platform/winpeer), and carries every admitted connection over one long-lived wsl.exe child to
// `tego dashboard-relay serve` in Tego's Linux (internal/relaymux). This file holds what the Windows code decides,
// as pure functions over what it read, so they are tested on Linux.

// opensDashboard reports whether the command asks for the dashboard in the browser: tego dashboard, and tego serve
// --open, which Tego's Linux runs as tego dashboard.
func opensDashboard(args []string) bool {
	return len(args) == 1 && args[0] == "dashboard" || len(args) == 2 && args[0] == "serve" && args[1] == "--open"
}

// openLinePrefix starts the line `tego dashboard-relay open` prints (internal/cli dashboard_relay.go).
const openLinePrefix = "TEGO_DASHBOARD_OPEN "

// openInfo is that line: the dashboard's port, a one-time open code, and a fresh identity challenge with the proof
// the person's dashboard gives for it.
type openInfo struct {
	port      int
	code      string
	challenge string
	proof     string
}

// parseOpenLine reads the helper's output: exactly one line of the fixed shape, nothing else. Anything else (WSL's
// own warnings included) is refused rather than searched for a match.
func parseOpenLine(out string) (openInfo, error) {
	line, ok := strings.CutSuffix(out, "\n")
	if !ok || strings.ContainsAny(line, "\r\n") || !strings.HasPrefix(line, openLinePrefix) {
		return openInfo{}, errors.New("the dashboard's answer was not one open line")
	}
	f := strings.Fields(strings.TrimPrefix(line, openLinePrefix))
	if len(f) != 4 {
		return openInfo{}, errors.New("the open line has the wrong number of fields")
	}
	var o openInfo
	want := []string{"port", "code", "challenge", "proof"}
	for i, kv := range f {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k != want[i] {
			return openInfo{}, fmt.Errorf("the open line's field %d is not %s", i+1, want[i])
		}
		switch k {
		case "port":
			p, err := strconv.Atoi(v)
			if err != nil || p <= 0 || p > 65535 || strconv.Itoa(p) != v {
				return openInfo{}, errors.New("the open line's port is not a port")
			}
			o.port = p
		case "code":
			o.code = v
		case "challenge":
			o.challenge = v
		case "proof":
			o.proof = v
		}
	}
	if !lowerHex(o.code, 32) || !lowerHex(o.challenge, 64) || !lowerHex(o.proof, 64) {
		return openInfo{}, errors.New("the open line's code, challenge or proof is malformed")
	}
	return o, nil
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// relayState is what a running relay records in %LOCALAPPDATA%\Tego\relay.json: its pid, its process creation time
// (the identity that tells it from a later process given the same pid), the port it serves and its program.
type relayState struct {
	PID   uint32 `json:"pid"`
	Start uint64 `json:"start"`
	Port  int    `json:"port"`
	Exe   string `json:"exe"`
}

func parseRelayState(b []byte) (relayState, error) {
	var s relayState
	if err := json.Unmarshal(b, &s); err != nil {
		return relayState{}, err
	}
	if s.PID == 0 || s.Start == 0 || s.Port <= 0 || s.Port > 65535 || s.Exe == "" {
		return relayState{}, errors.New("the relay record is incomplete")
	}
	return s, nil
}

// processFacts is what Windows says about a pid: whether it could be opened, its creation time, program and user.
type processFacts struct {
	open  bool
	start uint64
	exe   string
	sid   string
}

// listenerFacts is one listener on the relay's port: its address and the pid that owns it.
type listenerFacts struct {
	addr string // "::1", "::", "127.0.0.1", "0.0.0.0" or another
	pid  uint32
}

// relayVerdict is what `tego dashboard` does about the relay it finds.
type relayVerdict int

const (
	relayStart   relayVerdict = iota // none is running, and the port is free: start one
	relayCheck                       // ours: reuse it once the identity challenge through it passes
	relayReplace                     // ours, but for another port: stop it, then start one
	relayTaken                       // another program listens on the port: open nothing
)

// judgeRelay decides from the record (nil when there is none), the facts about the recorded pid, the listeners on
// [::1] or [::] at the dashboard's port, this program's path and this user's SID. A relay is ours only when the
// recorded pid is alive with the recorded creation time, runs this program as this user, and is the only listener
// on the port. Any other listener there, whoever owns it, means the port is taken: R1's relay never shares it.
func judgeRelay(rec *relayState, proc processFacts, port int, listeners []listenerFacts, exe, sid string) relayVerdict {
	ours := rec != nil && proc.open && proc.start == rec.Start && sameProgram(proc.exe, exe) && sameProgram(rec.Exe, exe) &&
		proc.sid == sid && sid != ""
	if ours && rec.Port != port {
		return relayReplace
	}
	if len(listeners) == 0 {
		return relayStart
	}
	if ours && len(listeners) == 1 && listeners[0].pid == rec.PID && listeners[0].addr == "::1" {
		return relayCheck
	}
	return relayTaken
}

// sameProgram compares two Windows paths as Windows does: case-insensitively, after the full-path forms Windows
// itself reports.
func sameProgram(a, b string) bool {
	return a != "" && strings.EqualFold(a, b)
}

// Words the person reads (R7): one line, what is missing and the one command to run.
func portTakenWords(port int, owner string) string {
	if owner == "" {
		owner = "another program"
	}
	return fmt.Sprintf("tego: port %d on this computer is used by %s, so the dashboard cannot open in your browser; close it, then run: tego dashboard", port, owner)
}

// portReservedWords is the bind refusal when no program listens on the port: measured in WSL 3.0.5's mirrored
// networking, where a Linux listener on 127.0.0.1:<port> (the dashboard's own) reserves the port on Windows for
// every address, so [::1]:<port> cannot be bound while the dashboard runs (docs/adr/0123, "A browser on Windows").
func portReservedWords(port int) string {
	return fmt.Sprintf("tego: port %d on this computer is reserved though no Windows program listens there, as WSL's mirrored networking does for the dashboard's own port, so the dashboard cannot open in your browser; it needs WSL's default networking (networkingMode=nat in %%USERPROFILE%%\\.wslconfig, then wsl --shutdown), and meanwhile the terminal shows your sessions: run: tego session list", port)
}

func relayFailedWords(cause string) string {
	return "tego: the dashboard's private connection to your browser did not start (" + oneLine(cause) + "); run: tego dashboard"
}

func notYourDashboardWords(port int) string {
	return fmt.Sprintf("tego: the connection on [::1]:%d does not reach your dashboard; run: tego dashboard --stop, then: tego dashboard", port)
}

// oneLine is s on one line, at most 300 bytes, for a cause inside a sentence.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// serveRelay accepts on ln until it is closed. Each connection must pass owner (R2 on Windows) before one byte is
// read from it or forwarded; a refused one is closed as it is. An admitted one rides its own stream.
func serveRelay(ln net.Listener, sess *relaymux.Session, owner func(net.Conn) (uint32, error), logf func(string, ...any)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go admit(c, sess, owner, logf)
	}
}

func admit(c net.Conn, sess *relaymux.Session, owner func(net.Conn) (uint32, error), logf func(string, ...any)) {
	defer func() { _ = c.Close() }()
	pid, err := owner(c)
	if err != nil {
		logf("refused %s: %v", c.RemoteAddr(), err)
		return
	}
	logf("admitted %s (pid %d)", c.RemoteAddr(), pid)
	st, err := sess.Open()
	if err != nil {
		logf("no stream for %s (pid %d): %v", c.RemoteAddr(), pid, err)
		return
	}
	defer func() { _ = st.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(c, st); err != nil {
			_ = c.Close()
			return
		}
		if hc, ok := c.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}()
	if _, err := io.Copy(st, c); err != nil {
		_ = st.Abort("the browser's connection failed")
	} else {
		_ = st.CloseWrite()
	}
	<-done
}

// helloPort is the check of the Linux end's HELLO: it must announce the port the relay was started for, the
// dashboard's own; another means the dashboard moved, and the relay refuses rather than serve the old port.
func helloPort(announced uint16, port int) error {
	if int(announced) != port {
		return fmt.Errorf("the dashboard serves port %d, not %d", announced, port)
	}
	return nil
}
