// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/winpeer"
	"golang.org/x/sys/windows"
)

// openDashboard opens the person's dashboard in their browser, after the Linux `tego dashboard` (or the guide) has
// started or reused it: it asks Tego's Linux for the port and a one-time open code, starts or reuses the relay,
// proves the relay reaches the person's dashboard, then opens http://[::1]:<port>/?o=<code>. On any failure it
// prints one line (R7) and opens nothing.
func openDashboard() int {
	info, err := dashboardOpenInfo()
	if err != nil {
		fmt.Fprintln(os.Stderr, relayFailedWords(err.Error()))
		return 125
	}
	got := time.Now()
	if code := ensureRelay(info); code != 0 {
		return code
	}
	if time.Since(got) > openCodeFresh {
		// A cold relay start can outlast the code's minute: ask for a fresh one, for the same port.
		fresh, err := dashboardOpenInfo()
		if err != nil || fresh.port != info.port {
			fmt.Fprintln(os.Stderr, relayFailedWords("the dashboard changed while its connection started"))
			return 125
		}
		info = fresh
	}
	link := "http://[::1]:" + strconv.Itoa(info.port) + "/?o=" + info.code
	if err := openBrowser(link); err != nil {
		fmt.Fprintln(os.Stderr, "tego: your browser did not open ("+oneLine(err.Error())+"); run: tego dashboard")
		return 125
	}
	fmt.Println("Opened the dashboard in your browser.")
	return 0
}

// openCodeFresh is how old an open code may be when the browser is opened: the dashboard honours one for 60 s
// (web/opencode.go), and a browser takes some seconds to start.
const openCodeFresh = 40 * time.Second

// errLinuxSilent is shown to the person as it is; Tego is a name, so the message starts with a capital.
var errLinuxSilent = errors.New("Tego's Linux did not answer within 90 seconds") //nolint:staticcheck // ST1005: a name, not a sentence start

// dashboardOpenInfo runs `windows-entry --dashboard-open` (`tego dashboard-relay open` in the person's scope) and
// reads its one line from a private pipe.
func dashboardOpenInfo() (openInfo, error) {
	cmd := proc.Command(systemProgram("wsl.exe"), append(wslBaseArguments(), "--dashboard-open")...)
	var stdout, stderr startupLog
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := startWindowsCommand(cmd); err != nil {
		return openInfo{}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			cause := strings.TrimSpace(string(stderr.data))
			if cause == "" {
				cause = err.Error()
			}
			return openInfo{}, errors.New(cause)
		}
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		<-done //nolint:errcheck // the killed child's status says nothing more
		return openInfo{}, errLinuxSilent
	}
	return parseOpenLine(string(stdout.data))
}

// ensureRelay leaves one relay of this user serving info.port and proven to reach the person's dashboard, or says
// why not and returns nonzero.
func ensureRelay(info openInfo) int {
	sid, err := winpeer.SelfUser()
	if err != nil {
		fmt.Fprintln(os.Stderr, relayFailedWords("this Windows user could not be read: "+err.Error()))
		return 125
	}
	exe := processImage(uint32(os.Getpid()))
	for attempt := 0; ; attempt++ {
		if attempt > 3 {
			fmt.Fprintln(os.Stderr, relayFailedWords("the previous relay could not be stopped"))
			return 125
		}
		rec := readRelayState()
		var facts processFacts
		if rec != nil {
			facts = readProcess(rec.PID)
		}
		listeners := listenersOn(info.port)
		switch judgeRelay(rec, facts, info.port, listeners, exe, sid) {
		case relayTaken:
			owner, _ := portOwner(info.port)
			fmt.Fprintln(os.Stderr, portTakenWords(info.port, owner))
			return 1
		case relayReplace:
			stopRelayProcess(*rec)
			continue
		case relayCheck:
			if challengeAnswered(info) {
				return 0
			}
			if attempt > 0 {
				fmt.Fprintln(os.Stderr, notYourDashboardWords(info.port))
				return 1
			}
			stopRelayProcess(*rec) // ours but not reaching the dashboard: repair once
			continue
		case relayStart:
			if attempt > 1 {
				fmt.Fprintln(os.Stderr, relayFailedWords("the relay did not stay up"))
				return 125
			}
			if err := startRelay(info.port); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return 125
			}
			if !challengeAnswered(info) {
				fmt.Fprintln(os.Stderr, notYourDashboardWords(info.port))
				return 1
			}
			return 0
		}
	}
}

// listenersOn are the IPv6 listeners on port: [::1] and [::] are the ones that can answer [::1].
func listenersOn(port int) []listenerFacts {
	rows, err := winpeer.Listeners()
	if err != nil {
		// Unknown listeners: report one that is no relay's, so judgeRelay refuses rather than guesses.
		return []listenerFacts{{addr: "unknown"}}
	}
	var out []listenerFacts
	for _, r := range rows {
		if int(r.Local.Port()) == port {
			out = append(out, listenerFacts{addr: r.Local.Addr().WithZone("").String(), pid: r.PID})
		}
	}
	return out
}

// challengeAnswered sends the helper's fresh challenge through [::1]:port, naming the dashboard's own Host, and
// reports whether the answer is the proof only the person's dashboard can give.
func challengeAnswered(info openInfo) bool {
	port := strconv.Itoa(info.port)
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "tcp6", net.JoinHostPort("::1", port))
	}}
	client := &http.Client{Timeout: 15 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirects are refused")
	}}
	defer tr.CloseIdleConnections()
	resp, err := client.Get("http://127.0.0.1:" + port + "/_tego/identity?challenge=" + info.challenge)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 257))
	return err == nil && resp.StatusCode == http.StatusOK && string(b) == info.proof
}

// startRelay starts `tego.exe __relay <port>` with no console window, outside the caller's console, process group
// and (where Windows allows it) job, so it outlives this command and its terminal, and waits for its one status line.
func startRelay(port int) error {
	self, err := os.Executable()
	if err != nil {
		return errors.New(relayFailedWords(err.Error()))
	}
	flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP)
	cmd, out, err := startHidden(self, port, flags|windows.CREATE_BREAKAWAY_FROM_JOB)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		// The caller's job does not allow breakaway; the relay then ends with that job.
		cmd, out, err = startHidden(self, port, flags)
	}
	if err != nil {
		return errors.New(relayFailedWords(err.Error()))
	}
	defer func() { _ = out.Close(); _ = cmd.Process.Release() }()
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReaderSize(out, 4096).ReadString('\n')
		line <- strings.TrimRight(s, "\r\n")
	}()
	select {
	case s := <-line:
		if s == "READY" {
			return nil
		}
		if words, ok := strings.CutPrefix(s, "FAIL "); ok {
			return errors.New(words)
		}
		return errors.New(relayFailedWords("the relay ended before it was ready"))
	case <-time.After(150 * time.Second):
		_ = cmd.Process.Kill()
		return errors.New(relayFailedWords("the relay was not ready within 150 seconds"))
	}
}

func startHidden(self string, port int, flags uint32) (*proc.Cmd, io.ReadCloser, error) {
	cmd := proc.Command(self, relayVerb, strconv.Itoa(port))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := startWindowsCommand(cmd); err != nil {
		_ = out.Close()
		return nil, nil, err
	}
	return cmd, out, nil
}

// openBrowser hands the link to Windows' handler for http links, the person's default browser.
func openBrowser(link string) error {
	cmd := proc.Command(systemProgram("rundll32.exe"), "url.dll,FileProtocolHandler", link)
	if err := startWindowsCommand(cmd); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		return nil // the handler is still busy starting the browser; it has the link
	}
}

func readRelayState() *relayState {
	p, err := relayStatePath()
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	s, err := parseRelayState(b)
	if err != nil {
		return nil
	}
	return &s
}

// stopRelayProcess ends the recorded relay, only when the pid still is that relay (same creation time, this
// program, this user), and removes its record.
func stopRelayProcess(rec relayState) bool {
	sid, _ := winpeer.SelfUser()
	f := readProcess(rec.PID)
	exe := processImage(uint32(os.Getpid()))
	if !f.open || f.start != rec.Start || !sameProgram(f.exe, exe) || f.sid != sid || sid == "" {
		removeStaleRelayState(rec)
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, rec.PID)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if start, err := handleCreationTime(h); err != nil || start != rec.Start {
		return false // the pid was reused between the check and the open
	}
	_ = windows.TerminateProcess(h, 0)
	_, _ = windows.WaitForSingleObject(h, 10000)
	removeStaleRelayState(rec)
	return true
}

func handleCreationTime(h windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

// removeStaleRelayState removes the record when it still is rec.
func removeStaleRelayState(rec relayState) {
	if cur := readRelayState(); cur != nil && *cur == rec {
		if p, err := relayStatePath(); err == nil {
			_ = os.Remove(p)
		}
	}
}

// wslOutput runs a system program (wsl.exe) with argv, in the person's session, and returns what it printed on standard
// output; the program is ended when limit passes. Standard error is dropped: WSL's own warnings are not an answer.
func wslOutput(argv []string, limit time.Duration) (string, error) {
	cmd := proc.Command(systemProgram("wsl.exe"), argv...)
	cmd.Env = append(os.Environ(), "WSL_UTF8=1")
	var stdout startupLog
	cmd.Stdout = &stdout
	if err := startWindowsCommand(cmd); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return string(stdout.data), err
	case <-time.After(limit):
		_ = cmd.Process.Kill()
		<-done //nolint:errcheck // the killed child's status says nothing more
		return string(stdout.data), errors.New("wsl.exe did not answer in time")
	}
}

// linuxRunning reports whether Tego's distribution is running, without starting it. When wsl.exe cannot say, it is
// taken as running: the command that follows then starts it, which is harmless.
func linuxRunning() bool {
	out, err := wslOutput([]string{"--list", "--running", "--quiet"}, 20*time.Second)
	return err != nil && out == "" || listsDistribution([]byte(out), "tego")
}

// releaseLinux asks Tego's Linux to stop what the dashboard command started there, unless a run is going
// (`tego dashboard-relay release`, through the same fixed entry as every command, inside the user scope).
func releaseLinux() releaseResult {
	argv, err := wslArguments([]string{"dashboard-relay", "release"})
	if err != nil {
		return releaseResult{}
	}
	out, _ := wslOutput(argv, 60*time.Second)
	return parseReleaseLine(out)
}

// linuxMirrored reports whether WSL's networking is mirrored, asked of the running WSL (`wslinfo --networking-mode`
// in Tego's Linux), and of .wslconfig only when WSL gave no answer. Tego's Linux is already up here, so this does not
// depend on how long it took to start.
func linuxMirrored() bool {
	out, _ := wslOutput([]string{"--distribution", "tego", "--user", "tego", "--exec", "/usr/bin/wslinfo", "--networking-mode"}, 20*time.Second)
	cfg := ""
	if dir := os.Getenv("USERPROFILE"); dir != "" && filepath.IsAbs(dir) {
		if b, err := os.ReadFile(filepath.Join(dir, ".wslconfig")); err == nil {
			cfg = string(b)
		}
	}
	return networkingMirrored(out, cfg)
}

// stopDashboard is `tego dashboard --stop`: it ends this user's relay and then, in Tego's Linux and only when no run is
// going, the dashboard the command started there, whose connection to the Linux session is what kept Tego's Linux from
// stopping (dashboardStopWords says what happened).
func stopDashboard() int {
	ended := false
	if rec := readRelayState(); rec != nil {
		ended = stopRelayProcess(*rec)
	}
	up := linuxRunning()
	var rel releaseResult
	if up {
		rel = releaseLinux()
	}
	fmt.Println(dashboardStopWords(ended, up, rel))
	return 0
}
