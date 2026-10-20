// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ADR 0017 space 6: a third party's fanotify permission listener refuses a file the contract allows. The kernel's
// answer is that listener's EPERM on every axis; the ledger line is Tego's own answer (ADR 0016), which a cell's
// want states with `ledger:`. The listener is test/vm/cmd/permlistener in its deny mode (one binary,
// two modes), which needs CAP_SYS_ADMIN, so a fixture that names third_party_deny runs only as root.

var (
	permOnce sync.Once
	permPath string
	permErr  error
)

// buildPermListener builds the listener once per test run (in the KVM guest test/vm/go-shim.sh serves the copy
// root-suites.sh built, a HELPERS entry).
func buildPermListener(t *testing.T) string {
	t.Helper()
	permOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tego-permlistener-")
		if err != nil {
			permErr = err
			return
		}
		permPath = filepath.Join(dir, "permlistener")
		cmd := exec.Command("go", "build", "-o", permPath, "github.com/attention-span-ai/tego/test/vm/cmd/permlistener")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			permErr = fmt.Errorf("go build permlistener: %v: %s", err, out)
		}
	})
	if permErr != nil {
		t.Fatal(permErr)
	}
	return permPath
}

// listenerStats is the listener's last line; denied counts the opens it refused.
var listenerStats = regexp.MustCompile(`^PERMLISTENER-STATS .*\bdenied=([0-9]+)\b`)

// startThirdParty starts one deny-mode listener per path and returns once each has placed its marks. stop ends them
// and returns a problem for each that did not stop cleanly or refused nothing: a cell refused while the listener
// refused nothing was refused by something else.
func startThirdParty(t *testing.T, paths []string) (stop func() []string) {
	t.Helper()
	bin := buildPermListener(t)
	type listener struct {
		path  string
		cmd   *exec.Cmd
		lines chan string
	}
	var ls []*listener
	stopAll := func() (problems []string) {
		for _, l := range ls {
			_ = l.cmd.Process.Signal(syscall.SIGTERM)
		}
		for _, l := range ls {
			// Every line first, to the reader's EOF, and Wait after: Wait closes the stdout pipe, and before the
			// reader is done that loses the listener's last line, its count (a THIRD-PARTY "refused -1 opens" on
			// 6.17, 2026-10-19).
			denied := -1
			for line := range l.lines {
				if m := listenerStats.FindStringSubmatch(line); m != nil {
					denied, _ = strconv.Atoi(m[1])
				}
			}
			err := l.cmd.Wait()
			switch {
			case err != nil:
				problems = append(problems, fmt.Sprintf("the third-party listener for %s stopped with %v", l.path, err))
			case denied < 1:
				problems = append(problems, fmt.Sprintf("the third-party listener for %s refused %d opens: the cell's refusal was not its", l.path, denied))
			}
		}
		return problems
	}
	for _, p := range paths {
		cmd := exec.Command(bin, "-mode", "deny", "-path", p)
		cmd.Stderr = os.Stderr
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			stopAll()
			t.Fatalf("permlistener -mode deny -path %s: %v", p, err)
		}
		l := &listener{path: p, cmd: cmd, lines: make(chan string, 16)}
		ls = append(ls, l)
		ready := make(chan bool, 1)
		go func() {
			defer close(l.lines)
			sc := bufio.NewScanner(out)
			for sc.Scan() {
				if strings.TrimSpace(sc.Text()) == "PERMLISTENER-READY" {
					ready <- true
					continue
				}
				l.lines <- sc.Text()
			}
			ready <- false
		}()
		select {
		case ok := <-ready:
			if !ok {
				stopAll()
				t.Fatalf("permlistener -mode deny -path %s ended before it was ready", p)
			}
		case <-time.After(15 * time.Second):
			stopAll()
			t.Fatalf("permlistener -mode deny -path %s: not ready in 15 s", p)
		}
	}
	return stopAll
}
