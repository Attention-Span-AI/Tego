// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// CheckVerb is the hidden verb that performs one check: `tego __check <name> <workdir>`. cmd/tego dispatches it
// before any CLI setup, as it does the child stage, so under `tego run` the agent's system calls are the check's.
const CheckVerb = "__check"

// The four checks, in the order they run and print.
const (
	CheckReadSecret   = "read-secret"
	CheckWriteOutside = "write-outside"
	CheckRunUnlisted  = "run-unlisted"
	CheckConnect      = "connect-unlisted"
)

// check is one harmless action: its name, what it does in plain words, the reason a refusal of it carries, and the
// target a refusal names, both read from the ledger.
type check struct {
	name   string
	action string
	reason string
	target func(t layout) string
	do     func(t layout) (string, error)
}

// checks is the fixed list. Each acts on the workdir's decoys alone, so the baseline (run with no Tego) harms
// nothing: the key and .env are fake, the write lands in the temporary tree, the program is a copy of /bin/true and
// the connection reaches the listener `tego test` owns.
var checks = []check{
	{
		name: CheckReadSecret, action: "read a fake SSH key in a fake home", reason: "read-denied",
		target: func(t layout) string { return t.key() },
		do:     readSecret,
	},
	{
		name: CheckWriteOutside, action: "write a file outside the project's writable folder", reason: "write-outside-contract",
		target: func(t layout) string { return t.outside() },
		do:     writeOutside,
	},
	{
		name: CheckRunUnlisted, action: "run a program the contract does not list", reason: "exec-not-allowed",
		target: func(t layout) string { return t.program() },
		do:     runUnlisted,
	},
	{
		name: CheckConnect, action: "connect to a local port the contract does not allow", reason: "net-not-allowed",
		target: func(t layout) string {
			port, err := t.port()
			if err != nil {
				return ""
			}
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		},
		do: connectUnlisted,
	},
}

// Names is the check names in the order they run.
func Names() []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.name
	}
	return out
}

// checkByName is the check called name, or false.
func checkByName(name string) (check, bool) {
	for _, c := range checks {
		if c.name == name {
			return c, true
		}
	}
	return check{}, false
}

// resultPrefix starts the one line CheckMain prints on stdout, so the driver finds it among whatever else tego run
// passes through.
const resultPrefix = "tego-selftest-result "

// checkResult is what one check did, as CheckMain prints it.
type checkResult struct {
	Check string `json:"check"`
	// Done reports whether the action took effect.
	Done bool `json:"done"`
	// Blocked reports a refusal by permission (EACCES or EPERM), the way an enforced rule fails a call.
	Blocked bool   `json:"blocked,omitempty"`
	Detail  string `json:"detail"`
	// Run is $TEGO_RUN_ID, set under tego run and empty in the baseline.
	Run string `json:"run,omitempty"`
}

// CheckMain is the hidden verb: it performs the one named check against workdir and prints its result line. It
// accepts only a check name from the fixed list and a workdir Tree made (it carries the marker), so the verb can do
// nothing but its four harmless actions on its own decoys. Exit 0 when the action took effect, 1 when it did not,
// 2 on any other argument.
func CheckMain(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintf(stderr, "tego %s: takes a check name and the workdir tego test made; run tego test\n", CheckVerb)
		return identity.ExitUsage
	}
	c, ok := checkByName(args[0])
	if !ok {
		fmt.Fprintf(stderr, "tego %s: unknown check %q (one of %s)\n", CheckVerb, args[0], strings.Join(Names(), ", "))
		return identity.ExitUsage
	}
	t, err := openLayout(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "tego %s: %v\n", CheckVerb, err)
		return identity.ExitUsage
	}
	res := checkResult{Check: c.name, Run: os.Getenv("TEGO_RUN_ID")}
	detail, err := c.do(t)
	if err == nil {
		res.Done, res.Detail = true, detail
	} else {
		res.Blocked = errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
		res.Detail = err.Error()
	}
	line, err := json.Marshal(res)
	if err != nil {
		fmt.Fprintf(stderr, "tego %s: %v\n", CheckVerb, err)
		return identity.ExitError
	}
	fmt.Fprintf(stdout, "%s%s\n", resultPrefix, line)
	if !res.Done {
		return identity.ExitFinding
	}
	return identity.ExitOK
}

// readSecret opens the fake SSH key and reads it.
func readSecret(t layout) (string, error) {
	f, err := os.OpenFile(t.key(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("read %d bytes", len(b)), nil
}

// writeOutside creates a file beside the project, outside its writable folder.
func writeOutside(t layout) (string, error) {
	f, err := os.OpenFile(t.outside(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(sentinel); err != nil {
		_ = f.Close() // the write error is the one reported
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return "wrote " + filepath.Base(t.outside()), nil
}

// runUnlisted runs the copy of /bin/true in the workdir.
func runUnlisted(t layout) (string, error) {
	cmd := proc.Command(t.program())
	// Its output, if any, is the check's own; a nil stream would open /dev/null for writing, which the contract does
	// not grant, and the start would fail before the exec the check is about.
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if _, err := proc.Start(cmd); err != nil {
		return "", err
	}
	if err := cmd.Wait(); err != nil {
		return "", err
	}
	return "ran " + filepath.Base(t.program()), nil
}

// connectUnlisted connects to the listener tego test owns and sends the sentinel.
func connectUnlisted(t layout) (string, error) {
	port, err := t.port()
	if err != nil {
		return "", err
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }() // the sentinel's write is the effect; a close error changes nothing
	if _, err := conn.Write([]byte(sentinel)); err != nil {
		return "", err
	}
	return "connected to " + addr, nil
}

// sentinel is what the write and the connection send: decoy content, never anything of the user's.
const sentinel = "tego-selftest sentinel\n"
