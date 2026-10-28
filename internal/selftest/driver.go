// SPDX-License-Identifier: Apache-2.0

package selftest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// Options are tego test's inputs.
type Options struct {
	// Tego is the tego binary to test: the running one, for tego test.
	Tego string
	// Tier, when not empty, is passed to each tego run as --tier.
	Tier string
	// TempDir is where the tree is made; "" is the system temp directory.
	TempDir string
	// Env is the environment the tego processes start with; nil is os.Environ(). $TEGO_CONFIG in it is replaced by
	// the tree's layer (writeConfig), which keeps the caller's own layer's settings.
	Env []string
	// Timeout bounds each tego process; zero is 60 seconds.
	Timeout time.Duration
}

// configVar is the machine config layer's variable (pkg/spec/config.EnvConfigVar).
const configVar = "TEGO_CONFIG"

// Run makes the tree, runs every check directly and under tego run, reads each run's verdict from its ledger, and
// removes the tree. An error is one tego test could not get past (no tree, no listener, a tego that did not
// start); a check whose result cannot be read is reported in its row, with ResultError.
func Run(ctx context.Context, o Options) (Report, error) {
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	env := o.Env
	if env == nil {
		env = os.Environ()
	}
	parent, err := treeParent(o.TempDir, o.Tego, env)
	if err != nil {
		return Report{}, err
	}
	t, err := newTree(parent)
	if err != nil {
		return Report{}, fmt.Errorf("make the temporary tree: %w", err)
	}
	defer func() { _ = os.RemoveAll(t.root) }() // best effort: the report is already made
	if err := t.writeConfig(lookupEnv(env, configVar)); err != nil {
		return Report{}, err
	}
	if err := t.writeContract(o.Tego); err != nil {
		return Report{}, fmt.Errorf("write the contract: %w", err)
	}
	sink, err := listen()
	if err != nil {
		return Report{}, fmt.Errorf("open the loopback listener: %w", err)
	}
	defer sink.close()
	if err := t.writePort(sink.port()); err != nil {
		return Report{}, err
	}
	d := driver{o: o, t: t, env: withEnv(env, configVar, t.config()), sink: sink}
	rep := Report{Schema: Schema, Dir: t.root}
	for _, c := range checks {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		row, tier := d.one(ctx, c)
		if rep.Tier == "" {
			rep.Tier = tier
		}
		rep.Checks = append(rep.Checks, row)
	}
	rep.finish()
	return rep, nil
}

// treeParent is the directory the tree is made in: tempDir ("" is the system temp directory), unless it lies in the
// tego binary's own directory: a binary downloaded to /tmp and run with no TMPDIR. R10 refuses a write entry at or over
// the binary, not one beside it, but a tree there sits one mistake from every run ending with exit 125 and a message
// about a contract entry the person never wrote. Then $XDG_RUNTIME_DIR, then the user cache directory, is used
// instead, and with neither usable the error says what to change.
func treeParent(tempDir, tego string, env []string) (string, error) {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	bin := filepath.Dir(tego)
	if r, err := filepath.EvalSymlinks(tego); err == nil {
		bin = filepath.Dir(r)
	}
	candidates := []string{tempDir, lookupEnv(env, "XDG_RUNTIME_DIR")}
	if cache, err := os.UserCacheDir(); err == nil {
		candidates = append(candidates, cache)
	}
	for _, c := range candidates {
		if c == "" || !filepath.IsAbs(c) {
			continue
		}
		r, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue // absent: the next one
		}
		if fi, err := os.Stat(r); err != nil || !fi.IsDir() || within(bin, r) {
			continue
		}
		return c, nil
	}
	return "", fmt.Errorf("the temporary folder %s is inside tego's own directory %s, where tego test does not make its folder; "+
		"set TMPDIR to a folder elsewhere", tempDir, bin)
}

// within reports whether path is dir or lies below it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// driver runs the checks of one tego test.
type driver struct {
	o    Options
	t    tree
	env  []string
	sink *sink
}

// one runs check c directly, undoes its effect, then runs it under tego run and judges the run by its ledger and
// by the effect itself (the file written, the connection accepted).
func (d driver) one(ctx context.Context, c check) (Row, string) {
	row := Row{Name: c.name, Action: c.action}
	before := d.sink.count()
	res, out, err := d.check(ctx, []string{d.o.Tego, CheckVerb, c.name, d.t.work})
	switch {
	case err != nil:
		row.Baseline = Outcome{Result: ResultError, Detail: oneLine(err.Error(), out)}
	case res.Done && c.name == CheckConnect && !d.sink.above(before, 2*time.Second):
		// The listener must count the baseline's connection before the run under Tego starts: one still in the
		// backlog would be accepted during that run and counted against it. The count is also the stronger evidence.
		row.Baseline = Outcome{Result: ResultFailed, Detail: res.Detail + ", but the listener counted no connection"}
	case res.Done:
		row.Baseline = Outcome{Result: ResultSucceeded, Detail: res.Detail}
	default:
		row.Baseline = Outcome{Result: ResultFailed, Detail: res.Detail}
	}
	if err := d.undo(c); err != nil {
		row.Baseline = Outcome{Result: ResultError, Detail: "undo the baseline: " + err.Error()}
	}
	accepted := d.sink.count()
	argv := []string{d.o.Tego, "run"}
	if d.o.Tier != "" {
		argv = append(argv, "--tier", d.o.Tier)
	}
	argv = append(argv, d.t.contract(), "--", d.o.Tego, CheckVerb, c.name, d.t.work)
	res, out, err = d.check(ctx, argv)
	if err != nil {
		row.UnderTego = Outcome{Result: ResultError, Detail: oneLine(err.Error(), out)}
		return row, ""
	}
	if res.Run == "" {
		row.UnderTego = Outcome{Result: ResultError, Detail: "the check ran without a run id: was it under tego run?"}
		return row, ""
	}
	ev, err := d.events(ctx, res.Run)
	if err != nil {
		row.UnderTego = Outcome{Result: ResultError, Run: res.Run, Detail: err.Error()}
		return row, ""
	}
	took := res.Done || d.effect(c, accepted)
	row.UnderTego = judge(c, d.t.layout, res, ev, took)
	return row, ev.tier
}

// effect reports whether c's action left its mark despite what the check said: the file outside the project exists,
// or the listener accepted a connection during the run.
func (d driver) effect(c check, acceptedBefore int) bool {
	switch c.name {
	case CheckWriteOutside:
		_, err := os.Lstat(d.t.outside())
		return err == nil
	case CheckConnect:
		return d.sink.above(acceptedBefore, 300*time.Millisecond)
	}
	return false
}

// undo removes what the baseline left, so the run under tego starts from the same tree.
func (d driver) undo(c check) error {
	if c.name == CheckWriteOutside {
		if err := os.Remove(d.t.outside()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// check starts argv, a direct `tego __check` or a tego run of one, and reads the check's result line from its
// stdout. The process's exit code is not the verdict: the result line and the ledger are.
func (d driver) check(ctx context.Context, argv []string) (checkResult, []byte, error) {
	out, err := startTego(ctx, d.env, d.t.project(), d.o.Timeout, argv)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), resultPrefix); ok {
			var res checkResult
			if jerr := json.Unmarshal([]byte(rest), &res); jerr != nil {
				return checkResult{}, out, fmt.Errorf("read the check's result: %w", jerr)
			}
			return res, out, nil
		}
	}
	if err == nil {
		err = errors.New("the check printed no result")
	}
	return checkResult{}, out, err
}

// startTego runs one tego process in dir to its end, stdout and stderr together, killed after timeout or when ctx
// ends. tego test holds no fanotify group (nothing it links calls proc.Arm), so the start is never refused for marks.
func startTego(ctx context.Context, env []string, dir string, timeout time.Duration, argv []string) ([]byte, error) {
	cmd := proc.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if _, err := proc.Start(cmd); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	defer close(done)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	go func() {
		select {
		case <-ctx.Done():
		case <-timer.C:
		case <-done:
			return
		}
		_ = cmd.Process.Kill() // the Wait below reports the end
	}()
	err := cmd.Wait()
	return out.Bytes(), err
}

// runEvents is what tego test reads from a run's ledger: its tier and its refusals.
type runEvents struct {
	tier    string
	refused []refusal
}

// refusal is one refused line of the ledger.
type refusal struct {
	Kind   string `json:"kind"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
	Op     string `json:"op"`
	Target string `json:"target"`
	Tier   string `json:"tier"`
}

// events reads run's ledger through `tego events <run> --json`, the stored lines byte for byte.
func (d driver) events(ctx context.Context, run string) (runEvents, error) {
	out, err := startTego(ctx, d.env, d.t.project(), d.o.Timeout, []string{d.o.Tego, "events", run, "--json"})
	if err != nil {
		return runEvents{}, fmt.Errorf("read the run's ledger: %s", oneLine(err.Error(), out))
	}
	var ev runEvents
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		var l refusal
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue // a line this reader does not need
		}
		switch l.Kind {
		case "run_start":
			ev.tier = l.Tier
		case "refused":
			ev.refused = append(ev.refused, l)
		}
	}
	if err := sc.Err(); err != nil {
		return runEvents{}, fmt.Errorf("read the run's ledger: %w", err)
	}
	return ev, nil
}

// oneLine is err with the last line the process printed, for a row's detail.
func oneLine(err string, out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != "" {
		return err + ": " + last
	}
	return err
}

// lookupEnv is name's value in env, or "".
func lookupEnv(env []string, name string) string {
	v := ""
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, name+"="); ok {
			v = rest
		}
	}
	return v
}

// withEnv is env with name set to value, any earlier setting removed.
func withEnv(env []string, name, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return append(out, name+"="+value)
}

// sink is the loopback listener tego test owns: the connect check's target. It counts the connections it accepts
// and reads what each sends, so a connection that got through is seen even if the check says otherwise.
type sink struct {
	ln       net.Listener
	mu       sync.Mutex
	accepted int
	wg       sync.WaitGroup
}

// listen opens the sink on a free loopback port.
func listen() (*sink, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &sink{ln: ln}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

func (s *sink) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// above waits up to d for the count to pass n and reports whether it did. A connection the kernel completed sits in
// the listen backlog until serve accepts it, so a count read right after the check ends can miss it.
func (s *sink) above(n int, d time.Duration) bool {
	for deadline := time.Now().Add(d); ; time.Sleep(10 * time.Millisecond) {
		if s.count() > n {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

func (s *sink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// serve accepts until close: each connection is counted at once, then read briefly and closed on its own goroutine,
// so a slow sender never holds up the next accept.
func (s *sink) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // closed
		}
		s.mu.Lock()
		s.accepted++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // a read that times out is still a connection
			_, _ = io.Copy(io.Discard, io.LimitReader(conn, 4096))
			_ = conn.Close() // nothing is lost: the count is the evidence
		}()
	}
}

// close stops the sink and waits for serve to end.
func (s *sink) close() {
	_ = s.ln.Close() // Accept returns and serve ends
	s.wg.Wait()
}
