// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/relaymux"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdDashboardRelay) }

// cmdDashboardRelay is the Linux end of the Windows dashboard relay (docs/adr/0123-dashboard-threat-model.md, "A
// browser on Windows"). Only the Windows tego command starts it, through the fixed guest entry
// (/usr/local/lib/tego/windows-entry) inside the person's systemd user scope, so it is hidden.
//
//	serve  speaks relaymux on standard input and output: one loopback connection to the dashboard per stream, made
//	       by this process, so the dashboard's peer check sees the person's uid and its governed check this scope
//	open   prints the one line the Windows command opens the browser with: the dashboard's port, a one-time open
//	       code, and a fresh identity challenge with its expected proof
//
// Both refuse inside a tego run, and both take the dashboard's address from the dashboard's own log and identity
// proof, never from the Windows side.
func cmdDashboardRelay() Command {
	return Command{
		Name:    "dashboard-relay",
		Summary: "the Linux end of the Windows dashboard relay",
		Usage:   "serve|open",
		Hidden:  true,
		Flags:   func(*flag.FlagSet) {},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 || fs.Arg(0) != "serve" && fs.Arg(0) != "open" {
				message(stderr, "", 0, 0, "tego dashboard-relay: takes serve or open", codeUsage)
				return identity.ExitUsage
			}
			scope := realRelayScope()
			// Inside a run is refused before anything is read; what the rule cannot decide waits for the dashboard.
			if a := scope.answer(); !a.Outside() && !runscope.CouldNotTell(a) {
				message(stderr, "", 0, 0, "tego dashboard-relay: this process is inside a tego run; the dashboard relay runs only outside every tego run", codeGoverned)
				return identity.ExitError
			}
			m, _, err := loadMachine(config.TrustWarn)
			if err != nil {
				message(stderr, "", 0, 0, "tego dashboard-relay: machine config: "+err.Error(), config.CodeUntrusted)
				return identity.ExitError
			}
			t, err := findRelayTarget(m.Home, relayDashboardAt, dashboardProof)
			if err != nil {
				message(stderr, "", 0, 0, "tego dashboard-relay: "+err.Error(), codeIO)
				return identity.ExitError
			}
			code := ""
			prove := func() error {
				c, err := mintOpenCode(ctx, t)
				code = c
				return err
			}
			if err := scope.outsideRuns(prove); err != nil {
				message(stderr, "", 0, 0, "tego dashboard-relay: "+err.Error()+"; the dashboard relay runs only outside every tego run", codeGoverned)
				return identity.ExitError
			}
			if fs.Arg(0) == "open" {
				return relayOpen(ctx, t, code, stdout, stderr)
			}
			r := &relayServer{home: m.Home, target: t, find: func(home string) (relayTarget, error) {
				return findRelayTarget(home, relayDashboardAt, dashboardProof)
			}, dial: dialDashboard}
			return r.serve(ctx, os.Stdin, os.Stdout, stderr)
		},
	}
}

// relayProbeLimit is how long the relay waits for the dashboard's identity proof: a dashboard busy serving a page
// load may take longer than tego dashboard's 300 ms probe allows.
const relayProbeLimit = 3 * time.Second

func relayDashboardAt(home string) (string, bool) { return dashboardWithin(home, relayProbeLimit) }

// relayTarget is the running dashboard the relay carries connections to: its loopback port on 127.0.0.1, read from
// the dashboard's own log, and its sign-in token, which the dashboard has just proved it holds.
type relayTarget struct {
	port  int
	token string
	proof func(token, challenge string) (string, error)
}

// findRelayTarget is the dashboard tego dashboard started for this user: the link in its private log, accepted only
// when a listener at that address proves it holds the link's token (dashboardAt's identity challenge). The address
// is always 127.0.0.1 (dashboardLink admits no other), so the relay never dials anything but the dashboard.
func findRelayTarget(home string, at func(string) (string, bool), proof func(token, challenge string) (string, error)) (relayTarget, error) {
	link, _ := at(home)
	if link == "" {
		return relayTarget{}, errors.New("the dashboard is not running; run tego dashboard")
	}
	u, err := url.Parse(link)
	if err != nil {
		return relayTarget{}, fmt.Errorf("the dashboard's link: %w", err)
	}
	host, p, err := net.SplitHostPort(u.Host)
	port, perr := strconv.Atoi(p)
	if err != nil || perr != nil || host != "127.0.0.1" || port <= 0 || port > 65535 {
		return relayTarget{}, fmt.Errorf("the dashboard's link names %q, not 127.0.0.1 and a port", u.Host)
	}
	token := u.Query().Get("t")
	if len(token) != 32 {
		return relayTarget{}, errors.New("the dashboard's link carries no sign-in token")
	}
	return relayTarget{port: port, token: token, proof: proof}, nil
}

// dashboardProof is the identity proof the running dashboard gives for challenge (control/cli serve.go's
// /_tego/identity): an HMAC under its sign-in token of the challenge and this user's dashboard configuration.
func dashboardProof(token, challenge string) (string, error) {
	_, _, scope, err := dashboardConfiguration()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte("tego-dashboard-v1\n" + challenge + "\n" + scope))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// relayOpenLine starts the one line `tego dashboard-relay open` prints.
const relayOpenLine = "TEGO_DASHBOARD_OPEN"

// relayOpen prints the port, a one-time open code from the dashboard's own loopback listener (POST
// /_tego/open-code with the sign-in token: the peer check admits this uid, the governed check this scope; code
// when outsideRuns already minted one) and a fresh challenge with its proof, which the Windows command checks
// through its relay before opening the browser. Only the one-time code reaches a Windows command line; the
// reusable token never leaves Linux.
func relayOpen(ctx context.Context, t relayTarget, code string, stdout, stderr io.Writer) int {
	if code == "" {
		var err error
		if code, err = mintOpenCode(ctx, t); err != nil {
			message(stderr, "", 0, 0, "tego dashboard-relay: the dashboard gave no open code: "+err.Error(), codeIO)
			return identity.ExitError
		}
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		message(stderr, "", 0, 0, "tego dashboard-relay: "+err.Error(), codeIO)
		return identity.ExitError
	}
	challenge := hex.EncodeToString(nonce[:])
	proof, err := t.proof(t.token, challenge)
	if err != nil {
		message(stderr, "", 0, 0, "tego dashboard-relay: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if _, err := fmt.Fprintf(stdout, "%s port=%d code=%s challenge=%s proof=%s\n", relayOpenLine, t.port, code, challenge, proof); err != nil {
		return identity.ExitError
	}
	return identity.ExitOK
}

// mintOpenCode is one POST /_tego/open-code to the dashboard at 127.0.0.1 (web/opencode.go).
func mintOpenCode(ctx context.Context, t relayTarget) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(t.port))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/_tego/open-code", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirects are refused")
	}}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", err
	}
	code := strings.TrimSpace(string(b))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, relayFirstLine(code))
	}
	if !isHex(code, 32) {
		return "", errors.New("the answer is not an open code")
	}
	return code, nil
}

func relayFirstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// relayRecheck is how long one identity check of the dashboard stands before a new stream checks it again, and
// relayMisses how many checks in a row may go unanswered before the relay ends: one slow answer refuses only that
// stream.
const (
	relayRecheck = 5 * time.Second
	relayMisses  = 3
)

// relayServer is the serve mode: one session, one dashboard connection per stream.
type relayServer struct {
	home string
	find func(home string) (relayTarget, error)
	dial func(ctx context.Context, port int) (net.Conn, error)

	mu      sync.Mutex
	target  relayTarget
	checked time.Time
	misses  int
}

func dialDashboard(ctx context.Context, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// serve runs the session on in and out until the Windows end or the pipe ends it, or the dashboard stops or moves
// to another port, which ends it with a GOAWAY saying so.
func (r *relayServer) serve(ctx context.Context, in io.ReadCloser, out io.WriteCloser, stderr io.Writer) int {
	r.checked = time.Now()
	s, err := relaymux.Start(in, out, relaymux.Options{Port: uint16(r.target.port)})
	if err != nil {
		message(stderr, "", 0, 0, "tego dashboard-relay: "+err.Error(), codeIO)
		return identity.ExitError
	}
	go func() {
		select {
		case <-ctx.Done():
			s.GoAway("the Linux end was stopped")
		case <-s.Done():
		}
	}()
	for {
		st, err := s.Accept()
		if err != nil {
			break
		}
		port, why, end := r.current()
		if end {
			s.GoAway(why)
			break
		}
		if why != "" {
			_ = st.Abort(why)
			continue
		}
		go r.carry(ctx, st, port)
	}
	<-s.Done()
	err = s.Err()
	if errors.Is(err, io.EOF) || errors.Is(err, relaymux.ErrClosed) {
		return identity.ExitOK
	}
	fmt.Fprintln(stderr, "tego dashboard-relay:", err)
	return identity.ExitError
}

// current is the dashboard port to dial for a new stream, checking the dashboard's identity again when the last
// check is older than relayRecheck. A dashboard that now answers on another port ends the relay at once; one that
// does not prove itself refuses this stream, and ends the relay after relayMisses such checks in a row: the
// person's next tego dashboard starts one for the dashboard that runs. why says what happened; end says whether
// the relay ends.
func (r *relayServer) current() (port int, why string, end bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) < relayRecheck {
		return r.target.port, "", false
	}
	t, err := r.find(r.home)
	if err != nil {
		if r.misses++; r.misses >= relayMisses {
			return 0, "the dashboard stopped; run tego dashboard", true
		}
		return 0, "the dashboard did not prove itself in time", false
	}
	if t.port != r.target.port {
		return 0, "the dashboard moved to port " + strconv.Itoa(t.port) + "; run tego dashboard", true
	}
	r.target, r.checked, r.misses = t, time.Now(), 0
	return t.port, "", false
}

// carry relays one stream to one new connection to the dashboard, each direction half-closed when its sender is
// done, the stream aborted with the reason when the dashboard cannot be reached.
func (r *relayServer) carry(ctx context.Context, st *relaymux.Stream, port int) {
	c, err := r.dial(ctx, port)
	if err != nil {
		_ = st.Abort("the dashboard could not be reached: " + err.Error())
		return
	}
	defer func() { _ = c.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := io.Copy(c, st); err != nil {
			_ = c.Close() // the browser's side aborted: drop the dashboard connection too
			return
		}
		if hc, ok := c.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
	}()
	if _, err := io.Copy(st, c); err != nil {
		_ = st.Abort("the dashboard connection failed: " + err.Error())
	} else {
		_ = st.CloseWrite()
	}
	<-done
	_ = st.Close()
}

// relayScope reads what decides whether this process is outside every tego run. Tests replace each read.
type relayScope struct {
	answer     func() runscope.Answer
	selfCgroup func() ([]byte, error)
}

func realRelayScope() relayScope {
	return relayScope{
		answer:     selfAnswer,
		selfCgroup: func() ([]byte, error) { return os.ReadFile("/proc/self/cgroup") },
	}
}

// outsideRuns returns nil only when this process can be shown to be outside every tego run. The rule's answer
// (selfAnswer) decides first: an outside answer passes, an inside one refuses. An answer that cannot tell is the one
// WSL gives where the rule's proof fails (a manager that does not answer, a distribution with one mark of WSL, a
// build from before the rule was on) and the one a distribution gave every ordinary build (every distribution has a cgroup namespace of its own, measured: every process of
// Tego's distribution, the user manager included, is in one, and the user manager's own namespace cannot be read by
// its user to compare, its process not being dumpable), so there it would refuse every Windows command. Only in that
// case this asks the authority on the question instead: prove makes a request the dashboard admits only after its governed check, which reads
// this process's socket's cgroup from the kernel and walks the whole hierarchy from the dashboard's own view
// (internal/control/web governed.go), unchanged; and the path this process reads must itself be no run's.
func (s relayScope) outsideRuns(prove func() error) error {
	a := s.answer()
	if a.Outside() {
		return nil
	}
	if !runscope.CouldNotTell(a) {
		return errors.New("this process is inside a tego run")
	}
	why := runscope.Why(a)
	b, rerr := s.selfCgroup()
	if rerr != nil {
		return fmt.Errorf("this process cannot be shown outside every tego run: %w", rerr)
	}
	cg, uerr := runscope.Unified(b)
	switch {
	case uerr != nil:
		return fmt.Errorf("this process cannot be shown outside every tego run: %w", uerr)
	case runscope.OutsideNamespace(cg):
		return fmt.Errorf("this process cannot be shown outside every tego run: its cgroup %q lies above its namespace's root", cg)
	case runscope.LooksGoverned(cg):
		return errors.New("this process is inside a tego run")
	}
	if perr := prove(); perr != nil {
		return fmt.Errorf("this process cannot be shown outside every tego run (%v), and the dashboard's own check did not admit it: %w", why, perr)
	}
	return nil
}
