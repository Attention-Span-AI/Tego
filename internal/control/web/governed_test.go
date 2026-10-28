// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const govRun = "r-3f9c2a1b-0dmeinxsdi3zq-ntnymw"

// cgroupTree is a fake cgroup2 mount: the serving user's tego.slice with one agent slice holding a run's scope (with
// a child cgroup), a look-alike scope outside tego.slice, and the user's own app slice.
type cgroupTree struct {
	root, scope, child, lookAlike, app string
}

func newCgroupTree(t *testing.T, uid int) cgroupTree {
	t.Helper()
	root := t.TempDir()
	user := filepath.Join(root, "user.slice", fmt.Sprintf("user-%d.slice", uid), fmt.Sprintf("user@%d.service", uid))
	c := cgroupTree{root: root,
		scope:     filepath.Join(user, "tego.slice", "tego-demo.slice", "run-"+govRun+".scope"),
		lookAlike: filepath.Join(user, "app.slice", "run-"+govRun+".scope"),
		app:       filepath.Join(user, "app.slice", "terminal.scope"),
	}
	c.child = filepath.Join(c.scope, "agent")
	for _, d := range []string{c.child, c.lookAlike, c.app} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func inode(t *testing.T, dir string) uint64 {
	t.Helper()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// govRequest is a request from 127.0.0.1:40000 to the dashboard on 127.0.0.1:8484.
func govRequest(method, target string, form url.Values) *http.Request {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", own)
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.Host = "127.0.0.1:8484"
	r.RemoteAddr = clientRemote
	la := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8484}
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(la)))
}

// TestGovernedCheck: a socket made in a run's scope, or in a cgroup below it, names the run; one made in the user's
// own terminal, or in a look-alike scope outside tego.slice, names none; a socket whose cgroup cannot be read, a
// missing cgroup2 mount, a cgroup found nowhere (removed after the socket was made: a child of the run's scope
// included), or a run scope too deep to walk refuses (fails closed).
func TestGovernedCheck(t *testing.T) {
	tree := newCgroupTree(t, 1000)
	check := func(id uint64, sockErr error) error {
		g := &governedCheck{cgroupRoot: func() (string, error) { return tree.root, nil },
			socketCgroup: func(c, s netip.AddrPort) (uint64, error) {
				if c != netip.MustParseAddrPort(clientRemote) || s != netip.MustParseAddrPort("127.0.0.1:8484") {
					t.Errorf("asked about %s -> %s", c, s)
				}
				return id, sockErr
			}}
		return g.refuse(govRequest("POST", "/approvals/answer", url.Values{}))
	}
	for name, dir := range map[string]string{"the run's scope": tree.scope, "a cgroup below it": tree.child} {
		var ge *governedError
		if err := check(inode(t, dir), nil); !errors.As(err, &ge) || ge.Run != govRun {
			t.Errorf("%s: %v, want the run %s", name, err, govRun)
		}
	}
	for name, dir := range map[string]string{"the terminal": tree.app, "a look-alike scope": tree.lookAlike, "the root": tree.root} {
		if err := check(inode(t, dir), nil); err != nil {
			t.Errorf("%s: %v, want none", name, err)
		}
	}
	if err := check(0, errors.New("sock_diag: no socket")); !errors.Is(err, errGovernedUnknown) {
		t.Errorf("an unreadable socket cgroup: %v", err)
	}
	g := &governedCheck{cgroupRoot: func() (string, error) { return "", errors.New("no cgroup2 mount") },
		socketCgroup: func(netip.AddrPort, netip.AddrPort) (uint64, error) { return 7, nil }}
	if err := g.refuse(govRequest("POST", "/", url.Values{})); !errors.Is(err, errGovernedUnknown) {
		t.Errorf("no cgroup2 mount: %v", err)
	}
	// The dying child: a socket made in a child cgroup of the run's scope, which was removed afterwards. Its id is in
	// no directory now, so it is refused, not taken for outside every run.
	dying := filepath.Join(tree.scope, "x")
	if err := os.Mkdir(dying, 0o700); err != nil {
		t.Fatal(err)
	}
	gone := inode(t, dying)
	if err := os.Remove(dying); err != nil {
		t.Fatal(err)
	}
	if err := check(gone, nil); !errors.Is(err, errGovernedUnknown) || !strings.Contains(err.Error(), "not in the cgroup tree") {
		t.Errorf("a removed child of the run's scope: %v, want a refusal", err)
	}
	deep := tree.scope
	for i := 0; i <= maxCgroupDepth; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := check(inode(t, deep), nil); !errors.Is(err, errGovernedUnknown) || !strings.Contains(err.Error(), govRun) {
		t.Errorf("a run scope too deep to walk: %v, want a refusal naming where the walk stopped", err)
	}
}

// TestGovernedCheckCachesOutside: a cgroup found outside every run is remembered, so the next request walks nothing;
// one found inside a run, or found nowhere, is walked and refused every time.
func TestGovernedCheckCachesOutside(t *testing.T) {
	tree := newCgroupTree(t, 1000)
	walks := 0
	var id uint64
	g := &governedCheck{
		cgroupRoot:   func() (string, error) { walks++; return tree.root, nil },
		socketCgroup: func(netip.AddrPort, netip.AddrPort) (uint64, error) { return id, nil },
	}
	post := func() error { return g.refuse(govRequest("POST", "/", url.Values{})) }
	id = inode(t, tree.app)
	for i := 0; i < 3; i++ {
		if err := post(); err != nil {
			t.Fatalf("the terminal: %v", err)
		}
	}
	if walks != 1 {
		t.Errorf("the terminal's cgroup was walked %d times, want once", walks)
	}
	id = inode(t, tree.child)
	for i := 0; i < 2; i++ {
		var ge *governedError
		if err := post(); !errors.As(err, &ge) {
			t.Fatalf("the run's child cgroup: %v", err)
		}
	}
	if walks != 3 {
		t.Errorf("walks %d after two refusals, want 3: a refusal is never cached", walks)
	}
	id = 1 << 62
	if err := post(); !errors.Is(err, errGovernedUnknown) {
		t.Errorf("an id found nowhere: %v", err)
	}
	if g.knownOutside(1 << 62) {
		t.Error("an id found nowhere was cached as outside")
	}
}

// TestGovernedPeerRefused: with the connection made inside a live run's cgroup, every POST (an answer, Never allow,
// Stop, a rules change) and the ?t= sign-in get 403 naming the run, and nothing is written; a GET of a page is
// answered (200). The same POST from the person's own terminal is served.
func TestGovernedPeerRefused(t *testing.T) {
	s, c, contract, _ := askServer(t)
	tree := newCgroupTree(t, 1000)
	from := tree.scope
	s.governed = (&governedCheck{cgroupRoot: func() (string, error) { return tree.root, nil },
		socketCgroup: func(netip.AddrPort, netip.AddrPort) (uint64, error) { return inode(t, from), nil }}).refuse
	line := "/runs/" + actRun + "/lines/3"
	base := baseOf(t, do(s, "GET", line+"?a=block", "127.0.0.1:8484", c).Body.String())
	for _, tc := range []struct {
		target string
		form   url.Values
	}{
		{line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"1"}, "base": {base}}},
		{"/approvals/answer", url.Values{"csrf": {s.csrf}, "run": {actRun}, "ask": {"a1"}, "decision": {"approve"}}},
		{"/runs/" + actRun + "/stop", url.Values{"csrf": {s.csrf}}},
		{"/runs/" + actRun + "/unblock", url.Values{"csrf": {s.csrf}, "kind": {"exec"}, "value": {"/usr/bin/curl"}}},
		{"/rules/revert", url.Values{"csrf": {s.csrf}, "id": {"rc-x"}, "base": {base}}},
	} {
		r := govRequest("POST", tc.target, tc.form)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "a governed agent cannot change its own governance (run "+govRun+")") ||
			!strings.Contains(w.Body.String(), "outside any tego run") {
			t.Errorf("POST %s from inside the run: %d %s", tc.target, w.Code, w.Body.String())
		}
	}
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Fatal("a POST from inside the run wrote the contract")
	}
	if _, err := os.Stat(filepath.Join(s.cfg.Ledger, ".rule-changes")); err == nil {
		t.Error("a POST from inside the run journaled a change")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, govRequest("GET", "/?t=tok123", nil))
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Errorf("the sign-in from inside the run: %d, cookies %v", w.Code, w.Result().Cookies())
	}
	r := govRequest("GET", line, nil)
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("a GET from inside the run: %d", w.Code)
	}
	// The person's own terminal: the same Never allow is served and written.
	from = tree.app
	r = govRequest("POST", line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"1"}, "base": {base}})
	r.AddCookie(c)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), line+"?saved=") {
		t.Fatalf("Never allow from the terminal: %d %q", w.Code, w.Header().Get("Location"))
	}
	if b, _ := os.ReadFile(contract); string(b) == askContract {
		t.Error("Never allow from the terminal wrote nothing")
	}
}

// TestGovernedRealSocket: through a real listener, the real check (sock_diag and this host's cgroup2 mount) serves
// this test's own client, which no tego run holds; were the test itself run inside a run, it would be refused, so it
// skips there.
func TestGovernedRealSocket(t *testing.T) {
	g := procGoverned()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- g.refuse(r) })}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	resp, err := http.Post("http://"+ln.Addr().String()+"/", "application/x-www-form-urlencoded", strings.NewReader("x=1"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	err = <-got
	var ge *governedError
	switch {
	case errors.As(err, &ge):
		t.Skipf("this test runs inside run %s", ge.Run)
	case err != nil && strings.Contains(err.Error(), "sock_diag") && !strings.Contains(err.Error(), "another socket"):
		t.Skipf("this kernel answers no socket cgroup: %v", err)
	case err != nil:
		t.Fatalf("this test's own client: %v", err)
	}
}

// TestCgroup2MountIn: the cgroup2 line's mount point, with mountinfo's octal escapes undone.
func TestCgroup2MountIn(t *testing.T) {
	info := "22 1 0:21 / /proc rw,nosuid - proc proc rw\n" +
		"30 25 0:26 / /sys/fs/cgroup\\040x rw,nosuid shared:9 - cgroup2 cgroup2 rw,nsdelegate\n"
	if got, err := cgroup2MountIn([]byte(info)); err != nil || got != "/sys/fs/cgroup x" {
		t.Errorf("mount: %q %v", got, err)
	}
	if _, err := cgroup2MountIn([]byte("22 1 0:21 / /proc rw - proc proc rw\n")); err == nil {
		t.Error("no cgroup2 line was taken for a mount")
	}
}
