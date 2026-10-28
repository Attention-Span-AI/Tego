// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/runscope"
)

// The governed-agent refusal. The peer check (peer.go) lets in only the serving user, and every
// agent tego runs or watches is the serving user too: an agent that reads the sign-in token (the browser opener's
// argv) could otherwise sign in, read a form's token, and answer its own asks, lift its own live blocks or widen its
// own contract. So every state-changing request (each POST, and the ?t= sign-in that hands out the session) also
// has to come from a socket made outside every tego run: the kernel records the cgroup each socket was made in
// (peer.TCPSocketCgroup, sock_diag), and a socket made inside a run's scope (tego.slice/tego-<agent>.slice/
// run-<id>.scope, an adoption's adopt-<id>.scope, or the Docker parent tego/<agent>/<id>, wherever runscope.GovernedBy
// names a run, and any cgroup below one) is refused with 403 and the run's id. A GET is answered as before: reading
// is not governance.
//
// It fails closed: a connection whose socket cannot be found, a cgroup2 mount that cannot be found, or a socket
// cgroup the walk of the whole hierarchy does not find (removed after the socket was made, outside this process's
// view, or past a part of the tree too large or unreadable to walk) refuses the change, with what failed. Only a
// cgroup found, and found outside every run, lets a change in. What it does not cover is
// in docs/adr/0123-dashboard-threat-model.md: a same-user process outside every run (one that left its run's cgroup
// with systemd-run --user, for one) is out of scope, as is anything that writes the files itself.

// errGovernedUnknown marks a change refused because the check could not show the connection is outside every run.
var errGovernedUnknown = errors.New("the dashboard could not show that this connection comes from outside every tego run")

// governedError is a change refused because its connection was made inside a run.
type governedError struct{ Run string }

func (e *governedError) Error() string {
	return "a governed agent cannot change its own governance (run " + e.Run + ")"
}

// Bounds on the walk of the cgroup hierarchy: a run's own scope is the user's to fill with child cgroups, so a walk
// that would pass them stops, and an id it did not reach is refused rather than taken for outside every run.
const (
	maxCgroupDirs  = 1 << 16
	maxCgroupDepth = 32
	// maxOutside bounds the cache of cgroups found outside every run; it is emptied when full.
	maxOutside = 1024
)

// governedCheck answers whether a request's client socket was made inside a tego run.
type governedCheck struct {
	// socketCgroup is the id of the cgroup a client socket was made in: peer.TCPSocketCgroup, or a fake in tests.
	socketCgroup func(client, server netip.AddrPort) (uint64, error)
	// cgroupRoot is the cgroup2 mount: cgroup2Mount, or a fake tree in tests.
	cgroupRoot func() (string, error)

	// outside holds the ids of cgroups a walk found outside every run. That verdict cannot go stale: a cgroup v2
	// directory cannot be renamed or moved to another parent (cgroup2 has no rename; only cgroup v1 does), and kernfs
	// does not hand an id out again, so the path a walk found for an id is its path for as long as the id lives. The
	// browser's sockets all come from one cgroup, so a sign-in or POST after the first walks nothing (on a box left
	// with hundreds of empty agent slices by tests, each walk took 6 to 12 ms). Ids found inside a run, or found
	// nowhere, are never cached: they are walked, and refused, each time.
	mu      sync.Mutex
	outside map[uint64]bool
}

// procGoverned is the real check: sock_diag and the cgroup2 mount of this process's /proc/self/mountinfo.
func procGoverned() *governedCheck {
	return &governedCheck{socketCgroup: peer.TCPSocketCgroup, cgroupRoot: cgroup2Mount}
}

// refuse returns nil when the request's client socket was made outside every run, a *governedError naming the run
// when it was made inside one, and an errGovernedUnknown error when that cannot be shown.
func (g *governedCheck) refuse(r *http.Request) error {
	client, server, err := connEnds(r)
	if err != nil {
		return fmt.Errorf("%w: %w", errGovernedUnknown, err)
	}
	id, err := g.socketCgroup(client, server)
	if err != nil {
		return fmt.Errorf("%w: the connection's cgroup: %w", errGovernedUnknown, err)
	}
	if g.knownOutside(id) {
		return nil
	}
	root, err := g.cgroupRoot()
	if err != nil {
		return fmt.Errorf("%w: %w", errGovernedUnknown, err)
	}
	rel, err := findCgroup(root, id)
	if err != nil {
		return fmt.Errorf("%w: %w", errGovernedUnknown, err)
	}
	if run := runscope.GovernedBy(rel); run != "" {
		return &governedError{Run: run}
	}
	g.markOutside(id)
	return nil
}

func (g *governedCheck) knownOutside(id uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.outside[id]
}

func (g *governedCheck) markOutside(id uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.outside == nil || len(g.outside) >= maxOutside {
		g.outside = make(map[uint64]bool)
	}
	g.outside[id] = true
}

// findCgroup is the path, from the cgroup2 mount root, of the cgroup whose directory has inode id. It fails closed:
// an id the walk did not find is an error, whether its cgroup was removed after the socket was made (a child of a
// run's own scope included), lies outside this process's view of the hierarchy, or sits past a part of the tree the
// walk could not read or passed over for its bounds. Only a cgroup actually found outside every run lets a change in.
func findCgroup(root string, id uint64) (string, error) {
	w := cgroupWalk{root: root, id: id}
	if rel, ok := w.dir("/", 0); ok {
		return rel, nil
	}
	if w.skipped != nil {
		return "", fmt.Errorf("the connection's cgroup (id %d) was not found, and part of the cgroup tree was not read: %w", id, w.skipped)
	}
	return "", fmt.Errorf("the connection's cgroup (id %d) is not in the cgroup tree: it was removed after the connection was made, or lies outside this dashboard's view", id)
}

// cgroupWalk is one depth-first search of the cgroup2 hierarchy for an inode.
type cgroupWalk struct {
	root    string
	id      uint64
	seen    int
	skipped error // the first part of the tree not read, for the refusal's words
}

func (w *cgroupWalk) skip(err error) {
	if w.skipped == nil {
		w.skipped = err
	}
}

// dir reports whether rel, or a directory below it, has the inode searched for, and that directory's path.
func (w *cgroupWalk) dir(rel string, depth int) (string, bool) {
	if w.seen++; w.seen > maxCgroupDirs {
		w.skip(fmt.Errorf("more than %d cgroups to read", maxCgroupDirs))
		return "", false
	}
	full := filepath.Join(w.root, filepath.FromSlash(rel))
	fi, err := os.Lstat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false // a cgroup removed while the tree was read
	}
	if err != nil {
		w.skip(err)
		return "", false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		w.skip(fmt.Errorf("stat %s: no inode", full))
		return "", false
	}
	if st.Ino == w.id {
		return rel, true
	}
	es, err := os.ReadDir(full)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false
	}
	if err != nil {
		w.skip(fmt.Errorf("read %s: %w", full, err))
		return "", false
	}
	subs := es[:0]
	for _, e := range es {
		if e.IsDir() {
			subs = append(subs, e)
		}
	}
	if len(subs) > 0 && depth >= maxCgroupDepth {
		w.skip(fmt.Errorf("%s holds cgroups more than %d deep", full, maxCgroupDepth))
		return "", false
	}
	for _, e := range subs {
		if hit, ok := w.dir(path.Join(rel, e.Name()), depth+1); ok {
			return hit, true
		}
	}
	return "", false
}

// cgroup2Mount is where the cgroup v2 hierarchy is mounted in this process's mount namespace: the mount point of the
// first cgroup2 line of /proc/self/mountinfo (proc(5): mount point is field 5, the filesystem type the first field
// after the " - " separator).
func cgroup2Mount() (string, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	return cgroup2MountIn(b)
}

func cgroup2MountIn(b []byte) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4<<10), 64<<10)
	for sc.Scan() {
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		f, typ := strings.Fields(pre), strings.Fields(post)
		if len(f) >= 5 && len(typ) >= 1 && typ[0] == "cgroup2" {
			return unescapeMount(f[4]), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no cgroup2 mount in /proc/self/mountinfo")
}

// unescapeMount undoes mountinfo's octal escapes of space, tab, newline and backslash.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// governedRefused is the 403 for a change the governed check refused: which run, and what to do instead.
func (s *Server) governedRefused(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	var ge *governedError
	if errors.As(err, &ge) {
		_, _ = fmt.Fprintf(w, "tego-control serve: %v.\nThis request came from a program inside that run. "+
			"Open the dashboard from a terminal outside any tego run, then try again.\n", err)
		return
	}
	_, _ = fmt.Fprintf(w, "tego-control serve: nothing was changed: %v.\n"+
		"Open the dashboard from a terminal outside any tego run, or make the change in a terminal (tego approve, tego deny, tego stop).\n", err)
}
