// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrNoContract is a ref that names no contract the dashboard may change: not one a run under this ledger root
// recorded as its contract_source, so not one the browser can name .
var ErrNoContract = errors.New("no such contract among the ones the runs here ran")

// ContractRef is one contract file a run under this ledger root ran, as the Change rules pages list it. The browser
// names it by Ref alone; Path is shown and never read back from a request.
type ContractRef struct {
	// Ref is the first 16 hex digits of the sha256 of the resolved path: opaque, so a request cannot smuggle a path
	// in (ref=../../etc/passwd names nothing), and stable across runs of the same file.
	Ref string
	// Path is the contract's path as its newest run recorded it, for display only.
	Path string
	// Agent is the contract's name:, else its file name.
	Agent string
	// Runs is how many runs here ran it; LastRun the newest of them and LastAt its start.
	Runs    int
	LastRun string
	LastAt  time.Time
	// Live are the runs of it running now, newest first: the runs "also apply now" can reach.
	Live []string
	// Writable says the file passes every write guard (rulefile.Check); Why says why not otherwise.
	Writable bool
	Why      string
	// Base is the sha256 of the text now, when it was read: the base a change form carries back.
	Base string
}

// start is what a run recorded at its start that the service reads: the contract it ran and the context it ran it
// in. run_start is a run's first line and never changes, so it is cached by run id.
type start struct {
	Run      string
	At       time.Time
	Contract string // run_start.contract_source.path as recorded; "" for a generated contract
	Resolved string // Contract with its directory's symlinks resolved (rulefile's File.Path spelling)
	Ref      string // refOf(Resolved), worked out once with the start rather than on every listing
	Cwd      string
	Tier     string
	Grant    string // run_command_grant
}

// listing is the ledger root as starts last listed it: the root's key then (rootKey), the runs whose first line
// read, newest first, and the run directories whose first line did not read yet. A run writes run_start in its own
// directory, which leaves the root's key as it was, so those are read again on every call.
type listing struct {
	key     string
	sts     []start
	pending []string
}

// listingSettle is how long before a listing the root must have last changed for starts to keep it. File times move
// in ticks of the kernel's coarse clock, a second on some file systems: a run directory made after the listing but in
// the same tick as the change the key holds could leave the key as it was, so a root changed more recently is listed
// again on the next call.
const listingSettle = 2 * time.Second

// starts is every run under the ledger root whose first line reads, newest first; one that does not read yet is left
// out. The Change rules page asks it three times a request (Contracts, Current, History) and a run page once (Feed),
// on every live update, and listing a root of thousands of runs cost milliseconds each time (BenchmarkContracts), so
// the listing is kept while the root's key stays the same: a run directory made, removed or renamed there moves it,
// and a run's run_start never changes once read. The slice is shared: callers only read it.
func (s *Service) starts() ([]start, error) {
	at := time.Now()
	if s.clock != nil {
		at = s.clock()
	}
	// The key is read through the opened root, not by a stat of its path: an NFS client fetches a directory's
	// attributes again when it is opened (close-to-open), where a stat may answer from its cache for up to a minute.
	// A listing then reads that same directory.
	d, err := os.OpenFile(s.Ledger, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }() // read-only
	key, changed, keyed := rootKey(d)
	s.mu.Lock()
	if l := s.listing; keyed && l != nil && l.key == key {
		sts := s.readPending(l)
		s.mu.Unlock()
		return sts, nil
	}
	s.mu.Unlock()
	ents, err := d.ReadDir(-1) // in the directory's order: sortStarts orders the runs
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string]start{}
	}
	seen := make(map[string]bool, len(ents))
	l := &listing{key: key, sts: make([]start, 0, len(ents))}
	for _, e := range ents {
		id := e.Name()
		if !e.IsDir() || !runID(id) {
			continue
		}
		seen[id] = true
		st, ok := s.startOf(id)
		if !ok {
			l.pending = append(l.pending, id)
			continue
		}
		l.sts = append(l.sts, st)
	}
	for id := range s.cache { // runs removed (gc, retention) leave the cache
		if !seen[id] {
			delete(s.cache, id)
		}
	}
	sortStarts(l.sts)
	l.sts = slices.Clip(l.sts) // a caller's append copies instead of writing into the kept array
	s.listing = nil
	if keyed && at.Sub(changed) > listingSettle {
		s.listing = l
	}
	return l.sts, nil
}

// readPending is l's runs with those of its pending run directories whose first line reads now, which then leave
// pending. l's slice is never written: a caller may still hold it. Called with s.mu held.
func (s *Service) readPending(l *listing) []start {
	var more []start
	var still []string
	for _, id := range l.pending {
		if st, ok := s.startOf(id); ok {
			more = append(more, st)
		} else {
			still = append(still, id)
		}
	}
	if len(more) == 0 {
		return l.sts
	}
	sts := slices.Concat(l.sts, more)
	sortStarts(sts)
	s.listing = &listing{key: l.key, sts: slices.Clip(sts), pending: still}
	return s.listing.sts
}

// startOf is run id's start, read once and then cached (run_start never changes); false while its first line does not
// read. Called with s.mu held.
func (s *Service) startOf(id string) (start, bool) {
	if st, ok := s.cache[id]; ok {
		return st, true
	}
	st, err := readStart(filepath.Join(s.Ledger, id))
	if err != nil || st.Run == "" {
		return start{}, false
	}
	s.cache[id] = st
	return st, true
}

// sortStarts orders sts newest first: by start time, then by run id.
func sortStarts(sts []start) {
	slices.SortFunc(sts, func(a, b start) int {
		if c := b.At.Compare(a.At); c != 0 {
			return c
		}
		return strings.Compare(b.Run, a.Run)
	})
}

// rootKey is what says the ledger root open at d still lists the run directories starts listed, and the later of the
// root's modification and change times. It holds the root's device and inode, its link count and size, which a run
// directory made or removed moves on most file systems whatever the clock, and those two times, which every entry
// made, removed or renamed in it moves. It reports false when the root cannot be looked at, which is never kept.
func rootKey(d *os.File) (string, time.Time, bool) {
	fi, err := d.Stat()
	if err != nil {
		return "", time.Time{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", time.Time{}, false
	}
	mtime, ctime := time.Unix(st.Mtim.Unix()), time.Unix(st.Ctim.Unix())
	key := fmt.Sprintf("%d:%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Nlink, st.Size, mtime.UnixNano(), ctime.UnixNano())
	if ctime.After(mtime) {
		return key, ctime, true
	}
	return key, mtime, true
}

// readStart reads run_start from the run directory dir.
func readStart(dir string) (start, error) {
	var st start
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return st, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	for e, err := range r.Iter() {
		if err != nil {
			return st, err
		}
		if e.Kind != record.KindRunStart {
			return st, fmt.Errorf("the first line of %s is a %s, not run_start", dir, e.Kind)
		}
		var p record.RunStartPayload
		if err := e.DecodePayload(&p); err != nil {
			return st, err
		}
		st = start{Run: e.Run, At: e.TS, Cwd: p.Cwd, Tier: p.Tier, Grant: p.RunCommandGrant}
		if p.ContractSource != nil && filepath.IsAbs(p.ContractSource.Path) {
			st.Contract = filepath.Clean(p.ContractSource.Path)
			st.Resolved = resolvedPath(st.Contract)
			st.Ref = refOf(st.Resolved)
		}
		return st, nil
	}
	return st, nil
}

// resolvedPath is p with its directory's symlinks resolved, as rulefile pins it and the journal spells it; p itself
// when the directory does not resolve.
func resolvedPath(p string) string {
	if d, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(d, filepath.Base(p))
	}
	return p
}

// refOf is the opaque ref of the contract at the resolved path p.
func refOf(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])[:16]
}

// contractInfo is a contract of the bounded set with the newest run's context.
type contractInfo struct {
	ContractRef
	newest start
}

// context is the context the contract is compiled in: its newest run's.
func (c *contractInfo) context(s *Service) CheckContext {
	cc := CheckContext{Contract: c.newest.Contract, Cwd: c.newest.Cwd, Tier: c.newest.Tier, RunCommandGrant: c.newest.Grant}
	if c.newest.Run != "" { // a contract set up here and not run yet has no run to read exec directories from
		cc.runDir = filepath.Join(s.Ledger, c.newest.Run)
	}
	return cc
}

// Contracts is every contract file a run under the ledger root ran, newest first, then every one set up here that no
// run ran yet (createdHere), each with whether the dashboard may change it. This is the whole set a change can name: a
// file no run here recorded and the dashboard did not create is never offered, whatever a request says.
func (s *Service) Contracts() ([]ContractRef, error) {
	cs, err := s.contracts()
	if err != nil {
		return nil, err
	}
	out := make([]ContractRef, len(cs))
	for i, c := range cs {
		out[i] = c.ContractRef
	}
	return out, nil
}

func (s *Service) contracts() ([]*contractInfo, error) {
	sts, err := s.starts()
	if err != nil {
		return nil, err
	}
	byRef := map[string]*contractInfo{}
	var out []*contractInfo
	listed := s.liveIndex()
	for _, st := range sts {
		if st.Contract == "" {
			continue
		}
		c, ok := byRef[st.Ref]
		if !ok {
			c = &contractInfo{ContractRef: ContractRef{Ref: st.Ref, Path: st.Contract, LastRun: st.Run, LastAt: st.At}, newest: st}
			byRef[st.Ref] = c
			out = append(out, c)
		}
		c.Runs++
		if (listed == nil || listed[st.Run]) && s.isLive(filepath.Join(s.Ledger, st.Run)) {
			c.Live = append(c.Live, st.Run)
		}
	}
	out = append(out, s.createdHere(byRef)...)
	for _, c := range out {
		v := s.readView(c.newest.Contract)
		c.Writable, c.Why, c.Base, c.Agent = v.writable, v.why, v.base, v.agent
		if !v.writable {
			c.Agent = strings.TrimSuffix(filepath.Base(c.Path), filepath.Ext(c.Path))
		}
	}
	return out, nil
}

// liveIndex is the runs the ledger root's live index lists (internal/ledger LiveDir): a launcher lists its run
// there before run_start, holding its lock, and fails the run when it cannot, so a run that is not listed holds no
// lock and need not be probed. Nil means probe every run: a test's liveness seam is set, or the index cannot be read
// for a reason other than not existing yet.
func (s *Service) liveIndex() map[string]bool {
	if s.live != nil {
		return nil
	}
	ents, err := os.ReadDir(filepath.Join(s.Ledger, ledger.LiveDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	out := make(map[string]bool, len(ents))
	for _, e := range ents {
		out[e.Name()] = true
	}
	return out
}

// contractView is what the Change rules pages show of a contract file: whether it passes the write guards (why not
// otherwise), its text's sha256 and its name.
type contractView struct {
	writable         bool
	why, base, agent string
}

// readMemo is one guarded read's view, kept while the file and its folder look the same.
type readMemo struct {
	id   string
	view contractView
}

// maxReadMemo bounds the views kept; past it the memo starts again.
const maxReadMemo = 256

// readView is the contract at path's view, read through every write guard once for each version of the file. A
// rules page or line page that refreshes while an agent runs used to repeat the guarded read of every contract
// about once a second. The key is the file's identity, size, mode, owner and times and its folder's identity, mode
// and owner, so a write (rulefile replaces by rename: a new inode), an edit in place, or a folder whose owner or mode
// changed reads again. The view only fills the page; every plan and every write reads the file through the guards itself, so a
// stale view can at most show an old base, which the write then refuses as changed.
func (s *Service) readView(path string) contractView {
	id, ok := fileIdentity(path)
	if ok {
		s.readMu.Lock()
		m, hit := s.reads[path]
		s.readMu.Unlock()
		if hit && m.id == id {
			return m.view
		}
	}
	var v contractView
	f, err := s.writer().Read(path)
	if err != nil {
		v.why = err.Error()
	} else {
		v = contractView{writable: true, base: f.SHA256, agent: agentName(f.Text, path)}
	}
	if ok {
		s.readMu.Lock()
		if s.reads == nil || len(s.reads) >= maxReadMemo {
			s.reads = map[string]readMemo{}
		}
		s.reads[path] = readMemo{id: id, view: v}
		s.readMu.Unlock()
	}
	return v
}

// fileIdentity is a key that changes whenever the file at path or what the guards check of its folder may have:
// the file's device, inode, size, mode, owner and modification and change times (not followed), and its folder's
// device, inode, mode and owner (followed, and not followed, so a retargeted folder link shows). It reports false
// when the file cannot be looked at, which is never memoized.
func fileIdentity(path string) (string, bool) {
	var b strings.Builder
	for i, p := range []string{path, filepath.Dir(path), filepath.Dir(path)} {
		var st syscall.Stat_t
		var err error
		if i == 2 {
			err = syscall.Stat(p, &st)
		} else {
			err = syscall.Lstat(p, &st)
		}
		if err != nil {
			return "", false
		}
		fmt.Fprintf(&b, "%d:%d:%o:%d|", st.Dev, st.Ino, st.Mode, st.Uid)
		if i == 0 { // a folder's times move with every file made in it (a .bak, a sibling's rename): not kept
			fmt.Fprintf(&b, "%d:%d.%d:%d.%d|", st.Size, st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec)
		}
	}
	return b.String(), true
}

// createdHere are the contracts this ledger root's journal records as created ("Set up a new agent", new.go) that no
// run here ran yet and whose file is still there, newest first: they join the bounded set, so the Rules page offers a
// new agent's rules before its first run. Their context is the contract's own folder as the cwd, with no tier, no run
// command grant and no run to read exec directories from.
func (s *Service) createdHere(seen map[string]*contractInfo) []*contractInfo {
	es, err := rulefile.ReadJournal(s.Ledger)
	if err != nil {
		return nil
	}
	var out []*contractInfo
	for i := len(es) - 1; i >= 0; i-- {
		e := es[i]
		if e.Op != rulefile.OpCreate || !filepath.IsAbs(e.Contract) {
			continue
		}
		ref := refOf(e.Contract)
		if _, ok := seen[ref]; ok {
			continue
		}
		if _, err := os.Lstat(e.Contract); err != nil {
			continue
		}
		st := start{At: e.At, Contract: e.Contract, Resolved: e.Contract, Ref: ref, Cwd: filepath.Dir(e.Contract)}
		c := &contractInfo{ContractRef: ContractRef{Ref: ref, Path: e.Contract, LastAt: e.At}, newest: st}
		seen[ref] = c
		out = append(out, c)
	}
	return out
}

// contract is the contract ref names in the bounded set, ErrNoContract when none.
func (s *Service) contract(ref string) (*contractInfo, error) {
	if len(ref) != 16 || strings.Trim(ref, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("%w: %q is not a contract ref", ErrNoContract, ref)
	}
	cs, err := s.contracts()
	if err != nil {
		return nil, err
	}
	for _, c := range cs {
		if c.Ref == ref {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNoContract, ref)
}

// contractOfPath is the contract of the bounded set at the resolved path p (a journal entry's contract).
func (s *Service) contractOfPath(p string) (*contractInfo, error) {
	return s.contract(refOf(p))
}

// isLive is whether a launcher holds the run directory's lock: the run is running and enforces live blocks.
func (s *Service) isLive(dir string) bool {
	if s.live != nil {
		return s.live(dir)
	}
	held, _, err := runlock.ProbeLock(dir)
	return err == nil && held
}

// agentName is the contract's name: field, else its file name without the extension.
func agentName(text []byte, path string) string {
	var top struct {
		Name string `yaml:"name"`
	}
	if yaml.Unmarshal(text, &top) == nil && top.Name != "" && len(top.Name) <= 128 {
		return top.Name
	}
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

// guard is where a contract the dashboard writes may not be: the ledger root it serves (which also journals each
// write), tego's home, and Service.Refuse (the machine's ledger root, tego's home under the machine's home).
func (s *Service) guard() rulefile.Guard {
	g := rulefile.DefaultGuard(s.Ledger)
	g.Refuse = append(g.Refuse, s.Refuse...)
	return g
}
