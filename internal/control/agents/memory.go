// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

const discoveryEntries = 256
const discoveryBytes = 256 << 10
const discoveryRetention = 30 * 24 * time.Hour
const discoveryFile = "discoveries.json"

const discoveryRepair = " Check the owner, mode and links at ~/.tego/agents and ~/.tego/agents/discoveries.json. Move links or invalid state aside; do not chmod through a link. For your checked directory and regular file with one link, run chmod 700 ~/.tego/agents and chmod 600 ~/.tego/agents/discoveries.json. Then run tego scan from your project folder and refresh this page."

var errDiscoveryStore = errors.New("unsafe or invalid discovery store")

// The ways Forget stops. Each leaves the store as it was, except ErrForgetSave, whose replacement durability is
// unknown (the same words remember uses).
var (
	ErrForgetUnavailable = errors.New("the dashboard has no way to read the user's own state")
	ErrNotRemembered     = errors.New("this discovery is not remembered")
	ErrForgetBusy        = errors.New("remembered discoveries are busy")
	ErrForgetUnsafe      = errors.New("remembered discoveries could not be read safely")
	ErrForgetSave        = errors.New("remembered discoveries could not be saved")
)

// forgetDiscovery drops the entry whose row ID is id. The ID is compared with each stored entry's own identity, so
// a request cannot name a file, a path or a run: an unknown ID changes nothing.
func forgetDiscovery(home string, uid uint32, id string, now time.Time) error {
	if !strings.HasPrefix(id, "agent-discovery-") {
		return ErrNotRemembered
	}
	d, err := discoveryDir(home, uid, false)
	if errors.Is(err, unix.ENOENT) {
		return ErrNotRemembered
	}
	if err != nil {
		return ErrForgetUnsafe
	}
	defer func() { _ = d.Close() }()
	if err = d.Borrow(func(n int) error { return unix.Flock(n, unix.LOCK_EX|unix.LOCK_NB) }); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return ErrForgetBusy
		}
		return ErrForgetUnsafe
	}
	entries, before, err := readDiscoveries(d, uid, now)
	if err != nil {
		return ErrForgetUnsafe
	}
	kept := make([]discovery, 0, len(entries))
	for _, e := range entries {
		if discoveryID(e.Found) != id {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(entries) {
		return ErrNotRemembered
	}
	if err = saveDiscoveries(d, uid, kept, before); err != nil {
		return ErrForgetSave
	}
	return nil
}

// A remembered discovery is an untrusted observation, never evidence of a run.
// Keep only the identity that scans actually supply, never arguments or settings.
type discovery struct {
	Found      agentid.Found `json:"observed"`
	Kind       string        `json:"kind"`
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
	ScanResult string        `json:"scan_result"`
}
type discoveryStore struct {
	Version int         `json:"version"`
	Entries []discovery `json:"entries"`
}

func discoveryKey(f agentid.Found) string {
	b, _ := json.Marshal([]string{f.Command, f.Folder, strconv.FormatUint(uint64(f.UID), 10), strconv.FormatBool(f.UIDKnown)})
	return string(b)
}

// remember preserves every unexpired existing identity before admitting new
// identities. A maximum-size replacement can truncate newcomers, never evict a
// previously displayed identity. The directory lock serializes store writers.
func (v *View) remember(home string, uid uint32, r result.ReadResult, scanErr error, now time.Time) {
	v.normalizeDiscoveries()
	defer v.sortDiscoveries()
	current := map[string]agentid.Found{}
	kinds := map[string]string{}
	usableScan := scanErr == nil && r.Freshness == "fresh" && r.Snapshot.Status != "failed"
	if usableScan {
		for _, f := range guide.ScanAgents(r.Snapshot, uid, filepath.Join(home, ".tego", "scan", "last.json")) {
			current[discoveryKey(f)] = f
		}
		for _, item := range r.Snapshot.Items {
			kinds[item.ID] = item.Kind
		}
	}
	d, err := discoveryDir(home, uid, len(current) > 0)
	if errors.Is(err, unix.ENOENT) {
		return
	}
	if err != nil {
		v.DiscoveryNotice = "The remembered programs could not be read: the folder or file has an unsafe owner, permissions or links. Nothing was changed." + discoveryRepair
		return
	}
	defer func() { _ = d.Close() }()
	locked := true
	if err = d.Borrow(func(n int) error { return unix.Flock(n, unix.LOCK_EX|unix.LOCK_NB) }); err != nil {
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			v.DiscoveryNotice = "The list of remembered programs could not be locked. Nothing was changed. Refresh to try again."
			return
		}
		// Atomic replacement makes the committed snapshot readable without holding
		// the writer lock. The same pinned descriptor checks still apply.
		locked = false
		v.DiscoveryNotice = "The list of remembered programs is in use right now. This page shows the last saved copy and did not update it. Refresh to try again."
	}
	entries, before, err := readDiscoveries(d, uid, now)
	if err != nil {
		v.DiscoveryNotice = "The remembered programs could not be read: the file is unsafe, too large, damaged or missing. Tego treats it as empty and changed nothing." + discoveryRepair
		return
	}
	retained := make([]discovery, 0, len(entries))
	known := map[string]int{}
	for _, e := range entries {
		if now.Sub(e.LastSeen) > discoveryRetention {
			continue
		}
		known[discoveryKey(e.Found)] = len(retained)
		retained = append(retained, e)
	}
	// Existing rows win the bound. Sorted newcomers make truncation deterministic.
	keys := make([]string, 0, len(current))
	for k := range current {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		f := current[k]
		f.Fact = "Saved scan observation; the scan keeps no arguments and establishes no run stage."
		if i, ok := known[k]; ok {
			if !f.SeenAt.Before(retained[i].LastSeen) {
				f.ID = retained[i].Found.ID
				retained[i].Found = f
				retained[i].LastSeen = f.SeenAt
				retained[i].ScanResult = r.Identity
			}
			continue
		}
		if len(retained) >= discoveryEntries {
			v.DiscoveryTruncated = true
			continue
		}
		e := discovery{Found: f, Kind: kinds[f.ID], FirstSeen: f.SeenAt, LastSeen: f.SeenAt, ScanResult: r.Identity}
		if !validDiscovery(e, uid, now) {
			v.DiscoveryTruncated = true
			continue
		}
		candidate := append(slices.Clone(retained), e)
		b, _ := json.Marshal(discoveryStore{Version: 1, Entries: candidate})
		if len(b) > discoveryBytes {
			v.DiscoveryTruncated = true
			continue
		}
		known[k] = len(retained)
		retained = append(retained, e)
	}
	// Oldest last-seen appears first so retained omissions are visible first.
	slices.SortFunc(retained, func(a, b discovery) int {
		if n := a.LastSeen.Compare(b.LastSeen); n != 0 {
			return n
		}
		return strings.Compare(discoveryKey(a.Found), discoveryKey(b.Found))
	})
	if locked && (len(current) > 0 || len(entries) > 0) {
		if err = saveDiscoveries(d, uid, retained, before); err != nil {
			v.DiscoveryNotice = "The remembered programs could not be saved. The old list was kept, or Tego cannot tell whether the new one reached the disk."
		}
	}
	if v.DiscoveryTruncated {
		v.DiscoveryNotice += " The list of remembered programs reached its size limit, or some details could not be kept safely, so it was cut short. Programs already remembered were kept. Newer ones were not added."
	}
	// Relations are explanations of this load's recorded facts, never saved
	// authority. Recompute them even after the source scan disappears.
	var runs []agentid.Run
	for _, row := range v.Rows {
		runs = append(runs, row.Agent.Runs...)
	}
	for _, e := range retained {
		k := discoveryKey(e.Found)
		_, seen := current[k]
		foundRow := -1
		for i := range v.Rows {
			if len(v.Rows[i].Agent.Runs) == 0 {
				for _, f := range v.Rows[i].Agent.Found {
					if discoveryKey(f) == k {
						foundRow = i
						break
					}
				}
			}
		}
		if foundRow < 0 {
			var a agentid.Agent
			for _, candidate := range agentid.Resolve([]agentid.Found{e.Found}, runs, nil) {
				if len(candidate.Found) > 0 {
					a = candidate
					break
				}
			}
			a.ID = discoveryID(e.Found)
			row := Row{Agent: a, ID: a.ID, Name: a.Name, Stage: "Previously seen", URL: "/agents/" + a.ID, SeenAt: e.LastSeen, Age: age(e.LastSeen, now), RecordCommand: watchLine(a.Folder), RecordNotice: "Record it with the command you start it with; the scan keeps no arguments."}
			v.Rows = append(v.Rows, row)
			foundRow = len(v.Rows) - 1
		}
		row := &v.Rows[foundRow]
		row.Remembered = true
		row.FirstSeen = e.FirstSeen
		row.LastSeen = e.LastSeen
		row.SeenAt = e.LastSeen
		row.Age = age(e.LastSeen, now)
		row.Agent.LastSeen = e.LastSeen
		row.ScanResult = e.ScanResult
		row.NotSeenLatest = usableScan && !seen
		if !seen {
			row.Stage = "Previously seen"
			row.Agent.Current = ""
			status := "Not seen in the latest scan; this is a remembered observation."
			row.Membership, row.WhereAt = "Not seen in the latest scan; last seen", e.LastSeen
			if !usableScan {
				status = v.ScanNotice
				row.Membership, row.WhereAt = status+" Last seen", e.LastSeen
				row.Agent.NextStep = "Scan again: run tego scan from your project folder, then refresh this page."
			}
			for i := range row.Agent.Stages {
				row.Agent.Stages[i].Fact.Established = false
				// Preserve the relation explanation as well as scan availability.
				row.Agent.Stages[i].Fact.CannotTell += " " + status
			}
		}
	}
}

func discoveryDir(home string, uid uint32, create bool) (*sys.FD, error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return nil, errDiscoveryStore
	}
	// The ancestors of the store are opened O_PATH: a walk needs search permission on them, never read. Only
	// the store itself, whose entries are read and replaced, is opened for reading.
	const ancestor = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	d, err := sys.Own(unix.Open("/", ancestor&^unix.O_NOFOLLOW, 0))
	if err != nil {
		return nil, err
	}
	// Walk each directory without following links, including the configured home.
	for _, name := range strings.Split(strings.TrimPrefix(home, "/"), "/") {
		if name == "" {
			continue
		}
		next, e := d.Openat(name, ancestor, 0)
		_ = d.Close()
		if e != nil {
			return nil, e
		}
		d = next
	}
	for _, name := range []string{".tego", "agents"} {
		if create {
			err = d.Borrow(func(n int) error { return unix.Mkdirat(n, name, 0700) })
			if err != nil && !errors.Is(err, unix.EEXIST) {
				_ = d.Close()
				return nil, err
			}
		}
		flags := ancestor
		if name == "agents" {
			flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		}
		next, e := d.Openat(name, flags, 0)
		_ = d.Close()
		if e != nil {
			return nil, e
		}
		d = next
		var st unix.Stat_t
		if e = d.Fstat(&st); e != nil || st.Uid != uid || st.Mode&0022 != 0 || name == "agents" && st.Mode&07777 != 0700 {
			_ = d.Close()
			return nil, errDiscoveryStore
		}
	}
	return d, nil
}
func discoveryStat(st unix.Stat_t, uid uint32) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == uid && st.Nlink == 1 && st.Mode&07777 == 0600 && st.Size >= 0 && st.Size <= discoveryBytes
}
func sameDiscovery(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func readDiscoveries(d *sys.FD, uid uint32, now time.Time) ([]discovery, *unix.Stat_t, error) {
	pin, err := d.Openat(discoveryFile, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = pin.Close() }()
	var before unix.Stat_t
	if err = pin.Fstat(&before); err != nil || !discoveryStat(before, uid) {
		return nil, nil, errDiscoveryStore
	}
	var fd *sys.FD
	err = pin.ProcPath(func(p string) error {
		var e error
		fd, e = sys.Own(unix.Open(p, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
		return e
	})
	if err != nil {
		return nil, nil, err
	}
	f, err := fd.Release("discoveries")
	if err != nil {
		_ = fd.Close()
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	var after unix.Stat_t
	if err = sys.FstatFile(f, &after); err != nil || !sameDiscovery(before, after) {
		return nil, nil, errDiscoveryStore
	}
	b, err := io.ReadAll(io.LimitReader(f, discoveryBytes+1))
	if err != nil || len(b) > discoveryBytes {
		return nil, nil, errDiscoveryStore
	}
	if err = sys.FstatFile(f, &after); err != nil || !sameDiscovery(before, after) {
		return nil, nil, errDiscoveryStore
	}
	if !discoveryUnchanged(d, &before) {
		return nil, nil, errDiscoveryStore
	}
	var store discoveryStore
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&store); err != nil || store.Version != 1 || store.Entries == nil || len(store.Entries) > discoveryEntries {
		return nil, nil, errDiscoveryStore
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return nil, nil, errDiscoveryStore
	}
	keys := map[string]bool{}
	for _, e := range store.Entries {
		if !validDiscovery(e, uid, now) {
			return nil, nil, errDiscoveryStore
		}
		k := discoveryKey(e.Found)
		if keys[k] {
			return nil, nil, errDiscoveryStore
		}
		keys[k] = true
	}
	return store.Entries, &before, nil
}
func discoveryUnchanged(d *sys.FD, before *unix.Stat_t) bool {
	f, err := d.Openat(discoveryFile, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if before == nil {
		if err == nil {
			_ = f.Close()
			return false
		}
		return errors.Is(err, unix.ENOENT)
	}
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	return f.Fstat(&st) == nil && sameDiscovery(*before, st)
}
func saveDiscoveries(d *sys.FD, uid uint32, entries []discovery, before *unix.Stat_t) error {
	if entries == nil {
		entries = []discovery{}
	}
	b, err := json.Marshal(discoveryStore{Version: 1, Entries: entries})
	if err != nil || len(b) > discoveryBytes {
		return errDiscoveryStore
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".discoveries-" + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := d.Openat(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = d.Borrow(func(n int) error { return unix.Unlinkat(n, name, 0) }) }()
	var st unix.Stat_t
	if err = fd.Fstat(&st); err != nil || !discoveryStat(st, uid) {
		_ = fd.Close()
		return errDiscoveryStore
	}
	f, err := fd.Release("discoveries-temp")
	if err != nil {
		_ = fd.Close()
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if !discoveryUnchanged(d, before) {
		return errDiscoveryStore
	}
	if err = d.Borrow(func(n int) error { return unix.Renameat(n, name, n, discoveryFile) }); err != nil {
		return err
	}
	return d.Fsync()
}

func validDiscovery(e discovery, uid uint32, now time.Time) bool {
	if e.FirstSeen.IsZero() || e.LastSeen.Before(e.FirstSeen) || e.LastSeen.After(now) || e.ScanResult == "" || e.Kind != "process" && e.Kind != "program" || !e.Found.UIDKnown || e.Found.UID != uid || !e.Found.SeenAt.Equal(e.LastSeen) {
		return false
	}
	for _, s := range []string{e.Found.ID, e.Found.Name, e.Found.Command, e.Found.Folder, e.Found.Source, e.Found.Fact, e.ScanResult} {
		if len(s) > 4096 || record.Printable(s) != s {
			return false
		}
	}
	return true
}
func discoveryID(f agentid.Found) string {
	sum := sha256.Sum256([]byte(discoveryKey(f)))
	return "agent-discovery-" + hex.EncodeToString(sum[:])
}
func (v *View) normalizeDiscoveries() {
	out := make([]Row, 0, len(v.Rows))
	seen := map[string]int{}
	for _, row := range v.Rows {
		if len(row.Agent.Runs) > 0 || len(row.Agent.Found) == 0 {
			out = append(out, row)
			continue
		}
		id := discoveryID(row.Agent.Found[0])
		if n, ok := seen[id]; ok {
			out[n].Observations = append(out[n].Observations, row.Observations...)
			out[n].Agent.Found = append(out[n].Agent.Found, row.Agent.Found...)
			continue
		}
		row.ID = id
		row.Agent.ID = id
		row.URL = "/agents/" + id
		seen[id] = len(out)
		out = append(out, row)
	}
	v.Rows = out
}

// Keep recorded-run order intact, then show the oldest observed identities first,
// including current observations that exceeded the memory store's bound.
func (v *View) sortDiscoveries() {
	slices.SortStableFunc(v.Rows, func(a, b Row) int {
		ar, br := len(a.Agent.Runs) > 0, len(b.Agent.Runs) > 0
		if ar && br {
			return 0
		}
		if ar {
			return -1
		}
		if br {
			return 1
		}
		return a.SeenAt.Compare(b.SeenAt)
	})
}
