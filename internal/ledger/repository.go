// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// runIDPattern is the run id shape r-<host8>-<time36>-<rand6> (docs/p0/identity-config.md R2).
var runIDPattern = regexp.MustCompile(`^r-[0-9a-f]{8}-[0-9a-z]{13}-[0-9a-z]{6}$`)

// IsRunID reports whether s has the run id shape.
func IsRunID(s string) bool { return runIDPattern.MatchString(s) }

// CompareRunIDs orders run ids by mint time: time36 then rand6, the host8 prefix only as the last tie-break.
// The whole id sorts by mint time within one host alone (identity-config.md R1), and a ledger root may hold
// several host prefixes (a machine-id change, a shared home). A string that is not a run id sorts by its
// whole text, before every run id.
func CompareRunIDs(a, b string) int {
	okA, okB := IsRunID(a), IsRunID(b)
	switch {
	case okA && okB:
		if c := strings.Compare(a[len("r-00000000-"):], b[len("r-00000000-"):]); c != 0 {
			return c
		}
	case okA:
		return 1
	case okB:
		return -1
	}
	return strings.Compare(a, b)
}

// RunRepository is the contract internal/check, internal/cli and internal/doctor use over a ledger_root that
// holds many runs. It keeps no state between calls (I7).
type RunRepository interface {
	// List returns every run-shaped directory with the agent read from its run_start. It skips entries that
	// are not run-shaped and returns what it could read together with the first error it met.
	List(ctx context.Context) ([]record.RunRef, error)
	// Open returns a Reader for the run.
	Open(ctx context.Context, id string) (*Reader, error)
	// Lock opens the run for writing (Open with LOCK_EX|LOCK_NB): what run, stop and gc's sweep call.
	Lock(ctx context.Context, id string, run record.RunRef) (*Writer, error)
	// State reports the run's state without blocking; a directory without a ledger is StateEmpty (E22).
	State(ctx context.Context, id string) (RunState, error)
}

// NewRunRepository returns the repository over root, the ledger_root of the machine config; opts apply to
// every Writer it opens through Lock.
func NewRunRepository(root string, opts ...Option) RunRepository {
	return &fsRunRepository{root: root, opts: opts}
}

type fsRunRepository struct {
	// root is the ledger root's path: what a repository over a path resolves every run through, and, for a
	// pinned one, only what its errors name.
	root string
	opts []Option
	// rootDir, set for a pinned repository, is the ledger root a GC or SweepLive pass holds open (the pass's
	// owner, closed by the pass). Every lookup of a pinned repository is an *at() call under it with a link
	// refused, never a path, so a rename of the root or of an ancestor during the pass changes nothing it reads
	// or writes.
	rootDir *sys.FD
}

// pinnedRepository binds every run lookup to rootDir, the ledger root a pass holds; root is the configured path,
// which its errors name. Writers use OpenAt, retaining their privileged link checks.
func pinnedRepository(root string, rootDir *sys.FD, opts ...Option) *fsRunRepository {
	// The default anchor is beside the declared ledger root. Explicit caller options still win. It is a
	// separately protected file opened by the anchor's own directory walk.
	writer := append([]Option{WithAnchor(NewFileChainAnchor(DefaultAnchorPath(filepath.Join(root, "run"))))}, opts...)
	return &fsRunRepository{root: root, opts: writer, rootDir: rootDir}
}

// dir is the run directory's path: the one a repository over a path opens, and what a pinned one's errors name.
func (r *fsRunRepository) dir(id string) string { return filepath.Join(r.root, id) }

// openRun opens the pinned repository's run directory id under the held root, refusing a link.
func (r *fsRunRepository) openRun(id string) (*sys.FD, error) {
	d, err := r.rootDir.Openat(id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: r.dir(id), Err: err}
	}
	return d, nil
}

// reader opens run id's ledger for reading: under the held root for a pinned repository, by path otherwise.
func (r *fsRunRepository) reader(id string) (*Reader, error) {
	if r.rootDir == nil {
		return OpenReader(r.dir(id))
	}
	d, err := r.openRun(id)
	if err != nil {
		return nil, fmt.Errorf("ledger: open events: %w", err)
	}
	return openReaderIn(d, r.dir(id))
}

// openFile opens run id's file name for reading as openRegular does, under the held root for a pinned
// repository.
func (r *fsRunRepository) openFile(id, name string) (*os.File, error) {
	path := filepath.Join(r.dir(id), name)
	if r.rootDir == nil {
		return openRegular(path)
	}
	d, err := r.openRun(id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	return openRegularAt(d, name, path)
}

// lockFree probes run id's lock as lockFree does, under the held root for a pinned repository.
func (r *fsRunRepository) lockFree(id string) (bool, error) {
	f, err := r.openFile(id, LockFile)
	return probeLock(f, err)
}

// List implements RunRepository over the directory entries of root.
func (r *fsRunRepository) List(ctx context.Context) ([]record.RunRef, error) {
	entries, err := r.entries()
	if err != nil {
		return nil, fmt.Errorf("ledger: list runs: %w", err)
	}
	var refs []record.RunRef
	var first error
	for _, ent := range entries {
		if err := ctx.Err(); err != nil {
			return refs, err
		}
		if !ent.IsDir() || !IsRunID(ent.Name()) {
			continue
		}
		ref := record.RunRef{ID: ent.Name()}
		agent, err := r.agentOf(ent.Name())
		if err != nil && first == nil {
			first = fmt.Errorf("ledger: run %s: %w", ent.Name(), err)
		}
		ref.Agent = agent
		refs = append(refs, ref)
	}
	return refs, first
}

// entries lists the ledger root, sorted by name as os.ReadDir sorts it: the held root, through a descriptor of
// its own, for a pinned repository.
func (r *fsRunRepository) entries() ([]os.DirEntry, error) {
	if r.rootDir == nil {
		return os.ReadDir(r.root)
	}
	fd, err := r.rootDir.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: r.root, Err: err}
	}
	d, err := fd.Release(r.root)
	if err != nil {
		_ = fd.Close()
		return nil, &os.PathError{Op: "open", Path: r.root, Err: err}
	}
	defer func() { _ = d.Close() }()
	entries, err := d.ReadDir(-1)
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, err
}

// agentOfContract is the agent named by the run's contract.yaml, which Open writes before the run's first
// line: the only record of which agent a run that died before run_start belongs to, and so of where its cgroup
// is. The copy is Canonical's YAML, whose top-level `name:` line carries the agent id; "" when
// the file is missing, unreadable, or names no agent id.
func (r *fsRunRepository) agentOfContract(id string) string {
	return contractAgent(r.openFile(id, ContractFile))
}

// contractAgent is agentOfContract's answer from the contract copy f, opened with err: "" when it is not there.
func contractAgent(f *os.File, err error) string {
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if name, ok := strings.CutPrefix(line, "name: "); ok {
			name = strings.Trim(strings.TrimSpace(name), `"'`)
			if record.IsAgentID(name) {
				return name
			}
			return ""
		}
	}
	return ""
}

// agentOf reads the agent id from the first line; "" when the ledger is absent or empty.
func (r *fsRunRepository) agentOf(id string) (string, error) {
	return firstAgent(r.reader(id))
}

// firstAgent is agentOf's answer from the ledger rd, opened with err, which it closes.
func firstAgent(rd *Reader, err error) (string, error) {
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer func() { _ = rd.Close() }()
	rd.scanSize = 4 << 10 // the first line only: run_start is a few hundred bytes, not a 64 KiB fill per run
	for line, err := range rd.Lines() {
		if err != nil {
			return "", err
		}
		e, derr := record.Decode(line)
		if errors.Is(derr, record.ErrNewerVersion) {
			return "", nil // a newer binary's run_start is no error: the contract copy names the agent
		}
		if derr != nil {
			return "", fmt.Errorf("%w 1: at byte offset 0: %w", ErrCorruptLedger, derr)
		}
		return e.Agent, nil
	}
	return "", nil
}

// Open implements RunRepository; the id must be run-shaped so a caller cannot name a path outside root.
func (r *fsRunRepository) Open(ctx context.Context, id string) (*Reader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !IsRunID(id) {
		return nil, fmt.Errorf("%w: %q", ErrBadRunRef, id)
	}
	return r.reader(id)
}

// Lock implements RunRepository: Open on root/<id> with LOCK_EX|LOCK_NB, the id and run.ID must agree.
func (r *fsRunRepository) Lock(ctx context.Context, id string, run record.RunRef) (*Writer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if id != run.ID {
		return nil, fmt.Errorf("%w: directory %q, run %q", ErrBadRunRef, id, run.ID)
	}
	opts := append([]Option{WithExistingRunDir()}, r.opts...)
	if r.rootDir != nil {
		d, err := r.openRun(id)
		if err != nil {
			return nil, err
		}
		defer func() { _ = d.Close() }()
		return OpenAt(d, r.dir(id), run, opts...)
	}
	return Open(r.dir(id), run, opts...)
}

// State implements RunRepository; an absent ledger is StateEmpty (E22).
func (r *fsRunRepository) State(ctx context.Context, id string) (RunState, error) {
	rd, err := r.Open(ctx, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No ledger yet is also a Writer between its flock and its first open of events.jsonl:
			// liveness is the lock's to say, here as everywhere (I7).
			free, lerr := r.lockFree(id)
			switch {
			case lerr != nil:
				return "", lerr
			case !free:
				return StateRunning, nil
			}
			return StateEmpty, nil
		}
		return "", err
	}
	defer func() { _ = rd.Close() }()
	return rd.State()
}
