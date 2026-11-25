// SPDX-License-Identifier: Apache-2.0

package budgetwindow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrUnprovable is a window whose earlier spend the ledgers cannot prove: the run named in the error is of this agent
// and its record does not verify, is unreadable, or is closed with no chain.log line. The run is refused rather than
// started with a count that could be low.
var ErrUnprovable = errors.New("budgetwindow: the spend in the window cannot be proved")

// ErrLockFile is a window lock that cannot be opened, with ErrUnprovable: no run's ledger is at fault, and the fix is
// the lock file's mode or owner, not a ledger.
var ErrLockFile = errors.New("budgetwindow: the window's lock file cannot be opened")

// ErrTooLarge is a window whose ledgers are too big to read at a start: this agent's runs in it hold more than
// MaxReadBytes of record. The start is refused, not slowed without end (ADR 0165, "What a start costs").
var ErrTooLarge = errors.New("budgetwindow: the agent's ledgers in the window are too large to read at a start")

// MaxReadBytes bounds what one start reads: the events.jsonl bytes of this agent's runs that are read whole (those not
// proved to have ended before the window). Reading and checking cost 4.5 to 9 MB a second (ADR 0165), so the bound is
// one to two minutes of waiting before run_start, with no agent process running.
const MaxReadBytes int64 = 512 << 20

// readBudget is MaxReadBytes, a variable only so that a test can make a small ledger too large.
var readBudget = MaxReadBytes

// ErrLive is a run of this agent that is still running: its spend is still growing, so no count of it is a count, and
// two runs of one agent would each take the other's as what it was at their start.
var ErrLive = errors.New("budgetwindow: another run of this agent is live")

// Identity names an agent across its restarts, and the choice is permanent: a run's identity is taken from what its own
// run_start recorded (record.ContractSource), so a ledger written by one build is read by every later one under the same
// name. A contract named in the user registry is that registry and name: the user registry is one folder per account, and
// a name is one agent in it. A contract named in the project registry is the contract file's absolute path with its name:
// the project registry is the working directory's, so `bot` in /a and `bot` in /b are two agents with two budgets and two
// locks, and an agent moved to another folder starts a new count. One named by a path is that absolute path, so `--agent
// NAME` and the same file given by path are two identities. A contract tego generated has none, and a window needs one.
type Identity string

// IdentityOf is the identity of a run whose run_start carries cs, and false when cs names nothing.
func IdentityOf(cs *record.ContractSource) (Identity, bool) {
	switch {
	case cs == nil:
		return "", false
	case cs.Name != "" && cs.Registry == registryProject:
		// The project registry has no machine-wide meaning: its name is only unique beside its file.
		if cs.Path == "" {
			return "", false
		}
		return Identity("project:" + cs.Name + "@" + cs.Path), true
	case cs.Name != "":
		return Identity("name:" + cs.Registry + ":" + cs.Name), true
	case cs.Path != "":
		return Identity("path:" + cs.Path), true
	}
	return "", false
}

// registryProject is run_start's contract_source.registry for the working directory's registry (registry.Project).
const registryProject = "project"

// Request is one reading of the window.
type Request struct {
	// Root is the ledger root; Anchor is chain.log, where an ended run's head is looked up.
	Root   string
	Anchor ledger.ChainAnchor
	// Self is this run's id, never counted: its directory exists before this is read.
	Self string
	// Identity is the agent whose runs count.
	Identity Identity
	// Now and Window bound the span: spend stamped before Now-Window is not returned.
	Now    time.Time
	Window time.Duration
	// Foreign names a run another host minted (a root shared between machines): its chain.log is that host's, so it
	// is not read. nil reads every run.
	Foreign func(id string) bool
}

// Result is what the window holds.
type Result struct {
	// Carry is the earlier runs' spend inside the window, one entry per minute, model and billing modifier.
	Carry []limits.CarryUse
	// Runs counts the runs of this agent that were read; Lost is those of them that never wrote run_end (their
	// launcher died), whose chain verifies to its last line but has no anchor to say nothing after it was lost.
	Runs int
	Lost []string
	// Unanchored are this agent's runs that ended but have no line in chain.log (the anchor write failed, or the line
	// was lost). Their chain verifies on its own and they are counted as the record holds them: nothing says the record
	// was cut or edited after it closed, since nothing was written to check it against.
	Unanchored []string
	// Unattributed are run directories whose first line could not be read as a run_start, so no agent can be named:
	// not counted, and said so. Only someone who can write the ledger root makes one (a torn or edited first line, or a
	// directory of an account that is not the launcher's, which this launcher cannot read).
	Unattributed []string
}

// maxCarry bounds the entries one reading may hold (a minute, a model and a modifier each): more is a ledger that is
// not an agent's, and the window is refused rather than read without end.
const maxCarry = 200_000

// slack is how much older than the window a line may be and still be returned: the watcher counts in minutes and
// drops a minute once all of it has left the window, so this is what it may still need.
const slack = time.Minute

// sslMarker is what a model response's line holds; a line without it is not decoded for the count.
var sslMarker = []byte(string(record.KindSSLResponse))

type carryKey struct {
	minute   int64
	model    string
	modified bool
}

// Read returns the spend of this agent's earlier runs inside the window.
func Read(ctx context.Context, req Request) (Result, error) {
	ents, err := os.ReadDir(req.Root)
	if err != nil {
		return Result{}, fmt.Errorf("%w: read the ledger root: %w", ErrUnprovable, err)
	}
	from := req.Now.Add(-req.Window).Add(-slack)
	sums := map[carryKey]*limits.CarryUse{}
	var res Result
	var ids []string
	for _, e := range ents {
		id := e.Name()
		if e.IsDir() && ledger.IsRunID(id) && id != req.Self && (req.Foreign == nil || !req.Foreign(id)) {
			ids = append(ids, id)
		}
	}
	heads := anchoredHeads(req.Anchor, ids)
	budget := readBudget
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		out, err := readRun(ctx, filepath.Join(req.Root, id), id, req, from, heads, sums, &budget)
		if err != nil {
			return Result{}, err
		}
		if out.counted {
			res.Runs++
		}
		if out.lost {
			res.Lost = append(res.Lost, id)
		}
		if out.unanchored {
			res.Unanchored = append(res.Unanchored, id)
		}
		if out.unattributed {
			res.Unattributed = append(res.Unattributed, id)
		}
		if len(sums) > maxCarry {
			return Result{}, fmt.Errorf("%w: more than %d minutes of spend in %s", ErrUnprovable, maxCarry, id)
		}
	}
	for _, c := range sums {
		res.Carry = append(res.Carry, *c)
	}
	return res, nil
}

// runRead is what readRun found of one run directory.
type runRead struct {
	counted      bool // the run is this agent's and its spend was added
	lost         bool // ... and it never ended
	unanchored   bool // ... and it ended with no line in chain.log
	unattributed bool // no agent could be named for it: it was not counted
}

// readRun adds one run's spend to sums when the run is this agent's and was not proved to have ended before the window.
//
// Whose run it is comes first, from the run's first line alone, and a run that is another agent's is left there: its
// state, its chain and the rest of it are never read, so nothing wrong in another agent's record can stop this one.
// Every refusal below is about a run that has said it is this agent's, and names it. A run whose first line cannot say
// is left out and reported (unattributed), except one that this launcher's own account owns and cannot read: the one
// way an agent reaches its records is chmod, which tego restores at the start of a run, so a mode that is still wrong
// here is refused with the command that fixes it.
func readRun(ctx context.Context, dir, id string, req Request, from time.Time, heads map[string]ledger.AnchorHead, sums map[carryKey]*limits.CarryUse, budget *int64) (runRead, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return runRead{}, nil
		}
		if ownedByOtherAccount(dir, err) || notALedger(err) {
			return runRead{unattributed: true}, nil
		}
		return runRead{}, fmt.Errorf("%w: %s: it may be this agent's, and it cannot be read: %w", ErrUnprovable, id, err)
	}
	defer func() { _ = r.Close() }()
	own, perr := peekOwner(r, req.Identity)
	switch {
	case perr == errEmptyRun:
		return runRead{}, nil
	case perr != nil && ownedByOtherAccount(dir, perr):
		return runRead{unattributed: true}, nil
	case perr != nil && errors.Is(perr, fs.ErrPermission):
		return runRead{}, fmt.Errorf("%w: %s: it may be this agent's, and it cannot be read: %w", ErrUnprovable, id, perr)
	case perr != nil:
		return runRead{unattributed: true}, nil
	case !own:
		return runRead{}, nil
	}
	state, err := r.State()
	if err != nil {
		return runRead{}, fmt.Errorf("%w: %s (this agent's): %w", ErrUnprovable, id, err)
	}
	if state == ledger.StateRunning {
		return runRead{}, fmt.Errorf("%w: %s", ErrLive, id)
	}
	// A run that ended before the window began holds nothing in it. What says so is its closing line, proved against
	// chain.log's head for the run, never a file's modification time: the agent runs as the ledgers' owner and can set
	// that to any date, and a run read as old would count 0. Every other run is read and checked whole.
	if state == ledger.StateEnded && endedBefore(r, heads[id], from) {
		return runRead{}, nil
	}
	if size, err := r.Size(); err == nil {
		if *budget -= size; *budget < 0 {
			return runRead{}, fmt.Errorf("%w: %s and the runs before it hold more than %d MiB", ErrTooLarge, id, MaxReadBytes>>20)
		}
	}
	// One pass reads the raw lines, which the chain check steps over as they come (VerifyAlong). Only the model
	// responses are decoded for the count; the check itself decodes and validates every line, so decoding them again
	// here would double the cost of a large ledger for nothing.
	v := r.VerifyAlong()
	first := true
	for line, lerr := range r.Lines() {
		if lerr != nil {
			return runRead{}, fmt.Errorf("%w: %s (this agent's): %w", ErrUnprovable, id, lerr)
		}
		if first { // run_start, read above
			first = false
			continue
		}
		if !bytes.Contains(line, sslMarker) {
			continue
		}
		ev, err := record.Decode(line)
		if err != nil {
			return runRead{}, fmt.Errorf("%w: %s (this agent's): %w", ErrUnprovable, id, err)
		}
		u, ok := ledger.Usage(ev)
		if !ok || ev.TS.Before(from) {
			continue
		}
		k := carryKey{minute: ev.TS.Unix() / 60, model: u.Model, modified: u.Modified}
		c := sums[k]
		if c == nil {
			c = &limits.CarryUse{At: time.Unix(k.minute*60, 0).UTC(), Usage: ledger.TokenUsage{Model: u.Model, Modified: u.Modified}}
			sums[k] = c
		}
		add(&c.Usage, u)
		if err := ctx.Err(); err != nil {
			return runRead{}, err
		}
	}
	if first {
		return runRead{}, nil // no complete line after all
	}
	// The chain is checked in the same pass. An ended run must match its chain.log line, so a ledger cut or edited after
	// it closed is found here; a run that never ended has no line yet, and its chain is checked to its last line. An
	// ended run chain.log has no line for at all (the write of it failed, or the line was lost) has nothing to match: it
	// is checked as a chain on its own and counted, which is what a run that never ended gets too, and said so.
	anchor, unanchored := req.Anchor, false
	if state == ledger.StateEnded && noAnchorLine(req.Anchor, heads, id) {
		anchor, unanchored = nil, true
	}
	if _, err := v.Finish(ctx, anchor); err != nil {
		return runRead{}, fmt.Errorf("%w: %s (this agent's): %w", ErrUnprovable, id, err)
	}
	return runRead{counted: true, lost: state == ledger.StateLost, unanchored: unanchored}, nil
}

// errEmptyRun is a run directory whose events file holds no complete line yet.
var errEmptyRun = errors.New("budgetwindow: no complete first line")

// peekOwner reports whether the run's first line is a run_start of the agent with identity want. It reads that line and
// nothing else. An error says the line could not tell (unreadable, not a run_start, does not decode).
func peekOwner(r *ledger.Reader, want Identity) (bool, error) {
	for line, err := range r.Lines() {
		if err != nil {
			return false, err
		}
		ev, err := record.Decode(line)
		if err != nil {
			return false, err
		}
		return ownedBy(ev, want)
	}
	return false, errEmptyRun
}

// ownedByOtherAccount is an error that is a refusal of permission on a path another account owns, which this launcher
// cannot open and the agent of this account cannot have made: a root run that is still live under its own mode, or an
// account's directory in a shared root. A root launcher reads everything, so it never says this.
func ownedByOtherAccount(dir string, err error) bool {
	if !errors.Is(err, fs.ErrPermission) {
		return false
	}
	var st unix.Stat_t
	if unix.Lstat(dir, &st) != nil {
		return false
	}
	return int(st.Uid) != launcherEUID()
}

// launcherEUID is the uid this launcher runs as; a variable so a test can stand in for a launcher that is not the
// owner of a directory it cannot open, which as an ordinary user it cannot otherwise make.
var launcherEUID = os.Geteuid

// notALedger is an open that found something other than a ledger at the events file's name: a link, a directory, a FIFO.
// It is nobody's record, so no agent's spend is in it.
func notALedger(err error) bool {
	return errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EISDIR) ||
		strings.Contains(err.Error(), "not a regular file")
}

// noAnchorLine reports that chain.log has no line for run: its head was asked for and chain.log answered that it has
// none (and not that it could not be read, which refuses).
func noAnchorLine(a ledger.ChainAnchor, heads map[string]ledger.AnchorHead, id string) bool {
	if a == nil {
		return false
	}
	if h, ok := heads[id]; ok {
		return !h.OK && h.Err == nil
	}
	_, ok, err := a.Head(id)
	return !ok && err == nil
}

// anchoredHeads is chain.log's head for each of ids, read once when the anchor can answer for many runs; nil otherwise,
// and a run then has no cut (it is read whole).
func anchoredHeads(a ledger.ChainAnchor, ids []string) map[string]ledger.AnchorHead {
	b, ok := a.(interface {
		Heads(runs []string) map[string]ledger.AnchorHead
	})
	if !ok || len(ids) == 0 {
		return nil
	}
	return b.Heads(ids)
}

// endedBefore reports whether r's last line is its run_end, proved: the line's own digest is the id chain.log anchors
// for the run, so its stamp is the one the launcher wrote and nothing in the run is stamped later. Anything short of
// that proof (no anchor line, a different head, a line that does not read) is false, and the run is read in full.
func endedBefore(r *ledger.Reader, head ledger.AnchorHead, from time.Time) bool {
	if !head.OK || head.Err != nil {
		return false
	}
	for ent, err := range r.Backward() {
		if err != nil || ent.Event == nil || ent.Event.Kind != record.KindRunEnd {
			return false
		}
		id, err := record.VerifyLine(ent.Line)
		return err == nil && id == head.Head && ent.Event.TS.Before(from)
	}
	return false
}

// ownedBy reports whether the run's first line is a run_start of the agent with identity want.
func ownedBy(ev *record.Event, want Identity) (bool, error) {
	if ev.Kind != record.KindRunStart {
		return false, fmt.Errorf("the first line is a %s, not run_start", ev.Kind)
	}
	var p record.RunStartPayload
	if err := ev.DecodePayload(&p); err != nil {
		return false, fmt.Errorf("run_start does not read: %w", err)
	}
	got, ok := IdentityOf(p.ContractSource)
	return ok && got == want, nil
}

// add sums u into into, a count held at the largest value rather than wrapped.
func add(into *ledger.TokenUsage, u ledger.TokenUsage) {
	into.In = ledger.SatAdd(into.In, u.In)
	into.Out = ledger.SatAdd(into.Out, u.Out)
	into.CacheRead = ledger.SatAdd(into.CacheRead, u.CacheRead)
	into.CacheWrite = ledger.SatAdd(into.CacheWrite, u.CacheWrite)
	into.CacheWrite1h = ledger.SatAdd(into.CacheWrite1h, u.CacheWrite1h)
	for name, n := range u.ServerTool {
		if n <= 0 {
			continue
		}
		if into.ServerTool == nil {
			into.ServerTool = map[string]int{}
		}
		into.ServerTool[name] += n
	}
}

// The name of an agent's window lock in the ledger root is lockPrefix, 16 hex digits of the agent's hash and lockSuffix.
const (
	lockPrefix = ".window-"
	lockSuffix = ".lock"
)

// IsLockName reports whether name is the name of an agent's window lock in the ledger root. A lock file is the one
// object of this package a held agent can reach: chmod is denied by no tier, and the name follows from the agent's
// identity, so whoever restores tego's own modes at a run's start (runtime.RestoreOwnState) looks for it by this name.
func IsLockName(name string) bool {
	h, ok := strings.CutPrefix(name, lockPrefix)
	if !ok {
		return false
	}
	h, ok = strings.CutSuffix(h, lockSuffix)
	if !ok || len(h) != 16 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Lock is the hold on one agent's window for a run's life.
type Lock struct{ f *os.File }

// Acquire takes the lock of the window of identity under root, without waiting. A second run of the same agent finds it
// held and is refused (ErrLive), so the count each reads at its start is never missing a run that is spending beside it.
// The lock is the kernel's: it is released when the run's launcher exits, however it exits.
func Acquire(root string, id Identity) (*Lock, error) {
	sum := sha256.Sum256([]byte(id))
	path := filepath.Join(root, lockPrefix+hex.EncodeToString(sum[:8])+lockSuffix)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: the window's lock %s: %w", ErrLockFile, ErrUnprovable, filepath.Base(path), err)
	}
	// A root launcher makes the file, and the next run of the agent may not be root: the file goes to the ledger root's
	// owner, as the run directories do (the hand-over), or that run could not open it and would be refused.
	if os.Geteuid() == 0 {
		var st unix.Stat_t
		if unix.Stat(root, &st) == nil {
			_ = f.Chown(int(st.Uid), int(st.Gid))
		}
	}
	if err := sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: its window lock %s is held", ErrLive, filepath.Base(path))
		}
		return nil, fmt.Errorf("%w: the window's lock: %w", ErrUnprovable, err)
	}
	return &Lock{f: f}, nil
}

// Close releases the lock. It is safe on nil and more than once.
func (l *Lock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	return f.Close()
}
