// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// codeAdoptRefused is the diagnostic code of a process an adoption refuses (adopt.Check, the guard's uid filter) or
// a boundary rule it cannot hold on a running process.
const codeAdoptRefused = "adopt-refused"

// Variables so a test can take the privileged path without privilege, read a fake /proc and stand in for the run.
var (
	adoptPrivileged = config.InitNSRoot
	adoptProc       = func() adopt.Proc { return adopt.NewFS("") }
	adoptSelf       = func(p adopt.Proc) (adopt.Self, error) { return adopt.SelfOf(p, os.Getpid()) }
	adoptPrepare    = prepareAdoption
	adoptRun        = tegoruntime.Adopt
	adoptRelease    = tegoruntime.ReleaseAdoption
	adoptStateDir   = ""
	// adoptInvokingUID is the user `tego adopt` acts for: sudo's caller, or root itself (config.InvokingUID).
	adoptInvokingUID = func() int { uid, _ := config.InvokingUID(); return uid }
	// adoptHomeOf is a uid's home from the passwd database (never $HOME), which an adopted agent's table compiles
	// against: its owner's ~/.ssh, ~/.aws and startup files, not the adopter's.
	adoptHomeOf = passwdHome
	// adoptGroupOf is a uid's primary group from the passwd database: the group of the ~/.tego a boundary adoption
	// makes for its owner (makeOwnRecords).
	adoptGroupOf = passwdGroup
	// adoptGroupsOf is a uid's groups, primary and supplementary: whether a group-writable home is its to write.
	adoptGroupsOf = passwdGroups
	// adoptEUID is the uid tego runs as: makeOwnRecords makes and chowns as root only for another uid.
	adoptEUID = os.Geteuid
	// adoptOwnRecordsMade is called with the home once makeOwnRecords' mkdirat made ~/.tego, before it opens it to
	// chown: a test stands in there for an owner that swaps another directory in at the name.
	adoptOwnRecordsMade = func(home string) {}
)

// passwdHome is uid's home directory from the passwd database (never $HOME); an error when it names none.
var passwdHome = config.PasswdHome

func init() { register(cmdAdopt) }

// passwdGroup is uid's primary gid from the passwd database (config.LookupPasswd, never $USER or $HOME).
func passwdGroup(uid int) (int, error) {
	u, err := config.LookupPasswd(uid)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Gid)
}

// cmdAdopt is `tego adopt --pid <pid> [--uid <uid>]... [--boundary <contract>] [--record <mode>]` and `tego adopt
// --release --pid <pid>` (ADR 0055; ADR 0054 stage 2). It governs an agent that is already running,
// started by the operator in any terminal or IDE: its own process tree, and nothing else, moves into a fresh cgroup
// of a run, whose tier-2 programs record its execs, opens and connects from the kernel into a normal ledger run. With
// --boundary the contract's file rules and exec allow-list are held by the kernel decision plane, and a rule nothing can add to
// a running process is refused, named. It holds the run until the agent's tree ends; SIGINT or SIGTERM, or a release
// request (`tego stop <run>`, `tego adopt --release --pid <pid>`), releases the agent, its tree moved back where it
// came from, and never kills it. Root only, and only the invoking user's own process (the user sudo ran it for, or
// root's when root ran it directly) unless --uid names its owner.
func cmdAdopt() Command {
	var (
		pid        int
		boundary   string
		recordMode string
		release    bool
		uids       []int
	)
	return Command{
		Name:       "adopt",
		Summary:    "(root) govern an agent that is already running: move its process tree into a run and record it from the kernel",
		Usage:      "--pid <pid> [--uid <uid>]... [--boundary <agent.yaml | name>] [--record <full|summary|off>] | --release --pid <pid>",
		Supervises: true,
		Flags: func(fs *flag.FlagSet) {
			fs.IntVar(&pid, "pid", 0, "the agent's process id (its whole tree is adopted: the process and its descendants in its cgroup)")
			fs.StringVar(&boundary, "boundary", "", "hold the agent to this contract's file rules and exec allow-list through the kernel decision plane; "+
				"a rule that cannot be added to a running process is refused, named")
			fs.StringVar(&recordMode, "record", "", "record level (full|summary|off); without --boundary full, with it the contract's")
			fs.BoolVar(&release, "release", false, "release the adoption that holds --pid: its tree goes back where it came from, the run ends")
			fs.Func("uid", "also adopt a process of this uid (repeatable): without it only the invoking user's own process is adopted "+
				"(the user sudo ran tego for; root's when root runs it directly); real, effective and saved uid must all be one of them",
				func(v string) error {
					n, err := strconv.ParseUint(v, 10, 32)
					if err != nil || n == 0xffffffff {
						return fmt.Errorf("%q is not a uid", v)
					}
					uids = append(uids, int(n))
					return nil
				})
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego adopt: no arguments; the process is --pid", codeUsage)
				return identity.ExitUsage
			}
			if pid <= 0 {
				message(stderr, "", 0, 0, "tego adopt: --pid <pid> is required", codeUsage)
				return identity.ExitUsage
			}
			if boundary == "" && flagGiven(fs, "boundary") {
				// An unset "$CONTRACT" would otherwise adopt the agent record-only, no rule refusing anything.
				message(stderr, "", 0, 0, "tego adopt: --boundary is an empty string; name a contract, or leave --boundary out to only record", codeUsage)
				return identity.ExitUsage
			}
			if release && (boundary != "" || recordMode != "" || len(uids) > 0) {
				message(stderr, "", 0, 0, "tego adopt: --release takes --pid alone", codeUsage)
				return identity.ExitUsage
			}
			if recordMode != "" {
				if _, err := parseRecordMode(recordMode); err != nil {
					message(stderr, "", 0, 0, "tego adopt: "+err.Error(), codeUsage)
					return identity.ExitUsage
				}
			}
			if !adoptPrivileged() {
				message(stderr, "", 0, 0, adoptPrivilegeMessage, codePrivilege)
				return identity.ExitLauncher
			}
			if release {
				return runAdoptRelease(ctx, pid, stdout, stderr)
			}
			return runAdopt(ctx, adoptOptions{pid: pid, boundary: boundary, record: recordMode, uids: uids}, stdout, stderr)
		},
	}
}

// adoptPrivilegeMessage is the one sentence a refusal for want of privilege says.
const adoptPrivilegeMessage = "tego adopt: needs root of the initial user namespace (it moves another user's process " +
	"between cgroups and loads kernel programs): run it with sudo"

// adoptOptions are one adoption's inputs.
type adoptOptions struct {
	pid      int
	boundary string
	record   string
	// uids are `tego adopt --uid`: owners admitted besides the invoking user (adoptOwners). The guard has its own.
	uids []int
}

// adoptOwners is the owner filter of `tego adopt --pid`: the invoking user (adoptInvokingUID) and every --uid. Root
// naming a pid is not by itself consent to move another user's process: that takes its owner named with --uid.
func adoptOwners(listed []int) adopt.UIDs {
	return append(adopt.UIDs{adoptInvokingUID()}, listed...)
}

// adoptionRules are every rule an adoption applies to its root, as one check: adopt.Check (what is never adopted,
// whoever asks) and then the owner filter. It runs when the process is identified and again, as AdoptSpec.Recheck,
// right before the move.
func adoptionRules(self adopt.Self, owners adopt.UIDs) func(adopt.Process) error {
	return func(t adopt.Process) error {
		if err := adopt.Check(t, self); err != nil {
			return err
		}
		return owners.Admit(t)
	}
}

// pinnedOwner is rules, as the recheck before the move, for a process identified as owner's: the run's table was
// compiled against owner's home (prepareAdoption), so a root that changed its user since, even to another admitted
// one, is refused under the owner rule rather than held to another user's lists.
func pinnedOwner(rules func(adopt.Process) error, owner int) func(adopt.Process) error {
	return func(t adopt.Process) error {
		if err := rules(t); err != nil {
			return err
		}
		if t.Owner() != owner {
			return &adopt.Refusal{Rule: adopt.RefuseUID, PID: t.PID, Detail: fmt.Sprintf("it ran as uid %d when it was "+
				"identified and as uid %d now; its run was prepared for uid %d", owner, t.Owner(), owner)}
		}
		return nil
	}
}

// identifyForAdoption reads pid and applies every rule that refuses it (adoptionRules: adopt.Check, then the owner
// filter of the invoking user and --uid), and prints whose it is. A refusal is printed and is exit 125
// [adopt-refused]. It returns the rules too, for the recheck before the move.
func identifyForAdoption(p adopt.Proc, o adoptOptions, stderr io.Writer) (adopt.Process, func(adopt.Process) error, bool) {
	pid := o.pid
	t, err := adopt.Identify(p, pid)
	if err != nil {
		if errors.Is(err, adopt.ErrGone) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego adopt: no process %d", pid), codeAdoptRefused)
		} else {
			message(stderr, "", 0, 0, fmt.Sprintf("tego adopt: read process %d: %v", pid, err), codeIO)
		}
		return adopt.Process{}, nil, false
	}
	fmt.Fprintf(stderr, "tego adopt: pid %d (%s) runs as uid %d (real %d, effective %d, saved %d) in %s\n", t.PID,
		printableExe(t), t.UID[1], t.UID[0], t.UID[1], t.UID[2], record.Printable(t.Cgroup))
	self, err := adoptSelf(p)
	if err != nil {
		message(stderr, "", 0, 0, "tego adopt: "+err.Error(), codeIO)
		return adopt.Process{}, nil, false
	}
	rules := adoptionRules(self, adoptOwners(o.uids))
	if err := rules(t); err != nil {
		msg := "tego adopt: " + err.Error()
		if rule, _ := adopt.IsRefusal(err); rule == adopt.RefuseUID && t.Owner() >= 0 {
			msg += fmt.Sprintf("; this tego acts for uid %d: name the owner with --uid %d to adopt it", adoptInvokingUID(), t.Owner())
		}
		message(stderr, "", 0, 0, msg, codeAdoptRefused)
		return adopt.Process{}, nil, false
	}
	return t, rules, true
}

// printableExe is the process's program for a line on root's terminal, escaped (record.Printable): the program's
// path, and a cgroup's name below a delegated one, are the adopted user's to choose, and a control byte in either
// must never reach the terminal raw.
func printableExe(t adopt.Process) string {
	if t.Exe == "" {
		return record.Printable(t.Comm)
	}
	return record.Printable(t.Exe)
}

func runAdopt(ctx context.Context, o adoptOptions, stdout, stderr io.Writer) int {
	p := adoptProc()
	identified := time.Now()
	t, rules, ok := identifyForAdoption(p, o, stderr)
	if !ok {
		return identity.ExitLauncher
	}
	m, cds, err := loadMachine(config.TrustAbort)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		configRefused(stderr, "tego adopt", err)
		return identity.ExitConfig
	}
	makeOwnDirs(m)
	a, code := adoptPrepare(ctx, m, o, t, t.Owner(), stderr)
	if a == nil {
		return code
	}
	defer a.cleanup()
	fmt.Fprint(stderr, adoptNotice(t, o.boundary != "", a.rt.Record))
	exits := watchExit(p, t.Identity)
	defer exits.stop()
	// ctx ends on SIGINT or SIGTERM, which is the adoption's release; `tego stop` and `tego adopt --release` signal
	// nothing: they leave a release request this adoption alone answers (tegoruntime.ReleaseAdoption).
	res, err := adoptRun(ctx, a.rt, tegoruntime.AdoptSpec{
		Root: t, Env: adopt.Env{Proc: p}, Boundary: o.boundary != "", Recheck: pinnedOwner(rules, t.Owner()),
		Keyed:      a.keyed(),
		Started:    func(s tegoruntime.AdoptStarted) { fmt.Fprint(stderr, adoptedLine(t, s)) },
		ExitStatus: exits.status,
	}, a.deps(identified, ownLogger(m)))
	if err != nil {
		message(stderr, "", 0, 0, "tego adopt: "+err.Error(), codeRun)
		return identity.ExitLauncher
	}
	fmt.Fprint(stderr, adoptEndLine(res))
	if res.RecordErr != nil {
		message(stderr, "", 0, 0, "tego adopt: the record is incomplete: "+res.RecordErr.Error(), codeLedger)
	}
	return res.ExitCode
}

// preparedAdoption is what every adoption of one invocation needs, compiled and selected once.
type preparedAdoption struct {
	rt       *agent.RuleTable
	backend  enforce.Backend
	m        *config.Machine
	yaml     []byte
	anchor   string
	cleanup  func()
	boundary bool
	// owner is the uid the table was compiled for, and home that uid's home it compiled against ("" the machine's).
	owner int
	home  string
	// source is the boundary contract's file, which run_start records (agent-contract.md R26); nil with no boundary.
	source *record.ContractSource
	// records is the directory the owner's ~/.tego was (followed, as the compile resolves it) when a boundary table
	// was compiled against home, which R6a's deny of the owner's own records attached to; the zero value for a
	// record-only table or one with no home.
	records adopt.FileID
	// homeMissing says home itself did not exist when a boundary table was compiled (a service user's /nonexistent):
	// no records of the owner can be there, and tego makes no home, so records is the zero value.
	homeMissing bool
	// homeNotOwners says tego, as root, made no ~/.tego in a home the owner may not write (makeOwnRecords,
	// errHomeNotOwners) and none was there: no `tego run` of the owner's can have made records there, so records is
	// the zero value too.
	homeNotOwners bool
	// fmodRet says the backend was selected with the decision plane in fmod_ret mode, which the kernel's preemption
	// model must still admit before each adoption under it (fmodRetLapsed, ADR 0024 (16)).
	fmodRet bool
}

// adoptFmodRetRefused is doctor.FmodRetRefusedNow: why this kernel, read afresh, no longer admits fmod_ret mode, ""
// when it does. A variable so a test can change the kernel's mode between two adoptions.
var adoptFmodRetRefused = doctor.FmodRetRefusedNow

// fmodRetLapsed reports a backend selected in fmod_ret mode on a kernel that no longer admits the mode (root changed
// a PREEMPT_DYNAMIC kernel's mode in debugfs, or debugfs can no longer be read): the guard selects again before it
// adopts under it (guard.sharedTable), as every `tego run` reads the mode again (ADR 0024 (16)). An adoption already
// running keeps its mode: a change made while it lives is not watched.
func (a *preparedAdoption) fmodRetLapsed() string {
	if !a.fmodRet {
		return ""
	}
	return adoptFmodRetRefused()
}

// stale reports a boundary table whose owner's ~/.tego is no longer the directory the table denies (records): it was
// removed, replaced, or is no directory now, and a deny attaches to the directory a compile found, so the records the
// owner's next `tego run` writes there would be readable to an agent adopted under the old table. The guard compiles
// such a table again before it adopts under it (guard.sharedTable); an adoption already running keeps its table (ADR
// 0055 Decision 5). A table compiled while home itself did not exist is stale once it does, and one compiled with no
// ~/.tego in a home the owner may not write once a ~/.tego is there.
func (a *preparedAdoption) stale() bool {
	if !a.boundary || a.home == "" {
		return false
	}
	if a.homeMissing {
		return !homeAbsent(a.home)
	}
	if a.homeNotOwners {
		_, err := os.Lstat(ownRecords(a.home))
		return !errors.Is(err, fs.ErrNotExist)
	}
	id, ok := ownRecordsDir(a.home)
	return !ok || id != a.records
}

// keyed is what a boundary adoption requires the plane's rows to hold (tegoruntime.AdoptSpec.Keyed): the owner's
// ~/.tego at the directory the table was compiled against (records), which R6a's deny attaches to. The agent runs
// unconfined until the arm, so a directory removed or replaced after the compile and before Prepare keyed its row
// would leave the deny on nothing, or on another directory, with nothing said; the
// runtime fails such an adoption before the attach. Nothing is required of a record-only table, of one compiled with
// no ~/.tego to deny (no home, or one the owner may not write), or of one with no deny of it (a write entry the
// compile kept it for, said as ledger-readable). The row is the deny_read row at that directory, built in or the
// contract's own: a contract that declares it gets no built-in row beside it (tegoOwn), and its row is R6a's deny all
// the same.
func (a *preparedAdoption) keyed() []tegoruntime.AdoptKeyed {
	if !a.boundary || a.home == "" || a.records == (adopt.FileID{}) || a.rt == nil {
		return nil
	}
	want := ownRecords(a.home)
	resolved, err := filepath.EvalSymlinks(want)
	if err != nil {
		resolved = want
	}
	for _, r := range a.rt.FS {
		if r.Kind == agent.FSDenyRead && (filepath.Clean(r.Path) == want || r.Canonical() == resolved) {
			return []tegoruntime.AdoptKeyed{{Path: r.Canonical(), Name: want, ID: a.records,
				What: "the agent owner's own tego records"}}
		}
	}
	return nil
}

// ownRecords is ~/.tego under home.
func ownRecords(home string) string { return filepath.Join(home, ".tego") }

// homeAbsent reports that home leads to nothing (followed, as makeOwnRecords opens it): no ~/.tego can be under it.
func homeAbsent(home string) bool {
	_, err := os.Stat(home)
	return errors.Is(err, fs.ErrNotExist)
}

// ownRecordsDir is the directory home's ~/.tego is, itself: false when it is none (missing, a file, a link). R6a's
// deny attaches only to a directory, and a row keys the inode it was written at: at a link to a directory it would key
// the target, and the link itself would be under no row, so under a write entry over the home the agent could replace
// the link with a fresh directory once armed, where the owner's next run writes its records. A link at ~/.tego is
// therefore no records directory a boundary can
// deny, and the boundary is refused, named; links above it (a home reached through one) are followed.
func ownRecordsDir(home string) (adopt.FileID, bool) {
	fi, err := os.Lstat(ownRecords(home))
	if err != nil || !fi.IsDir() {
		return adopt.FileID{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return adopt.FileID{}, false
	}
	return adopt.FileID{Dev: uint64(st.Dev), Ino: st.Ino}, true //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
}

// errHomeNotOwners is a home the agent's owner may not write (makeOwnRecords): no ~/.tego of its own can be made
// there by it, so none is made for it.
var errHomeNotOwners = errors.New("the agent owner may not write its home")

// homeWritableBy reports whether uid may make a name in a directory of st by its mode: it owns it (an owner may chmod
// it writable), its other write bit is set, or its group write bit is and uid is in its group (adoptGroupsOf).
func homeWritableBy(st unix.Stat_t, uid int) (bool, error) {
	switch {
	case int(st.Uid) == uid, st.Mode&0o002 != 0:
		return true, nil
	case st.Mode&0o020 == 0:
		return false, nil
	}
	gids, err := adoptGroupsOf(uid)
	if err != nil {
		return false, fmt.Errorf("the groups of uid %d, which its home's group may write: %w", uid, err)
	}
	return slices.Contains(gids, int(st.Gid)), nil
}

// passwdGroups is uid's primary and supplementary gids from the passwd (config.LookupPasswd) and group databases.
func passwdGroups(uid int) ([]int, error) {
	u, err := config.LookupPasswd(uid)
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(ids)+1)
	for _, s := range append(ids, u.Gid) {
		if g, err := strconv.Atoi(s); err == nil {
			out = append(out, g)
		}
	}
	return out, nil
}

// makeOwnRecords makes home's ~/.tego for its owner uid, as the owner's first `tego run` would, when nothing is
// there: mode 0700, and, when tego runs as root for another uid, owned by uid and its passwd group. A name already
// there (a directory, a link, a file) is left as it is, never followed: what it is is judged after the compile. mkdirat
// never follows a link at the name, and the new directory is chowned through a descriptor opened with O_NOFOLLOW. The
// owner can rename a directory of its home into that name between the mkdirat and the open, so the descriptor's
// directory is chowned only when it is what tego's mkdirat makes: tego's own, with no group or other bits, and empty
// (madeByTego); anything else is refused and left as it is. The passwd
// group is looked up before the mkdirat, so only the open lies between the two, and only when nothing is at the name
// yet: a ~/.tego already there is neither made nor chowned, and needs no group. One that cannot be chowned is removed
// again rather than left root's, which the owner's own runs could not write.
//
// As root for another uid it makes the directory only in a home that uid may write by its mode (its owner, or one
// whose group or other write bit admits it): root making ~/.tego in a home the uid cannot write (a service account's
// / or /var/www, root's own) would hand it a writable directory it could not make itself, and no `tego run` of that
// uid could have made records there to deny. Such a home gives errHomeNotOwners, unless
// a ~/.tego is there already (made by someone else), which is judged as any other. An ACL is not read: a home only an
// ACL lets the uid write is taken as one it may not, and the guard compiles the table again once ~/.tego appears.
func makeOwnRecords(home string, uid int) error {
	h, err := sys.Own(unix.Open(home, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return err
	}
	defer func() { _ = h.Close() }()
	return h.Borrow(func(hfd int) error { return makeOwnRecordsAt(home, hfd, uid) })
}

// makeOwnRecordsAt is makeOwnRecords in the home hfd opens.
func makeOwnRecordsAt(home string, hfd, uid int) error {
	euid := adoptEUID()
	asRoot := euid == 0 && uid != euid
	gid := 0
	if asRoot {
		var st unix.Stat_t
		if err := unix.Fstat(hfd, &st); err != nil {
			return err
		}
		may, err := homeWritableBy(st, uid)
		if err != nil {
			return err
		}
		var at unix.Stat_t
		switch err := unix.Fstatat(hfd, ".tego", &at, unix.AT_SYMLINK_NOFOLLOW); {
		case err == nil:
			return nil // there already (made by someone who could, when !may): judged after the compile
		case !may:
			return errHomeNotOwners
		}
		if gid, err = adoptGroupOf(uid); err != nil {
			return err
		}
	}
	switch err := unix.Mkdirat(hfd, ".tego", 0o700); {
	case errors.Is(err, unix.EEXIST):
		return nil
	case err != nil:
		return err
	}
	if !asRoot {
		return nil // made as the uid tego runs as: a test's, or root's own
	}
	adoptOwnRecordsMade(home)
	dir, err := sys.Own(unix.Openat(hfd, ".tego", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return err // what is at the name now is not known to be tego's: left as it is
	}
	defer func() { _ = dir.Close() }()
	return dir.Borrow(func(fd int) error {
		if err := madeByTego(fd); err != nil {
			return err
		}
		if err := unix.Fchown(fd, uid, gid); err != nil {
			_ = unix.Unlinkat(hfd, ".tego", unix.AT_REMOVEDIR) // tego's own, empty: removed rather than left root's
			return err
		}
		return nil
	})
}

// errNotMadeByTego is a ~/.tego that makeOwnRecords opened to chown and found not to be the directory its mkdirat
// made: another was renamed in at the name meanwhile.
var errNotMadeByTego = errors.New("what is at that name now is not the directory tego made there, so it is not given to the owner")

// madeByTego reports whether the directory fd opens is one tego's mkdirat made: owned by the uid tego runs as (the
// kernel's own answer, never adoptEUID's), with no group or other mode bits (a mkdirat of 0700 makes none, whatever
// the umask), and empty (no other uid can write into it). Every other directory errs with errNotMadeByTego, saying why.
func madeByTego(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case int(st.Uid) != unix.Geteuid():
		return fmt.Errorf("%w: it is uid %d's", errNotMadeByTego, st.Uid)
	case st.Mode&0o077 != 0:
		return fmt.Errorf("%w: its mode is %#o", errNotMadeByTego, st.Mode&0o7777)
	}
	buf := make([]byte, 4096)
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return nil
		}
		if _, count, _ := unix.ParseDirent(buf[:n], 1, nil); count > 0 {
			return fmt.Errorf("%w: it is not empty", errNotMadeByTego)
		}
	}
}

func (a *preparedAdoption) deps(identified time.Time, log *slog.Logger) tegoruntime.AdoptDeps {
	return tegoruntime.AdoptDeps{
		Config: a.m, Enforce: a.backend, ObserveFactory: recorderFor(a.rt, log), Build: runBuild(),
		ContractYAML: a.yaml, AnchorPath: a.anchor, Logger: log, StateDir: adoptStateDir, Identified: identified,
		ContractSource: a.source,
	}
}

// prepareAdoption compiles the adoption's table (the record-only one, or the boundary contract with every rule an
// adopted process cannot be held to refused), selects its tier-2 backend and checks the chain anchor. A nil result is
// a refusal already printed, with its exit code.
//
// The table compiles against the home of owner, the uid the adopted process runs as, from the passwd database: "~"
// in the contract, the built-in deny_read list (~/.ssh, ~/.aws, ~/.netrc, ~/.gnupg, the browsers' profiles) and the
// deny_write list in the home (shell startup files, the global git config's hooks) are the agent's owner's, not the
// adopter's (root's /root under the guard's unit, or sudo's caller's under `tego adopt --uid`). The ledger, the chain
// anchor and tego's own state stay the machine's. A boundary for an owner with no home there is refused, named: its
// built-in lists could not be compiled. Rejected: compiling against the adopter's home (the agent's own credentials
// stayed readable while run_start claimed fs.deny_read), and refusing every adoption of another user's process.
func prepareAdoption(ctx context.Context, m *config.Machine, o adoptOptions, t adopt.Process, owner int, stderr io.Writer) (*preparedAdoption, int) {
	a := &preparedAdoption{m: m, boundary: o.boundary != "", cleanup: func() {}, owner: owner}
	rt, code := compileAdoptionTable(ctx, m, o, t, a, stderr)
	if rt == nil {
		a.cleanup()
		return nil, code
	}
	if a.boundary {
		rt.Capture = agent.CaptureOff
		sel := runOptions{cmd: "tego adopt", tier: string(backend.TierCgroup), adopted: true}
		b, srt, rep, code := selectBackend(ctx, sel, m, rt, stderr)
		if b == nil {
			return nil, code
		}
		a.backend, a.rt = b, srt
		a.fmodRet = rep != nil && rep.Plane != nil && rep.Plane.Selected == config.PlaneFmodRet
	} else {
		b, err := enforce.AdoptionRecorder(m)
		if err != nil {
			a.cleanup()
			message(stderr, "", 0, 0, "tego adopt: "+err.Error(), backend.CodeTierUnavailable)
			return nil, identity.ExitLauncher
		}
		a.backend, a.rt = b, recordOnly(rt.AtTier(backend.TierCgroup))
	}
	yaml, err := contractCopy(a.rt)
	if err != nil {
		a.cleanup()
		message(stderr, "", 0, 0, "tego adopt: contract copy: "+err.Error(), codeIO)
		return nil, identity.ExitLauncher
	}
	a.yaml = yaml
	anchor, err := anchorPath(m)
	if err == nil {
		err = ledger.ProbeAnchor(anchor)
	}
	if err != nil {
		a.cleanup()
		message(stderr, "", 0, 0, "tego adopt: chain anchor: "+err.Error(), codeRun)
		return nil, identity.ExitLauncher
	}
	a.anchor = anchor
	return a, identity.ExitOK
}

// compileAdoptionTable is prepareAdoption's compile: a.owner's home resolved (a.home), the contract (the boundary, or
// the record-only one written for t, whose removal goes in a.cleanup) compiled against it, and, for a boundary, every
// rule an adopted process cannot be held to refused, each printed. A nil table is a refusal already printed.
func compileAdoptionTable(ctx context.Context, m *config.Machine, o adoptOptions, t adopt.Process, a *preparedAdoption, stderr io.Writer) (*agent.RuleTable, int) {
	// "-" is refused before anything is made for the owner (makeOwnRecords, below), as compileForRun would refuse it
	// after: a usage error changes nothing. As root it made /root/.tego before the refusal.
	if o.boundary == stdinContract {
		return nil, refuseStdinContract(stderr)
	}
	home, err := adoptHomeOf(a.owner)
	switch {
	case err != nil && a.boundary:
		message(stderr, o.boundary, 0, 0, fmt.Sprintf("tego adopt: a boundary's built-in deny_read and deny_write lists "+
			"compile against the agent owner's home, and uid %d has none: %v", a.owner, err), codeAdoptRefused)
		return nil, identity.ExitLauncher
	case err != nil:
		home = "" // a record-only table refuses nothing: the machine's home
	}
	a.home = home
	path := o.boundary
	if path == "" {
		if path, a.cleanup, err = writeAdoptContract(t, o.record); err != nil {
			a.cleanup = func() {}
			message(stderr, "", 0, 0, "tego adopt: "+err.Error(), codeIO)
			return nil, identity.ExitLauncher
		}
	}
	diags := stderr
	if o.boundary == "" {
		diags = io.Discard // the generated contract's own warnings (its empty deny_read) are tego's choice, not the user's
	}
	// R6a's deny of the owner's own records (~/.tego: its earlier runs' events and blobs, its machine config) attaches
	// only to a directory that exists when the table compiles, and an adoption keeps its table while it runs: an owner
	// who had never run tego would have its first run's records readable to the agent for the rest of the adoption.
	// So the directory is made first, as that run would make it, and must be the same directory on both sides of the
	// compile; one that is no directory (a file, a dangling link) or changed meanwhile is refused. A home that does not
	// exist (a service user's /nonexistent) holds no records and is not made: it must still not exist after the
	// compile, and the guard compiles the table again once it does (stale). Nor is it made, as root, in a home the
	// owner may not write (makeOwnRecords): none of its runs can have made records there, and none is made for it.
	//
	// The boundary is loaded before that, as the compile would load it: a missing file, a name the registries refuse
	// or a file that does not load is refused with nothing made for the owner, as "-" is above. As root the owner's
	// ~/.tego was made first, as its first run would, and the refusal came after. The run path's lines (a refused name,
	// an interrupt, the tier's selection) say tego adopt, as this function's own do.
	ro := runOptions{cmd: "tego adopt", contract: path, generated: o.boundary == "", record: o.record, home: home, adopted: true}
	if a.boundary {
		l, code := loadRunContract(ro, m, diags)
		if l == nil {
			return nil, code
		}
		ro.loaded = l
	}
	a.homeMissing = a.boundary && home != "" && homeAbsent(home)
	if a.boundary && home != "" && !a.homeMissing {
		switch err := makeOwnRecords(home, a.owner); {
		case errors.Is(err, errHomeNotOwners):
			a.homeNotOwners = true
		case err != nil:
			message(stderr, o.boundary, 0, 0, fmt.Sprintf("tego adopt: a boundary read-denies the agent owner's own tego "+
				"records, %s, which must be a directory to be denied, and it could not be made: %v", ownRecords(home), err), codeAdoptRefused)
			return nil, identity.ExitLauncher
		}
	}
	before, okBefore := ownRecordsDir(home)
	rt, _, src, code := compileForRun(ctx, ro, m, diags)
	if rt == nil {
		return nil, code
	}
	a.source = src
	if a.homeMissing && !homeAbsent(home) {
		message(stderr, o.boundary, 0, 0, fmt.Sprintf("tego adopt: the agent owner's home %s did not exist when the "+
			"boundary began to compile and does now, so the deny of its own tego records could not attach; adopt again",
			home), codeAdoptRefused)
		return nil, identity.ExitLauncher
	}
	if a.homeNotOwners && a.stale() {
		message(stderr, o.boundary, 0, 0, fmt.Sprintf("tego adopt: %s appeared while the boundary compiled, in a home "+
			"the agent owner may not write, so the deny of its own tego records could not attach; adopt again",
			ownRecords(home)), codeAdoptRefused)
		return nil, identity.ExitLauncher
	}
	if a.boundary && home != "" && !a.homeMissing && !a.homeNotOwners {
		after, okAfter := ownRecordsDir(home)
		if !okBefore || !okAfter || before != after {
			message(stderr, o.boundary, 0, 0, fmt.Sprintf("tego adopt: a boundary read-denies the agent owner's own tego "+
				"records, %s, which is not a directory itself (a file, or a link, which no row would hold) or changed while "+
				"the boundary compiled, so the deny could not attach; make it a directory the owner owns (mode 0700) and "+
				"adopt again", ownRecords(home)), codeAdoptRefused)
			return nil, identity.ExitLauncher
		}
		a.records = after
	}
	if a.boundary {
		if refused := unenforceableForAdoption(rt); len(refused) > 0 {
			for _, r := range refused {
				message(stderr, o.boundary, 0, 0, "tego adopt: "+r, codeAdoptRefused)
			}
			message(stderr, o.boundary, 0, 0, fmt.Sprintf("tego adopt: %d rule(s) of this contract cannot be held on a running "+
				"process; remove them, or adopt with no --boundary to record the agent", len(refused)), codeAdoptRefused)
			return nil, identity.ExitLauncher
		}
	}
	// An adopted process runs under no Landlock domain, so nothing leaves out an absent built-in row's name, and the
	// models must not answer its reads refused (ADR 0067 D3): with no chain
	// return the recorder would infer a refusal the kernel never made.
	rt.AbsentDenyRead = nil
	return rt, identity.ExitOK
}

// recordOnly is a record-only adoption's table: no deny_read or immutable refusal state. The compiler read-denies
// tego's own records whatever a contract says (an empty deny_read keeps that entry), and at tier 2 with no plane a
// deny_read row is the fanotify listener's: it would refuse the agent's reads there, mark the mount for every process
// on the host, and arm the adopter, which then could start no reaper for the guard's next adoption. A record-only
// adoption refuses nothing, and the agent could read those records before it was adopted.
func recordOnly(rt *agent.RuleTable) *agent.RuleTable {
	out := *rt
	// ADR 0113 adds Unix hooks even without net:. A record-only adoption
	// must omit that immutable enforcement state, as observe compilation does.
	out.Builtins = nil
	out.FS = nil
	for _, r := range rt.FS {
		if r.Kind != agent.FSDenyRead {
			out.FS = append(out.FS, r)
		}
	}
	return &out
}

// adoptContract is the contract of an adoption with no --boundary: the agent's program, the record level, tier
// cgroup, capture off (the agent's environment cannot be changed), and an empty deny_read, so that no built-in entry
// is refused by a listener: a record-only adoption refuses nothing.
type adoptContract struct {
	Version int      `yaml:"version"`
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
	Record  string   `yaml:"record"`
	Tier    string   `yaml:"tier"`
	Capture string   `yaml:"capture"`
	FS      struct {
		DenyRead []string `yaml:"deny_read"`
	} `yaml:"fs"`
}

// adoptName is the run's agent name for a process: adopt- and its name as the kernel gives it (comm: a script's own
// name rather than its interpreter's), else its program's base name, made a contract name as watchName makes one.
func adoptName(t adopt.Process) string {
	base := t.Comm
	if base == "" {
		base = t.Exe
	}
	return "adopt-" + strings.TrimPrefix(watchName(base), "watch-")
}

// writeAdoptContract writes the record-only contract into a private temporary directory, as watch writes its own.
func writeAdoptContract(t adopt.Process, record string) (string, func(), error) {
	if record == "" {
		record = string(agent.RecordFull)
	}
	c := adoptContract{Version: 0, Name: adoptName(t), Command: []string{t.Exe}, Record: record,
		Tier: string(backend.TierCgroup), Capture: string(agent.CaptureOff)}
	c.FS.DenyRead = []string{}
	data, err := agent.EncodeYAML(c) // Canonical's writer, so the program loads back as it is (genericContractYAML)
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "tego-adopt-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "adopt.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// unenforceableForAdoption names every rule of a boundary contract that cannot be held on a process tego did not
// start, one line each: what needs a seccomp filter, Landlock, the supervisor, the forwarder, the environment or a
// budget, and every network rule (a socket keeps the cgroup it was made in, so the run's network programs never
// govern one the agent made before the adoption, and with no supervisor the record cannot tell its connects from a
// governed socket's), and every exec command rule (exec.deny, exec.ask, an exec.allow entry with words: argv is the
// supervisor's to decide). What remains is held by the decision plane: fs.write (and the refusal of every other
// write), fs.deny_read (the built-in list included), exec.allow's programs and exec.anonymous, keyring.
func unenforceableForAdoption(rt *agent.RuleTable) []string {
	c := rt.Contract
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	if t := string(c.Tier); t != "" && t != string(backend.TierAuto) && t != string(backend.TierCgroup) {
		add("tier: %s: an adoption runs at tier cgroup", t)
	}
	if n := c.Net; n != nil {
		const socketWhy = "a socket keeps the cgroup it was made in, so a socket the agent made before it was adopted is " +
			"not governed, and with no supervisor the record cannot tell its connects from a governed one's"
		for _, a := range n.Allow {
			add("net.allow %s: %s", a, socketWhy)
		}
		for _, a := range n.Ask {
			add("net.ask %s: an approval needs the supervisor, which a running process does not have", a)
		}
		for _, l := range n.Listen {
			add("net.listen %s: %s", l, socketWhy)
		}
		if len(n.HTTP) != 0 || n.Proxy != nil {
			add("net.http and net.proxy: request rules need the forwarder, which a running process does not use")
		}
		if len(n.Ingress) != 0 || n.Limits != nil || n.DNS != nil {
			add("net.ingress, net.limits and net.dns: %s", socketWhy)
		}
		if len(n.Allow)+len(n.Ask)+len(n.Listen) == 0 {
			add("net: a net section refuses every connect it does not list, which the run's network programs can hold only "+
				"on sockets made after the adoption: %s", socketWhy)
		}
	}
	for _, r := range rt.FSAsk {
		add("fs.ask %s: an approval needs the supervisor, which a running process does not have", r.Path)
	}
	if e := c.Env; e.Pass != nil || len(e.Deny)+len(e.Mask)+len(e.Set) > 0 {
		add("env: a running process's environment cannot be changed")
	}
	if len(c.Models) != 0 {
		add("models: the model's traffic goes through the forwarder only when the agent was started with its environment")
	}
	if c.Capture != "" && c.Capture != agent.CaptureAuto && c.Capture != agent.CaptureOff {
		add("capture: %s: an adopted agent's model traffic is not captured", c.Capture)
	}
	l := c.Limits
	for name, set := range map[string]bool{"cpu": l.CPU != nil, "cpu_weight": l.CPUWeight != nil, "memory": l.Memory != nil,
		"memory_high": l.MemoryHigh != nil, "pids": l.Pids != nil, "tokens": l.Tokens != nil, "cost_usd": l.CostUSD != nil,
		"wall": l.Wall != nil, "stall_after": l.StallAfter != nil, "repeats": l.Repeats != nil} {
		if set {
			add("limits.%s: an adoption sets no limit (memory already charged elsewhere stays there, and a budget would end "+
				"the agent, which an adoption never does)", name)
		}
	}
	if ec := rt.ExecCommands; ec != nil {
		// Every command pattern (exec.deny, exec.ask, an exec.allow entry with words) is decided on the supervisor's
		// copy of argv (ADR 0048): the plane holds image rows alone. One is refused even when it could decide nothing
		// at a launch (an allow entry for a tool an implicit grant keeps unconstrained): nothing was granted
		// implicitly to a process tego did not start.
		for _, e := range ec.Entries {
			add("exec.%s %s: argv rules are decided by the supervisor, which a running process does not have; the decision "+
				"plane holds exec.allow's programs, never their arguments", e.Pattern.List, e.Pattern.Entry)
		}
	}
	if c.Gate.Kind != 0 {
		add("gate: command rules are the supervisor's, which a running process does not have")
	}
	if len(c.MCP) != 0 {
		add("mcp: MCP servers are recorded by the supervisor, which a running process does not have")
	}
	if c.Ask.Kind != 0 {
		add("ask: approvals need the supervisor, which a running process does not have")
	}
	if c.Docker.Kind != 0 || c.Containers != "" {
		add("docker and containers: a container's processes are its runtime's, never adopted")
	}
	sort.Strings(out)
	return out
}

// adoptNotice is what tego says before it adopts, so nobody mistakes an adoption for a launch: what is recorded,
// and what an adoption can never give a process that was already running.
func adoptNotice(t adopt.Process, bounded bool, rec agent.RecordMode) string {
	held := "  holds: nothing. No rule refuses anything.\n"
	if bounded {
		held = "  holds: the contract's file rules and exec allow-list (programs, never arguments), through the kernel\n" +
			"  decision plane, from the attach on. The plane refuses CAP_SYS_ADMIN in every user namespace, holding\n" +
			"  the mount topology (mount APIs and mount-namespace changes), and other uses of that capability.\n" +
			"  Not what only a seccomp filter refuses: System V IPC (even without\n" +
			"  ipc: true), socket families outside the network rules (AF_VSOCK, AF_PACKET, SCTP...), io_uring, openat2,\n" +
			"  open_by_handle_at, clone3, the terminal-input ioctls (a gap says so).\n"
	}
	recorded := "every program it starts, every file it opens, every connection it makes"
	switch rec {
	case agent.RecordSummary:
		recorded = "every program it starts, every file it writes, every connection it makes"
	case agent.RecordOff:
		recorded = "its refusals only"
	}
	return fmt.Sprintf(`tego adopt: adopting pid %d (%s) and its descendants in its cgroup; nothing else moves.
  records from the kernel, from the attach on: %s.
%s  never: what it did before the attach (a gap says so); a seccomp filter, Landlock, a new environment or the model
  forwarder (none can be added to a running process); reads, writes or sends through descriptors or memory
  mappings it already held.
  Ctrl-C, SIGTERM or tego stop releases it: its tree goes back where it came from. It is never killed.
`, t.PID, printableExe(t), recorded, held)
}

// adoptedLine is the summary line of one adoption: what moved, from where, how long after it was found the record
// began, and the run.
func adoptedLine(t adopt.Process, s tegoruntime.AdoptStarted) string {
	plane := ""
	if s.DecisionPlane != "" {
		plane = ", held by the decision plane (" + s.DecisionPlane + ")"
	}
	notMoved := ""
	if len(s.Skipped) > 0 {
		notMoved = fmt.Sprintf("; %d of its tree not moved", len(s.Skipped))
	}
	return fmt.Sprintf("tego adopt: adopted pid %d as run %s: %d process(es) moved from %s%s; recording since %d ms "+
		"after it was found%s\n", t.PID, s.RunID, len(s.Moved), record.Printable(s.From), notMoved, s.Window.Milliseconds(), plane)
}

// adoptEndLine says how the adoption ended and where its record is.
func adoptEndLine(res tegoruntime.Result) string {
	if res.RunID == "" {
		return ""
	}
	return fmt.Sprintf("tego adopt: run %[1]s ended (%[2]s)\n  tego status %[1]s    tego events %[1]s    tego drift %[1]s\n",
		res.RunID, res.Reason)
}

// runAdoptRelease is `tego adopt --release --pid <pid>`: the adoption that holds pid ends, its tree released.
func runAdoptRelease(ctx context.Context, pid int, stdout, stderr io.Writer) int {
	run, err := tegoruntime.AdoptionOf(adoptProc(), adoptStateDir, pid)
	if err != nil {
		message(stderr, "", 0, 0, "tego adopt --release: "+err.Error(), codeAdoptRefused)
		return identity.ExitError
	}
	return releaseAdoption(ctx, "tego adopt --release", run, stdout, stderr)
}

// releaseAdoption releases run's adoption (tego adopt --release, tego stop) and says who did it.
func releaseAdoption(ctx context.Context, cmd, run string, stdout, stderr io.Writer) int {
	rep, err := adoptRelease(ctx, adoptStateDir, run, releaseRequester(cmd), nil)
	switch {
	case err != nil:
		message(stderr, "", 0, 0, cmd+": "+err.Error(), codeRun)
		return identity.ExitError
	case rep.Again && rep.Unstarted:
		fmt.Fprintf(stdout, "%s: the adoption had failed before it recorded, leaving process(es) in its scope; they are "+
			"released now and run on, outside tego\n", run)
	case rep.Again:
		fmt.Fprintf(stdout, "%s: the run had ended with process(es) left in its scope; they are released now and run on, "+
			"outside tego\n", run)
	case rep.Adopter != 0:
		fmt.Fprintf(stdout, "%s: released by its adopter (pid %d); the agent runs on, outside tego\n", run, rep.Adopter)
	case rep.Reaper:
		fmt.Fprintf(stdout, "%s: released by its reaper (its adopter was gone); the agent runs on, outside tego\n", run)
	default:
		fmt.Fprintf(stdout, "%s: released here (its adopter was gone); the agent runs on, outside tego\n", run)
	}
	return identity.ExitOK
}

// releaseRequester is who asks for a release, as run_end says it: the command, its pid, and the user sudo ran it for.
func releaseRequester(cmd string) string {
	who := fmt.Sprintf("%s (pid %d", cmd, os.Getpid())
	if uid, viaSudo := config.InvokingUID(); viaSudo {
		who += fmt.Sprintf(", sudo by uid %d", uid)
	}
	return who + ")"
}
