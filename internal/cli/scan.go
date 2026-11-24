// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/scan"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/watch/sig"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func init() { register(cmdScan) }

// Test seams supply explicit fixture roots and kernel facts, never fixture HOME
// fallbacks to the operator's real account or proc tree.
var scanInputs = func() scan.Options {
	_, sudo := os.LookupEnv("SUDO_UID")
	recipient, _ := config.InvokingUID()
	pid := os.Getpid()
	ns, pidns := scan.Namespaces("/proc", pid) // zero when unread: the scan then refuses a negative answer
	membership := selfAnswer()
	return scan.Options{ProcRoot: "/proc", AdvancedSystemUnitRoots: []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"}, Cron: scan.CronRoots{Crontab: "/etc/crontab", Directory: "/etc/cron.d", Spool: "/var/spool/cron", Crontabs: "/var/spool/cron/crontabs"}, SystemUnitRoots: []string{"/etc/systemd/user", "/usr/lib/systemd/user"}, Passwd: "/etc/passwd", Boot: "/proc/sys/kernel/random/boot_id", ResolveDirectory: os.Getwd, Path: os.Getenv("PATH"), Version: buildinfo.Resolve(debug.ReadBuildInfo).Version, NamedProgram: namedDashboard(), Caller: scan.Caller{Recipient: uint32(recipient), InitialRoot: scanPrivileged(), UID: uint32(os.Getuid()), EUID: uint32(os.Geteuid()), PID: pid, Sudo: sudo, CgroupNamespace: ns, PIDNamespace: pidns, Membership: membership}}
}

// namedDashboard is scan.Options.NamedProgram for the dashboard: an unreadable program is the dashboard when the lock
// it holds says so, proved as a launcher is (runlock.DashboardPID); anything else stays unreadable. The proof is made
// once per scan, for the first unreadable program asked about, and never when none is.
func namedDashboard() func(home string, pid int) bool {
	var once sync.Once
	var dashboard int
	return func(home string, pid int) bool {
		once.Do(func() { dashboard, _ = runlock.DashboardPID(dashboardLockHome(home)) })
		return dashboard > 0 && dashboard == pid
	}
}

// dashboardLockHome is the home the dashboard's lock is under, given the caller's own: the same. A variable so a binary
// built with -tags tegotesthooks reads the lock where tego-control's test build wrote it (ownlog_testhook.go), and
// holds none when no test home is named, never the developer's own ~/.tego/dashboard.
var dashboardLockHome = func(home string) string { return home }

var scanCollect = scan.Collect
var scanPrivileged = config.InitNSRoot
var scanDrop = dropScanPrivileges
var scanSave = result.Save
var scanLedgerRoot = func(home string, uid uint32) (string, error) {
	secure, err := config.DetectSecureExec()
	if err != nil {
		return "", err
	}
	src := config.Sources{Etc: config.EtcPath, User: filepath.Join(home, config.UserRelPath)}
	if !secure {
		src.EnvFile = os.Getenv(config.EnvConfigVar)
	}
	m, _, err := config.LoadSourcesBounded(src, home, int(uid), config.TrustAbort, 1<<20)
	if err != nil {
		return "", err
	}
	return ledgerRootOf(m)
}

func cmdScan() Command {
	var asJSON, verbose, check, all, advanced, noDefaults, allowUnreadable bool
	specs := []string{}
	oversized := false
	return Command{Name: "scan", Summary: "look for your running agents, installed candidates and settings metadata", Usage: "[--advanced] [--json] [-v|--verbose] [--check [--allow-unreadable-programs]] [--all-mine] [--signature <rule>]... [--no-default-signatures]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one versioned JSON object, including coverage")
			fs.BoolVar(&verbose, "verbose", false, "include rule ids, identity and source details")
			fs.BoolVar(&verbose, "v", false, "include rule ids, identity and source details")
			fs.BoolVar(&check, "check", false, "exit 1 for an observed outside match; never save the result")
			fs.BoolVar(&allowUnreadable, "allow-unreadable-programs", false, "with --check, accept reported own processes whose program file cannot be read. "+result.UnreadableProgramsWarning+" With this flag, exit 0 does NOT mean no agent runs outside Tego")
			fs.BoolVar(&all, "all-mine", false, "list other interpreters whose purpose is unknown")
			fs.BoolVar(&advanced, "advanced", false, "as initial-namespace root, read all users' processes and fixed units, system units, cron and container cgroup hints")
			fs.BoolVar(&noDefaults, "no-default-signatures", false, "use only your supplied signatures")
			fs.Func("signature", "add, replace or remove a signature (repeatable; match input is never printed)", func(s string) error {
				if len(s) > 4096 || len(specs) >= 64 {
					oversized = true
					return nil
				}
				specs = append(specs, s)
				return nil
			})
			fs.Usage = func() {
				fmt.Fprintln(fs.Output(), "usage: tego scan [--advanced] [--json] [-v|--verbose] [--check [--allow-unreadable-programs]] [--all-mine] [--signature <rule>]... [--no-default-signatures]")
				visible := flag.NewFlagSet("tego scan", flag.ContinueOnError)
				visible.SetOutput(fs.Output())
				fs.VisitAll(func(f *flag.Flag) {
					{
						visible.Var(f.Value, f.Name, f.Usage)
						visible.Lookup(f.Name).DefValue = f.DefValue
					}
				})
				visible.PrintDefaults()
			}
		}, Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) (code int) {
			// Catch scan-local parser/collector panics before Main's own-log recovery.
			collectorUID := uint32(os.Getuid())
			s := result.New(time.Now(), collectorUID, "dev")
			if advanced {
				s = result.NewAdvanced(time.Now(), collectorUID, collectorUID, "dev")
			}
			if check {
				s.Check = "unknown"
			}
			collectionStarted := false
			defer func() {
				if recover() != nil {
					recipient := s.As.Recipient
					s = result.New(time.Now(), collectorUID, "dev")
					if advanced {
						s = result.NewAdvanced(time.Now(), collectorUID, recipient, "dev")
					}
					if check {
						s.Check = "unknown"
					}
					if !collectionStarted {
						s.Exclusions = append(s.Exclusions, "scan-not-performed")
					}
					s.AddFailure("meta", "bug")
					_ = result.Render(stdout, stderr, s, asJSON, verbose, nil)
					code = identity.ExitError
				}
			}()
			rows, err := scanRules(noDefaults, specs)
			if fs.NArg() != 0 || allowUnreadable && !check || oversized || err != nil {
				fmt.Fprintln(stderr, "tego scan: invalid arguments or signature [usage]")
				fs.Usage()
				return identity.ExitUsage
			}
			if advanced && !scanPrivileged() {
				s = result.NewAdvanced(time.Now(), uint32(os.Getuid()), uint32(os.Getuid()), "dev")
				if check {
					s.Check = "unknown"
				}
				s.AddFailure("meta", "privilege")
				s.Exclusions = append(s.Exclusions, "scan-not-performed")
				fmt.Fprintln(stderr, "tego scan: --advanced needs root in the initial user namespace; use tego scan for your own processes [privilege]")
				_ = result.Render(stdout, stderr, s, asJSON, verbose, nil)
				return identity.ExitError
			}
			if advanced && !scanRuntimeQuotaClosed(os.Getenv("GODEBUG")) {
				s.AddFailure("meta", "unsupported")
				s.Exclusions = append(s.Exclusions, "scan-not-performed")
				fmt.Fprintln(stderr, "tego scan: --advanced requires GODEBUG=containermaxprocs=0 to disable runtime quota adaptation before collection [unsupported]")
				_ = result.Render(stdout, stderr, s, asJSON, verbose, nil)
				return identity.ExitError
			}
			duration := 2 * time.Second
			if advanced {
				duration = 10 * time.Second
			}
			ctx, cancel := context.WithTimeout(ctx, duration)
			defer cancel()
			o := scanInputs()
			o.Rows = rows
			o.Check = check
			o.AllowUnreadablePrograms = allowUnreadable
			o.AllMine = all
			o.Advanced = advanced
			recipientReady, dropFailed := !advanced, false
			if advanced {
				o.BeforeRecipient = func(uid, gid uint32) error {
					s.As.Recipient = uid
					err := scanDrop(uid, gid)
					recipientReady, dropFailed = err == nil, err != nil
					return err
				}
			}
			collectionStarted = true
			outcome := scanCollect(ctx, o)
			s = outcome.Snapshot
			if advanced && !recipientReady && s.Status != "failed" {
				s.AddFailure("result", "privilege")
			}
			if dropFailed {
				fmt.Fprintln(stderr, "tego scan: recipient sources not read and result not saved; could not drop privilege to its recipient [privilege]")
			}
			live := map[string]bool{}
			probed := map[string]bool{}
			root := ""
			rootRead := false
			var rootErr error
			for _, i := range s.Items {
				if s.Status == "failed" {
					break
				}
				if i.Kind != "process" {
					continue
				}
				p := i.Process()
				if p.RunID == nil || probed[*p.RunID] {
					continue
				}
				if len(probed) == 8 {
					// Collection reserves source space for eight record checks, one
					// remainder and save failures. Repeated unprobed ids must not
					// consume the source allowance and erase the observed items.
					s.Sources = append(s.Sources, result.Source{ID: fmt.Sprintf("source-%d", len(s.Sources)+1), Kind: "meta", State: "not-read", Reason: "limit", NotRead: 1})
					if !slices.Contains(s.Limits, "source-limit") {
						s.Limits = append(s.Limits, "source-limit")
					}
					if s.Status == "ok" {
						s.Status = "partial"
					}
					break
				}
				probed[*p.RunID] = true
				// At most eight bounded record probes, and the command-wide deadline.
				ok, reason := false, "limit"
				if ctx.Err() != nil {
					reason = "deadline"
				}
				if ctx.Err() == nil {
					if !rootRead {
						root, rootErr = scanLedgerRoot(outcome.Home, s.As.Recipient)
						rootRead = true
					}
					if rootErr == nil {
						if advanced {
							ok, reason = scanRecordProbeFor(ctx, root, *p.RunID, s.Finished, s.As.Recipient)
						} else {
							ok, reason = scanRecordProbe(ctx, root, *p.RunID, s.Finished)
						}
					} else {
						reason = "io"
					}
				}
				live[*p.RunID] = ok
				state, read, notRead := "read", 1, 0
				if !ok {
					state, read, notRead = "not-read", 0, 1
					if s.Status == "ok" {
						s.Status = "partial"
					}
				}
				locator := (*string)(nil)
				if root != "" {
					locator = result.CheckedPath(filepath.Join(root, *p.RunID))
				}
				s.Sources = append(s.Sources, result.Source{ID: fmt.Sprintf("source-%d", len(s.Sources)+1), Kind: "meta", Locator: locator, State: state, Reason: reason, Read: read, NotRead: notRead})
			}
			// Validate every mode, so text and disk cannot bypass the JSON contract.
			if _, err := result.Encode(s); err != nil {
				s = result.New(time.Now(), o.Caller.UID, o.Version)
				if advanced {
					s = result.NewAdvanced(time.Now(), o.Caller.UID, o.Caller.Recipient, o.Version)
				}
				if check {
					s.Check = "unknown"
				}
				s.AddFailure("meta", "bug")
			}
			if !check && s.Status != "failed" {
				if s.Status != "failed" {
					if err := scanSave(outcome.Home, s.As.Recipient, s); err != nil {
						s.AddFailure("result", "io")
						switch {
						case errors.Is(err, result.ErrMode):
							fmt.Fprintln(stderr, "tego scan: saved result refused; fix its directory: chmod 700 ~/.tego/scan [io]")
						case errors.Is(err, result.ErrSync):
							fmt.Fprintln(stderr, "tego scan: saved result state unknown after replacement [io]")
						default:
							fmt.Fprintln(stderr, "tego scan: result not saved; the prior saved result, if any, remains [io]")
						}
					}
				}
			}
			if err := result.Render(stdout, stderr, s, asJSON, verbose, live); err != nil {
				_ = result.Footer(stderr, s, false)
				return identity.ExitError
			}
			nameLaunchers(ctx, stderr, outcome.Home, s)
			return s.ExitCode()
		}}
}

// nameLaunchers says, beside the unreadable count, which of the unreadable programs is the launcher of a live run: a
// launcher holds secrets, so it makes itself undumpable and its program file cannot be read (ADR 0126, "Amendment
// 2026-11-21: the secret-holding launcher is not dumpable"). It only attributes. The pid stays in the scan's own list,
// the count and the exit code do not change, and a pid is named only when the run's lock proves it the holder (the proof
// `tego stop` makes), never by its name or a lock line alone: a program that wrote a lock line could otherwise make
// itself disappear from the scan. The lines go to stderr, so the JSON result keeps its published shape.
func nameLaunchers(ctx context.Context, stderr io.Writer, home string, s result.Snapshot) {
	if s.Status == "failed" || len(s.UnreadableProgramPIDs) == 0 || ctx.Err() != nil {
		return
	}
	root, err := scanLedgerRoot(home, s.As.Recipient)
	if err != nil {
		return
	}
	named := launcherRuns(ctx, root, s.UnreadableProgramPIDs)
	for _, pid := range s.UnreadableProgramPIDs {
		if id, ok := named[pid]; ok {
			fmt.Fprintf(stderr, "tego scan: pid %d is the launcher of run %s; it is not dumpable because it holds secrets, and it stays counted as unreadable above\n", pid, record.Printable(id))
		}
	}
}

// maxLauncherRuns bounds the run directories nameLaunchers looks at, newest first.
const maxLauncherRuns = 200

// launcherRuns maps each of pids that is the proved launcher of a live run under root to that run's id.
func launcherRuns(ctx context.Context, root string, pids []int) map[int]string {
	if len(pids) == 0 {
		return nil
	}
	ids, err := runIDsNewestFirst(root)
	if err != nil {
		return nil
	}
	if len(ids) > maxLauncherRuns {
		ids = ids[:maxLauncherRuns]
	}
	out := map[int]string{}
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		dir := filepath.Join(root, id)
		held, info, err := runlock.ProbeLock(dir)
		if err != nil || !held || !slices.Contains(pids, info.PID) {
			continue
		}
		t, err := runlock.OpenStopTargetFor(dir, info)
		if err != nil {
			continue
		}
		_ = t.Close()
		out[info.PID] = id
	}
	return out
}

func scanRules(noDefaults bool, specs []string) ([]catalog.Row, error) {
	rows := catalog.Rows()
	if noDefaults {
		rows = nil
	}
	tokens := 0
	for n, text := range specs {
		tokens += len(strings.Fields(text))
		if tokens > 256 || len(text) > 4096 {
			return nil, errors.New("signature limit")
		}
		r, err := sig.Parse(text)
		if err != nil && !errors.Is(err, sig.ErrRemove) {
			return nil, errors.New("invalid signature")
		}
		kept := rows[:0]
		for _, row := range rows {
			if row.Rule.Name != r.Name {
				kept = append(kept, row)
			}
		}
		rows = kept
		if errors.Is(err, sig.ErrRemove) {
			continue
		}
		// The input alias is used only while applying overrides. Observations resolve
		// to numbered ids in catalog, never aliases or tokens chosen by the input.
		rows = append(rows, catalog.Row{ID: fmt.Sprintf("user-%d", n+1), Rule: r})
	}
	if len(rows) == 0 {
		return nil, errors.New("no signatures")
	}
	return rows, nil
}

// dropScanPrivileges changes every Go thread before recipient-controlled reads
// or the first destination open, including in check mode.
// The shipped CGO_ENABLED=0 binary can clear capabilities across all threads;
// a cgo build that cannot do so fails without opening a result directory.
// Use syscall.Setgroups: x/sys/unix.Setgroups changes only its calling thread.
func dropScanPrivileges(uid, gid uint32) error {
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	scanDropBetweenSteps("groups")
	if err := syscall.Setresgid(int(gid), int(gid), int(gid)); err != nil {
		return err
	}
	scanDropBetweenSteps("gid")
	if err := syscall.Setresuid(int(uid), int(uid), int(uid)); err != nil {
		return err
	}
	scanDropBetweenSteps("uid")
	if _, _, err := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); err != 0 {
		return err
	}
	scanDropBetweenSteps("no-new-privs")
	if err := sys.ClearProcessCapabilities(); err != nil {
		return err
	}
	r, e, s := unix.Getresuid()
	gr, ge, gs := unix.Getresgid()
	groups, err := unix.Getgroups()
	if err != nil {
		return err
	}
	if uint32(r) != uid || uint32(e) != uid || uint32(s) != uid || uint32(gr) != gid || uint32(ge) != gid || uint32(gs) != gid || len(groups) != 0 {
		return errors.New("privilege drop")
	}
	return nil
}
