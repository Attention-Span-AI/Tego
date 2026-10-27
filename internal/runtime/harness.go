// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The harness provisioning point (agent-contract.md R27, ADR 0062). A provisioner (internal/adapters/*, connected by
// internal/cli) is told about the run (harness.Run) and returns what the harness needs (harness.Provision): files by
// name and bytes, a new argv, TEGO_ environment additions and the hook it will exec. The launcher creates every file
// itself, by directory descriptor, because it alone owns the run's runtime directory: so the files are read-only to
// the agent, and hook-state/ is the one place there it may write.

// Provisioner provisions one harness for one run. It returns bytes and names and writes nothing; an error refuses the
// run before run_start (exit 125).
type Provisioner interface {
	Provision(harness.Run) (harness.Provision, error)
}

// ErrHarnessProvision is a provision the launcher refuses to make: its provisioner failed, it names a file that is no
// single path element, one that already exists or one the launcher reserves (CheckProvision), an environment name
// without the TEGO_ prefix, one the launcher reserves or one the contract's env.set gives, or an argv whose argv[0] is
// not the resolved command. Refused before run_start, exit 125.
var ErrHarnessProvision = errors.New("runtime: harness provision refused")

// ErrHookStateExecutable is a run whose hook-state grant would land inside an exec directory entry, so the agent could
// run what it writes there (agent-contract.md R10a, as ErrCodexHomeExecutable): refused before run_start, exit 125.
var ErrHookStateExecutable = errors.New("runtime: an exec directory entry covers the run's hook-state directory")

// hookStateName is the agent-writable directory beside last-refusal.json in the run's runtime directory.
const hookStateName = "hook-state"

// GapReasonUnavailable is gap what=record why=reason-unavailable: a run provisioned for a harness (any harness: but
// none) that has no readable reason file, since it has no usable runtime directory (no absolute XDG_RUNTIME_DIR, or a
// root launcher). The agent has no TEGO_REASON and nothing was provisioned; the ledger says so right after run_start.
const GapReasonUnavailable = "reason-unavailable"

// harnessState is what the run provisioned for its harness (provisionHarness), for childSpec and run_start.
type harnessState struct {
	// start is run_start's harness, nil for harness: none.
	start *record.HarnessStart
	// env holds the provision's environment additions, appended to the agent's by childSpec.
	env []string
	// stateDir is hook-state/, and stateID the directory makeHookState made, which grantHookState requires.
	stateDir string
	stateID  fileID
}

// provisionHarness is the provisioning point, called once in prepare after createRuntimeDir and before Prepare, since
// the hook-state grant is one every backend builds with. The harness is the table's, auto resolved from the resolved
// command. harness: none does nothing at all. A run with no reason file (no usable runtime directory), or a harness
// with no provisioner, is recorded unprovisioned and otherwise unchanged. A provision whose hook the run's exec rules
// do not admit exactly (AdmitHook: under an allow-list contract, through the launcher's grant of its exact argv, ADR
// 0064) is dropped whole and recorded so, with a warning: provisioned, the hook would be refused on every tool call.
// Anything else wrong with a provision refuses the run.
func (r *runner) provisionHarness() error {
	argv := resolveCommand(r.rt, r.cmd)
	if len(argv) == 0 {
		return nil // newRunner refuses a run with no command; a hand-built runner provisions nothing
	}
	name := declaredHarness(r.rt).Resolve(argv[0])
	if name == harness.None {
		return nil
	}
	r.harness.start = &record.HarnessStart{Name: string(name), ReasonFile: r.reasonFile}
	var p Provisioner
	if r.deps.Harness != nil {
		p = r.deps.Harness(name)
	}
	switch {
	case r.runtimeDir == "" || r.reasonFile == "":
		r.harness.start.Why = record.HarnessWhyReasonUnavailable
		return nil
	case p == nil:
		r.harness.start.Why = record.HarnessWhyNoProvisioner
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: the tego binary's path: %w", ErrHarnessProvision, err)
	}
	run := harness.Run{
		RunID: string(r.id), Tier: string(r.tier()), Root: os.Geteuid() == 0, RuntimeDir: r.runtimeDir,
		ReasonFile: r.reasonFile, StateDir: filepath.Join(r.runtimeDir, hookStateName), CodexHome: r.codexHome,
		TegoExe: exe, Argv: argv, Env: r.agentEnv(), AllowList: !r.rt.ExecUnrestricted(), ReadUserFile: r.readUserFile,
	}
	prov, err := p.Provision(run)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrHarnessProvision, name, err)
	}
	if err := CheckProvision(r.rt, run, prov); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrHarnessProvision, name, err)
	}
	var inherited []string
	for _, kv := range prov.Env {
		if k, _, _ := strings.Cut(kv, "="); envHas(run.Env, k) {
			inherited = append(inherited, k) // a parent run's provision, or the launcher's own environment: replaced
		}
	}
	if len(inherited) > 0 {
		r.log.Info("run: the harness provision replaces inherited variables", "harness", name, "names", inherited)
	}
	d := AdmitHook(r.rt, r.tier(), exe, prov.Hook)
	if prov.Hook != nil {
		r.harness.start.Hook = &record.HarnessHook{Argv: slices.Clone(prov.Hook.Argv), Granted: d.Granted}
	}
	if d.Why != "" {
		r.harness.start.Why = d.Why
		what := fmt.Sprintf("harness %s is not provisioned: its hook %q is not admitted by the run's exec rules (%s, rule %s%s); "+
			"the agent learns of refusals through TEGO_REASON only", name, prov.Hook.Argv, d.Why, d.Rule, detailOf(d.Detail))
		r.log.Warn("run: " + what)
		if r.deps.Warn != nil {
			r.deps.Warn(WarnHarnessHookRefused, what)
		}
		return nil
	}
	r.rt = d.Table // the hook's exact-argv grant, when an allow-list contract needed one (ADR 0064)
	return r.applyProvision(prov)
}

// detailOf is ": "+detail, or "" for none.
func detailOf(detail string) string {
	if detail == "" {
		return ""
	}
	return ": " + detail
}

// reservedRuntimeNames are the names the engine itself uses in the run's runtime directory, refused as a harness file
// whether or not they exist when the provision is made: last-refusal.json (the file TEGO_REASON names, which the
// ledger first writes at the run's first refusal, so O_EXCL alone would let a provision forge it until then), the lock,
// hook-state and the CODEX_HOME. The ledger's temporary names for last-refusal.json (".last-refusal.json.<n>") are
// reservedRuntimePrefix's.
var reservedRuntimeNames = []string{ledger.LastRefusalFile, runtimeLockFile, hookStateName, codexHomeName}

// reservedRuntimePrefix is the prefix of the ledger's temporary names for last-refusal.json (writeFileAt).
const reservedRuntimePrefix = "." + ledger.LastRefusalFile + "."

// reservedEnvNames are the environment names a provision may not set, whether or not the agent's environment holds
// them: the ones the launcher sets or strips itself (the identity set, the DNS broker's pair, the cgroup helper's
// marker) and the one tego reads as its machine config. Names with reservedEnvPrefix (tego's test hooks) are too.
var reservedEnvNames = []string{
	identity.EnvRunID, identity.EnvAgent, identity.EnvParentRun, identity.EnvLedger, identity.EnvTier, identity.EnvReason,
	dnsBrokerDirEnv, dnsBrokerPIDEnv, cgroup.HelperEnvUnplaced, config.EnvConfigVar,
}

// reservedEnvPrefix is the prefix of tego's test-hook variables (TEGO_TEST_..., TEGO_TESTUTIL_...).
const reservedEnvPrefix = "TEGO_TEST"

// CheckProvision is every refusal of a provision that the run's table, the run and the provision decide alone, so that a
// run (provisionHarness) and compile's harness lines refuse the same provisions: the provision's own shape (Check), a
// name the launcher reserves (checkReserved), and an environment name the table's env.set gives (the contract would
// set it, and the harness would overwrite it). Only what exists on disk when the run starts (a file the provision
// names that already exists) is left to the run.
func CheckProvision(rt *agent.RuleTable, run harness.Run, p harness.Provision) error {
	if err := p.Check(run); err != nil {
		return err
	}
	if err := checkReserved(p); err != nil {
		return err
	}
	for _, kv := range p.Env {
		k, _, _ := strings.Cut(kv, "=")
		if _, set := rt.Set[k]; set {
			return fmt.Errorf("the contract's env.set gives %s, which the harness would set", k)
		}
	}
	return nil
}

// checkReserved refuses a provision that names a runtime-directory file or an environment variable the engine
// reserves: the launcher holds these guarantees itself, whatever an adapter returns.
func checkReserved(p harness.Provision) error {
	for _, f := range p.Files {
		if f.Dir == harness.Runtime && (slices.Contains(reservedRuntimeNames, f.Name) || strings.HasPrefix(f.Name, reservedRuntimePrefix)) {
			return fmt.Errorf("harness file %q is a name the launcher reserves in the runtime directory", f.Name)
		}
	}
	for _, kv := range p.Env {
		if k, _, _ := strings.Cut(kv, "="); slices.Contains(reservedEnvNames, k) || strings.HasPrefix(k, reservedEnvPrefix) {
			return fmt.Errorf("harness environment name %s is one the launcher reserves", k)
		}
	}
	return nil
}

// declaredHarness is the harness the contract declares, auto for the key absent: the launcher resolves auto from the
// command it runs, never from the table's compiled name, which compile resolved from the contract's own command when
// `tego run` was given none (a hand-built table with no contract has only that name).
func declaredHarness(rt *agent.RuleTable) harness.Name {
	n := rt.Harness
	if rt.Contract != nil {
		n = rt.Contract.Harness
	}
	if n == "" {
		return harness.Auto
	}
	return n
}

// WarnHarnessHookRefused is the diagnostic code of the warning a run, and compile, print when a harness's provision is
// dropped because the run's exec rules do not admit its hook.
const WarnHarnessHookRefused = "harness-hook-refused"

// applyProvision makes the provision: hook-state/ first (so no file can take its name), then each file, exclusively and
// by directory descriptor, then the hook-state grant; the argv replaces the run's command, and the environment
// additions wait for childSpec. A failure part way refuses the run, and unwind removes the runtime directory whole.
func (r *runner) applyProvision(p harness.Provision) error {
	if err := r.makeHookState(); err != nil {
		return err
	}
	files := make([]string, 0, len(p.Files))
	for _, f := range p.Files {
		dir, mode, id := r.runtimeDir, uint32(0o444), (*fileID)(nil)
		if f.Dir == harness.CodexHome {
			dir, mode, id = r.codexHome, 0o600, &r.codexHomeID
		}
		path, err := writeHarnessFile(dir, id, f.Name, mode, f.Bytes)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrHarnessProvision, err)
		}
		files = append(files, path)
	}
	if err := r.grantHookState(); err != nil {
		return err
	}
	if p.Argv != nil {
		r.cmd = slices.Clone(p.Argv)
	}
	r.harness.env = slices.Clone(p.Env)
	r.harness.start.Provisioned, r.harness.start.Files, r.harness.start.StateDir = true, files, r.harness.stateDir
	r.log.Info("run: harness provisioned", "harness", r.harness.start.Name, "summary", p.Summary, "files", files)
	return nil
}

// openOwnDir opens dir without following a link and requires a directory of this euid that no one else can write;
// with id, also exactly the directory id names.
func openOwnDir(dir string, id *fileID) (*sys.FD, error) {
	dfd, err := sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := dfd.Fstat(&st); err != nil {
		_ = dfd.Close()
		return nil, err
	}
	switch {
	case int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0:
		err = fmt.Errorf("%s is not a directory of uid %d that only it can write", dir, os.Geteuid())
	case id != nil && (uint64(st.Dev) != id.dev || st.Ino != id.ino):
		err = fmt.Errorf("%s is no longer the directory the run made", dir)
	}
	if err != nil {
		_ = dfd.Close()
		return nil, err
	}
	return dfd, nil
}

// writeHarnessFile makes dir/name with exactly mode, O_CREAT|O_EXCL|O_NOFOLLOW relative to dir's descriptor, and
// writes b: a name that already exists, as a file, a directory or a link, is refused, never written through.
func writeHarnessFile(dir string, id *fileID, name string, mode uint32, b []byte) (string, error) {
	if err := harness.CheckName(name); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	dfd, err := openOwnDir(dir, id)
	if err != nil {
		return "", fmt.Errorf("harness file %s: %w", path, err)
	}
	defer func() { _ = dfd.Close() }()
	ffd, err := dfd.Openat(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return "", fmt.Errorf("harness file %s: %w", path, err)
	}
	f, err := ffd.Release(path)
	if err != nil {
		_ = ffd.Close()
		return "", fmt.Errorf("harness file %s: %w", path, err)
	}
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Chmod(os.FileMode(mode)) // exactly mode, whatever the umask took from it at the create
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", fmt.Errorf("harness file %s: %w", path, werr)
	}
	return path, nil
}

// makeHookState makes hook-state/ (0700) in the run's runtime directory, by its descriptor, beside last-refusal.json and
// never above it or the harness files, and keeps its identity for grantHookState.
func (r *runner) makeHookState() error {
	dfd, err := openOwnDir(r.runtimeDir, nil)
	if err != nil {
		return fmt.Errorf("runtime: hook-state: %w", err)
	}
	defer func() { _ = dfd.Close() }()
	if err := dfd.Borrow(func(n int) error { return unix.Mkdirat(n, hookStateName, 0o700) }); err != nil {
		return fmt.Errorf("runtime: hook-state: %w", err)
	}
	sfd, err := dfd.Openat(hookStateName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("runtime: hook-state: %w", err)
	}
	defer func() { _ = sfd.Close() }()
	if err := sfd.Borrow(func(n int) error { return unix.Fchmod(n, 0o700) }); err != nil {
		return fmt.Errorf("runtime: hook-state: %w", err)
	}
	var st unix.Stat_t
	if err := sfd.Fstat(&st); err != nil {
		return fmt.Errorf("runtime: hook-state: %w", err)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("runtime: hook-state: owned by uid %d, not this launcher's", st.Uid)
	}
	r.harness.stateDir = filepath.Join(r.runtimeDir, hookStateName)
	r.harness.stateID = fileID{dev: uint64(st.Dev), ino: st.Ino}
	return nil
}

// grantHookState adds hook-state/ to the table as a write grant the runtime makes on its own authority
// (agent.HarnessStateGrant, rule fs.harness-state[<path>]), as grantCodexHome grants the CODEX_HOME: exactly that
// directory, only while it and its resolved spelling still name the directory makeHookState made, and refused when an
// exec directory entry covers it (ErrHookStateExecutable). The compiled table is never mutated (agent.RuleTable I4).
func (r *runner) grantHookState() error {
	dir := r.harness.stateDir
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("runtime: hook-state: %w", err)
	}
	for _, p := range []string{dir, resolved} {
		if err := r.harness.stateID.same(p); err != nil {
			return fmt.Errorf("runtime: hook-state: %w", err)
		}
	}
	if err := execOverGrant(r.rt, ErrHookStateExecutable, "hook-state directory", dir, resolved); err != nil {
		return err
	}
	out := *r.rt
	out.FS = append(slices.Clone(r.rt.FS), agent.FSRule{
		Path: dir, Resolved: resolved, Kind: agent.FSWrite, Access: agent.AccessWriteSet,
		Runtime: agent.HarnessStateGrant, RuntimeDev: r.harness.stateID.dev, RuntimeIno: r.harness.stateID.ino,
	})
	r.rt = &out
	return nil
}

// harnessEnv is env with the provision's additions appended, each replacing every entry of its name env inherited (a
// parent run's provision, as the identity set replaces TEGO_RUN_ID); provisionHarness refused a name the contract's
// env.set gives.
func (r *runner) harnessEnv(env []string) []string {
	if len(r.harness.env) == 0 {
		return env
	}
	names := make(map[string]bool, len(r.harness.env))
	for _, kv := range r.harness.env {
		k, _, _ := strings.Cut(kv, "=")
		names[k] = true
	}
	out := make([]string, 0, len(env)+len(r.harness.env))
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); !ok || !names[k] {
			out = append(out, kv)
		}
	}
	return append(out, r.harness.env...)
}

// emitReasonUnavailableGap writes GapReasonUnavailable once, right after run_start, for a run provisioned for a harness
// that has no reason file.
func (r *runner) emitReasonUnavailableGap() {
	if r.harness.start == nil || r.reasonFile != "" {
		return
	}
	r.emitGap(source.Gap{What: record.GapRecord, Why: GapReasonUnavailable})
}

// tier is the run's enforcement tier, "" for a runner built with no backend (a test's).
func (r *runner) tier() backend.Tier {
	if r.deps.Enforce == nil {
		return ""
	}
	return r.deps.Enforce.Tier()
}

// readUserFile is harness.Run.ReadUserFile: one of the user's own files, read for a provisioner as writeCodexHome reads
// the user's config.toml. It is refused at euid 0 (a root launcher reads no path a user names), for a path that is not
// absolute, under a deny_read entry of the run (the copy would sit where the agent reads it, the original not), for
// anything but a regular file (a final link is not followed, a FIFO not waited on), and above harness.MaxUserFile.
func (r *runner) readUserFile(path string) ([]byte, error) {
	if launcherEUID() == 0 {
		return nil, fmt.Errorf("%s: a root launcher reads none of the user's files for a harness", path)
	}
	if err := CheckUserFile(r.rt, path); err != nil {
		return nil, err
	}
	return readRegular(path, harness.MaxUserFile)
}

// CheckUserFile is readUserFile's refusals that the table and the path decide alone, before anything is read: a path
// that is not absolute, and one under a deny_read entry of rt. Compile's harness lines make the same checks, so that a
// path compile says a run reads is one a run does not refuse for these reasons.
func CheckUserFile(rt *agent.RuleTable, path string) error {
	switch {
	case !filepath.IsAbs(path):
		return fmt.Errorf("%s: not an absolute path", path)
	case readDenied(rt, path):
		return fmt.Errorf("%s: the run's deny_read covers it [%s]", path, identity.CodeContradiction)
	}
	return nil
}

// launcherEUID is the launcher's effective uid; a variable so a test can be the root launcher readUserFile refuses.
var launcherEUID = os.Geteuid

// readRegular reads path, opened without following a final link and without blocking on a FIFO, when it is a regular
// file of at most limit bytes.
func readRegular(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s grew past %d bytes while it was read", path, limit)
	}
	return b, nil
}

// envHas reports whether env assigns key.
func envHas(env []string, key string) bool {
	for _, kv := range env {
		if k, _, ok := strings.Cut(kv, "="); ok && k == key {
			return true
		}
	}
	return false
}
