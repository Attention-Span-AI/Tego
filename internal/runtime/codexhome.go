// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Codex routing (docs/p0/capture-derive.md R19b, spec/identity/RUN-IDENTITY.md's CODEX_HOME row). Codex
// ignores OPENAI_BASE_URL and reads openai_base_url only from the config.toml under CODEX_HOME, so a run
// whose forwarder has an openai listener gives Codex a CODEX_HOME of its own: a directory in the run's
// runtime directory holding identity.CodexConfig's file, tego's key first and the user's own config.toml
// after it. It is removed with the runtime directory when the run ends.

// codexHomeName is the run's CODEX_HOME inside its runtime directory.
const codexHomeName = "codex"

// codexConfigFile is the file Codex reads under CODEX_HOME.
const codexConfigFile = "config.toml"

// envOpenAIBaseURL is the variable the forwarder's openai listener is named by (forwarder.ProviderVars);
// the run's Codex config carries the same URL.
const envOpenAIBaseURL = identity.EnvOpenAIBaseURL

// maxCodexConfig bounds how much of the user's own config.toml is copied into the run's.
const maxCodexConfig = 1 << 20

// writeCodexHome writes the run's CODEX_HOME when the run has an openai listener and a runtime
// directory, and records it for forwarderVars. It writes nothing when there is no listener to route to
// or no runtime directory to put the file in, and nothing for a root launcher: its runtime directory
// is root's 0700, which the agent, dropped to the invoking uid, cannot enter, so a CODEX_HOME there would
// be one Codex could neither read nor write.
func (r *runner) writeCodexHome() error {
	base := r.forwarderVars()[envOpenAIBaseURL]
	if base == "" || r.runtimeDir == "" {
		return nil
	}
	if os.Geteuid() == 0 {
		// Unreachable while createRuntimeDir makes no directory for root; kept so the rule holds on its own.
		r.log.Info("run: codex is not routed through the forwarder: a root launcher's runtime directory is not the agent's")
		return nil
	}
	agentEnv := buildEnv(r.rt, r.environ())
	var user []byte
	var err error
	if path := codexConfigPath(agentEnv, os.Getuid()); path != "" && readDenied(r.rt, path) {
		// The copy would sit in the agent's own runtime directory, readable, while the original is not:
		// a deny_read over the user's codex config must not be undone by the launcher's own read.
		r.log.Info("run: the user's codex config.toml is denied to the agent and is not copied into the run's", "path", path)
	} else {
		user, err = userCodexConfig(agentEnv, os.Getuid())
	}
	if err != nil {
		// The user's settings are not what routes the traffic: the run's own key does. A file that
		// cannot be read is said in the own log and the run goes on with tego's key alone.
		r.log.Warn("run: the user's codex config.toml is not copied into the run's", "err", err)
		user = nil
	}
	dir := filepath.Join(r.runtimeDir, codexHomeName)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("runtime: codex home: %w", err)
	}
	// The directory is opened without following a link and the file made relative to it, so both are the directory
	// just made, and its identity is kept for grantCodexHome, which grants the path only while it still names it.
	dfd, err := sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return fmt.Errorf("runtime: codex home: %w", err)
	}
	defer func() { _ = dfd.Close() }()
	var st unix.Stat_t
	if err := dfd.Fstat(&st); err != nil {
		return fmt.Errorf("runtime: codex home: %w", err)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("runtime: codex home: %s is owned by uid %d, not this launcher's", dir, st.Uid)
	}
	ffd, err := dfd.Openat(codexConfigFile, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("runtime: codex config: %w", err)
	}
	f, err := ffd.Release(filepath.Join(dir, codexConfigFile))
	if err != nil {
		_ = ffd.Close()
		return fmt.Errorf("runtime: codex config: %w", err)
	}
	_, werr := f.Write(identity.CodexConfig(base, user))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("runtime: codex config: %w", werr)
	}
	r.codexHome = dir
	r.codexHomeID = fileID{dev: uint64(st.Dev), ino: st.Ino}
	return nil
}

// fileID is a file's device and inode.
type fileID struct{ dev, ino uint64 }

// GapCodexUnrouted is gap what=capture why=codex-unrouted binary=codex: a run with an openai listener that wrote no
// CODEX_HOME, which only a root launcher does (agent-contract.md R10a (3)), so a Codex in it is not routed through
// the forwarder; the models[] guard refuses its own calls to the model (E27), so it fails closed, and the record says
// why.
const GapCodexUnrouted = "codex-unrouted"

// emitCodexUnroutedGap writes GapCodexUnrouted once, right after run_start, when the run has an openai listener and no
// CODEX_HOME: a root launcher's (createRuntimeDir), where it was said only in tego's own log.
func (r *runner) emitCodexUnroutedGap() {
	if r.codexHome != "" || r.forwarderVars()[envOpenAIBaseURL] == "" {
		return
	}
	r.emitGap(source.Gap{What: record.GapCapture, Why: GapCodexUnrouted, Binary: "codex"})
}

// environ is the launcher's environment, the one the agent's is built from (childSpec).
func (r *runner) environ() []string {
	if r.deps.Environ != nil {
		return r.deps.Environ
	}
	return os.Environ()
}

// userCodexConfig is the config.toml Codex would have read without tego's CODEX_HOME. agentEnv is the
// agent's environment before tego's own variables: the launcher's with the contract's env pass-list,
// deny list and set entries applied (buildEnv), since a contract that sets or denies CODEX_HOME or HOME
// changes which file Codex reads, and the launcher's own environment would name another. The file is
// under that CODEX_HOME when it is non-empty, else under ~/.codex, ~ being that HOME when it is non-empty
// and uid's passwd home otherwise — the order Codex resolves its home in. It is only ever read by an
// unprivileged launcher (writeCodexHome), and never when a deny_read entry covers the file (readDenied).
// A missing file is nil and no error. The file is opened without following a final symlink and without
// blocking on a FIFO, and must be a regular file of at most maxCodexConfig bytes.
func userCodexConfig(agentEnv []string, uid int) ([]byte, error) {
	path := codexConfigPath(agentEnv, uid)
	if path == "" {
		return nil, nil
	}
	b, err := readRegular(path, maxCodexConfig)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// codexConfigPath is where userCodexConfig reads: "" when the agent's environment names no home.
func codexConfigPath(agentEnv []string, uid int) string {
	home := lookupEnv(agentEnv, identity.EnvCodexHome)
	if home == "" {
		h := lookupEnv(agentEnv, "HOME")
		if h == "" {
			h = passwdHome(uid)
		}
		if h == "" {
			return ""
		}
		home = filepath.Join(h, ".codex")
	}
	return filepath.Join(home, codexConfigFile)
}

// readDenied reports whether a deny_read entry of the table (declared or built in) covers path, by the
// spelling as given and by the one with its directory's symlinks resolved.
func readDenied(rt *agent.RuleTable, path string) bool {
	if rt == nil {
		return false
	}
	paths := []string{filepath.Clean(path)}
	if d, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		paths = append(paths, filepath.Join(d, filepath.Base(path)))
	}
	for _, f := range rt.FS {
		if f.Kind != agent.FSDenyRead {
			continue
		}
		for _, e := range f.Spellings() {
			for _, p := range paths {
				if agent.Covers(e, p) {
					return true
				}
			}
		}
	}
	return false
}

// lookupEnv is the first value of key in environ, the one getenv(3) — and so Codex — finds when a name
// is assigned twice; "" when it is unset.
func lookupEnv(environ []string, key string) string {
	for _, kv := range environ {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			return val
		}
	}
	return ""
}
