// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/harness"
)

// ErrClaudeSocketDir refuses a Claude runtime path before the client can fall back
// to a shared /tmp socket directory (ADR 0113, agent-contract R12).
var ErrClaudeSocketDir = errors.New("runtime: Claude session socket directory")

// configureClaudeSockets resolves env.set.XDG_RUNTIME_DIR: "%R" to the existing
// pinned, writable harness state. It creates no host grant and never changes the
// invoking environment. Explicit paths are checked too: Claude 2.1.318 switches to
// /tmp/cc-socks-<uid> above 103 bytes, below the kernel's sun_path limit.
func (r *runner) configureClaudeSockets() error {
	dir, set := r.rt.Set["XDG_RUNTIME_DIR"]
	if !set {
		return nil
	}
	argv := resolveCommand(r.rt, r.cmd)
	if len(argv) == 0 || declaredHarness(r.rt).Resolve(argv[0]) != harness.ClaudeCode {
		if dir == "%R" {
			return fmt.Errorf("%w: XDG_RUNTIME_DIR %%R requires a provisioned claude-code harness", ErrClaudeSocketDir)
		}
		return nil
	}
	if dir == "%R" {
		if r.harness.start == nil || !r.harness.start.Provisioned || r.harness.stateDir == "" {
			return fmt.Errorf("%w: XDG_RUNTIME_DIR %%R needs a private runtime and a provisioned claude-code harness; run unprivileged with an absolute, short invoking XDG_RUNTIME_DIR (normally /run/user/<uid>)", ErrClaudeSocketDir)
		}
		dir = r.harness.stateDir
	}
	if err := checkClaudeSocketPath(dir); err != nil {
		return err
	}
	// RuleTable I4: retain the compiled contract and its literal %R; only this
	// run's effective environment receives the resolved directory.
	out := *r.rt
	out.Set = maps.Clone(r.rt.Set)
	out.Set["XDG_RUNTIME_DIR"] = dir
	r.rt = &out
	return nil
}

func checkClaudeSocketPath(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: XDG_RUNTIME_DIR %q is not absolute; use %%R for the run's private harness runtime", ErrClaudeSocketDir, dir)
	}
	path := filepath.Join(dir, "cc-socks", "9999999.sock")
	if len(path) > 103 {
		return fmt.Errorf("%w: XDG_RUNTIME_DIR %q gives %q (%d bytes; maximum 103 including a seven-digit PID filename); use %%R with a shorter invoking XDG_RUNTIME_DIR (normally /run/user/<uid>); the shared /tmp/cc-socks-<uid> fallback is not granted", ErrClaudeSocketDir, dir, path, len(path))
	}
	return nil
}
