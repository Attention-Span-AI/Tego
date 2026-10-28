// SPDX-License-Identifier: Apache-2.0

package profilesrc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Dir resolves `extends: <name>` to <Root>/<name>.yaml and never outside Root (agent-contract.md E7). The containment
// is the resolution's, not the name's: a name that leaves Root lexically ("../x", an absolute path) is reported as not
// found without a read, and the file is then read through os.Root, which walks every component beneath Root with
// openat and refuses a symlink that leads out of it. A lexical check alone let profiles/evil.yaml ->
// ../outside/secret.yaml through, and the outside file became contract input. os.Root also refuses every symlink
// whose target is absolute, even one naming a file inside Root, so a link in the profiles directory resolves only when
// it is relative and stays inside Root. An empty Root resolves nothing.
type Dir struct{ Root string }

// Location implements agent.ProfileLocator: the file Resolve reads name from, "" for a name that resolves to no file
// under Root, which extends-not-found names as the file to create.
func (s Dir) Location(name string) string {
	if s.Root == "" || name == "" || strings.Contains(name, "\x00") {
		return ""
	}
	rel := filepath.FromSlash(name) + ".yaml"
	if !filepath.IsLocal(rel) {
		return ""
	}
	return filepath.Join(s.placed(), rel)
}

// placed is Root spelled where the kernel's walk of it lands (agent.WalkedPath), the directory os.OpenRoot opens: the
// files named under it are joined with filepath.Join, which cleans, and with a ".." after a link in profiles: a
// profile's recorded path named a file beside the link's spelling, not the one read. A root
// the walk cannot place is kept as written.
func (s Dir) placed() string {
	if w, ok := agent.WalkedPath(s.Root); ok {
		return w
	}
	return s.Root
}

// Holds implements agent.ProfileProber: whether Root holds a file, a link or a directory entry for name, found by an
// lstat through os.Root and never read. ProfileChain asks it for a name under tego/ alone, so such a file is reported
// shadowed-builtin rather than passed over in silence (ADR 0066 D2).
func (s Dir) Holds(name string) (string, bool) {
	where := s.Location(name)
	if where == "" {
		return "", false
	}
	r, err := os.OpenRoot(s.Root)
	if err != nil {
		return "", false
	}
	defer func() { _ = r.Close() }()
	if _, err := r.Lstat(filepath.FromSlash(name) + ".yaml"); err != nil {
		return "", false
	}
	return where, true
}

// Resolve implements agent.ProfileSource. A link that escapes Root is not mapped to os.ErrNotExist: its error ("path
// escapes from parent") reaches Load, which reports extends-not-found with it as the fix, so the operator sees why a
// profile that exists was not read.
func (s Dir) Resolve(name string) (string, []byte, error) {
	if s.Root == "" || name == "" || strings.Contains(name, "\x00") {
		return "", nil, fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
	}
	rel := filepath.FromSlash(name) + ".yaml"
	if !filepath.IsLocal(rel) {
		return "", nil, fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
	}
	r, err := os.OpenRoot(s.Root)
	if err != nil {
		return "", nil, fmt.Errorf("profile %q: %w", name, err)
	}
	defer func() { _ = r.Close() }()
	// Opened as a contract is (agent.OpenFlags), and read under the same cap: a FIFO planted as a profile does not
	// hang compile or run, and a huge one is not read whole before the size check.
	f, err := r.OpenFile(rel, agent.OpenFlags, 0)
	if err != nil {
		return "", nil, fmt.Errorf("profile %q: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	path := filepath.Join(s.placed(), rel)
	if err := trusted(r, s.placed(), rel, f); err != nil {
		return "", nil, fmt.Errorf("profile %q: %w", name, err)
	}
	data, err := agent.ReadCapped(f, path)
	if err != nil {
		return "", nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return path, data, nil
}

// trusted applies the machine config's trust rule (config.CheckTrusted, spec/config/v0 R20) to the profile f opened
// as rel under r, to every directory between it and root, and to root itself, wherever the machine config's
// profiles: puts root (limits-check-doctor-cli.md §3): a profile is merged into every contract that extends it, so
// whoever may rewrite one, or swap one in, widens those contracts. Each directory is opened through r, as the file
// was, so a link cannot send the check somewhere the read did not go.
func trusted(r *os.Root, root, rel string, f *os.File) error {
	uid, _ := config.InvokingUID()
	if err := config.CheckTrusted(f, filepath.Join(root, rel), uid); err != nil {
		return err
	}
	dirs := []string{"."}
	for d := filepath.Dir(rel); d != "."; d = filepath.Dir(d) {
		dirs = append(dirs, d)
	}
	for _, d := range dirs {
		df, err := r.Open(d)
		if err != nil {
			return err
		}
		err = config.CheckTrusted(df, filepath.Join(root, d), uid)
		_ = df.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
