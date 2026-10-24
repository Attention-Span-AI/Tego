// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// projectID names a project's approval record: a hash of its folder, so the record lives outside the project
// and an agent working in the project can't rewrite what was approved.
func projectID(root string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(root)))
	return hex.EncodeToString(sum[:8])
}

// approvalPath is where the approved copy of a project's workspace file is kept.
func approvalPath(home, root string) string {
	return filepath.Join(home, approvedDir, projectID(root)+".yaml")
}

// Approve records data (the workspace file as saved) as what the person approved for root.
func Approve(home, root string, data []byte) error {
	return writeFile(approvalPath(home, root), data, 0o600, 0o700)
}

// forget removes root's approval record.
func forget(home, root string) error {
	err := os.Remove(approvalPath(home, root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Change is one difference between the approved rules and the rules on disk, as one effect (Atom).
type Change struct {
	// Kind is added, removed or flipped.
	Kind string
	Rule Rule
}

// Approval is how the workspace file on disk compares with what the person last approved.
type Approval struct {
	// Recorded is false when nothing was ever approved for this project on this computer (a teammate's
	// committed file, a project moved to another folder).
	Recorded bool
	// Same is true when the file enforces what was approved: byte for byte, or with only notes and order changed.
	Same bool
	// Changes lists what differs, one effect each, riskiest first.
	Changes []Change
	// Rules are the file's rules, for a project nothing was approved for yet.
	Rules []Rule
	// Ignored are rules Maze didn't take as written, with why.
	Ignored []IgnoredRule
}

// CheckApproval compares <root>/.maze/workspace.yaml with the approved copy, by what each enforces.
func CheckApproval(home, root string) (Approval, error) {
	w, ok, err := LoadWorkspace(root)
	if err != nil || !ok {
		return Approval{}, err
	}
	current, _, err := readFile(filepath.Join(root, WorkspaceFile))
	if err != nil {
		return Approval{}, err
	}
	approved, ok, err := readFile(approvalPath(home, root))
	if err != nil {
		return Approval{}, err
	}
	if !ok {
		return Approval{Rules: w.Rules, Ignored: w.Ignored}, nil
	}
	if sha256.Sum256(current) == sha256.Sum256(approved) {
		return Approval{Recorded: true, Same: true}, nil
	}
	var a Workspace
	if err := yaml.Unmarshal(approved, &a); err != nil {
		return Approval{}, fmt.Errorf("read the approved copy: %w", err)
	}
	a.Rules, _ = normalize(os.Getenv("HOME"), a.Rules, true)
	ch := diffAtoms(a.Rules, w.Rules)
	return Approval{Recorded: true, Same: len(ch) == 0 && len(w.Ignored) == 0, Changes: ch, Ignored: w.Ignored}, nil
}

// Restore puts back the workspace file the person last approved, replacing whatever changed it.
func Restore(home, root string) error {
	data, ok, err := readFile(approvalPath(home, root))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("nothing was approved for this project on this computer")
	}
	return writeFile(filepath.Join(root, WorkspaceFile), data, 0o644, 0o755)
}

// ApproveCurrent records the workspace file as it is now as approved.
func ApproveCurrent(home, root string) error {
	data, ok, err := readFile(filepath.Join(root, WorkspaceFile))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("this project isn't set up")
	}
	return Approve(home, root, data)
}
