// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is one rule as a person sees and approves it: in a category, an action on something, allowed or
// blocked. The review page, the saved files and the contract all start from it.
type Rule struct {
	// Scope is "personal" (outside any project) or "workspace" (inside this project).
	Scope string `yaml:"-" json:"scope"`
	// Category is files, programs, websites or logins.
	Category string `yaml:"category" json:"category"`
	// Verb is the action: read, write, run, reach, use or see.
	Verb string `yaml:"verb" json:"verb"`
	// Value is what the action applies to, as the person reads it.
	Value string `yaml:"value" json:"value"`
	// Allow is the effect: allowed (true) or blocked (false).
	Allow bool `yaml:"allow" json:"allow"`
	// Always marks a rule the engine enforces whatever is chosen.
	Always bool `yaml:"always,omitempty" json:"always,omitempty"`
	// Why says in a few words where the rule came from.
	Why string `yaml:"why,omitempty" json:"why,omitempty"`
	// Programs, Hosts and Paths are what the rule applies to, for the contract: programs it lets run, websites
	// it lets the agent reach, and files it blocks (project-relative in the workspace, ~/… in personal).
	Programs []string `yaml:"programs,omitempty" json:"programs,omitempty"`
	Hosts    []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Paths    []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	// From is the shared row a program or website was split out of when the person blocked it alone (the row's
	// whole list, in order), so allowing it again puts it back where it was.
	From []string `yaml:"from,omitempty" json:"from,omitempty"`
	// Added marks a rule the person added; Suggested is what Maze proposed, to count what they changed.
	Added     bool `yaml:"added,omitempty" json:"added,omitempty"`
	Suggested bool `yaml:"-" json:"-"`
}

// Key identifies a rule across runs: the same category, action and target is the same rule.
func (r Rule) Key() string { return r.Category + "/" + r.Verb + "/" + r.Value }

// Version is the version of the saved files. Bump it when a field changes meaning or goes away.
const Version = 1

// Workspace is <project>/.maze/workspace.yaml.
type Workspace struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"name"`
	Owner   string `yaml:"owner"`
	Agent   string `yaml:"agent"`
	Rules   []Rule `yaml:"rules"`
	// Ignored are rules Maze didn't take as written (normalize), with why.
	Ignored []IgnoredRule `yaml:"-"`
}

// Personal is ~/.maze/personal.yaml.
type Personal struct {
	Version int           `yaml:"version"`
	Rules   []Rule        `yaml:"rules"`
	Ignored []IgnoredRule `yaml:"-"`
}

// Paths of Maze's files, relative to the project root or the home folder.
const (
	WorkspaceDir  = ".maze"
	WorkspaceFile = ".maze/workspace.yaml"
	// StateDir, in the project, is where Claude Code keeps its settings and sessions during a run (gitignored).
	StateDir     = ".maze/state"
	PersonalFile = ".maze/personal.yaml"
	approvedDir  = ".maze/approved"
	// projectsDir, in the home folder, holds each project's generated engine contract. It is outside the
	// project on purpose: the agent may write the project, and the engine refuses a contract it could rewrite
	// (Landlock can't deny a folder inside a writable one).
	projectsDir   = ".maze/projects"
	gitignoreLine = ".maze/state/"
)

// header opens the saved files, so someone who opens one knows what it is.
const workspaceHeader = "# Maze rules for this project. Commit this file so your team gets the same rules.\n" +
	"# Change it with `maze` (Review rules); a change made any other way is shown and must be approved again.\n"

const personalHeader = "# Your Maze rules outside any project. Change them with `maze`.\n"

// errNotRegular marks a path that is a symbolic link or not a regular file.
var errNotRegular = errors.New("is a symbolic link or not a regular file; Maze won't read or replace it")

// maxFile bounds what is read of a Maze file: a hand-sized YAML is far smaller.
const maxFile = 1 << 20

// readFile reads path, refusing a symbolic link or anything but a regular file. exists is false when there is
// nothing at path.
func readFile(path string) (data []byte, exists bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if !fi.Mode().IsRegular() {
		return nil, true, fmt.Errorf("%s %w", path, errNotRegular)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = f.Close() }() // read-only: a close error loses nothing
	data, err = io.ReadAll(io.LimitReader(f, maxFile))
	return data, true, err
}

// writeFile writes data to path atomically: a temporary file in the same folder, then a rename, which replaces
// a symbolic link at path rather than the file it leads to. dir mode is used for missing folders.
func writeFile(path string, data []byte, mode, dirMode os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s %w", path, errNotRegular)
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return fmt.Errorf("make %s: %w", filepath.Dir(path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after the rename; only a failed write leaves it
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// LoadWorkspace reads <root>/.maze/workspace.yaml; ok is false when the project isn't set up.
func LoadWorkspace(root string) (w Workspace, ok bool, err error) {
	data, ok, err := readFile(filepath.Join(root, WorkspaceFile))
	if err != nil || !ok {
		return Workspace{}, ok, err
	}
	if err := decodeRules(WorkspaceFile, data, &w); err != nil {
		return Workspace{}, true, err
	}
	if err := checkRules(WorkspaceFile, w.Rules); err != nil {
		return Workspace{}, true, err
	}
	w.Rules, w.Ignored = normalize(os.Getenv("HOME"), w.Rules, true)
	for i := range w.Rules {
		w.Rules[i].Scope = "workspace"
		w.Rules[i].Suggested = w.Rules[i].Allow
	}
	return w, true, nil
}

// LoadPersonal reads ~/.maze/personal.yaml; ok is false when there is none yet.
func LoadPersonal(home string) (p Personal, ok bool, err error) {
	data, ok, err := readFile(filepath.Join(home, PersonalFile))
	if err != nil || !ok {
		return Personal{}, ok, err
	}
	if err := decodeRules("~/"+PersonalFile, data, &p); err != nil {
		return Personal{}, true, err
	}
	if err := checkRules("~/"+PersonalFile, p.Rules); err != nil {
		return Personal{}, true, err
	}
	p.Rules, p.Ignored = normalize(os.Getenv("HOME"), p.Rules, false)
	for i := range p.Rules {
		p.Rules[i].Scope = "personal"
		p.Rules[i].Suggested = p.Rules[i].Allow
	}
	return p, true, nil
}

// encode is a saved file's bytes: its header, then the YAML.
func encode(header string, v any) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(header)
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// CurrentWorkspace is the project's rules file exactly as it is on disk: what approving a change records, so the
// file a teammate committed is approved as committed (not rewritten, which would fight their next commit).
func CurrentWorkspace(root string) ([]byte, error) {
	data, ok, err := readFile(filepath.Join(root, WorkspaceFile))
	if err == nil && !ok {
		err = errors.New("this project isn't set up")
	}
	return data, err
}

// WorkspaceBytes is what SaveWorkspace writes for w: also what approval hashes.
func WorkspaceBytes(w Workspace) ([]byte, error) {
	w.Version = Version
	return encode(workspaceHeader, w)
}

// SaveWorkspace writes <root>/.maze/workspace.yaml and adds the compiled folder to the project's .gitignore.
func SaveWorkspace(root string, w Workspace) ([]byte, error) {
	data, err := WorkspaceBytes(w)
	if err != nil {
		return nil, err
	}
	if err := realDirs(root, WorkspaceDir); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(root, WorkspaceFile), data, 0o644, 0o755); err != nil {
		return nil, err
	}
	if err := ensureGitignore(root); err != nil {
		return nil, err
	}
	return data, nil
}

// SavePersonal writes ~/.maze/personal.yaml, readable by the person only.
func SavePersonal(home string, p Personal) error {
	p.Version = Version
	data, err := encode(personalHeader, p)
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(home, PersonalFile), data, 0o600, 0o700)
}

// ensureGitignore adds .maze/state/ to the project's .gitignore unless a line already says so.
func ensureGitignore(root string) error {
	path := filepath.Join(root, ".gitignore")
	data, _, err := readFile(path)
	if err != nil {
		return err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == gitignoreLine {
			return nil
		}
	}
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		data = append(data, '\n')
	}
	data = append(data, []byte(gitignoreComment+"\n"+gitignoreLine+"\n")...)
	return writeFile(path, data, 0o644, 0o755)
}

// gitignoreComment is the line ensureGitignore writes above gitignoreLine.
const gitignoreComment = "# Claude Code's settings and sessions during Maze runs"

// cleanGitignore takes out the lines ensureGitignore added (its comment and the line under it), leaving the rest
// of the file as it was; a .maze/state/ line the person wrote themselves, without Maze's comment, stays. A file
// left with nothing in it was Maze's alone and is removed.
func cleanGitignore(root string) error {
	path := filepath.Join(root, ".gitignore")
	data, ok, err := readFile(path)
	if err != nil || !ok {
		return err
	}
	lines := strings.Split(string(data), "\n")
	var keep []string
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == gitignoreComment {
			if i+1 < len(lines) && strings.TrimSpace(lines[i+1]) == gitignoreLine {
				i++
			}
			continue
		}
		keep = append(keep, lines[i])
	}
	out := strings.Join(keep, "\n")
	if out == string(data) {
		return nil
	}
	if strings.TrimSpace(out) == "" {
		return os.Remove(path)
	}
	return writeFile(path, []byte(out), 0o644, 0o755)
}

// RemoveWorkspace deletes <root>/.maze/ and the approval record for it. A .maze that is a link is unlinked,
// never followed.
func RemoveWorkspace(home, root string) error {
	if filepath.Clean(home) == filepath.Clean(root) {
		return errors.New("this is your home folder: Maze keeps your own rules and keys in ~/.maze, so it won't remove that; use maze profile remove for your rules")
	}
	dir := filepath.Join(root, WorkspaceDir)
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(dir); err != nil {
			return err
		}
	} else if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	if err := os.RemoveAll(CompiledFolder(home, root)); err != nil {
		return err
	}
	if err := cleanGitignore(root); err != nil {
		return err
	}
	if err := RemovePrePush(root); err != nil {
		return err
	}
	return forget(home, root)
}

// CompiledFolder is where root's generated engine contract and checks are kept: ~/.maze/projects/<project id>.
func CompiledFolder(home, root string) string {
	return filepath.Join(home, projectsDir, projectID(root))
}

// RemovePersonal deletes ~/.maze/personal.yaml.
func RemovePersonal(home string) error {
	err := os.Remove(filepath.Join(home, PersonalFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
