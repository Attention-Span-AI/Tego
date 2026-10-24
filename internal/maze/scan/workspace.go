// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Workspace is the folder `maze init` sets up: the enclosing git repository's root when there is
// one, the starting folder otherwise.
type Workspace struct {
	// Root is the absolute path of the workspace.
	Root string `json:"root"`
	// Name is the folder's name as the person sees it ("my app ü").
	Name string `json:"name"`
	// ID is a short id derived from Name, the shape the engine wants for a contract name ("my-app-u").
	ID string `json:"id"`
	// Started is the folder maze was run from, which may sit below Root.
	Started string `json:"-"`
	// Git reports whether Root is a git repository's root.
	Git bool `json:"git"`
	// SetUp reports whether Root already holds .maze/workspace.yaml.
	SetUp bool `json:"set_up"`
}

// WorkspaceFile is where a workspace's own scope lives, relative to its root.
const WorkspaceFile = ".maze/workspace.yaml"

// FindWorkspace walks up from dir to the nearest folder that is set up with Maze (.maze/workspace.yaml) or holds
// .git (a directory, or the file a linked worktree has) and returns it as the workspace; with neither, dir itself
// is the workspace. The errors say what is wrong with dir in plain words.
func FindWorkspace(dir string) (Workspace, error) {
	start, err := filepath.Abs(dir)
	if err != nil {
		return Workspace{}, fmt.Errorf("resolve %s: %w", dir, err)
	}
	fi, err := os.Stat(start)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Workspace{}, fmt.Errorf("there's no folder at %s", dir)
	case errors.Is(err, fs.ErrPermission):
		return Workspace{}, fmt.Errorf("maze isn't allowed to open %s", dir)
	case err != nil:
		return Workspace{}, fmt.Errorf("can't open %s: %w", dir, err)
	case !fi.IsDir():
		return Workspace{}, fmt.Errorf("%s is a file, not a folder", dir)
	}
	// The real path, links resolved: the read walks it (a walk does not enter a link at its root), the project's
	// id hashes it, and the contract names it, so a project reached through a link (a symlinked folder, macOS's
	// /tmp and /var) is the same project, read in full.
	if start, err = filepath.EvalSymlinks(start); err != nil {
		return Workspace{}, fmt.Errorf("resolve %s: %w", dir, err)
	}
	root, git := start, false
	for d := start; ; d = filepath.Dir(d) {
		if set, _ := exists(filepath.Join(d, WorkspaceFile)); set {
			root = d
			git, _ = exists(filepath.Join(d, ".git"))
			break
		}
		ok, err := exists(filepath.Join(d, ".git"))
		if err != nil {
			return Workspace{}, fmt.Errorf("look for .git in %s: %w", d, err)
		}
		if ok {
			root, git = d, true
			break
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	setUp, err := exists(filepath.Join(root, WorkspaceFile))
	if err != nil {
		return Workspace{}, fmt.Errorf("look for %s: %w", WorkspaceFile, err)
	}
	// The root is written into the contract and shown on screen: a name with a newline or an escape would end a
	// line of either and start another.
	if !printable(root) || !utf8.ValidString(root) {
		return Workspace{}, fmt.Errorf("the folder's path %q holds a control character or a byte that isn't text; rename it to set it up", root)
	}
	name := filepath.Base(root)
	if name == string(filepath.Separator) || name == "." {
		name = "workspace"
	}
	return Workspace{Root: root, Name: name, ID: workspaceName(root), Git: git, SetUp: setUp, Started: start}, nil
}

// workspaceName lower-cases root's last component and turns every other rune into '-', trimmed to
// 40; "workspace" when nothing is left. The same shape as the engine's agent ids.
func workspaceName(root string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(filepath.Base(root)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		return "workspace"
	}
	return s
}

// ReadDepth is how many folders deep the project read goes.
const ReadDepth = maxDepth

// SkippedFolders are the folder names the project read never enters, in a fixed order.
func SkippedFolders() []string {
	return []string{"node_modules", ".git", "vendor", ".venv", "venv", "target"}
}

// NestedProjects names the folders directly inside root that are git projects of their own, sorted. It looks at
// names only (a folder holding .git), so it can run before the person allows the read: it tells them that a
// folder like ~/Documents/work holds several repositories and all of them would be read.
func NestedProjects(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || skipDirs[name] || strings.HasPrefix(name, ".") {
			continue
		}
		if _, err := os.Lstat(filepath.Join(root, name, ".git")); err == nil {
			out = append(out, name)
		}
	}
	return out // os.ReadDir sorts by name
}
