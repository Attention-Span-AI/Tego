// SPDX-License-Identifier: Apache-2.0

// Package registry resolves an agent's name to its contract file, which makes
// `tego run retriever` and `tego compile retriever` mean the contract of the agent named retriever
// (docs/p0/agent-contract.md R26).
//
// There are two registries, read in this order:
//
//   - the project registry, the working directory: its agent.yaml when that file's name: is the name (the file
//     `tego init` writes), and its .tego/agents/<name>.yaml;
//   - the user registry, the machine config's registry: directory (default ~/.config/tego): its agents/<name>.yaml.
//
// The project registry answers a name the user registry does not hold, and the user registry one the project does not
// hold. Resolution is deterministic and fails closed. A name both registries hold, the project registry holds twice,
// or that is also a file in the working directory, is refused as ambiguous: a project entry never silently replaces
// the user's, since a run of the user's entry may write the working directory. A name no registry holds is refused
// with the files that would hold it; an entry whose name: is not its file's name, that is not a regular file, that
// someone other than the invoking user or root could have written, or that has a second name (config.CheckTrusted, the
// rule profiles follow) is refused. An entry is read through its agents/ directory, and no link leads out of it, so
// every name it is read by is one R10 keeps every write entry off (ADR 0059). An entry is read once, through the
// descriptor that was checked, and the caller compiles those bytes, so the file a run records is the file whose bytes
// it compiled.
//
// A registry is also the home of skills: <registry>/skills/<name>/ in either registry is where a skill a contract
// declares will be found when skills are provisioned (FEATURES.md I6c). Until then `skills:` does not compile
// (agent-contract.md R23), and nothing here reads that directory.
package registry

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"gopkg.in/yaml.v3"
)

// The registries a name resolves in, as run_start's contract_source.registry spells them.
const (
	Project = "project"
	User    = "user"
)

// The registry's layout.
const (
	// ProjectFile is the project's own contract, the file `tego init` writes; it answers for the name its
	// name: field holds.
	ProjectFile = "agent.yaml"
	// ProjectDir is the project registry's directory in the working directory.
	ProjectDir = ".tego"
	// AgentsDir holds one contract per agent, <name>.yaml, in a registry directory.
	AgentsDir = "agents"
	// SkillsDir is where a registry's skills will live, one directory per skill (reserved until FEATURES.md I6c).
	SkillsDir = "skills"
)

// The diagnostic codes of a refused resolution (the bracketed suffix, spec/identity/RUN-IDENTITY.md "Messages").
const (
	// CodeNotFound: no registry holds the name.
	CodeNotFound = "agent-not-found"
	// CodeAmbiguous: the name means two files, and which one is not the registry's to choose.
	CodeAmbiguous = "agent-ambiguous"
	// CodeEntry: the file that holds the name cannot be its contract (wrong name:, not a regular file, unreadable).
	CodeEntry = "registry-entry"
	// CodeUntrusted: the file that holds the name, or a directory above it in its registry, could have been written
	// by someone other than the invoking user or root.
	CodeUntrusted = config.CodeUntrusted
)

// Places are the registries a name is resolved in.
type Places struct {
	// Dir is the project registry's directory: the working directory, absolute.
	Dir string
	// User is the user registry's directory (the machine config's registry:), absolute; "" for none.
	User string
	// UID is the invoking user, whose files (and root's) are trusted.
	UID int
	// Own are tego's own paths, which every run read-denies (agent-contract.md R6a): its own directory, the ledger
	// root, the profiles directory. A contract's directory is one a run needs, and Compile lifts that deny from a
	// directory that holds one, so an entry inside any of them is refused rather than resolved, unless the working
	// directory is inside it too: the run needs the working directory as well, which lifts the deny whatever
	// contract runs (and Compile warns ledger-readable, as for a contract given by its path).
	Own []string
}

// Entry is a name resolved to its contract.
type Entry struct {
	// Name is the agent's name, as given and as the file's name: holds it.
	Name string
	// Registry is Project or User.
	Registry string
	// Path is the absolute path of the contract file.
	Path string
	// Data are the file's bytes, read through the descriptor that was checked.
	Data []byte
	// file is that descriptor's stat, which says whether another registry's entry is this same file (notInUser).
	file fs.FileInfo
}

// Error is a refused resolution: what is wrong, the diagnostic code and the fix.
type Error struct {
	Code string
	// Path is the file the refusal is about, "" when it is about no one file.
	Path string
	What string
	Fix  string
	Err  error
}

func (e *Error) Error() string {
	if e.Fix == "" {
		return e.What
	}
	return e.What + "; " + e.Fix
}

func (e *Error) Unwrap() error { return e.Err }

// IsName says whether a command-line argument names an agent rather than a contract file: it is an agent id
// ([a-z0-9-]{1,40}), which holds no '/' and no '.', so no path to a .yaml file is one. "-" is standard input, never a
// name.
func IsName(arg string) bool {
	if arg == "-" {
		return false
	}
	_, err := identity.ParseAgentID(arg)
	return err == nil
}

// Resolve finds the contract of the agent named name in the one registry that holds it: the project registry is looked
// in first, then the user registry, and a name both hold (as two files) is agent-ambiguous, never the project's
// (agent-contract.md R26), as is a name the project holds twice or a file of that name in the working
// directory.
func (p Places) Resolve(name string) (*Entry, error) {
	if !IsName(name) {
		return nil, &Error{Code: CodeNotFound, What: fmt.Sprintf("%q is not an agent name ([a-z0-9-]{1,40})", name),
			Fix: "give an agent's name or the contract's path"}
	}
	p, perr := p.placed()
	if perr != nil {
		return nil, perr
	}
	// A file of the name could be the contract a path means; a directory (often the agent's own code) could not.
	if fi, err := os.Stat(filepath.Join(p.Dir, name)); p.Dir != "" && err == nil && !fi.IsDir() {
		return nil, &Error{Code: CodeAmbiguous, Path: filepath.Join(p.Dir, name),
			What: fmt.Sprintf("%s names an agent and a file in the working directory", name),
			Fix:  fmt.Sprintf("write ./%s to mean the file, or rename it to use the registry", name)}
	}
	var found []*Entry
	if e, err := p.projectFile(name); err != nil {
		return nil, err
	} else if e != nil {
		found = append(found, e)
	}
	if p.Dir != "" {
		e, err := entryIn(filepath.Join(p.Dir, ProjectDir), name, Project, p.UID)
		if err != nil {
			return nil, err
		}
		if e != nil {
			found = append(found, e)
		}
	}
	if len(found) == 2 && os.SameFile(found[0].file, found[1].file) {
		found = found[:1] // agent.yaml a link to its .tego/agents entry: one file, one contract
	}
	if len(found) == 2 {
		return nil, &Error{Code: CodeAmbiguous, Path: found[1].Path,
			What: fmt.Sprintf("the project registry holds %s twice: %s and %s", name, found[0].Path, found[1].Path),
			Fix:  "remove one of them, or give the contract's path"}
	}
	userPath := ""
	if p.User != "" {
		userPath = filepath.Join(p.User, AgentsDir, name+".yaml")
	}
	if len(found) == 1 {
		if err := p.notInUser(found[0], userPath); err != nil {
			return nil, err
		}
		return p.notOwn(found[0])
	}
	if p.User != "" {
		e, err := entryIn(p.User, name, User, p.UID)
		if err != nil {
			return nil, err
		}
		if e != nil {
			return p.notOwn(e)
		}
	}
	return nil, p.notFound(name, userPath)
}

// placed is p with Dir and User spelled where the kernel's walk of each lands (agent.WalkedPath): filepath.Clean's
// spelling unless a ".." follows a name in it. Every path the lookup opens, looks at and records is joined under
// these with filepath.Join, which cleans, and a ".." after a link then named another place than the one opened
// (registry: <dir>/lnk/../tego is opened beside lnk's target): the entry recorded named a file that does not exist,
// and the user registry's entry was looked for there, so a project entry of its name silently replaced it. A path
// with a ".." the walk cannot place (a link that does not resolve) is refused.
func (p Places) placed() (Places, *Error) {
	for _, s := range []*string{&p.Dir, &p.User} {
		if *s == "" {
			continue
		}
		w, ok := agent.WalkedPath(*s)
		if !ok {
			return p, &Error{Code: CodeEntry, Path: *s,
				What: fmt.Sprintf("the registry %s cannot be placed as the kernel walks it (a relative path, or a link before a \"..\" that does not resolve)", *s),
				Fix:  "set registry: to an absolute path without \"..\", or give the contract's path"}
		}
		*s = w
	}
	return p, nil
}

// notInUser refuses a project entry whose name the user registry holds too: anything at userPath, an entry that would
// itself be refused included, or a userPath that cannot be looked at (a link loop, an unreadable directory). A project
// entry never silently replaces the user's: an agent run from the user registry with a write over its working
// directory could plant .tego/agents/<name>.yaml there, and the next run of the name would run the planted contract.
// Which file is meant is the user's to say, by its path. Only a userPath that is not there (or whose directory is no
// directory) leaves the project entry the answer, or one the user registry resolves, as it would for the name, to
// the very file the project entry was read from (registry: set to the project's .tego, or a link to it): one file is
// one contract, and there is nothing to remove or rename.
func (p Places) notInUser(e *Entry, userPath string) *Error {
	if userPath == "" {
		return nil
	}
	_, err := os.Lstat(userPath)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil
	}
	if err == nil {
		if u, uerr := entryIn(p.User, e.Name, User, p.UID); uerr == nil && u != nil && os.SameFile(u.file, e.file) {
			return nil
		}
	}
	if err != nil {
		return &Error{Code: CodeEntry, Path: userPath,
			What: fmt.Sprintf("the project registry holds %s (%s), and the user registry's %s cannot be looked at: %v", e.Name, e.Path, userPath, err),
			Fix:  "fix the user registry, or give the path of the one you mean", Err: err}
	}
	return &Error{Code: CodeAmbiguous, Path: e.Path,
		What: fmt.Sprintf("both registries hold %s: the project's %s and the user's %s, and a project entry never replaces the user's",
			e.Name, e.Path, userPath),
		Fix: fmt.Sprintf("give the path of the one you mean (%s, or %s), or remove or rename one of them", relProject(p.Dir, e.Path), userPath)}
}

// relProject is a project entry's path relative to the working directory, for a fix the user types there.
func relProject(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil && filepath.IsLocal(rel) {
		return "." + string(filepath.Separator) + rel
	}
	return path
}

// projectFile is the working directory's agent.yaml when its name: is name. The file is read for its name whoever
// wrote it, and trusted only once it is the one meant; a file whose name cannot be read is refused, since it may be
// the one meant and another registry's entry would then run in its place.
func (p Places) projectFile(name string) (*Entry, error) {
	if p.Dir == "" {
		return nil, nil
	}
	r, err := os.OpenRoot(p.Dir)
	if err != nil {
		return nil, &Error{Code: CodeEntry, Path: p.Dir, What: "the working directory cannot be read: " + err.Error(),
			Fix: "give the contract's path", Err: err}
	}
	defer func() { _ = r.Close() }()
	path := filepath.Join(p.Dir, ProjectFile)
	// Every name is refused while the file cannot be read, a user registry's too, and the fix says why:
	// an agent.yaml that is not tego's (another framework's, a link out of the directory) is in the way of them all.
	unreadable := fmt.Sprintf("while the working directory's %s cannot be read, no agent name resolves in this directory, "+
		"since it may be the one meant: fix it, rename or move %[1]s if it is not a tego contract, or give the contract's path",
		ProjectFile)
	f, fi, data, err := readEntry(r, ProjectFile, path, "the working directory")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		var e *Error
		if errors.As(err, &e) {
			e.Fix = "a project contract is a file inside the working directory, or a relative link that stays inside it; " + unreadable
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	got, err := nameOf(data)
	if err != nil {
		return nil, &Error{Code: CodeEntry, Path: path,
			What: fmt.Sprintf("the project's %s may be %s, and its name cannot be read: %v", ProjectFile, name, err),
			Fix:  unreadable, Err: err}
	}
	if got != name {
		return nil, nil
	}
	if err := config.CheckTrusted(f, path, p.UID); err != nil {
		return nil, untrustedError("registry entry", path, err)
	}
	return &Entry{Name: name, Registry: Project, Path: path, Data: data, file: fi}, nil
}

// entryIn is <root>/agents/<name>.yaml, nil when there is none. It is read through agents/ itself as an os.Root,
// opened through root as one, so neither a link nor "..", in the entry or in agents/, leads out of agents/ (ADR 0059):
// agents/ is what R10 keeps every write entry off, by every name on the way to it, and a link to elsewhere in the
// registry led to a file any run may write. The file, agents/ and root itself must be trusted, and the file has one
// name (config.CheckTrusted).
func entryIn(root, name, registry string, uid int) (*Entry, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &Error{Code: CodeEntry, Path: root, What: fmt.Sprintf("the %s registry %s cannot be read: %v", registry, root, err),
			Fix: "give the contract's path", Err: err}
	}
	defer func() { _ = r.Close() }()
	agentsPath := filepath.Join(root, AgentsDir)
	ar, err := r.OpenRoot(AgentsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, &Error{Code: CodeEntry, Path: agentsPath, What: fmt.Sprintf("the %s registry's %s cannot be read: %v", registry, agentsPath, err),
			Fix: fmt.Sprintf("make %s a directory in its registry, or give the contract's path", agentsPath), Err: err}
	}
	defer func() { _ = ar.Close() }()
	rel := name + ".yaml"
	path := filepath.Join(agentsPath, rel)
	f, fi, data, err := readEntry(ar, rel, path, AgentsDir+"/")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := config.CheckTrusted(f, path, uid); err != nil {
		return nil, untrustedError("registry entry", path, err)
	}
	for _, d := range []struct {
		r    *os.Root
		path string
	}{{ar, agentsPath}, {r, filepath.Clean(root)}} {
		df, err := d.r.Open(".")
		if err != nil {
			return nil, &Error{Code: CodeEntry, Path: d.path, What: err.Error(), Fix: "give the contract's path", Err: err}
		}
		err = config.CheckTrusted(df, d.path, uid)
		_ = df.Close()
		if err != nil {
			return nil, untrustedError("registry directory", d.path, err)
		}
	}
	got, err := nameOf(data)
	if err != nil {
		return nil, &Error{Code: CodeEntry, Path: path, What: fmt.Sprintf("%s holds no readable name: %v", path, err),
			Fix: fmt.Sprintf("write name: %q in it, or give the contract's path", name), Err: err}
	}
	if got != name {
		return nil, &Error{Code: CodeEntry, Path: path,
			What: fmt.Sprintf("%s is the %s registry's entry for %s, and its name: is %q", path, registry, name, got),
			Fix:  fmt.Sprintf("write name: %q in it, or rename it to %s.yaml", name, got)}
	}
	return &Entry{Name: name, Registry: registry, Path: path, Data: data, file: fi}, nil
}

// notOwn refuses an entry inside one of tego's own paths (Places.Own) that does not hold the working directory, each
// path compared as written and as its links resolve.
func (p Places) notOwn(e *Entry) (*Entry, error) {
	for _, o := range p.Own {
		if o == "" || within(o, p.Dir) {
			continue
		}
		if within(o, filepath.Dir(e.Path)) {
			return nil, &Error{Code: CodeEntry, Path: e.Path,
				What: fmt.Sprintf("%s is inside %s, which holds tego's own files and is read-denied to every run (agent-contract.md R6a); "+
					"a contract there would make it readable to the agent", e.Path, o),
				Fix: "move the file, or the registry (registry: in the machine config), outside it"}
		}
	}
	return e, nil
}

// within says whether dir is ancestor or itself, compared as written and as the links of each resolve.
func within(ancestor, dir string) bool {
	if dir == "" {
		return false
	}
	as, ds := []string{filepath.Clean(ancestor)}, []string{filepath.Clean(dir)}
	if r, err := filepath.EvalSymlinks(ancestor); err == nil {
		as = append(as, r)
	}
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		ds = append(ds, r)
	}
	for _, a := range as {
		for _, d := range ds {
			if rel, err := filepath.Rel(a, d); err == nil && (rel == "." || filepath.IsLocal(rel)) {
				return true
			}
		}
	}
	return false
}

// readEntry opens rel under r as a contract is opened (agent.OpenFlags) and reads it under the contract's cap. A
// registry entry is a regular file: a FIFO or a socket there names nothing. A missing file is an error wrapping
// fs.ErrNotExist; a link that leaves r (inside, as the refusal names it) is refused, not passed over.
func readEntry(r *os.Root, rel, path, inside string) (*os.File, fs.FileInfo, []byte, error) {
	f, err := r.OpenFile(rel, agent.OpenFlags, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil, err
		}
		return nil, nil, nil, &Error{Code: CodeEntry, Path: path, What: fmt.Sprintf("%s cannot be read: %v", path, err),
			Fix: fmt.Sprintf("a registry entry is a file inside %s, or a relative link that stays inside %[1]s; copy the contract there, "+
				"or give the contract's path", inside), Err: err}
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("it is a %s, not a regular file", kind(fi.Mode()))
	}
	var data []byte
	if err == nil {
		data, err = agent.ReadCapped(f, path)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, nil, &Error{Code: CodeEntry, Path: path, What: fmt.Sprintf("%s cannot be read: %v", path, err),
			Fix: "give the contract's path", Err: err}
	}
	return f, fi, data, nil
}

// kind names a file mode's type for a refusal.
func kind(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "directory"
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeDevice != 0:
		return "device"
	}
	return "special file"
}

// nameOf is a contract's top-level name:, read without loading the contract: the name is the top-level file's own
// (an extends: profile cannot set it), and the full load is the caller's, on the same bytes.
func nameOf(data []byte) (string, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var doc struct {
		Name string `yaml:"name"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return "", err
	}
	if doc.Name == "" {
		return "", errors.New("it has no name field")
	}
	return doc.Name, nil
}

// untrustedError is a refused entry, or a directory of its registry, whose owner or mode fails config.CheckTrusted;
// what is the thing at path ("registry entry", "registry directory"). It says what failed in the registry's words:
// config.UntrustedError's own text names the machine config, which this is not.
func untrustedError(what, path string, err error) *Error {
	text := what + " untrusted: " + err.Error()
	fix := "a registry entry, and its registry's directories, must be owned by you or root and not group- or other-writable; " +
		"fix the owner or mode (chmod go-w), or give the contract's path"
	var ue *config.UntrustedError
	if errors.As(err, &ue) {
		text = fmt.Sprintf("%s untrusted: %s uid=%d mode=%04o (%s)", what, ue.Path, ue.Owner, ue.Mode&fs.ModePerm, ue.Reason)
		if ue.Names > 1 {
			fix = "a registry entry has one name, so no write entry can reach it through another (ADR 0059); " +
				strings.ToLower(ue.Fix()[:1]) + ue.Fix()[1:]
		}
	}
	return &Error{Code: CodeUntrusted, Path: path, What: text, Fix: fix, Err: err}
}

// notFound is the refusal of a name no registry holds: the files that would hold it, and the names that are there.
func (p Places) notFound(name, userPath string) *Error {
	where := []string{filepath.Join(p.Dir, ProjectDir, AgentsDir, name+".yaml")}
	if userPath != "" {
		where = append(where, userPath)
	}
	names := p.Names()
	what := fmt.Sprintf("no agent named %s in the project registry (%s, %s) or the user registry", name,
		filepath.Join(p.Dir, ProjectFile), filepath.Join(p.Dir, ProjectDir, AgentsDir))
	if p.User == "" {
		what = fmt.Sprintf("no agent named %s in the project registry (%s, %s); no user registry is configured", name,
			filepath.Join(p.Dir, ProjectFile), filepath.Join(p.Dir, ProjectDir, AgentsDir))
	} else {
		what += " (" + filepath.Join(p.User, AgentsDir) + ")"
	}
	if len(names) > 0 {
		what += "; the names there: " + strings.Join(names, ", ")
	}
	return &Error{Code: CodeNotFound, What: what,
		Fix: "create " + strings.Join(where, " or ") + " with name: " + name + ", or give the contract's path", Err: fs.ErrNotExist}
}

// maxNames bounds the names a not-found refusal lists.
const maxNames = 20

// Names lists the names the registries hold, sorted, at most maxNames: the project's agent.yaml's name and the
// entries of both agents/ directories. It is for a refusal's fix, so it reads names only from file names, and the
// project file's name: as Resolve does; nothing it lists is checked or resolved.
func (p Places) Names() []string {
	var out, dirs []string
	p, perr := p.placed()
	if perr != nil {
		return nil
	}
	if p.Dir != "" {
		dirs = append(dirs, filepath.Join(p.Dir, ProjectDir, AgentsDir))
		if r, err := os.OpenRoot(p.Dir); err == nil {
			if f, _, data, err := readEntry(r, ProjectFile, filepath.Join(p.Dir, ProjectFile), "the working directory"); err == nil {
				if n, err := nameOf(data); err == nil && IsName(n) {
					out = append(out, n)
				}
				_ = f.Close()
			}
			_ = r.Close()
		}
	}
	if p.User != "" {
		dirs = append(dirs, filepath.Join(p.User, AgentsDir))
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if n, ok := strings.CutSuffix(e.Name(), ".yaml"); ok && IsName(n) {
				out = append(out, n)
			}
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxNames {
		out = append(out[:maxNames], "...")
	}
	return out
}
