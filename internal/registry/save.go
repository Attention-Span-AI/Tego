// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Save is one new entry of the user registry: the contract Text, whose name: is Name, written as
// <Places.User>/agents/<Name>.yaml, where `tego run <Name>` and the tego-agent@<Name> unit find it. It is the
// registry's one writer: `tego learn --save` and the dashboard's "Make a contract from this run" both write through it,
// so the two write in the same place, the same way, and refuse the same things. Text is each caller's: for one run
// the two differ only in the header's leaks: line, which the dashboard's draft leaves to the run's verdict
// (TestLearnSaveAndTheDashboardSaveTheSameFile in internal/cli).
type Save struct {
	// Places are the registries the name is looked up in; Dir is set to each folder of From in turn.
	Places Places
	// From are the folders the name must be free from: where `tego run <Name>` will be typed (the run's own folder,
	// and for the command line the folder it is typed in). None looks nothing up.
	From []string
	// Name is the agent's name, Text the contract.
	Name string
	Text []byte
	// Writes are the contract's own fs.write entries: tego refuses to run a contract its agent could rewrite, so an
	// entry inside one of them is refused before anything is written.
	Writes []string
	// Compile checks Text as the file at path, as `tego run <Name>` will compile it; nil checks nothing. An error is a
	// refusal (SaveNoCompile) and nothing is written.
	Compile func(path string, text []byte) error
}

// SaveStep is the check that refused a Save.
type SaveStep int

// The steps of a Save, in the order they are checked.
const (
	// SaveName: the name is not an agent name, or it starts with -, which tego run reads as a flag.
	SaveName SaveStep = iota + 1
	// SaveNoRegistry: the machine config names no user registry directory (an absolute path).
	SaveNoRegistry
	// SaveTaken: a registry resolves the name already from a folder of From (Entry is that contract), tego run would
	// find it ambiguous there, or the registry cannot say whether it is free (Err says why).
	SaveTaken
	// SaveInsideWrite: the file would lie inside one of the contract's own fs.write entries (Write).
	SaveInsideWrite
	// SaveNoCompile: Compile refused the contract.
	SaveNoCompile
	// SaveExists: a file, or a link, is at the entry's path already.
	SaveExists
	// SaveIO: making the folder, or creating or writing the file, failed (Op says which).
	SaveIO
	// SaveUnusable: written, the entry is not one tego run <name> would use from a folder of From (Dir); it was
	// removed again.
	SaveUnusable
)

// SaveError is a refused Save. Nothing is left written.
type SaveError struct {
	Step SaveStep
	// Path is the file or directory the refusal is about; Dir the folder of From the name was looked up from.
	Path, Dir string
	// Write is the fs.write entry the file would lie inside (SaveInsideWrite).
	Write string
	// Entry is the contract the name already is (SaveTaken with a registry's answer).
	Entry *Entry
	// Op is what failed for SaveIO: "mkdir", "create" or "write".
	Op  string
	Err error
}

func (e *SaveError) Error() string {
	switch e.Step {
	case SaveName:
		return e.Err.Error()
	case SaveNoRegistry:
		return fmt.Sprintf("the machine config names no user registry directory (registry: %q)", e.Path)
	case SaveTaken:
		var re *Error
		switch {
		case e.Entry != nil:
			return fmt.Sprintf("the agent name is already the contract %s", e.Entry.Path)
		case errors.As(e.Err, &re) && re.Code == CodeAmbiguous:
			return "the agent name is taken: " + e.Err.Error()
		}
		return "the registry cannot say whether the agent name is free: " + e.Err.Error()
	case SaveInsideWrite:
		return fmt.Sprintf("%s would lie inside the contract's own fs.write entry %q, which tego refuses to run", e.Path, e.Write)
	case SaveNoCompile:
		return "the contract does not compile here (" + e.Err.Error() + ")"
	case SaveExists:
		return e.Path + " exists already, and a contract is never written over a file"
	case SaveIO:
		return e.Op + " " + e.Path + ": " + e.Err.Error()
	case SaveUnusable:
		return "tego run in " + e.Dir + " would refuse " + e.Path + ": " + e.Err.Error()
	}
	return "the registry entry was not saved"
}

func (e *SaveError) Unwrap() error { return e.Err }

// Path is the file the entry is written as: <Places.User>/agents/<Name>.yaml. It refuses a name that is not an agent
// name or starts with - (SaveName), and a user registry that is not an absolute path (SaveNoRegistry). A name holds no
// '/' and no '.', so the file is always a direct child of agents/.
func (s Save) Path() (string, error) {
	switch {
	case !IsName(s.Name):
		return "", &SaveError{Step: SaveName, Err: fmt.Errorf("%q is not an agent name: lower-case letters, digits and -, at most 40", s.Name)}
	case strings.HasPrefix(s.Name, "-"):
		return "", &SaveError{Step: SaveName, Err: fmt.Errorf("%q starts with -, which tego run reads as a flag: give a name that starts "+
			"with a letter or a digit", s.Name)}
	case s.Places.User == "" || !filepath.IsAbs(s.Places.User):
		return "", &SaveError{Step: SaveNoRegistry, Path: s.Places.User}
	}
	return filepath.Join(s.Places.User, AgentsDir, s.Name+".yaml"), nil
}

// Check is every refusal Write makes before it compiles and writes, and the file's path: the name, the registry, the
// name free from each folder of From, and the file outside the contract's own fs.write entries. It writes nothing, so a
// preview can say what Write would refuse.
func (s Save) Check() (string, error) {
	path, err := s.Path()
	if err != nil {
		return "", err
	}
	places := s.Places
	for _, d := range s.From {
		places.Dir = d
		e, err := places.Resolve(s.Name)
		var re *Error
		switch {
		case err == nil:
			return path, &SaveError{Step: SaveTaken, Path: e.Path, Dir: d, Entry: e}
		case errors.As(err, &re) && re.Code == CodeNotFound:
		case errors.As(err, &re):
			return path, &SaveError{Step: SaveTaken, Path: re.Path, Dir: d, Err: err}
		default:
			return path, &SaveError{Step: SaveTaken, Dir: d, Err: err}
		}
	}
	dir := filepath.Dir(path)
	for _, w := range s.Writes {
		if w = strings.TrimSuffix(w, "/"); w != "" && (dir == w || strings.HasPrefix(dir, w+"/")) {
			return path, &SaveError{Step: SaveInsideWrite, Path: path, Write: w}
		}
	}
	return path, nil
}

// Write checks the entry (Check), compiles it (Compile), and creates the file, mode 0600, never over a file or a link,
// with the registry's directory and its agents/ made 0700 when missing. agents/ is opened as an os.Root inside the
// registry's directory, as Resolve reads it, so a link at agents/ that leads out of the registry is refused, never
// followed, and the file is created in it with O_EXCL, which a link at the file's name fails. The entry is then
// resolved from each folder of From as tego run <name> will: one that would be refused there (a registry inside a
// directory of tego's own, R6a) is removed again. It returns the file's path; a refusal is a *SaveError, with nothing
// left written.
func (s Save) Write() (string, error) {
	path, err := s.Check()
	if err != nil {
		return path, err
	}
	if s.Compile != nil {
		if err := s.Compile(path, s.Text); err != nil {
			return path, &SaveError{Step: SaveNoCompile, Path: path, Err: err}
		}
	}
	user := s.Places.User
	agents := filepath.Dir(path)
	if err := os.MkdirAll(user, 0o700); err != nil {
		return path, &SaveError{Step: SaveIO, Op: "mkdir", Path: user, Err: err}
	}
	root, err := os.OpenRoot(user)
	if err != nil {
		return path, &SaveError{Step: SaveIO, Op: "mkdir", Path: user, Err: err}
	}
	defer func() { _ = root.Close() }()
	if err := root.Mkdir(AgentsDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return path, &SaveError{Step: SaveIO, Op: "mkdir", Path: agents, Err: err}
	}
	ar, err := root.OpenRoot(AgentsDir)
	if err != nil {
		return path, &SaveError{Step: SaveIO, Op: "mkdir", Path: agents, Err: err}
	}
	defer func() { _ = ar.Close() }()
	rel := s.Name + ".yaml"
	f, err := ar.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return path, &SaveError{Step: SaveExists, Path: path, Err: err}
		}
		return path, &SaveError{Step: SaveIO, Op: "create", Path: path, Err: err}
	}
	_, err = f.Write(s.Text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = ar.Remove(rel)
		return path, &SaveError{Step: SaveIO, Op: "write", Path: path, Err: err}
	}
	places := s.Places
	for _, d := range s.From {
		places.Dir = d
		if _, err := places.Resolve(s.Name); err != nil {
			_ = ar.Remove(rel)
			return path, &SaveError{Step: SaveUnusable, Path: path, Dir: d, Err: err}
		}
	}
	return path, nil
}
