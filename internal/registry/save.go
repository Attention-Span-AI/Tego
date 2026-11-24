// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
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
	// ExpectedDirectory binds creation to the directory reviewed by the caller.
	ExpectedDirectory *DirectoryIdentity
	// BeforePublish repeats caller review checks after the temporary file is synced.
	BeforePublish func() error
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
	// removed again. A cleanup failure is SaveIO instead, reporting what may remain.
	SaveUnusable
)

// SaveError is a refused Save. A post-publication failure explicitly says that
// the complete file exists; a failure before publication leaves no new contract.
type SaveError struct {
	Step SaveStep
	// Path is the file or directory the refusal is about; Dir the folder of From the name was looked up from.
	Path, Dir string
	// Write is the fs.write entry the file would lie inside (SaveInsideWrite).
	Write string
	// Entry is the contract the name already is (SaveTaken with a registry's answer).
	Entry *Entry
	// Op is what failed for SaveIO; nested errors name the exact publication step.
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
		var nf interface{ NotFinishedWords() string }
		if errors.As(e.Err, &nf) {
			return nf.NotFinishedWords() + "; nothing was written; try again"
		}
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

// Write checks and compiles the entry, then publishes a synced 0600 file beneath
// a pinned directory descriptor. Registry and agents are opened without links;
// standalone saves retain linked-ancestor compatibility, while reviewed writes
// use the strict no-link walk from the root.
// Publication never replaces a file or link. It syncs the final directory.
// A post-publication directory-sync error says that the complete file exists.
func (s Save) Write() (string, error) {
	return s.WriteContext(context.Background())
}

// WriteContext is Write with cancellation checks before path work and each new write.
// Reads and compilation which resume after cancellation cannot create a new entry.
// A filesystem mutation already submitted can still have an uncertain outcome.
func (s Save) WriteContext(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path, err := s.Check()
	if err != nil {
		return path, err
	}
	if err := ctx.Err(); err != nil {
		return path, err
	}
	if s.Compile != nil {
		if err := s.Compile(path, s.Text); err != nil {
			return path, &SaveError{Step: SaveNoCompile, Path: path, Err: err}
		}
	}
	agents := filepath.Dir(path)
	placement := agents
	if s.ExpectedDirectory == nil {
		// TODO(next9): the builder's no-link rule for every ancestor is not
		// applied to standalone saves; retain b68fbcab6 parent-link compatibility.
		parent, err := saveParent(ctx, filepath.Dir(s.Places.User))
		if err != nil {
			return path, &SaveError{Step: SaveIO, Op: "open-directory", Path: agents, Err: err}
		}
		placement = filepath.Join(parent, filepath.Base(s.Places.User), AgentsDir)
	}
	dir, err := OpenDirectoryContext(ctx, placement, true)
	if err != nil {
		return path, &SaveError{Step: SaveIO, Op: "open-directory", Path: agents, Err: err}
	}
	defer func() { _ = dir.Close() }() // Directory was synced by Write; no buffered writes remain.
	rel := s.Name + ".yaml"
	if err := dir.Write(rel, s.Text, WriteOptions{Context: ctx, Mode: 0o600, ExpectedDirectory: s.ExpectedDirectory, BeforePublish: s.BeforePublish}); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return path, &SaveError{Step: SaveExists, Path: path, Err: err}
		}
		// Keep the established write operation: callers must not append a claim
		// that nothing was written after a post-publication sync failure.
		return path, &SaveError{Step: SaveIO, Op: "write", Path: path, Err: err}
	}
	places := s.Places
	for _, d := range s.From {
		places.Dir = d
		if _, err := places.Resolve(s.Name); err != nil {
			cleanupErr := dir.fd.Borrow(func(n int) error {
				e := publicationStep("unusable-remove")
				if e == nil {
					e = unix.Unlinkat(n, rel, 0)
				}
				if e != nil {
					return fmt.Errorf("unusable-remove: complete %s may remain: %w", rel, e)
				}
				if e := unix.Fsync(n); e != nil {
					return fmt.Errorf("unusable-directory-sync: removal of %s could not be synced: %w", rel, e)
				}
				return nil
			})
			if cleanupErr != nil {
				return path, &SaveError{Step: SaveIO, Op: "write", Path: path, Dir: d, Err: errors.Join(err, cleanupErr)}
			}
			return path, &SaveError{Step: SaveUnusable, Path: path, Dir: d, Err: err}
		}
	}
	return path, nil
}

// saveParent resolves existing ancestors only. Registry and agents themselves
// are subsequently opened without links; reviewed dashboard saves skip this
// compatibility path and keep the strict descriptor walk from the root.
func saveParent(ctx context.Context, path string) (string, error) {
	var missing []string
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err == nil {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, fs.ErrNotExist) || path == string(filepath.Separator) {
			return "", err
		}
		missing = append(missing, filepath.Base(path))
		path = filepath.Dir(path)
	}
}
