// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// cmdRulesEdit is `tego rules edit <agent | file>`: it opens a copy of the rules file in $VISUAL or $EDITOR (vi when
// neither is set), checks the copy as tego run will compile it, and writes it back only when it passes, so a mistake
// never leaves an agent that tego run refuses.
func cmdRulesEdit() Command {
	return Command{
		Name:    "rules edit",
		Summary: "edit a rules file, then check it",
		Usage:   "<agent | file>",
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego rules edit: give the agent or the rules file: tego rules edit <agent | file>", codeUsage)
				return identity.ExitUsage
			}
			m := verbMachine("rules edit", stderr)
			if m == nil {
				return identity.ExitError
			}
			ref, rerr := resolveContract(fs.Arg(0), false, m)
			if rerr != nil {
				printRefusedName(stderr, "tego rules edit", rerr)
				return identity.ExitUsage
			}
			path := ref.label()
			original, err := os.Lstat(path)
			if err == nil && !original.Mode().IsRegular() {
				err = errors.New("rules file must be a regular file, not a link")
			}
			var text []byte
			if err == nil {
				text, err = readRulesPath(path)
			}
			if err != nil {
				message(stderr, path, 0, 0, "tego rules edit: "+err.Error(), codeIO)
				return identity.ExitError
			}
			edited, code := editCopy(path, text, stderr)
			if edited == nil {
				return code
			}
			if string(edited) == string(text) {
				fmt.Fprintf(stdout, "✓ No changes to %s\n", path)
				return identity.ExitOK
			}
			if err := checkRules(ctx, m, path, edited, stderr); err != nil {
				keep := path + ".rejected"
				if err := atomicRulesWrite(keep, edited, 0o600, nil); err != nil {
					message(stderr, keep, 0, 0, "tego rules edit: could not keep the rejected edit: "+err.Error(), codeIO)
					return identity.ExitError
				}
				fmt.Fprintf(stdout, "✗ Not saved: the rules have errors (above). %s is unchanged; your edit is in %s\n", path, keep)
				return identity.ExitFinding
			}
			return saveEdit(ctx, m, path, edited, original, text, stdout, stderr)
		},
	}
}

// editSummary is the journal's words for a whole-text edit: the dashboard's free edit, so the history lists both in one wording.
const editSummary = "free edit of the whole text"

// editGuard is where `tego rules edit` journals an edit: the machine's ledger root holds the change journal (the one
// the dashboard and tego rules history read), and that root and tego's home are not places a contract may be changed.
// "" as the root journals nothing.
func editGuard(m *config.Machine) (rulefile.Guard, string) {
	root, err := ledgerRootOf(m)
	if err != nil || root == "" {
		return rulefile.Guard{}, "the ledger root is not known here"
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return rulefile.Guard{}, "the ledger root " + root + " does not exist yet"
	}
	g := rulefile.DefaultGuard(root)
	g.Refuse = append(g.Refuse, root)
	if m.Home != "" {
		g.Refuse = append(g.Refuse, filepath.Join(m.Home, ".tego"))
	}
	return g, ""
}

// saveEdit writes the checked edit over the file the editor was opened on and says so. The write goes through the one
// writer the dashboard uses (rulefile.Replace: the same guards, the old text kept as <file>.bak, one journal line via
// "cli"), so the edit is in the change history and tego rules undo can give the old text back. A file the writer's
// guards refuse (not yours alone, a link, under tego's own folders) or a machine with no ledger root yet is still
// saved as before, and the output says that the edit is not in the history and cannot be undone: the limit is stated,
// never silent.
func saveEdit(ctx context.Context, m *config.Machine, path string, edited []byte, original os.FileInfo, text []byte, stdout, stderr io.Writer) int {
	abs, err := filepath.Abs(path)
	if err != nil {
		message(stderr, path, 0, 0, "tego rules edit: "+err.Error(), codeIO)
		return identity.ExitError
	}
	g, why := editGuard(m)
	if why == "" {
		if _, err := rulefile.Read(abs, g); err != nil {
			why = "the writer that keeps the history refuses this file: " + err.Error()
		}
	}
	if why != "" {
		if err := writeOverUnchanged(path, edited, original, text); err != nil {
			message(stderr, path, 0, 0, "tego rules edit: "+err.Error(), codeIO)
			return identity.ExitError
		}
		fmt.Fprintf(stdout, "✓ Saved and checked %s\n", path)
		fmt.Fprintf(stdout, "Not in the change history, so tego rules undo cannot give the old text back (%s); the old text was not kept.\n", record.Printable(why))
		return identity.ExitOK
	}
	e, err := rulefile.Replace(ctx, g, abs, rulefile.Sum(text), edited,
		rulefile.Change{Via: "cli", Summary: editSummary, Direction: string(rule.Mixed)})
	switch {
	case errors.Is(err, rulefile.ErrStale):
		message(stderr, path, 0, 0, "tego rules edit: the rules file changed while the editor was open; nothing was saved", codeIO)
		return identity.ExitError
	case errors.Is(err, rulefile.ErrJournal) && e != nil:
		fmt.Fprintf(stdout, "✓ Saved and checked %s\n", path)
		message(stderr, path, 0, 0, "tego rules edit: "+record.Printable(err.Error())+"; the edit is not in the change history, so tego rules undo cannot undo it", codeIO)
		return identity.ExitError
	case err != nil:
		message(stderr, path, 0, 0, "tego rules edit: "+record.Printable(err.Error()), codeIO)
		return identity.ExitError
	}
	fmt.Fprintf(stdout, "✓ Saved and checked %s\n", path)
	fmt.Fprintf(stdout, "Recorded in the change history as %s; the old text is %s.\n"+
		"tego rules undo %s gives it back (history and undo list a rules file once a run here has run it).\n",
		record.Printable(e.ID), record.Printable(e.Bak), shellQuote(path))
	return identity.ExitOK
}

// editCopy opens a copy of text in the person's editor and returns what they saved; nil after printing why not.
func editCopy(path string, text []byte, stderr io.Writer) ([]byte, int) {
	dir, err := os.MkdirTemp("", "tego-edit-")
	if err != nil {
		message(stderr, "", 0, 0, "tego rules edit: "+err.Error(), codeIO)
		return nil, identity.ExitError
	}
	defer func() { _ = os.RemoveAll(dir) }()
	tmp := filepath.Join(dir, filepath.Base(path))
	if err := os.WriteFile(tmp, text, 0o600); err != nil {
		message(stderr, "", 0, 0, "tego rules edit: "+err.Error(), codeIO)
		return nil, identity.ExitError
	}
	editorVar := "VISUAL"
	editor := strings.Fields(os.Getenv("VISUAL"))
	if len(editor) == 0 {
		editorVar = "EDITOR"
		editor = strings.Fields(os.Getenv("EDITOR"))
	}
	if len(editor) == 0 {
		editorVar = "" // neither is set: vi is tried, and no variable is to blame for it
		editor = []string{"vi"}
	}
	cmd := proc.Command(editor[0], append(editor[1:], tmp)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	_, err = proc.Start(cmd)
	if err == nil {
		err = cmd.Wait()
	}
	if err != nil {
		// The editor's command line comes from the person's environment and may hold anything, so it is never
		// printed: the message names the variable, or says that vi was tried when neither is set, and gives the
		// cause (pkg/spec/identity envtext.go, rule (b)).
		asked, inspect := "vi, the editor tried when neither VISUAL nor EDITOR is set,", ""
		if editorVar != "" {
			asked, inspect = "the editor $"+editorVar+" names", "; "+identity.EnvInspect(editorVar)
		}
		message(stderr, "", 0, 0, fmt.Sprintf("tego rules edit: %s %s%s; nothing was saved", asked, editorFailure(err), inspect), codeIO)
		return nil, identity.ExitError
	}
	edited, err := readRulesPath(tmp)
	if err != nil {
		message(stderr, "", 0, 0, "tego rules edit: "+err.Error(), codeIO)
		return nil, identity.ExitError
	}
	return edited, identity.ExitOK
}

// writeOverUnchanged replaces only the version opened before the editor, keeping its mode.
func writeOverUnchanged(path string, text []byte, original os.FileInfo, before []byte) error {
	return atomicRulesWrite(path, text, original.Mode().Perm(), func() error {
		now, err := os.Lstat(path)
		if err != nil {
			return err
		}
		data, err := readRulesPath(path)
		if err != nil {
			return err
		}
		if !os.SameFile(original, now) || !now.ModTime().Equal(original.ModTime()) || !bytes.Equal(data, before) {
			return errors.New("the rules file changed while the editor was open; nothing was saved")
		}
		return nil
	})
}

// atomicRulesWrite publishes only a complete file. Neither a planted destination link nor the old predictable
// .tego-edit name is followed. The final check detects an edit made while the editor was open.
func atomicRulesWrite(path string, text []byte, mode os.FileMode, check func() error) error {
	regular := func() error {
		st, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return errors.New("destination must be a regular file, not a link")
		}
		return nil
	}
	if err := regular(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tego-edit-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer func() { _ = f.Close() }() // retain the created inode through publication; Sync reports write failures
	if _, err = f.Write(text); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	if err := regular(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	held, err := f.Stat()
	if err != nil {
		return err
	}
	published, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(held, published) {
		return errors.New("the rules file changed underneath publication; check it before running")
	}
	return nil
}

// checkRules compiles a rules file's text as the file at path, the way tego learn --save checks what it saves and
// tego compile --offline checks a file, and prints its errors.
func checkRules(ctx context.Context, m *config.Machine, path string, text []byte, stderr io.Writer, more ...agent.CompileOption) error {
	c, ds, err := agent.LoadBytes(path, text, profileSources(m))
	if err == nil {
		_, ds, err = agent.Compile(c, m, append(append(learnCompileOptions(ctx, m), agent.Offline()), more...)...)
	}
	if err != nil {
		if errs := slices.DeleteFunc(ds, func(d agent.Diagnostic) bool { return d.Severity != agent.SeverityError }); len(errs) > 0 {
			_ = agent.WriteDiagnostics(stderr, errs)
		} else {
			message(stderr, path, 0, 0, err.Error(), agent.CodeSchema)
		}
	}
	return err
}

// editorFailure says why an editor did not finish, without its command line: it was not found, it could not be
// started (with the system's reason, permission denied among them), it exited with a status, or a signal ended it.
func editorFailure(err error) string {
	// A finished process's state, as the error of a wait carries it (the standard library's exit error).
	var exit interface {
		ExitCode() int
		Sys() any
	}
	if errors.As(err, &exit) {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return "was ended by signal " + strconv.Itoa(int(ws.Signal())) + " (" + ws.Signal().String() + ")"
		}
		return "exited with status " + strconv.Itoa(exit.ExitCode())
	}
	var errno syscall.Errno
	switch {
	case proc.NotFound(err):
		return "was not found"
	case errors.Is(err, fs.ErrPermission):
		return "could not be started: permission denied"
	case errors.As(err, &errno):
		return "could not be started: " + errno.Error()
	}
	return "could not be started"
}
