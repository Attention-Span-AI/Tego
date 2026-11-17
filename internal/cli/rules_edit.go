// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
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
				text, err = os.ReadFile(path)
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
			if err := writeOverUnchanged(path, edited, original, text); err != nil {
				message(stderr, path, 0, 0, "tego rules edit: "+err.Error(), codeIO)
				return identity.ExitError
			}
			fmt.Fprintf(stdout, "✓ Saved and checked %s\n", path)
			return identity.ExitOK
		},
	}
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
	editor := strings.Fields(os.Getenv("VISUAL"))
	if len(editor) == 0 {
		editor = strings.Fields(os.Getenv("EDITOR"))
	}
	if len(editor) == 0 {
		editor = []string{"vi"}
	}
	cmd := proc.Command(editor[0], append(editor[1:], tmp)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	_, err = proc.Start(cmd)
	if err == nil {
		err = cmd.Wait()
	}
	if err != nil {
		message(stderr, "", 0, 0, fmt.Sprintf("tego rules edit: the editor %s: %v; nothing was saved", editor[0], err), codeIO)
		return nil, identity.ExitError
	}
	edited, err := os.ReadFile(tmp)
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
		data, err := os.ReadFile(path)
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
