// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
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
			text, err := os.ReadFile(path)
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
				_ = os.WriteFile(keep, edited, 0o600)
				fmt.Fprintf(stdout, "✗ Not saved: the rules have errors (above). %s is unchanged; your edit is in %s\n", path, keep)
				return identity.ExitFinding
			}
			if err := writeOver(path, edited); err != nil {
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

// writeOver replaces path's contents with text, keeping its mode: a new file beside it, renamed over it.
func writeOver(path string, text []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp := path + ".tego-edit"
	if err := os.WriteFile(tmp, text, st.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chmod(tmp, st.Mode().Perm()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// checkRules compiles a rules file's text as the file at path, the way tego learn --save checks what it saves and
// tego compile --offline checks a file, and prints its errors.
func checkRules(ctx context.Context, m *config.Machine, path string, text []byte, stderr io.Writer) error {
	c, ds, err := agent.LoadBytes(path, text, profileSources(m))
	if err == nil {
		_, ds, err = agent.Compile(c, m, append(learnCompileOptions(ctx, m), agent.Offline())...)
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
