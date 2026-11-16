// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdApply) }

// nameLine is a rules file's top-level name: line.
var nameLine = regexp.MustCompile(`(?m)^name:.*$`)

// cmdApply is `tego apply -f <file.yaml> [--name <n>]`: it checks a rules file as tego compile --offline would and
// saves it as an agent, where tego run <name> finds it, through registry.Save, the writer tego learn --save uses. An
// agent of that name saved before is replaced, and kept as it was when the new file is refused.
func cmdApply() Command {
	var file, name string
	return Command{
		Name:    "apply",
		Summary: "add or update an agent from a rules file",
		Usage:   "-f <file.yaml> [--name <n>]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&file, "f", "", "the rules file")
			fs.StringVar(&name, "name", "", "the agent's name (default: the file's name:, else its file name)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if file == "" || fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego apply: give the rules file: tego apply -f <file.yaml> [--name <n>]", codeUsage)
				return identity.ExitUsage
			}
			m := verbMachine("apply", stderr)
			if m == nil {
				return identity.ExitError
			}
			text, err := os.ReadFile(file)
			if err != nil {
				message(stderr, file, 0, 0, "tego apply: "+err.Error(), codeIO)
				return identity.ExitError
			}
			c, ds, err := agent.LoadBytes(file, text, profileSources(m))
			if err != nil {
				_ = agent.WriteDiagnostics(stderr, ds)
				message(stderr, file, 0, 0, "tego apply: ✗ the rules file does not load ("+err.Error()+"); nothing was saved", agent.CodeSchema)
				return identity.ExitFinding
			}
			if name == "" {
				name = c.Name
			}
			if name == "" {
				name = strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
			}
			if name != c.Name {
				text = []byte(nameLine.ReplaceAllLiteralString(string(text), "name: "+name))
			}
			places, rerr := registryPlaces(m)
			if rerr != nil {
				printRefusedName(stderr, "tego apply", rerr)
				return identity.ExitError
			}
			var writes []string
			if c.FS != nil {
				for _, w := range c.FS.Write {
					switch {
					case strings.HasPrefix(w, "~/"):
						w = filepath.Join(m.Home, w[2:])
					case !filepath.IsAbs(w):
						w = filepath.Join(places.Dir, w)
					}
					writes = append(writes, w)
				}
			}
			sv := registry.Save{Places: places, From: []string{places.Dir}, Name: name, Text: text, Writes: writes,
				Compile: func(path string, text []byte) error { return checkRules(ctx, m, path, text, stderr) }}
			path, err := applySave(sv)
			if err != nil {
				return applyRefused(stderr, path, name, err)
			}
			fmt.Fprintf(stdout, "✓ Agent %s configured: %s\n", name, path)
			return identity.ExitOK
		},
	}
}

// applySave writes sv. An agent of its name saved for this user before is replaced: the new file is checked first,
// and the old one is written back when the new one is refused.
func applySave(sv registry.Save) (string, error) {
	path, err := sv.Path()
	if err != nil {
		return path, err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return sv.Write() // a new agent
	}
	if err := sv.Compile(path, sv.Text); err != nil {
		return path, &registry.SaveError{Step: registry.SaveNoCompile, Path: path, Err: err}
	}
	if err := os.Remove(path); err != nil {
		return path, &registry.SaveError{Step: registry.SaveIO, Op: "write", Path: path, Err: err}
	}
	written, err := sv.Write()
	if err != nil {
		back := registry.Save{Places: registry.Places{User: sv.Places.User}, Name: sv.Name, Text: old}
		if _, berr := back.Write(); berr != nil {
			return path, fmt.Errorf("%w; and the agent saved before could not be written back: %v", err, berr)
		}
	}
	return written, err
}

// applyRefused prints why apply saved nothing, with learn --save's codes and exits.
func applyRefused(stderr io.Writer, path, name string, err error) int {
	var se *registry.SaveError
	if !errors.As(err, &se) {
		message(stderr, path, 0, 0, "tego apply: ✗ "+err.Error(), codeIO)
		return identity.ExitError
	}
	switch se.Step {
	case registry.SaveName:
		message(stderr, "", 0, 0, "tego apply: ✗ "+se.Err.Error(), codeUsage)
		return identity.ExitUsage
	case registry.SaveInsideWrite:
		message(stderr, path, 0, 0, fmt.Sprintf("tego apply: ✗ the rules file would be saved inside %s, a folder the agent may change, "+
			"and Tego never runs rules its agent could rewrite; nothing was saved", se.Write), agent.CodeContradiction)
		return identity.ExitFinding
	case registry.SaveNoCompile:
		message(stderr, path, 0, 0, "tego apply: ✗ the rules file has errors (above); nothing was saved", agent.CodeSchema)
		return identity.ExitFinding
	case registry.SaveTaken, registry.SaveExists, registry.SaveUnusable:
		message(stderr, path, 0, 0, fmt.Sprintf("tego apply: ✗ %s; nothing was saved; give another name with --name", se.Error()), codeExists)
		return identity.ExitFinding
	}
	message(stderr, path, 0, 0, "tego apply: ✗ "+se.Error()+"; nothing was saved", codeIO)
	return identity.ExitError
}
