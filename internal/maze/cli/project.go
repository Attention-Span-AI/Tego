// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// project is a project as the daily commands see it: where it is, its saved rules (the project's and the
// person's own) and whether they are still what the person approved.
type project struct {
	r        Report
	rules    []Rule
	setUp    bool
	approval scope.Approval
}

// openProject reads the project at dir without scanning it: the daily commands never look around, they only
// read what was saved.
func openProject(ctx context.Context, dir string) (project, error) {
	env, err := scan.FromOS()
	if err != nil {
		return project{}, err
	}
	r, err := buildReport(ctx, dir, env, false)
	if err != nil {
		return project{}, err
	}
	if msg := projectProblem(r.Workspace.Root, r.Home); msg != "" {
		return project{}, &projectError{msg}
	}
	rules, setUp, err := loadSaved(r)
	if err != nil {
		return project{}, err
	}
	r.personalLoaded = setUp
	p := project{r: r, rules: rules, setUp: setUp}
	if setUp {
		if p.approval, err = scope.CheckApproval(r.Home, r.Workspace.Root); err != nil {
			return project{}, err
		}
	}
	return p, nil
}

// counts is how many rules let Claude Code do something and how many stop it.
func counts(rules []Rule) (can, cant int) {
	for _, rl := range rules {
		if rl.Allow {
			can++
		} else {
			cant++
		}
	}
	return can, cant
}

// Status is `maze status --json`: the same facts as the line, for scripts.
type Status struct {
	Version  int    `json:"version"`
	Project  string `json:"project"`
	Path     string `json:"path"`
	SetUp    bool   `json:"set_up"`
	Approved bool   `json:"approved"`
	Can      int    `json:"can"`
	Cant     int    `json:"cant"`
	// Active is whether Maze enforces the rules now. It is false until `maze run` ships.
	Active bool `json:"active"`
	// Error says why the project's rules couldn't be read, when they couldn't.
	Error string `json:"error,omitempty"`
}

// cmdStatus is `maze status`: one line on the project's rules. It exits 1 when the project isn't set up or its
// rules changed since they were approved, so a script can check it.
func cmdStatus() Command {
	var (
		dir    string
		asJSON bool
	)
	return Command{
		Name:    "status",
		Summary: "This project's rules, in one line",
		Usage:   "[flags]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&dir, "C", ".", "the project in `<dir>` instead of the current folder")
			fs.BoolVar(&asJSON, "json", false, "print it as JSON")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, s Streams) int {
			if fs.NArg() > 0 {
				fmt.Fprintln(s.Err, "maze status: takes no arguments. Use -C <dir> for another project.")
				return identity.ExitUsage
			}
			p, err := openProject(ctx, dir)
			if err != nil && asJSON {
				code := fail(s, "maze status", err)
				return printJSON(s.Out, s.Err, "maze status", Status{Version: 1, Error: err.Error()}, code)
			}
			if err != nil {
				return fail(s, "maze status", err)
			}
			can, cant := counts(p.rules)
			st := Status{Version: 1, Project: p.r.Workspace.Name, Path: p.r.Workspace.Root, SetUp: p.setUp,
				Approved: p.setUp && p.approval.Same, Can: can, Cant: cant}
			code := identity.ExitOK
			if !st.SetUp || !st.Approved {
				code = identity.ExitFinding
			}
			if asJSON {
				return printJSON(s.Out, s.Err, "maze status", st, code)
			}
			t := newTerm(s, ui.Options{})
			name := t.Bold(p.r.Workspace.Name)
			switch {
			case !st.SetUp:
				t.Println("  " + name + " · not set up · " + t.Accent("maze init"))
			case !st.Approved && !p.approval.Recorded:
				t.Println("  " + name + " · " + t.Bad("rules not approved on this computer yet") + " · review: " + t.Accent("maze"))
			case !st.Approved:
				t.Println("  " + name + " · " + t.Bad("rules changed since you approved them") + " · review: " + t.Accent("maze"))
			default:
				t.Println("  " + name + fmt.Sprintf(" · %d can, %d can't · approved · ", can, cant) +
					t.Accent("not active yet") + t.Dim(" (maze run is coming)"))
			}
			return code
		},
	}
}

// printJSON writes v as indented JSON and returns code, or ExitError when it can't be written.
func printJSON(out, errOut io.Writer, cmd string, v any, code int) int {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(errOut, "%s: %v\n", cmd, err)
		return identity.ExitError
	}
	return code
}

// projectError is a folder that can't be a project, said in plain words with what to do instead.
type projectError struct{ msg string }

func (e *projectError) Error() string { return e.msg }

// projectProblem says why root can't be a project, or "" when it can. The home folder, the whole disk, and the
// folders that hold keys are refused: as a project, Claude Code could change everything in them, Maze's own
// rules and the agent's key in ~/.maze among them.
func projectProblem(root, home string) string {
	root = filepath.Clean(root)
	const pick = " Pick your project's folder, like ~/code/my-app."
	switch {
	case root == string(filepath.Separator):
		return "That's the whole disk." + pick
	case home == "":
		return ""
	case root == filepath.Clean(home):
		return "That's your home folder." + pick
	case strings.HasPrefix(filepath.Clean(home), root+string(filepath.Separator)):
		return "That folder holds your home folder." + pick
	case strings.HasPrefix(root, filepath.Join(home, ".maze")+string(filepath.Separator)) || root == filepath.Join(home, ".maze"):
		return "That's Maze's own folder." + pick
	}
	if key, ok := scan.KeyFolder(home, root); ok {
		return "That's inside " + key + ", where your keys are." + pick
	}
	return ""
}

// fail prints err for cmd in plain words, with the next step where there is one, and returns the exit code: 1 for
// a rules file Maze won't use or a link it won't follow, 2 for a folder that can't be the project, 125 otherwise.
func fail(s Streams, cmd string, err error) int {
	var (
		bad    *scope.BadFileError
		linked *scope.LinkedDirError
		proj   *projectError
	)
	switch {
	case errors.As(err, &bad):
		fmt.Fprintf(s.Err, "%s: %s.\nFix the file, or start this project over: maze workspace remove\n", cmd, bad.Error())
		return identity.ExitFinding
	case errors.Is(err, errStale), errors.Is(err, scope.ErrBusy):
		fmt.Fprintf(s.Err, "%s: %v.\n", cmd, err)
		return identity.ExitFinding
	case errors.As(err, &linked):
		fmt.Fprintf(s.Err, "%s: %s.\n", cmd, linked.Error())
		return identity.ExitFinding
	case errors.As(err, &proj):
		fmt.Fprintf(s.Err, "%s: %s\n", cmd, proj.msg)
		return identity.ExitUsage
	}
	fmt.Fprintf(s.Err, "%s: %v\n", cmd, err)
	return identity.ExitError
}
