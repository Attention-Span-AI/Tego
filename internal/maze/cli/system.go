// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Check is one line of `maze system doctor`: what was checked, how it stands, and the detail or the fix.
type Check struct {
	Name string `json:"name"`
	// State is "ok", "info" (worth knowing, nothing to fix) or "problem".
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// Doctor is `maze system doctor --json`.
type Doctor struct {
	Version int     `json:"version"`
	Maze    string  `json:"maze"`
	Checks  []Check `json:"checks"`
}

// cmdSystem is the system group: `maze system doctor` checks what Maze needs on this machine and in this project,
// and `maze system version` prints the build.
func cmdSystem() Command {
	var (
		dir    string
		asJSON bool
	)
	return Command{
		Name:    "system",
		Summary: "This machine: doctor, version",
		Usage:   "doctor|version [flags]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&dir, "C", ".", "doctor: check the project in `<dir>` instead of the current folder")
			fs.BoolVar(&asJSON, "json", false, "print it as JSON")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, s Streams) int {
			switch {
			case fs.Arg(0) == "version" && fs.NArg() == 1:
				v := struct {
					Version int    `json:"version"`
					Maze    string `json:"maze"`
					Commit  string `json:"commit,omitempty"`
					Go      string `json:"go"`
					OS      string `json:"os"`
				}{1, version, commit, runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH}
				if asJSON {
					return printJSON(s.Out, s.Err, "maze system version", v, identity.ExitOK)
				}
				fmt.Fprintf(s.Out, "%s · %s · %s\n", versionLine(), v.OS, v.Go)
				return identity.ExitOK
			case fs.Arg(0) != "doctor" || fs.NArg() > 1:
				subProblem(s, "system", fs.Args())
				fmt.Fprintln(s.Err, "Usage: maze system doctor [--json] [-C <dir>]")
				fmt.Fprintln(s.Err, "       maze system version [--json]")
				return identity.ExitUsage
			}
			d, err := doctor(ctx, dir)
			if err != nil {
				return fail(s, "maze system doctor", err)
			}
			code := identity.ExitOK
			for _, c := range d.Checks {
				if c.State == "problem" {
					code = identity.ExitFinding
				}
			}
			if asJSON {
				return printJSON(s.Out, s.Err, "maze system doctor", d, code)
			}
			t := newTerm(s, ui.Options{})
			w := 0
			for _, c := range d.Checks {
				w = max(w, len([]rune(c.Name)))
			}
			for _, c := range d.Checks {
				mark := t.Good("✓")
				switch c.State {
				case "info":
					mark = t.Dim("·")
				case "problem":
					mark = t.Bad("✗")
				}
				t.Println("  " + mark + " " + pad(c.Name, w) + "   " + t.Dim(c.Detail))
			}
			return code
		},
	}
}

// fileExists reports whether something is at path.
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// pad pads s with spaces to n columns.
func pad(s string, n int) string { return padRight(s, n+len(s)-len([]rune(s))) }

// doctor runs the checks: maze itself, Claude Code, git, the engine, this project, and the person's own rules.
// It reads only what is saved and what is on PATH; it changes nothing.
func doctor(ctx context.Context, dir string) (Doctor, error) {
	env, err := scan.FromOS()
	if err != nil {
		return Doctor{}, err
	}
	d := Doctor{Version: 1, Maze: version}
	add := func(name, state, detail string) { d.Checks = append(d.Checks, Check{name, state, detail}) }

	self, _ := os.Executable()
	add(versionLine(), "ok", tildePath(env.Home, self))
	if claude := env.LookPath("claude"); claude != "" {
		add("Claude Code", "ok", tildePath(env.Home, claude))
	} else {
		add("Claude Code", "problem", "not installed: https://code.claude.com/docs")
	}
	if git := env.LookPath("git"); git != "" {
		add("git", "ok", tildePath(env.Home, git))
	} else {
		add("git", "info", "not installed: Claude Code works best in a git repo")
	}
	switch tego := env.LookPath("tego"); {
	case runtime.GOOS != "linux":
		add("Engine", "info", "runs on Linux; on this Mac it comes with Maze's Linux layer (not built yet)")
	case tego == "":
		add("Engine", "info", "not installed yet: maze run will need it")
	default:
		add("Engine", "ok", tildePath(env.Home, tego))
	}

	p, err := openProject(ctx, dir)
	var bad *scope.BadFileError
	switch {
	case errors.As(err, &bad):
		add("This project", "problem", bad.Error()+": fix it, or start over with maze workspace remove")
	case err != nil:
		add("This project", "problem", err.Error())
	}
	name := "This project: " + p.r.Workspace.Name
	switch {
	case err != nil:
	case !p.setUp:
		add(name, "info", "not set up: maze init")
	case !p.approval.Same && !p.approval.Recorded:
		add(name, "problem", "rules not approved on this computer yet: maze")
	case !p.approval.Same:
		add(name, "problem", "rules changed since you approved them: maze")
	default:
		add(name, "ok", fmt.Sprintf("%d rules, approved · %s", len(onlyScope(p.rules, "workspace")), scope.WorkspaceFile))
	}
	personal, ok, err := scope.LoadPersonal(env.Home)
	switch {
	case err != nil:
		add("Your rules for every project", "problem", err.Error())
	case !ok:
		add("Your rules for every project", "info", "none yet: saved by your first maze init")
	default:
		add("Your rules for every project", "ok", fmt.Sprintf("%d rules · ~/%s", len(personal.Rules), scope.PersonalFile))
	}
	if p.setUp && p.r.Workspace.Git {
		hook := filepath.Join(p.r.Workspace.Root, ".git", "hooks", "pre-push")
		helper := filepath.Join(p.r.Workspace.Root, ".git", "hooks", "maze-pre-push")
		fi, statErr := os.Stat(hook)
		data, err := os.ReadFile(hook)
		switch elsewhere := scope.HooksPath(env.Home, p.r.Workspace.Root); {
		case elsewhere != "" && fileExists(helper):
			add("Pre-push check", "info", "git runs hooks from "+elsewhere+": its pre-push hook must call .git/hooks/maze-pre-push")
		case elsewhere != "":
			add("Pre-push check", "problem", "git runs hooks from "+elsewhere+", so Maze's check never runs: run maze and save for the line to add")
		case err == nil && strings.Contains(string(data), "maze-pre-push") && statErr == nil && fi.Mode().Perm()&0o111 == 0:
			add("Pre-push check", "problem", "not executable, so git skips it: chmod +x .git/hooks/pre-push")
		case err == nil && strings.Contains(string(data), "maze-pre-push"):
			add("Pre-push check", "ok", ".git/hooks/pre-push")
		default:
			add("Pre-push check", "problem", "missing: run maze and save to put it back")
		}
	}
	k := scope.AgentKeyPaths(env.Home)
	switch fi, err := os.Stat(k.Private); {
	case err != nil:
		add("Claude Code's signing key", "info", "made by your first maze init")
	case fi.Mode().Perm()&0o077 != 0:
		add("Claude Code's signing key", "problem", "others can read it, so git won't sign with it: chmod 600 "+tildePath(env.Home, k.Private))
	default:
		add("Claude Code's signing key", "ok", tildePath(env.Home, k.Public))
	}
	add("Protection", "info", "not active yet: Claude Code runs without Maze until maze run ships")
	return d, nil
}
