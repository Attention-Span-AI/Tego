// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"gopkg.in/yaml.v3"
)

const hiddenCompileError = "the draft does not compile; check its YAML in Full"

// A failed inherited load has no trustworthy merged assignment set. A second
// load just for redaction could read different profile bytes from the failure.
func redactLoadError(text []byte, msg string, where ...string) string {
	var doc struct {
		Extends yaml.Node `yaml:"extends"`
	}
	if err := yaml.Unmarshal(text, &doc); err != nil {
		// Only the submitted document's own parser location is safe here. The
		// diagnostic message may quote secrets or come from an inherited file.
		if location, ok := strings.CutPrefix(err.Error(), "yaml: line "); ok {
			if number, _, found := strings.Cut(location, ":"); found {
				line, parseErr := strconv.Atoi(number)
				if parseErr == nil && line >= 1 && line <= strings.Count(string(text), "\n")+2 {
					return hiddenCompileError + " at line " + strconv.Itoa(line)
				}
			}
		}
		return hiddenCompileError
	}
	if doc.Extends.Kind != 0 {
		out := "the draft or an inherited profile could not be loaded; check them in a terminal"
		if len(where) > 0 {
			// Where the loader found a fault, never what it said: the message may quote a value. Each line names
			// the file (a profile by its name too) and the line number, so the person can open it.
			out += "\n" + strings.Join(where, "\n")
		}
		return out
	}
	return redactError(text, msg)
}

func redactLoadedError(cc nextrun.Context, c *agent.Contract, msg string) string {
	if c == nil {
		return hiddenCompileError
	}
	cwd := cc.Cwd
	if cwd == "" {
		cwd = filepath.Dir(cc.Contract)
	}
	var values []string
	for name, raw := range c.Env.Set {
		expanded := strings.ReplaceAll(raw, agent.ProjectDirToken, cwd)
		values = append(values, raw, expanded)
		if name == "PATH" {
			// Missing-image diagnostics print PATH as separate search directories.
			values = append(values, filepath.SplitList(raw)...)
			values = append(values, filepath.SplitList(expanded)...)
		}
	}
	return redactValues(msg, values)
}

func redactValues(msg string, values []string) string {
	var forms []string
	for _, value := range values {
		if value == "" {
			continue
		}
		// Diagnostics quote command words. Escape-sensitive assignments must not
		// bypass redaction merely because %q rendered their quotes or newlines.
		quoted, ascii := strconv.Quote(value), strconv.QuoteToASCII(value)
		forms = append(forms, value, quoted, ascii, quoted[1:len(quoted)-1], ascii[1:len(ascii)-1])
	}
	// Longest first keeps overlapping assignments and PATH fragments deterministic.
	slices.SortFunc(forms, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	var pairs []string
	for _, form := range slices.Compact(forms) {
		pairs = append(pairs, form, "[hidden]")
	}
	// One pass never treats a replacement marker as another hidden assignment.
	return strings.NewReplacer(pairs...).Replace(msg)
}

func redactError(text []byte, msg string) string {
	var doc struct {
		Env struct {
			Set map[string]string `yaml:"set"`
		} `yaml:"env"`
	}
	if yaml.Unmarshal(text, &doc) != nil {
		return hiddenCompileError
	}
	var values []string
	for _, value := range doc.Env.Set {
		values = append(values, value)
	}
	return redactValues(msg, values)
}

// inheritedWhere says where each error of a failed load lies, without its message: "profile base · /p/profiles/base.yaml
// · line 4" for a file the draft extends (the profile's name is its path beneath the profiles folder, else its file
// name), "the draft · line 3" for the draft itself. A file path and a line number quote no value.
func inheritedWhere(ds []agent.Diagnostic, contract, profiles string) []string {
	var out []string
	for _, d := range ds {
		if !d.IsError() || d.Line < 1 {
			continue
		}
		w := "profile " + profileName(d.File, profiles) + " · " + d.File + " · line " + strconv.Itoa(d.Line)
		if d.File == "" || d.File == contract {
			w = "the draft · line " + strconv.Itoa(d.Line)
		}
		if !slices.Contains(out, w) {
			out = append(out, w)
		}
		if len(out) == 8 {
			break
		}
	}
	return out
}

// profileName is a profile file's name as extends writes it: its path beneath the profiles folder without the
// extension, else the file's own name.
func profileName(file, profiles string) string {
	name := filepath.Base(file)
	if profiles != "" {
		if rel, err := filepath.Rel(profiles, file); err == nil && !strings.HasPrefix(rel, "..") {
			name = rel
		}
	}
	return strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
}
