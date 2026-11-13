// SPDX-License-Identifier: Apache-2.0

package execmatchdiff

import (
	"reflect"
	"slices"
	"strings"

	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

// NpmCommandless certifies nopt's argv.remain is empty, using its independent
// String/Boolean and shorthand rules. It accepts only a deliberately small
// vocabulary: equals, negation and unsupported typed/shorthand forms decline.
// Callers must supply a complete argv; this helper makes no allow decision.
func NpmCommandless(tokens []string, readings any) bool {
	if !npmNoRemain(tokens) {
		return false
	}
	// Current conservative unknown-option readings may remain, but every one
	// must independently agree that no named command is located.
	return commandlessReadings(readings)
}

func npmNoRemain(tokens []string) bool {
	row := oldrows.Builtin().Lookup("npm")
	work := slices.Clone(tokens)
	for i := 0; i < len(work); i++ {
		tok := work[i]
		if len(tok) < 2 || tok[0] != '-' || strings.Contains(tok, "=") {
			return false
		}
		if strings.Trim(tok, "-") == "" {
			return i+1 == len(work)
		}
		name := strings.TrimLeft(tok, "-")
		if strings.HasPrefix(strings.ToLower(name), "no-") {
			return false
		}
		// nopt resolveShort: an exact type wins, then an exact shorthand;
		// a cluster expands ONLY if every character is a known shorthand.
		var option *old.Opt
		for j := range row.Root.Opts {
			if slices.Contains(row.Root.Opts[j].Long, name) {
				option = &row.Root.Opts[j]
				break
			}
		}
		if option == nil {
			if long, ok := npmSimpleShort(name); ok {
				name = long
				option = npmOpt(row.Root, "--"+name)
			} else if npmSpecialShort(name) {
				return false
			} else {
				allShort := true
				var expansion []string
				for _, ch := range name {
					if long, ok := npmSimpleShort(string(ch)); ok {
						expansion = append(expansion, "--"+long)
					} else if npmSpecialShort(string(ch)) {
						return false
					} else {
						allShort = false
					}
				}
				if allShort && len(expansion) > 0 {
					work = append(work[:i], append(expansion, work[i+1:]...)...)
					i--
					continue
				}
				option = npmOpt(row.Root, "--"+name)
				if option == nil && npmCouldAbbreviate(row.Root, name) {
					return false
				}
			}
		}
		boolean := option == nil || npmSourceBoolean(option.Name)
		if boolean {
			if i+1 < len(work) && (work[i+1] == "true" || work[i+1] == "false") {
				i++
			}
			continue
		}
		if !npmStringType(option.Name) {
			return false
		}
		if i+1 == len(work) {
			continue
		}
		next := work[i+1]
		allDash := len(next) >= 2 && strings.Trim(next, "-") == ""
		optionName := len(next) > 1 && next[0] == '-' && (next[1] != '-' || len(next) > 2 && next[2] != '-')
		if !allDash && !optionName {
			i++ // Exact String accepts even the empty value, but not another option.
		}
	}
	return true
}

func npmSimpleShort(name string) (string, bool) {
	// npm 9.2.0 definitions.js short fields, read with config/index.js.
	shorts := map[string]string{"a": "all", "c": "call", "f": "force", "g": "global", "L": "location", "l": "long", "m": "message", "p": "parseable", "C": "prefix", "S": "save", "B": "save-bundle", "D": "save-dev", "E": "save-exact", "O": "save-optional", "P": "save-prod", "?": "usage", "H": "usage", "h": "usage", "v": "version", "w": "workspace", "ws": "workspaces", "y": "yes"}
	long, ok := shorts[name]
	return long, ok
}

func npmSpecialShort(name string) bool {
	return slices.Contains(strings.Fields("enjoy-by d dd ddd quiet q s silent verbose desc help local n no porcelain readonly reg iwr"), name)
}

func npmCouldAbbreviate(lv *old.Level, name string) bool {
	for _, o := range lv.Opts {
		for _, long := range o.Long {
			if strings.HasPrefix(long, name) {
				return true
			}
		}
	}
	for _, short := range strings.Fields("enjoy-by d dd ddd quiet q s silent verbose desc help local n no porcelain readonly reg iwr a c f g L l m p C S B D E O P ? H h v w ws y") {
		if strings.HasPrefix(short, name) {
			return true
		}
	}
	return false
}

func npmSourceBoolean(name string) bool {
	return slices.Contains(strings.Fields("all force global long parseable save save-bundle save-dev save-exact save-optional save-prod usage version yes"), name)
}

func commandlessReadings(readings any) bool {
	v := reflect.ValueOf(readings)
	if v.Len() == 0 {
		return false
	}
	for i := 0; i < v.Len(); i++ {
		r := v.Index(i)
		if r.FieldByName("Unlocatable").Bool() || r.FieldByName("Path").Len() != 0 {
			return false
		}
	}
	return true
}
