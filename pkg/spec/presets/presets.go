// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"sync"
)

// files holds every revision of every preset, v<n>/<name>.yaml, and the host groups.
//
//go:embed v1/*.yaml hosts.yaml
var files embed.FS

// Prefix opens the reserved namespace the presets are named in (agent.BuiltinPrefix, ADR 0066 D2).
const Prefix = "tego/"

// PathPrefix begins the path Source.Resolve reports a preset's bytes under, which diagnostics print as the file a
// line is in: it names the embedded file (pkg/spec/presets/v<n>/<name>.yaml in the source tree) and, being no
// path on disk, cannot be taken for one.
const PathPrefix = "<builtin>/presets/"

// Preset is one built-in preset: its name under Prefix, its one-line promise and its newest revision. Revisions 1
// to Revision exist, each in v<n>/<name>.yaml.
type Preset struct {
	Name     string
	Promise  string
	Revision int
}

// Ref is the name a contract extends the newest revision by, such as tego/no-secrets.
func (p Preset) Ref() string { return Prefix + p.Name }

// Pinned is the name a contract extends revision n by, such as tego/no-secrets@1.
func (p Preset) Pinned(n int) string { return p.Ref() + "@" + strconv.Itoa(n) }

// catalog is every preset, in the order tego init lists them in an extends: line. A revision is added here and as
// its file in the same change, and frozen once released (README.md, released below).
var catalog = []Preset{
	{Name: "no-secrets", Promise: "the agent cannot read your secret files, and your secret variables never reach it", Revision: 1},
	{Name: "no-prod", Promise: "the agent reaches no network host except the ones your contract names", Revision: 1},
	{Name: "repo-only-writes", Promise: "the agent writes only in the folders your contract names", Revision: 1},
}

// released is the sha256 of every released revision's bytes, by its pinned name without the prefix
// (no-secrets@1). A revision listed here is frozen: TestReleasedRevisionsAreFrozen fails when its file changes,
// and a change is a new revision. Empty until the first release carries the presets; revision 1 is edited in place
// until then (README.md).
var released = map[string]string{}

// List returns every preset, in catalog order.
func List() []Preset { return append([]Preset(nil), catalog...) }

// Source serves the presets by name: tego/<preset> is its newest revision, tego/<preset>@<n> revision n. It has the
// shape of agent.ProfileSource and agent.ProfileNamer without importing pkg/spec/agent, so this package stays data.
type Source struct{}

// Resolve returns the path a preset's bytes are reported under and the bytes. A name this source does not serve,
// a preset it does not have or a revision that does not exist alike, is an error wrapping fs.ErrNotExist, so the
// chain asks its next built-in source and, when none holds the name, names the ones there are.
func (Source) Resolve(name string) (string, []byte, error) {
	p, n, ok := lookup(name)
	if !ok {
		return "", nil, fmt.Errorf("built-in preset %q: %w", name, fs.ErrNotExist)
	}
	file := revisionFile(p.Name, n)
	data, err := files.ReadFile(file)
	if err != nil {
		// The catalog names a revision with no file: a build defect TestEveryRevisionHasItsFile catches.
		return "", nil, fmt.Errorf("built-in preset %q: %w", name, err)
	}
	return PathPrefix + file, data, nil
}

// Names returns every name Resolve serves: each preset by its name and by each of its revision pins.
func (Source) Names() []string {
	var names []string
	for _, p := range catalog {
		names = append(names, p.Ref())
		for n := 1; n <= p.Revision; n++ {
			names = append(names, p.Pinned(n))
		}
	}
	return names
}

// lookup parses tego/<preset>[@<n>] into the preset and the revision it names.
func lookup(name string) (Preset, int, bool) {
	rest, ok := strings.CutPrefix(name, Prefix)
	if !ok {
		return Preset{}, 0, false
	}
	base, pin, pinned := strings.Cut(rest, "@")
	for _, p := range catalog {
		if p.Name != base {
			continue
		}
		if !pinned {
			return p, p.Revision, true
		}
		n, err := strconv.Atoi(pin)
		if err != nil || n < 1 || n > p.Revision || strconv.Itoa(n) != pin {
			return Preset{}, 0, false
		}
		return p, n, true
	}
	return Preset{}, 0, false
}

func revisionFile(name string, n int) string { return path.Join("v"+strconv.Itoa(n), name+".yaml") }

// HostGroup is one named set of host:port entries for a package ecosystem (hosts.yaml).
type HostGroup struct {
	Name  string
	Hosts []string
}

// hostGroups is hosts.yaml read once, when first asked for. The file is compiled in, so a malformed one is a build
// defect TestHostGroups catches before a binary ships it; it is still an error to the caller, never half a group,
// and never a failure of a command that asks for no group.
var hostGroups = sync.OnceValues(func() ([]HostGroup, error) {
	data, err := files.ReadFile("hosts.yaml")
	if err != nil {
		return nil, err
	}
	gs, err := parseHostGroups(data)
	if err != nil {
		return nil, fmt.Errorf("presets: hosts.yaml: %w", err)
	}
	return gs, nil
})

// HostGroups returns every host group, in the file's order, each a copy.
func HostGroups() ([]HostGroup, error) {
	gs, err := hostGroups()
	if err != nil {
		return nil, err
	}
	out := make([]HostGroup, len(gs))
	for i, g := range gs {
		out[i] = HostGroup{Name: g.Name, Hosts: append([]string(nil), g.Hosts...)}
	}
	return out, nil
}

// parseHostGroups reads hosts.yaml's one shape: comment and blank lines, a group's name at the start of a line
// followed by ':', and its entries beneath it as "  - host:port". Anything else is an error naming its line, so the
// file cannot hold a form this reader would take differently from a YAML parser.
func parseHostGroups(data []byte) ([]HostGroup, error) {
	var gs []HostGroup
	seen := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		at := i + 1
		switch {
		case strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "  - "):
			if len(gs) == 0 {
				return nil, fmt.Errorf("line %d: an entry before any group", at)
			}
			h := strings.TrimPrefix(line, "  - ")
			if !validHostPort(h) {
				return nil, fmt.Errorf("line %d: %q is not host:port", at, h)
			}
			gs[len(gs)-1].Hosts = append(gs[len(gs)-1].Hosts, h)
		case strings.HasSuffix(line, ":") && validGroupName(strings.TrimSuffix(line, ":")):
			if len(gs) > 0 && len(gs[len(gs)-1].Hosts) == 0 {
				return nil, fmt.Errorf("line %d: group %s has no entry", at, gs[len(gs)-1].Name)
			}
			name := strings.TrimSuffix(line, ":")
			if seen[name] {
				return nil, fmt.Errorf("line %d: group %s appears twice", at, name)
			}
			seen[name] = true
			gs = append(gs, HostGroup{Name: name})
		default:
			return nil, fmt.Errorf("line %d: %q is neither a group nor an entry", at, line)
		}
	}
	if len(gs) == 0 || len(gs[len(gs)-1].Hosts) == 0 {
		return nil, fmt.Errorf("no group, or a last group with no entry")
	}
	return gs, nil
}

func validGroupName(s string) bool {
	if s == "" || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// validHostPort is a lowercase DNS name of two labels or more and a port from 1 to 65535.
func validHostPort(s string) bool {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return false
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
