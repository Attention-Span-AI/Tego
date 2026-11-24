// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// ErrInvalid is fixed text: raw decoder errors may contain private input.
var ErrInvalid = errors.New("invalid or unsupported saved scan")

var groupPattern = regexp.MustCompile(`^([a-zA-Z0-9_.$-]{1,256}|gid [0-9]{1,10})$`)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`)
var containerPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Decode rejects the entire object on structural or semantic uncertainty.
// Future kinds and catalogs require a reader update; they are never salvaged.
func Decode(b []byte) (Snapshot, error) {
	var s Snapshot
	bad := func() (Snapshot, error) { return Snapshot{}, ErrInvalid }
	if len(b) > MaxBytes || !utf8.Valid(b) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := walkJSON(d, 0); err != nil {
		return bad()
	}
	if _, err := d.Token(); err != io.EOF {
		return bad()
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return bad()
	}
	for n, i := range s.Items {
		switch i.Kind {
		case "process", "other_program":
			var p Process
			if err := json.Unmarshal(i.Detail, &p); err != nil {
				return bad()
			}
			if p.Container != nil {
				var v Container
				if json.Unmarshal(*p.Container, &v) != nil {
					return bad()
				}
				encoded := Detail(v)
				p.Container = &encoded
			}
			s.Items[n].Detail = Detail(p)
		case "cron":
			var v Cron
			if json.Unmarshal(i.Detail, &v) != nil {
				return bad()
			}
			s.Items[n].Detail = Detail(v)
		case "mcp_server":
			var v Config
			if json.Unmarshal(i.Detail, &v) != nil {
				return bad()
			}
			s.Items[n].Detail = Detail(v)
		case "user_unit", "system_unit", "timer":
			var v Unit
			if json.Unmarshal(i.Detail, &v) != nil {
				return bad()
			}
			s.Items[n].Detail = Detail(v)
		case "project":
			var p Project
			if json.Unmarshal(i.Detail, &p) != nil {
				return bad()
			}
			s.Items[n].Detail = Detail(p)
		case "program", "settings":
			var f File
			if err := json.Unmarshal(i.Detail, &f); err != nil {
				return bad()
			}
			s.Items[n].Detail = Detail(f)
		default:
			return bad()
		}
	}
	// Re-encoding typed fields and comparing canonical JSON rejects missing,
	// unknown, null scalar and wrong-type fields without reflection or coercion.
	typed, err := json.Marshal(s)
	if err != nil {
		return bad()
	}
	left, err := canonical(b)
	if err != nil {
		return bad()
	}
	right, err := canonical(typed)
	if err != nil || !bytes.Equal(left, right) || !s.valid() {
		return bad()
	}
	return s, nil
}

func canonical(b []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func walkJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	switch v := t.(type) {
	case string:
		if len(v) > 4096 || !printable(v) {
			return ErrInvalid
		}
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return ErrInvalid
				}
				key, ok := k.(string)
				if !ok || seen[key] || len(key) > 64 {
					return ErrInvalid
				}
				seen[key] = true
				if err := walkJSON(d, depth+1); err != nil {
					return err
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if err := walkJSON(d, depth+1); err != nil {
					return err
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}

func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}
func validPath(p *string) bool {
	return p == nil || len(*p) > 0 && len(*p) <= 4096 && filepath.IsAbs(*p) && printable(*p)
}
func one(s string, choices string) bool { return strings.Contains("|"+choices+"|", "|"+s+"|") }
func count(n int) bool                  { return n >= 0 && n <= 1000000 }
func uniqueCodes(xs []string, codes string, max int) bool {
	if xs == nil || len(xs) > max {
		return false
	}
	seen := map[string]bool{}
	for _, s := range xs {
		if seen[s] || !one(s, codes) {
			return false
		}
		seen[s] = true
	}
	return true
}

const exclusions = "other-users|system-units|containers-unattributed|mcp-deferred|units-deferred|unreadable-processes|unknown-owners|between-scans|libraries|remote-agents|environment|memory|source-code|network|unknown-formats|other-user-settings|nonlocal-homes|unresolved-units|unresolved-cron|scan-not-performed|unknown-names|outer-pid-namespace|project-deferred|project-parents|project-children|project-alternates|project-includes|container-patterns"
const limits = "pid-limit|thread-limit|argv-limit|path-limit|glob-limit|file-limit|byte-limit|parse-limit|item-limit|source-limit|result-limit|deadline"
const caveats = "name-collision|settings-only|declaration-only|configured-only|identity-unknown|membership-unknown|container-hint|user-rule|metadata-omitted|historical"

func knownRule(r Rule) bool {
	if r.Origin == "user" {
		n, e := strconv.Atoi(strings.TrimPrefix(r.ID, "user-"))
		return e == nil && n >= 1 && n <= 64 && r.ID == fmt.Sprintf("user-%d", n) && r.Name == r.ID
	}
	if r.Origin != "catalog" {
		return false
	}
	switch r.ID {
	case "claude-native", "claude-node", "dep-claude", "mcp-claude", "unit-claude", "cron-claude":
		return r.Name == "claude"
	case "codex-native", "codex-node", "dep-codex", "mcp-codex", "unit-codex", "cron-codex":
		return r.Name == "codex"
	case "gemini-native", "gemini-node-bin", "gemini-node-dist", "dep-gemini", "mcp-gemini", "unit-gemini", "cron-gemini":
		return r.Name == "gemini"
	case "opencode-native", "opencode-node", "dep-opencode", "unit-opencode", "cron-opencode":
		return r.Name == "opencode"
	case "dep-langgraph", "dep-langgraph-js", "marker-langgraph":
		return r.Name == "langgraph"
	case "dep-crewai", "marker-crew":
		return r.Name == "crewai"
	case "marker-agents":
		return r.Name == "agents"
	case "other-interpreter":
		return r.Name == "other-interpreter"
	}
	return false
}

func (s Snapshot) valid() bool {
	if s.UnreadableProgramsWarning != UnreadableProgramsWarning {
		return false
	}
	if s.Schema != "tego.scan/1" || !one(s.Catalog, "c1|c2|c3|c4") || !versionPattern.MatchString(s.Tego) || s.Started.IsZero() || s.Finished.IsZero() || s.Started.After(s.Finished) || s.Started.Location().String() != "UTC" || s.Finished.Location().String() != "UTC" {
		return false
	}
	if s.Boot != nil && !bootPattern.MatchString(*s.Boot) {
		return false
	}
	if !one(s.Mode, "basic|advanced") || !one(s.Status, "ok|partial|failed") || !one(s.Check, "not-requested|none-observed|outside-observed|unknown|unreadable-observed|none-observed-allow-unreadable") || !validPath(s.Project) || s.As.UID == 4294967295 || s.As.Recipient == 4294967295 {
		return false
	}
	if s.Mode == "basic" && (s.As.UID != s.As.Recipient || s.As.Root != (s.As.UID == 0)) {
		return false
	}
	// A refusal can retain the actual unprivileged caller, but no observations.
	if s.Mode == "advanced" && s.Status != "failed" && (s.Catalog != "c4" || s.As.UID != 0 || !s.As.Root) {
		return false
	}
	if !uniqueCodes(s.Exclusions, exclusions, 64) || !uniqueCodes(s.Limits, limits, 32) {
		return false
	}
	for _, always := range []string{"unknown-names", "between-scans", "libraries", "remote-agents"} {
		if !one(always, strings.Join(s.Exclusions, "|")) {
			return false
		}
	}
	if s.Rules == nil || len(s.Rules) > 320 || s.Items == nil || len(s.Items) > 512 || len(s.Sources) == 0 || len(s.Sources) > 2048 {
		return false
	}
	rules := map[string]Rule{}
	for _, r := range s.Rules {
		if _, ok := rules[r.ID]; ok || !knownRule(r) {
			return false
		}
		if !one(s.Catalog, "c3|c4") && (strings.HasPrefix(r.ID, "mcp-") || strings.HasPrefix(r.ID, "unit-")) {
			return false
		}
		if s.Catalog == "c1" && (strings.HasPrefix(r.ID, "dep-") || strings.HasPrefix(r.ID, "marker-")) {
			return false
		}
		if strings.HasPrefix(r.ID, "cron-") && (s.Catalog != "c4" || s.Mode != "advanced") {
			return false
		}
		rules[r.ID] = r
	}
	if s.UnreadableProgramPIDs == nil || len(s.UnreadableProgramPIDs) > 2000 || s.Counts.UnreadablePrograms != len(s.UnreadableProgramPIDs) || !count(s.Counts.Exited) || !count(s.Counts.KernelThreads) {
		return false
	}
	if s.Mode == "advanced" && len(s.UnreadableProgramPIDs) != 0 {
		return false
	}
	unreadablePIDs := map[int]bool{}
	for _, pid := range s.UnreadableProgramPIDs {
		if pid < 1 || pid > 2147483647 || unreadablePIDs[pid] {
			return false
		}
		unreadablePIDs[pid] = true
	}
	unreadableSources := 0
	sources := map[string]Source{}
	unknown := false
	for _, p := range s.Sources {
		if _, ok := sources[p.ID]; ok || !namePattern.MatchString(p.ID) || !validPath(p.Locator) || !one(p.Kind, "A|B|C|D|E|F|G|advanced|meta|result|system|cron") || !one(p.State, "read|partial|missing|not-read|deferred|excluded|unreadable-program") || !one(p.Reason, "none|permission|gone|changed|owner|mode|symlink|type|size|syntax|unsupported|unresolved|limit|deadline|scope|not-built|mount|privilege|governed|io|usage|bug|not-live") || !count(p.Read) || !count(p.NotRead) {
			return false
		}
		if p.WritableGroup != nil && (p.Reason != "mode" || p.State != "not-read" && p.State != "partial" || !groupPattern.MatchString(*p.WritableGroup)) {
			return false
		}
		if p.GroupEvidence != "" && (p.WritableGroup == nil || !one(p.Kind, "D|E|F|system|cron") || !one(p.GroupEvidence, "accounts-unreadable|accounts-limit|accounts-malformed|directory-service|owner-not-local|group-missing|shared-primary|other-member|access-acl")) {
			return false
		}
		callerRepair := s.Status == "failed" && p.Kind == "meta" && p.Reason == "owner" && p.State == "not-read" && p.Read == 0 && p.NotRead == 1 && p.WritableGroup == nil && p.GroupEvidence == "" && one("scan-not-performed", strings.Join(s.Exclusions, "|"))
		discoveryRepair := p.GroupEvidence == "accounts-unreadable" && p.WritableGroup != nil
		if p.AccountRepair != "" && ((!callerRepair && !discoveryRepair) || len(p.AccountRepair) > 2048 || !printable(p.AccountRepair)) {
			return false
		}
		if (p.Kind == "system" || p.Kind == "cron") && (s.Mode != "advanced" || s.Catalog != "c4") {
			return false
		}
		if p.Reason == "unresolved" && (!one(p.Kind, "E|system|cron") || p.State != "not-read" && p.State != "partial") {
			return false
		}
		if p.State == "unreadable-program" {
			if p.Kind != "A" || p.Reason != "permission" || p.Read != 0 || p.NotRead != 1 || p.Locator != nil || s.Status == "ok" {
				return false
			}
			unreadableSources++
		}
		if p.State == "not-read" || p.State == "partial" {
			if s.Status == "ok" {
				return false
			}
			if p.Kind == "A" || p.Kind == "meta" {
				unknown = true
			}
		}
		sources[p.ID] = p
	}
	if s.Mode == "advanced" && (s.As.UID != 0 || !s.As.Root) {
		if s.Status != "failed" || len(s.Items) != 0 {
			return false
		}
		for _, src := range s.Sources {
			if src.Read != 0 {
				return false
			}
		}
	}
	if unreadableSources != len(s.UnreadableProgramPIDs) {
		return false
	}
	actual := Counts{Exited: s.Counts.Exited, KernelThreads: s.Counts.KernelThreads, UnreadablePrograms: s.Counts.UnreadablePrograms}
	seen := map[string]bool{}
	otherRows := 0
	for _, i := range s.Items {
		if seen[i.ID] || !namePattern.MatchString(i.ID) || !uniqueCodes(i.Caveats, caveats, 16) || len(i.Evidence) < 1 || len(i.Evidence) > 8 {
			return false
		}
		seen[i.ID] = true
		cgroup := false
		matched := false
		for _, e := range i.Evidence {
			r, ok := rules[e.RuleID]
			if !ok || r.Name != i.Name {
				return false
			}
			p, ok := sources[e.SourceID]
			if !ok || p.State != "read" && p.State != "partial" {
				return false
			}
			if strings.HasPrefix(r.ID, "mcp-") && i.Kind != "mcp_server" || strings.HasPrefix(r.ID, "unit-") && i.Kind != "user_unit" && i.Kind != "system_unit" && i.Kind != "timer" || strings.HasPrefix(r.ID, "cron-") && i.Kind != "cron" {
				return false
			}
			if i.Kind != "project" && (strings.HasPrefix(r.ID, "dep-") || strings.HasPrefix(r.ID, "marker-")) {
				return false
			}
			switch i.Kind {
			case "cron":
				v := i.Cron()
				if p.Kind != "cron" || p.State != "read" || p.Read != 1 || e.Fact != "cron-command" || r.ID != "cron-"+i.Name || v.Path == nil || p.Locator == nil || *v.Path != *p.Locator {
					return false
				}
			case "mcp_server", "user_unit", "system_unit", "timer":
				kind, fact, prefix := "D", "mcp-key", "mcp-"
				var path *string
				if i.Kind == "user_unit" || i.Kind == "system_unit" || i.Kind == "timer" {
					kind, fact, prefix = "E", "exec-start", "unit-"
					if i.Kind == "timer" {
						fact = "timer-unit"
					}
					if i.Kind == "system_unit" || i.Kind == "timer" && i.Unit().UID == nil {
						kind = "system"
					}
					path = i.Unit().Path
				} else {
					path = i.Config().Path
				}
				if p.Kind != kind || p.State != "read" || p.Read != 1 || e.Fact != fact || r.ID != prefix+i.Name || path == nil || p.Locator == nil || *path != *p.Locator {
					return false
				}
			case "project":
				pjt := i.Project()
				if p.Kind != "F" || p.State != "read" || p.Read != 1 || pjt.Path == nil || p.Locator == nil || *pjt.Path != *p.Locator {
					return false
				}
				if pjt.Dependency == nil {
					if e.Fact != "path" || !markerPath(r.ID, *pjt.Path) {
						return false
					}
				} else if e.Fact != "dependency" || e.RuleID != *pjt.Dependency || !dependencyPath(*pjt.Dependency, *pjt.Path) {
					return false
				}
			case "process":
				if p.Kind != "A" || !one(e.Fact, "exe-name|argv0-name|comm-name|argv-pattern|file-id|path|cgroup") {
					return false
				}
				if r.ID == "other-interpreter" {
					return false
				}
				if e.Fact != "cgroup" {
					if r.Origin == "catalog" {
						if strings.HasSuffix(r.ID, "-native") {
							if !one(e.Fact, "exe-name|argv0-name|comm-name") {
								return false
							}
						} else if e.Fact != "argv-pattern" {
							return false
						}
					}
					matched = true
				}
			case "other_program":
				if e.Fact == "interpreter" {
					matched = true
				}
				if p.Kind != "A" || e.RuleID != "other-interpreter" || !one(e.Fact, "interpreter|cgroup") {
					return false
				}
			case "program":
				if p.Kind != "B" || e.Fact != "path" {
					return false
				}
			case "settings":
				if p.Kind != "C" || e.Fact != "settings-path" {
					return false
				}
			}
			cgroup = cgroup || e.Fact == "cgroup"
		}
		switch i.Kind {
		case "mcp_server":
			v := i.Config()
			if !one(s.Catalog, "c3|c4") || len(i.Evidence) != 1 || !one("configured-only", strings.Join(i.Caveats, "|")) || v.Client != i.Name || !one(v.Scope, "user|project|local") || v.Scope == "local" && v.Client != "claude" || !validPath(v.Path) || v.Path == nil || v.Host != nil || !one(v.Transport, "stdio|http|sse|unknown") || !metadataName(v.Server) || v.Arguments < 0 || v.Arguments > 128 {
				return false
			}
			if v.Program != nil && (!catalogProgram(*v.Program) || v.Transport != "stdio") {
				return false
			}
			actual.MCP++
		case "user_unit", "system_unit", "timer":
			v := i.Unit()
			if !one(s.Catalog, "c3|c4") || len(i.Evidence) != 1 || !one("configured-only", strings.Join(i.Caveats, "|")) || v.Path == nil || !validPath(v.Path) || v.Program == nil || !unitProgram(*v.Program, i.Name) || !unitName(v.Name) || v.Arguments < 0 || v.Arguments > 256 {
				return false
			}
			system := i.Kind == "system_unit" || i.Kind == "timer" && v.UID == nil
			if system {
				if s.Mode != "advanced" || s.Catalog != "c4" || v.UID != nil {
					return false
				}
			} else if v.UID == nil || *v.UID == 4294967295 || s.Mode == "basic" && *v.UID != s.As.UID {
				return false
			}
			if i.Kind == "timer" {
				if !strings.HasSuffix(v.Name, ".timer") || v.Triggers == nil || !unitName(*v.Triggers) || !strings.HasSuffix(*v.Triggers, ".service") {
					return false
				}
			} else if !strings.HasSuffix(v.Name, ".service") || v.Triggers != nil {
				return false
			}
			if system {
				actual.SystemUnits++
			} else {
				actual.Units++
			}
		case "cron":
			v := i.Cron()
			if s.Mode != "advanced" || s.Catalog != "c4" || len(i.Evidence) != 1 || !one("configured-only", strings.Join(i.Caveats, "|")) || v.Path == nil || !validPath(v.Path) || v.UID == nil || *v.UID == 4294967295 || v.Program == nil || !unitProgram(*v.Program, i.Name) {
				return false
			}
			actual.Cron++
		case "process", "other_program":
			if !matched {
				return false
			}
			p := i.Process()
			if unreadablePIDs[p.PID] || p.PID < 1 || p.PID > 2147483647 || p.PPID < 0 || p.PPID > 2147483647 || p.UID == 4294967295 || !validPath(p.Exe) || !validPath(p.Cwd) || p.Unit != nil {
				return false
			}
			if s.Mode == "advanced" && p.UID != s.As.Recipient && p.Cwd != nil {
				return false
			}
			if p.Container != nil {
				var v Container
				if s.Mode != "advanced" || s.Catalog != "c4" || i.Kind != "process" || !cgroup || p.Membership == "unknown" || !one("container-hint", strings.Join(i.Caveats, "|")) || json.Unmarshal(*p.Container, &v) != nil || !one(v.Runtime, "docker|podman|containerd") || !containerPattern.MatchString(v.ID) {
					return false
				}
			} else if one("container-hint", strings.Join(i.Caveats, "|")) {
				return false
			}
			if s.Mode == "basic" && p.UID != s.As.UID || s.Mode == "advanced" && i.Kind == "other_program" && p.UID != s.As.Recipient {
				return false
			}
			if _, err := strconv.ParseUint(p.Start, 10, 64); err != nil || len(p.Start) > 20 || p.Start == "" || strings.Trim(p.Start, "0123456789") != "" {
				return false
			}
			switch p.Membership {
			case "in-run":
				if p.RunID == nil || !identity.RunID(*p.RunID).Valid() || !cgroup {
					return false
				}
				if i.Kind == "process" {
					actual.InRun++
				}
			case "outside-run":
				if p.RunID != nil {
					return false
				}
				if i.Kind == "process" {
					actual.Outside++
				}
			case "unknown":
				if p.RunID != nil || !unknown {
					return false
				}
				if i.Kind == "process" {
					actual.Unknown++
				}
			default:
				return false
			}
			if i.Kind == "process" {
				actual.Running++
			} else {
				otherRows++
			}
		case "project":
			if !one(s.Catalog, "c2|c3|c4") || len(i.Evidence) != 1 || !one("declaration-only", strings.Join(i.Caveats, "|")) || i.Project().Path == nil || !validPath(i.Project().Path) {
				return false
			}
			actual.Project++
		case "program", "settings":
			f := i.File()
			if f.Path == nil || !validPath(f.Path) || !validPath(f.Target) || f.Mtime == nil || !one(f.Type, "executable|directory|file") {
				return false
			}
			if i.Kind == "program" {
				if f.Type != "executable" {
					return false
				}
				actual.Installed++
			} else {
				actual.Settings++
			}
		}
	}
	if !count(s.Counts.Other) || s.OtherListed && (otherRows != s.Counts.Other && len(s.Limits) == 0) || !s.OtherListed && otherRows != 0 {
		return false
	}
	actual.Other = s.Counts.Other
	if actual != s.Counts {
		return false
	}
	if (s.Check == "unreadable-observed" || s.Check == "none-observed-allow-unreadable") && (len(s.UnreadableProgramPIDs) == 0 || s.Counts.Outside != 0 || s.Counts.Unknown != 0 || s.Status == "failed" || s.Boot == nil || one("outer-pid-namespace", strings.Join(s.Exclusions, "|"))) {
		return false
	}
	if s.Check == "none-observed" && len(s.UnreadableProgramPIDs) != 0 {
		return false
	}
	if s.Check == "outside-observed" && s.Counts.Outside == 0 || s.Check == "none-observed" && (s.Counts.Outside > 0 || s.Counts.Unknown > 0 || s.Status == "failed" || s.Boot == nil || one("outer-pid-namespace", strings.Join(s.Exclusions, "|"))) {
		return false
	}
	return true
}

func dependencyPath(id, path string) bool {
	switch id {
	case "dep-claude", "dep-codex", "dep-opencode", "dep-gemini", "dep-langgraph-js":
		return filepath.Base(path) == "package.json"
	case "dep-langgraph", "dep-crewai":
		return filepath.Base(path) == "requirements.txt"
	}
	return false
}
func markerPath(id, path string) bool {
	switch id {
	case "marker-langgraph":
		return filepath.Base(path) == "langgraph.json"
	case "marker-crew":
		return filepath.Base(path) == "crew.jsonc"
	case "marker-agents":
		return filepath.Base(path) == "agents.yaml" && filepath.Base(filepath.Dir(path)) == "config"
	}
	return false
}

func metadataName(s string) bool { return len(s) > 0 && len(s) <= 256 && printable(s) }
func catalogProgram(s string) bool {
	return one(s, "claude-native|codex-native|opencode-native|gemini-native")
}
func unitName(s string) bool {
	if !metadataName(s) || !(s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z' || s[0] >= '0' && s[0] <= '9' || s[0] == '_') {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.@:-", r)) {
			return false
		}
	}
	return true
}

func unitProgram(id, name string) bool {
	return strings.HasPrefix(id, name+"-") && one(id, "claude-native|claude-node|codex-native|codex-node|opencode-native|opencode-node|gemini-native|gemini-node-bin|gemini-node-dist")
}
