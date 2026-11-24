// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

type builderField struct{ Key, Meaning string }
type builderError struct{ Field, Message string }
type builderLine struct {
	N       int
	Text    string
	Changed bool
	RuleIDs []string
}

// Field definitions follow spec/agent/v0/agent.schema.json. The real compiler alone validates values.
var builderFields = func() []builderField {
	b, _ := assets.ReadFile("static/builder-fields.json")
	var guide struct{ Fields []builderField }
	if err := json.Unmarshal(b, &guide); err != nil {
		panic(err)
	}
	return guide.Fields
}()

func builderView(r *http.Request) string {
	v := r.FormValue("view")
	if v == "" && r.FormValue("raw") == "1" {
		v = "full"
	}
	if v == "" {
		v = r.FormValue("current-view")
	}
	if v != "simple" && v != "full" {
		if c, err := r.Cookie("tego-builder-view"); err == nil {
			v = c.Value
		}
	}
	if v != "full" {
		return "simple"
	}
	return v
}

func builderLines(text, source string, decisions []rules.Decision) []builderLine {
	old := strings.Split(source, "\n")
	var out []builderLine
	for i, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		line := builderLine{N: i + 1, Text: l, Changed: i >= len(old) || old[i] != l}
		for _, d := range decisions {
			if !d.Drop && d.Line == i+1 {
				line.RuleIDs = append(line.RuleIDs, d.ID)
			}
		}
		out = append(out, line)
	}
	return out
}

func newBuilderErrors(p *rules.NewPlan, view, mode string) []builderError {
	var out []builderError
	fieldOf := func(msg string) string {
		if view == "full" {
			return "builder-text"
		}
		for _, row := range []struct{ key, field string }{
			{"limits.wall", "builder-wall"}, {"net.ask", "builder-ask-hosts"},
			{"fs.ask_read", "builder-askread"}, {"fs.write", "builder-writes"},
			{"env.pass", "builder-pass"}, {"net.allow", "builder-hosts"},
			{"live.fence.read", "builder-fence-read"}, {"live.fence.net", "builder-fence-net"}, {"live.fence.exec", "builder-fence-exec"},
			{"command", "builder-command"}, {"destination", "builder-hosts"},
		} {
			if strings.Contains(strings.ToLower(msg), row.key) {
				return row.field
			}
		}
		return "builder-full-view"
	}
	for _, msg := range p.Problems {
		field := "builder-source"
		low := strings.ToLower(msg)
		if mode == "run" && p.FromRun == "" && strings.Contains(low, "preset") {
			msg, low = "Choose a finished run first.", "choose a finished run first."
		}
		switch {
		case strings.Contains(low, "run id") || strings.HasPrefix(low, "run ") || strings.Contains(low, "choose a finished run"):
			field = "builder-run"
		case strings.Contains(low, "preset"):
			field = "builder-presets"
		case strings.Contains(low, "name"):
			field = "builder-name"
		case strings.Contains(low, "folder") || strings.Contains(low, "directory"):
			field = "builder-dir"
		case strings.Contains(low, "hosts to ask"):
			field = "builder-ask-hosts"
		case strings.Contains(low, "host"):
			field = "builder-hosts"
		case strings.Contains(low, "compile"):
			field = fieldOf(msg)
		}
		for _, d := range p.Decisions {
			if d.Err != "" && strings.Contains(msg, d.Err) {
				field = "builder-host-" + d.ID
			}
		}
		out = append(out, builderError{Field: field, Message: msg})
	}
	for _, msg := range p.Diagnostics {
		if strings.HasPrefix(msg, "error:") {
			out = append(out, builderError{Field: fieldOf(msg), Message: msg})
		}
	}
	// The required source choice remains actionable even when an earlier preflight refuses.
	if mode == "run" && p.FromRun == "" && !builderHasError(out, "builder-run") {
		out = append(out, builderError{Field: "builder-run", Message: "Choose a finished run first."})
	}
	return out
}

func builderErrorText(es []builderError, key string) string {
	var words []string
	for _, e := range es {
		if e.Field == key {
			words = append(words, e.Message)
		}
	}
	return strings.Join(words, " ")
}

func rememberBuilderView(w http.ResponseWriter, view string) {
	http.SetCookie(w, &http.Cookie{Name: "tego-builder-view", Value: view, Path: "/rules", MaxAge: 365 * 24 * 60 * 60, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func builderHasError(es []builderError, key string) bool {
	for _, e := range es {
		if e.Field == key {
			return true
		}
	}
	return false
}
