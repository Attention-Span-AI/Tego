// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// baselinePostAllowed keeps observation-mode config loads from authorizing a live change.
// Every action POST passes this guard, including changes that bypass contract compilation (ADR 0144).
func (s *Server) baselinePostAllowed(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.Machine.BaselineKnown() {
		return true
	}
	if r.URL.Path == "/approvals/answer" && r.PostForm.Get("decision") == "deny" {
		return true
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/runs/"); ok {
		parts := strings.Split(rest, "/")
		if len(parts) == 2 && parts[0] != "" && (parts[1] == "stop" || parts[1] == "pause") {
			return true
		}
	}
	http.Error(w, "tego-control serve: "+s.baselineNotice(), http.StatusServiceUnavailable)
	return false
}

func (s *Server) baselineNotice() string {
	baseline, known := s.cfg.Machine.BaselineSnapshot()
	if known {
		if !baseline.Empty() {
			return "Machine baseline entries were read but are NOT YET APPLIED to any run. They do not enforce refusals yet."
		}
		return ""
	}
	var reasons []string
	if s.cfg.Machine != nil {
		for _, source := range s.cfg.Machine.LayerSources() {
			if source.State == config.LayerUnknown {
				where := source.Layer.String() + " layer"
				if source.File != "" {
					where += " " + source.File
				}
				reasons = append(reasons, where+": "+source.Reason)
			}
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no machine config snapshot is available")
	}
	return "Machine baseline UNKNOWN: it could not be read. " + strings.Join(reasons, "; ") +
		". Stop, Pause and Deny remain available. Restore the config and restart the dashboard before making other changes."
}
