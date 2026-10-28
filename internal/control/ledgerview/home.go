// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"path"
	"strings"
)

// RunHome is the folder the dashboard shows as "~/" for a run's paths. The run's HOME is not recorded in run_start
// (a known shortcut), so this is a display rule, never a fact the dashboard acts on: a folder named home beside the
// run's working directory tree (a demo's with/home next to with/proj) when the run touched a path under it, else
// /home/<the user who started the run>, else "". The full path always stays in the page's title attribute.
func RunHome(r *Run) string {
	if r == nil {
		return ""
	}
	m := r.memoOf()
	m.homeOnce.Do(func() { m.home = runHome(r) })
	return m.home
}

// runHome is RunHome, worked out from the run's lines (once per version of the run, runMemo).
func runHome(r *Run) string {
	if r.Cwd != "" {
		if parent := path.Dir(r.Cwd); strings.Count(parent, "/") >= 2 {
			cand := parent + "/home"
			evs := r.AllEvents()
			for i := range evs {
				e := &evs[i]
				switch e.Kind {
				case "fs", "refused":
				case "ask":
					if strings.HasPrefix(e.askTarget, cand+"/") {
						return cand
					}
					continue
				default:
					continue
				}
				if strings.HasPrefix(e.Target, cand+"/") {
					return cand
				}
			}
		}
	}
	if r.User != "" && !strings.Contains(r.User, "/") {
		return "/home/" + r.User
	}
	return ""
}
