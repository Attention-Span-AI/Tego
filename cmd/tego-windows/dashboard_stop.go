// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// What `tego dashboard --stop` and the mirrored-networking check decide, as pure functions over what was read, so they
// are tested on Linux (the Windows-only files run them).

// releaseLinePrefix starts the line `tego dashboard-relay release` prints (internal/cli dashboard_relay.go).
const releaseLinePrefix = "TEGO_DASHBOARD_RELEASE "

type releaseKind int

const (
	releaseUnknown releaseKind = iota // not asked, could not be asked, or the answer was not understood
	releaseDone                       // the dashboard's unit is stopped (or none was running)
	releaseKept                       // runs are going: nothing was stopped
)

// releaseResult is what Tego's Linux said to the release: the kind, whether a dashboard unit was running and how many
// runs kept it.
type releaseResult struct {
	kind       releaseKind
	wasRunning bool
	runs       int
}

// parseReleaseLine reads the release's line out of what the Linux command printed. WSL may print warnings of its own
// before it, so the last line of the fixed shape counts; a line of another shape is "unknown", never a guess.
func parseReleaseLine(out string) releaseResult {
	var line string
	for _, l := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimRight(l, "\r"), releaseLinePrefix); ok {
			line = rest
		}
	}
	f := strings.Fields(line)
	switch {
	case len(f) == 2 && f[0] == "released" && (f[1] == "was=running" || f[1] == "was=none"):
		return releaseResult{kind: releaseDone, wasRunning: f[1] == "was=running"}
	case len(f) == 2 && f[0] == "kept" && strings.HasPrefix(f[1], "runs="):
		n, err := strconv.Atoi(strings.TrimPrefix(f[1], "runs="))
		if err != nil || n < 1 || strconv.Itoa(n) != strings.TrimPrefix(f[1], "runs=") {
			return releaseResult{}
		}
		return releaseResult{kind: releaseKept, runs: n}
	}
	return releaseResult{}
}

// reopenWords ends every message that stopped something: the one command to run for the dashboard again.
const reopenWords = "To open the dashboard again, run: tego dashboard"

// dashboardStopWords is what `tego dashboard --stop` says. relayEnded: a relay of this user was running and is ended.
// linuxUp: Tego's Linux was running, so it was asked (rel); a Linux that was not running holds nothing of the
// dashboard's. The words are true in every case: Linux can stop by itself only when no run is going and the dashboard's
// unit is stopped; with runs going it stays up for them, and the person is told how many.
func dashboardStopWords(relayEnded, linuxUp bool, rel releaseResult) string {
	var parts []string
	if relayEnded {
		parts = append(parts, "Stopped the dashboard's connection to your browser.")
	}
	switch {
	case !linuxUp:
		if !relayEnded {
			return "No dashboard relay is running."
		}
	case rel.kind == releaseDone && rel.wasRunning:
		if !relayEnded {
			parts = append(parts, "No dashboard relay was running.")
		}
		parts = append(parts, "Stopped the dashboard in Tego's Linux too: nothing of it keeps Linux running now, so Windows can stop Tego's Linux shortly after the last tego command or Linux shell ends.")
	case rel.kind == releaseDone:
		if !relayEnded {
			return "No dashboard is running."
		}
		parts = append(parts, "No dashboard was running in Tego's Linux.")
	case rel.kind == releaseKept:
		parts = append(parts, fmt.Sprintf("%s still going, so Tego's Linux stays up and the dashboard keeps running there: Windows stopping Tego's Linux would end %s. Run tego dashboard --stop again when %s ended.",
			runsWords(rel.runs, "is", "are"), thisRun(rel.runs), haveHas(rel.runs)))
	default:
		parts = append(parts, `Could not check whether a run is going in Tego's Linux, so the dashboard there keeps running and Linux stays up. To stop it yourself: tego shell -c "systemctl --user stop tego-dashboard"`)
	}
	if relayEnded || rel.kind == releaseDone && rel.wasRunning || rel.kind == releaseKept {
		parts = append(parts, reopenWords)
	}
	return strings.Join(parts, " ")
}

func runsWords(n int, one, many string) string {
	if n == 1 {
		return "1 run " + one
	}
	return strconv.Itoa(n) + " runs " + many
}

func thisRun(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

func haveHas(n int) string {
	if n == 1 {
		return "it has"
	}
	return "they have"
}

// listsDistribution reports whether the output of `wsl.exe --list --running --quiet` names the distribution: one name
// per line, in UTF-16 (little endian) unless WSL was asked for UTF-8; both are read, a byte order mark and the NULs of
// the wide form dropped. The message "there are no running distributions" is not a name.
func listsDistribution(out []byte, name string) bool {
	out = bytes.TrimPrefix(out, []byte{0xff, 0xfe})
	out = bytes.TrimPrefix(out, []byte{0xef, 0xbb, 0xbf})
	out = bytes.ReplaceAll(out, []byte{0}, nil)
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(l), "(Default)"))
		if strings.EqualFold(l, name) {
			return true
		}
	}
	return false
}
