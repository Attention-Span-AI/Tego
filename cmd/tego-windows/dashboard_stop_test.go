// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestParseReleaseLine(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		want      releaseResult
	}{
		{"stopped", "TEGO_DASHBOARD_RELEASE released was=running\n", releaseResult{kind: releaseDone, wasRunning: true}},
		{"nothing to stop", "TEGO_DASHBOARD_RELEASE released was=none\n", releaseResult{kind: releaseDone}},
		{"runs going", "TEGO_DASHBOARD_RELEASE kept runs=3\n", releaseResult{kind: releaseKept, runs: 3}},
		{"unknown", "TEGO_DASHBOARD_RELEASE unknown\n", releaseResult{}},
		{"a WSL warning first", "wsl: Failed to mount\r\nTEGO_DASHBOARD_RELEASE kept runs=1\r\n", releaseResult{kind: releaseKept, runs: 1}},
		{"nothing printed", "", releaseResult{}},
		{"zero runs is no keeping", "TEGO_DASHBOARD_RELEASE kept runs=0\n", releaseResult{}},
		{"padded number", "TEGO_DASHBOARD_RELEASE kept runs=02\n", releaseResult{}},
		{"not a number", "TEGO_DASHBOARD_RELEASE kept runs=x\n", releaseResult{}},
		{"another word", "TEGO_DASHBOARD_RELEASE gone\n", releaseResult{}},
		{"extra field", "TEGO_DASHBOARD_RELEASE released was=running now\n", releaseResult{}},
		{"another line kind", "TEGO_DASHBOARD_OPEN port=8484\n", releaseResult{}},
	} {
		if got := parseReleaseLine(tc.out); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// What --stop says is true in every case, in one paragraph, and promises no duration.
func TestDashboardStopWords(t *testing.T) {
	stopped := releaseResult{kind: releaseDone, wasRunning: true}
	for _, tc := range []struct {
		name               string
		relay, up          bool
		rel                releaseResult
		has, lacks         []string
		exactlyThisMessage string
	}{
		{name: "relay ended, dashboard stopped, nothing going", relay: true, up: true, rel: stopped,
			has:   []string{"Stopped the dashboard's connection to your browser.", "Stopped the dashboard in Tego's Linux too", "Windows can stop Tego's Linux", reopenWords},
			lacks: []string{"stays up", "still going"}},
		{name: "relay ended, one run going", relay: true, up: true, rel: releaseResult{kind: releaseKept, runs: 1},
			has:   []string{"Stopped the dashboard's connection to your browser.", "1 run is still going", "Tego's Linux stays up", "would end it", "again when it has ended", reopenWords},
			lacks: []string{"Windows can stop Tego's Linux"}},
		{name: "relay ended, three runs going", relay: true, up: true, rel: releaseResult{kind: releaseKept, runs: 3},
			has: []string{"3 runs are still going", "would end them", "again when they have ended"}},
		{name: "relay ended, Linux not asked to tell", relay: true, up: true, rel: releaseResult{},
			has:   []string{"Could not check whether a run is going", "Linux stays up", `systemctl --user stop tego-dashboard`, reopenWords},
			lacks: []string{"Windows can stop Tego's Linux"}},
		{name: "relay ended, Linux already stopped", relay: true, up: false,
			has: []string{"Stopped the dashboard's connection to your browser.", reopenWords}, lacks: []string{"Linux stays up"}},
		{name: "no relay, a dashboard in Linux", up: true, rel: stopped,
			has: []string{"No dashboard relay was running.", "Stopped the dashboard in Tego's Linux too", reopenWords}},
		{name: "no relay, a dashboard in Linux, a run going", up: true, rel: releaseResult{kind: releaseKept, runs: 2},
			has: []string{"2 runs are still going", reopenWords}},
		{name: "nothing running, Linux up", up: true, rel: releaseResult{kind: releaseDone}, exactlyThisMessage: "No dashboard is running."},
		{name: "nothing running, Linux stopped", exactlyThisMessage: "No dashboard relay is running."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dashboardStopWords(tc.relay, tc.up, tc.rel)
			if tc.exactlyThisMessage != "" && got != tc.exactlyThisMessage {
				t.Fatalf("%q, want %q", got, tc.exactlyThisMessage)
			}
			for _, w := range tc.has {
				if !strings.Contains(got, w) {
					t.Errorf("lacks %q: %s", w, got)
				}
			}
			for _, w := range tc.lacks {
				if strings.Contains(got, w) {
					t.Errorf("must not say %q: %s", w, got)
				}
			}
			if strings.Contains(got, "\n") {
				t.Errorf("one paragraph: %q", got)
			}
			for _, bad := range []string{"second", "minute", "24/7", "forever", "always"} {
				if strings.Contains(strings.ToLower(got), bad) {
					t.Errorf("promises or measures something it must not (%q): %s", bad, got)
				}
			}
		})
	}
}

// The distribution's name is read out of wsl.exe's list in both of its encodings; a message is no name.
func TestListsDistribution(t *testing.T) {
	wide := func(s string) []byte {
		b := []byte{0xff, 0xfe}
		for _, r := range s {
			b = append(b, byte(r), 0)
		}
		return b
	}
	for _, tc := range []struct {
		name string
		out  []byte
		want bool
	}{
		{"utf-16", wide("Ubuntu\r\ntego\r\n"), true},
		{"utf-8", []byte("tego\n"), true},
		{"upper case", []byte("TEGO\r\n"), true},
		{"default mark", []byte("tego (Default)\n"), true},
		{"another only", wide("Ubuntu\r\n"), false},
		{"a longer name", []byte("tego-old\n"), false},
		{"the none message", []byte("There are no running distributions.\n"), false},
		{"nothing", nil, false},
	} {
		if got := listsDistribution(tc.out, "tego"); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}
