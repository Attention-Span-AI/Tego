// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestRulesPageSaysWhichLaunchContextItShows (C135): one rules file ran from two folders at two tiers. Opened by its
// file, the page shows the newest run's rules, and says where that run started and where the others did, since a
// relative entry and an automatic tier mean something else in each place and a change is checked as the newest run
// started. A file whose runs all started in one place says nothing of the kind.
func TestRulesPageSaysWhichLaunchContextItShows(t *testing.T) {
	f := newRulesFix(t)
	// A third run of rulesSource, from another folder at another tier, the newest of the file.
	elsewhere := f.proj + "/elsewhere"
	f.runAt(t, "r-aaaaaaaa-0000000000034-rulesx", f.source, rulesSource, time.Now().Add(-30*time.Minute).UTC().Truncate(time.Millisecond), false,
		elsewhere, "cgroup", `"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	ref := f.svcRef(t, f.source)
	code, body := f.get(t, "/rules?c="+ref)
	if code != http.StatusOK {
		t.Fatalf("GET: %d %s", code, body)
	}
	for _, want := range []string{
		"started in " + elsewhere + " at tier cgroup",
		"started in " + f.proj + " at tier landlock",
		"relative entry",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/rules?c= lacks %q", want)
		}
	}
	// Another run of the same file asked for by id says it is that run's context.
	code, body = f.get(t, "/rules?run="+rulesRunA)
	if code != http.StatusOK {
		t.Fatalf("GET run: %d", code)
	}
	if !strings.Contains(body, "started in "+f.proj+" at tier landlock") {
		t.Errorf("/rules?run=A does not say where run A started")
	}
	// A file whose runs all started in one place (the other agent's file here) says nothing of it.
	other := f.svcRef(t, f.other)
	_, body = f.get(t, "/rules?c="+other)
	if strings.Contains(body, "relative entry") {
		t.Error("a file with one launch context carries a context note")
	}
}
