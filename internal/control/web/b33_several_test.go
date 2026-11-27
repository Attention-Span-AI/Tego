// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// C125: the service takes up to rules.MaxEdits edits in one transaction; the Several changes at once form offers them.

// anyProgram is the program the tests of this package add to exec.allow when they need one the fixture contract does
// not name. A change is compiled before it is offered, and exec.allow "name" must be an executable the compile finds on
// the PATH (exec-not-on-path), so the name must be a program every Linux has: curl is not on a minimal machine (the
// root-suites guest has none), and the plan still found it on the dev host, because the compile's second try adds the
// directories the fixture run exec'd git from (nextrun.ExecDirs: /usr/bin), which holds curl there. uname is coreutils.
const anyProgram = "uname"

func severalQuery(ref rules.ContractRef, rows [][3]string) url.Values {
	q := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "batch": {"1"}}
	for _, r := range rows {
		q.Add("op", r[0])
		q.Add("key", r[1])
		q.Add("v", r[2])
	}
	return q
}

func TestEditsOf(t *testing.T) {
	good := func(rows ...[3]string) url.Values { return severalQuery(rules.ContractRef{}, rows) }
	many := make([][3]string, 0, rules.MaxEdits+1)
	for i := 0; i <= rules.MaxEdits; i++ {
		many = append(many, [3]string{"add", "fs.write", "./d" + strings.Repeat("x", i) + "/"})
	}
	for _, c := range []struct {
		name string
		v    url.Values
		n    int
		why  string
	}{
		{"one edit, the add form", url.Values{"op": {"add"}, "key": {"fs.write"}, "v": {" ./a/ "}}, 1, ""},
		{"no values", url.Values{}, 0, "Add, remove, or turn an ask into Never allow"},
		{"blank rows are skipped", good([3]string{"add", "fs.write", "./a/"}, [3]string{"add", "fs.write", ""}, [3]string{"remove", "exec.allow", "git"}), 2, ""},
		{"all rows blank", good([3]string{"add", "fs.write", ""}), 0, "Type the entry of at least one change"},
		{"a row names its number", good([3]string{"add", "fs.write", ""}, [3]string{"add", "limits.pids", "9"}), 0, "Change 2: Change one of the lists on Edit rules file"},
		{"twice the same", good([3]string{"add", "fs.write", "./a/"}, [3]string{"add", "fs.write", "./a/"}), 0, "Change 2 is the same as an earlier one"},
		{"arrays out of step", url.Values{"op": {"add", "add"}, "key": {"fs.write"}, "v": {"./a/", "./b/"}}, 0, "Each change needs its action, its list and its entry"},
		{"the most the service takes", good(many[:rules.MaxEdits]...), rules.MaxEdits, ""},
		{"one more", good(many...), 0, "At most 16 changes at once"},
		// The limit is checked before any row is read: a later row that is wrong is not named, and the work done is
		// bounded by the 16, not by the size of the body (the de-duplication is a linear scan).
		{"too many rows are refused before they are read", good(append([][3]string{many[0], {"add", "limits.pids", "9"}}, many[1:]...)...), 0, "At most 16 changes at once"},
		{"a single add form with no entry is still an error", url.Values{"op": {"add"}, "key": {"fs.write"}, "v": {""}}, 0, "Type the entry to add: " + hintOf("fs.write")},
	} {
		got, why := editsOf(c.v)
		if why != c.why || len(got) != c.n {
			t.Errorf("%s: %d edits, %q; want %d, %q", c.name, len(got), why, c.n, c.why)
		}
	}
}

func TestSeveralChangesAtOnce(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	before := readText(t, f.source)
	// The form: sixteen rows, four shown and the rest under More rows, each with its three named fields.
	code, page := f.get(t, "/rules/change?c="+ref.Ref)
	if code != http.StatusOK || !strings.Contains(page, `id="several"`) || !strings.Contains(page, "More rows") ||
		strings.Count(page, `id="sev-v-`) != rules.MaxEdits || strings.Count(page, `name="batch" value="1"`) != 1 {
		t.Fatalf("the Change rules page lacks the Several changes form (%d rows): %d", strings.Count(page, `id="sev-v-`), code)
	}
	rows := [][3]string{{"add", "fs.write", "./more/"}, {"add", "fs.write", ""}, {"add", "exec.allow", anyProgram}, {"remove", "exec.allow", "git"}}
	code, prev := f.get(t, "/rules/change/preview?"+severalQuery(ref, rows).Encode())
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, prev)
	}
	if n := strings.Count(prev, `<input type="hidden" name="op"`); n != 3 {
		t.Errorf("the Save form carries %d edits, want the 3 typed", n)
	}
	for _, want := range []string{"Check the change", "./more/", "Cannot run git", "tego rules check " + f.source, "then check them"} {
		if !strings.Contains(prev, want) {
			t.Errorf("the several preview lacks %q", want)
		}
	}
	if readText(t, f.source) != before || journalLen(t, f.root) != 0 {
		t.Fatal("a preview wrote")
	}
	// Save: the confirm's hidden fields are what the preview checked; one journal entry, all three edits in the file.
	form := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"add", "add", "remove"}, "key": {"fs.write", "exec.allow", "exec.allow"},
		"v": {"./more/", anyProgram, "git"}}
	form.Set("ack", ackIn(t, prev))
	_, saved := f.save(t, "/rules/change", form)
	after := readText(t, f.source)
	if !strings.Contains(after, "./more/") || !strings.Contains(after, anyProgram) || strings.Contains(after, "git]") || journalLen(t, f.root) != 1 {
		t.Fatalf("the three edits are not one journal entry in the file (journal %d):\n%s\n%s", journalLen(t, f.root), after, saved)
	}
	// Undo takes the whole transaction back.
	id := regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(saved)
	base := regexp.MustCompile(`action="/rules/revert"[^>]*>(?:<[^>]+>)*?<input type="hidden" name="base" value="([0-9a-f]+)"`).FindStringSubmatch(saved)
	if id == nil || base == nil {
		t.Fatalf("no Undo on the Saved page:\n%s", saved)
	}
	undo := url.Values{"c": {ref.Ref}, "id": {id[1]}, "base": {base[1]}}
	if m := ackField.FindStringSubmatch(saved); m != nil {
		undo.Set("ack", m[1])
	}
	if code, body := f.post(t, "/rules/revert", undo); code == http.StatusBadRequest && strings.Contains(body, "Next run may do more") {
		undo.Set("ack", ackIn(t, body))
		f.save(t, "/rules/revert", undo)
	}
	if readText(t, f.source) != before {
		t.Error("Undo did not give back the text from before the three edits")
	}
}

// One bad edit among several writes none of them, and the form says so and keeps what was typed.
func TestSeveralChangesAreOneTransaction(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	before := readText(t, f.source)
	// A second row the contract refuses: an ask scope outside everything it may write.
	rows := [][3]string{{"add", "fs.write", "./more/"}, {"add", "fs.ask", "/nowhere/else/"}}
	code, body := f.get(t, "/rules/change/preview?"+severalQuery(ref, rows).Encode())
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, `id="several" open`) || !strings.Contains(body, `value="./more/"`) || !strings.Contains(body, `value="/nowhere/else/"`) ||
		!strings.Contains(body, `href="#several"`) {
		t.Errorf("the refused transaction's page (%d) does not reopen the form with its rows and a link to it", code)
	}
	// A row naming a mistake is named by its number, and nothing is previewed.
	code, body = f.get(t, "/rules/change/preview?"+severalQuery(ref, [][3]string{{"add", "fs.write", "./more/"}, {"chmod", "fs.write", "./x/"}}).Encode())
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Change 2: Add, remove, or turn an ask into Never allow") {
		t.Errorf("the mistaken row is not named (%d)", code)
	}
	// Confirming the refused pair directly writes nothing either.
	form := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"add", "add"}, "key": {"fs.write", "fs.ask"}, "v": {"./more/", "/nowhere/else/"}, "ack": {"x"}}
	if code, _ := f.post(t, "/rules/change", form); code == http.StatusSeeOther {
		t.Errorf("the refused pair was accepted: %d", code)
	}
	if readText(t, f.source) != before || journalLen(t, f.root) != 0 {
		t.Error("a refused transaction wrote part of itself")
	}
}
