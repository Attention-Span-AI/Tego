// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

// TestAPrefixedHintSaysWhereToTypeIt: a next: command that begins with sudo -u <account> (forReader) is for the
// reader's own login shell. In a shell sudo or su opened, the account may not use sudo ("svc is not in the sudoers
// file", acceptance 4), so a guidance line before the block says to type exit first. A bare command, and a sudo
// command Tego wrote anyway, get no such line.
func TestAPrefixedHintSaysWhereToTypeIt(t *testing.T) {
	guidetest.SelfAs(t, guidetest.SelfWord, "")
	prev := readerAccount
	t.Cleanup(func() { readerAccount = prev })
	hintsAt(t, false, "on")
	const note = "The command below is for your own login shell: sudo runs it as the account tego ran as (in a shell sudo or su opened, type exit first)."
	for _, tc := range []struct {
		reader, command string
		note            bool
	}{
		{"svc", "tego receipt abc", true},
		{"svc", "sudo loginctl enable-linger svc", false},
		{"", "tego receipt abc", false},
	} {
		readerAccount = func() string { return tc.reader }
		var b bytes.Buffer
		writeHint(&b, "see it:", tc.command)
		if got := strings.Contains(b.String(), note); got != tc.note {
			t.Errorf("reader %q, %q: note %v, want %v:\n%s", tc.reader, tc.command, got, tc.note, b.String())
		}
		if i := strings.Index(b.String(), "next: "); tc.note && (i < 0 || strings.Index(b.String(), note) > i) {
			t.Errorf("the note does not come before the next: block:\n%s", b.String())
		}
	}
}

// TestTheShellFormSaysSudoersMayRefuseIt: the nested form, sudo -u svc sh -c 'cd <dir> && exec <tego> ...', needs a sudoers
// grant to run a shell as the account; a grant for the tego binary alone refuses it, and Tego cannot read the policy. The
// guidance line before the block says so and does not promise the line works; the plain form does not carry the sentence.
func TestTheShellFormSaysSudoersMayRefuseIt(t *testing.T) {
	guidetest.SelfAs(t, guidetest.SelfWord, "")
	prev := readerAccount
	t.Cleanup(func() { readerAccount = prev })
	readerAccount = func() string { return "svc" }
	hintsAt(t, false, "on")
	const sentence = "It runs sh as the account, which your sudoers may not allow; if sudo refuses it, open a shell as the account and run the same command there."
	var b bytes.Buffer
	writeHint(&b, "run it:", "cd /home/svc/bot && tego run bot")
	if !strings.Contains(b.String(), sentence) || strings.Contains(b.String(), "will work") {
		t.Errorf("the shell form does not warn:\n%s", b.String())
	}
	b.Reset()
	writeHint(&b, "see it:", "tego receipt abc")
	if strings.Contains(b.String(), sentence) {
		t.Errorf("the plain form carries the shell warning:\n%s", b.String())
	}
}
