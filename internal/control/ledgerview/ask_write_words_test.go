// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"
)

// TestHeldWriteIsNotWordedOpen (C116): a file open the contract's fs.ask entry holds is a write, so the line page's
// sentence for the ask and the answer names the change ("write to"), not "open".
func TestHeldWriteIsNotWordedOpen(t *testing.T) {
	x, seqs := codexShaped(t)
	seqs["ask"] = x.add(410, `"kind":"ask","source":"supervisor","ask_id":"q-w","ask_rule":"fs.ask[./out/]","hold":"open","op":"open","target":"/home/u/proj/out/a.txt"`)
	seqs["answer"] = x.add(410, `"kind":"answer","source":"supervisor","after_s":2,"approved":true,"ask_id":"q-w","ask_rule":"fs.ask[./out/]","by":"uid:1000 pid:77 dashboard","op":"open","target":"/home/u/proj/out/a.txt"`)
	r := x.write(t)
	for _, name := range []string{"ask", "answer"} {
		lv, err := Explain(x.root, r, seqs[name])
		if err != nil {
			t.Fatal(err)
		}
		s := lv.Ask.Sentence + " | " + lv.Sentence
		if !strings.Contains(lv.Ask.Sentence, "asked to write to /home/u/proj/out/a.txt") || strings.Contains(s, "to open") || strings.Contains(s, ": open ") {
			t.Errorf("%s: sentence %q", name, s)
		}
	}
}
