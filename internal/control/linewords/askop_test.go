// SPDX-License-Identifier: Apache-2.0

package linewords

import "testing"

// TestAskOpNamesTheChange (C116): a held open is a write under fs.ask and a read under fs.ask_read; nothing else
// moves.
func TestAskOpNamesTheChange(t *testing.T) {
	for _, c := range []struct{ op, rule, want string }{
		{"open", "fs.ask[./out/]", "write"}, {"open", "fs.ask_read[./s/]", "read"}, {"open", "", "open"},
		{"open", "fs.write[./]", "open"}, {"unlink", "fs.ask[./]", "unlink"}, {"read", "fs.ask_read[./s/]", "read"},
	} {
		if got := AskOp(c.op, c.rule); got != c.want {
			t.Errorf("AskOp(%q, %q) = %q, want %q", c.op, c.rule, got, c.want)
		}
	}
}
