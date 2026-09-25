// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

// FuzzLoadTestTable holds LoadTestTableBytes to its contract: a table or an error, never both and never
// neither; an error always comes with an error diagnostic; and a table it returns has at least one row, each
// with an action and an expectation, and no NUL in any value.
func FuzzLoadTestTable(f *testing.F) {
	for _, s := range []string{
		"version: 0\ntests:\n  - {action: fs.read, path: /x, expect: allow}\n",
		"version: 0\ntests:\n  - {action: net.connect, host_port: \"[::1]:80\", expect: refused, tier: landlock}\n",
		"version: 0\ntests:\n  - {action: exec, argv: [a, b], expect: refused, rule: x}\n",
		"version: 0\ntests:\n  - {action: fs.rename, path: a, dest: b, expect: ask}\n",
		"version: 0\ntests:\n  - {action: fs.read, path: /etc/passwd, expect: allow}\n---\ntests:\n  - {action: fs.read, path: /x, expect: refused}\n",
		"version: 0\ntests: []\n",
		"version: 0\ntests:\n  - {action: fs.read, path: !!binary L2V0Yy9zaGFkb3c=, expect: allow}\n",
		"version: 0\ntests:\n  - {action: fs.read, path: \"/a\\u0000b\", expect: allow}\n",
		"version: 00\ntests:\n  - {action: fs.read, path: /x, expect: allow}\n",
		"version: \"0\"\ntests:\n  - {action: fs.read, path: /x, expect: allow}\n",
		"\xef\xbb\xbfversion: 0\ntests:\n  - {action: fs.read, path: \"~/x\", expect: allow}\n",
		"tests:\n  - {action: fs.read, path: ~root/x, expect: allow}\n",
		"tests:\n  - {action: net.connect, host_port: \"[fe80::1%eth0]:443\", expect: allow}\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		tt, ds, err := LoadTestTableBytes("t.yaml", data)
		if (err == nil) != (tt != nil) {
			t.Fatalf("err=%v table=%v", err, tt)
		}
		if err != nil {
			if !HasErrors(ds) {
				t.Fatalf("error without an error diagnostic: %v", err)
			}
			return
		}
		if len(tt.Rows) == 0 {
			t.Fatalf("a table with no rows was accepted")
		}
		for _, r := range tt.Rows {
			if r.Action == "" || r.Expect == "" {
				t.Fatalf("row without action or expect: %+v", r)
			}
			for _, v := range append([]string{r.Name, r.Path, r.Dest, r.Script, r.Host, r.Rule}, r.Argv...) {
				if strings.ContainsRune(v, 0) {
					t.Fatalf("NUL in a row value: %+v", r)
				}
			}
		}
	})
}
