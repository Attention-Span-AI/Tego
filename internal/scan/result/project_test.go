// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"os"
	"testing"
)

func TestDecodeProjectContract(t *testing.T) {
	b, e := os.ReadFile("../../../spec/scan/v1/fixtures/project.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(b); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ old, new string }{
		{`"dep-langgraph"`, `"https://SECRET"`},
		{`"catalog": "c2"`, `"catalog": "c1"`},
		{`"requirements.txt"`, `"bad.txt"`},
		{`"kind": "F"`, `"kind": "C"`},
		{`"declaration-only"`, `"name-collision"`},
	} {
		mut := bytes.ReplaceAll(b, []byte(tc.old), []byte(tc.new))
		if bytes.Equal(mut, b) {
			if tc.old == `"requirements.txt"` {
				mut = bytes.ReplaceAll(b, []byte("requirements.txt"), []byte("bad.txt"))
			} else {
				t.Fatal("bad mutation")
			}
		}
		if _, e = Decode(mut); e == nil {
			t.Fatalf("accepted %s", tc.old)
		}
	}
}
