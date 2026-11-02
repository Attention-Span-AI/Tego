// SPDX-License-Identifier: Apache-2.0

package mcprelay

import "testing"

// TestAmbiguousKeysRefused: a client message naming its method or its tool twice, exactly or under the case folding
// encoding/json matches by, is unreadable to the relay and never decided on one reading while the server acts on
// another; a message with each key once is read as before.
func TestAmbiguousKeysRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		ok   bool
		tool string
	}{
		{"plain call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a"}}}`, true, "read_file"},
		{"tool named twice", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","name":"read_file"}}`, false, ""},
		{"tool named twice, folded", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","Name":"read_file"}}`, false, ""},
		{"method twice, folded", `{"jsonrpc":"2.0","id":1,"method":"tools/list","METHOD":"tools/call","params":{"name":"x"}}`, false, ""},
		{"params twice", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"},"params":{"name":"delete_file"}}`, false, ""},
		{"Kelvin-sign key folds to k", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","kind":1,"Kind":2}}`, false, ""},
		{"same key deeper in arguments is the server's business", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"p":1,"p":2}}}`, true, "read_file"},
		{"batch with one ambiguous member", `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"a","name":"b"}}]`, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, _, ok := readCalls([]byte(tc.line))
			if ok != tc.ok {
				t.Fatalf("ok %v, want %v", ok, tc.ok)
			}
			if ok && (len(calls) != 1 || calls[0].tool != tc.tool) {
				t.Fatalf("calls %+v, want one call of %q", calls, tc.tool)
			}
		})
	}
}
