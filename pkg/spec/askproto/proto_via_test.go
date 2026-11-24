// SPDX-License-Identifier: Apache-2.0

package askproto

import "testing"

func TestDecodeCommandVia(t *testing.T) {
	nonce := "0123456789abcdef0123456789abcdef"
	id := "q-0123456789abcdef0123456789abcdef"
	for _, c := range []struct {
		name, packet string
		ok           bool
		via          string
	}{
		{"answer by the dashboard", `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"via":"dashboard"}`, true, ViaDashboard},
		{"answer through its relay", `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":false,"via":"dashboard relay"}`, true, ViaDashboardRelay},
		{"answer, no claim", `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true}`, true, ""},
		{"a value nobody sends", `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"via":"root"}`, false, ""},
		{"an empty claim", `{"action":"answer","nonce":"` + nonce + `","ask_id":"` + id + `","approve":true,"via":""}`, false, ""},
		{"list takes none", `{"action":"list","nonce":"` + nonce + `","via":"dashboard"}`, false, ""},
		{"detail takes none", `{"action":"detail","nonce":"` + nonce + `","ask_id":"` + id + `","via":"dashboard"}`, false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeCommand([]byte(c.packet))
			if (err == nil) != c.ok || got.Via != c.via {
				t.Errorf("DecodeCommand = %+v, %v; want ok %v via %q", got, err, c.ok, c.via)
			}
		})
	}
}

func TestByWords(t *testing.T) {
	for in, want := range map[string]string{
		"uid:26743 pid:912":                  "uid:26743 pid:912",
		"uid:26743 pid:912 dashboard":        "uid:26743 pid:912, answered in the dashboard by the person signed in to it",
		"uid:26743 pid:912 dashboard always": "uid:26743 pid:912 always, answered in the dashboard by the person signed in to it",
		"uid:26743 pid:912 dashboard relay":  "uid:26743 pid:912, answered in the dashboard by the person signed in to it, from a browser on another system through the dashboard's relay",
		"standing:q-1":                       "standing:q-1",
		"service:dashboard":                  "service:dashboard",
		"x dashboard":                        "x dashboard",
	} {
		if got := ByWords(in); got != want {
			t.Errorf("ByWords(%q) = %q, want %q", in, got, want)
		}
	}
}
