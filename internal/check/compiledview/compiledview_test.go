// SPDX-License-Identifier: Apache-2.0

package compiledview

import "testing"

func TestDeclarationUsesSharedCompiledSentences(t *testing.T) {
	d := NewDeclaration("agent.yaml")
	d.Name = "fixture"
	d.HasFS, d.HasExec, d.HasNet = true, true, true
	d.ExecAllowKey = true
	d.Lists[kFSWrite] = []Item{{Entry: "./src/"}}
	d.Lists[kExecAllow] = []Item{{Entry: "git status"}}
	d.Lists[kNetAllow] = []Item{{Entry: "tcp://example.test:443"}}
	d.Limits = []Limit{{Key: "memory", Value: "4GiB"}}
	v := Build(d, nil, "", "")
	want := map[string]string{
		kFSWrite:        "Can change files in ./src/",
		kExecAllow:      "Can run git status",
		kNetAllow:       "Can connect to example.test on port 443",
		"limits.memory": "Can use at most 4 GiB of memory",
	}
	for _, r := range v.Rules() {
		if sentence, ok := want[r.Key]; ok {
			if r.Sentence != sentence {
				t.Errorf("%s: got %q, want %q", r.Key, r.Sentence, sentence)
			}
			delete(want, r.Key)
		}
		if r.State != StateNone {
			t.Errorf("declaration acquired enforcement claim: %+v", r)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing declarations: %v", want)
	}
}
