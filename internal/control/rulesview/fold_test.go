// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/check/inforce"
)

// TestFoldDevices: two or more terminal device rules of one effect fold into one row where the first stood, each
// kept whole and in order; a lone device rule and every other rule stay their own rows.
func TestFoldDevices(t *testing.T) {
	r := func(entry string, eff inforce.Effect) inforce.Rule {
		return inforce.Rule{Entry: entry, Effect: eff, Sentence: "Can change " + entry}
	}
	rules := []inforce.Rule{
		r("./src/", inforce.EffectAllow), r("/dev/null", inforce.EffectAllow), r("./tmp/", inforce.EffectAllow),
		r("/dev/tty", inforce.EffectAllow), r("/dev/ptmx", inforce.EffectAllow), r("/dev/pts/", inforce.EffectAllow),
		r("/dev/pts/3", inforce.EffectDeny), r("/dev/shm/", inforce.EffectAllow),
	}
	got := FoldDevices(rules)
	want := []struct {
		entry string
		devs  int
	}{{"./src/", 0}, {"/dev/null", 4}, {"./tmp/", 0}, {"/dev/pts/3", 0}, {"/dev/shm/", 0}}
	if len(got) != len(want) {
		t.Fatalf("%d rows, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Rule.Entry != w.entry || len(got[i].Devices) != w.devs {
			t.Errorf("row %d: %q with %d devices, want %q with %d", i, got[i].Rule.Entry, len(got[i].Devices), w.entry, w.devs)
		}
	}
	if d := got[1].Devices; d[0].Entry != "/dev/null" || d[3].Entry != "/dev/pts/" {
		t.Errorf("fold order: %+v", d)
	}
	if one := FoldDevices([]inforce.Rule{r("/dev/null", inforce.EffectAllow)}); len(one) != 1 || one[0].Devices != nil {
		t.Errorf("a lone device folded: %+v", one)
	}
}
