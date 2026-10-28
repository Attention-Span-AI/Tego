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

// TestOpenDefault: only the wide-open defaults are marked.
func TestOpenDefault(t *testing.T) {
	for _, c := range []struct {
		group, def string
		open       bool
	}{
		{inforce.GroupNetwork, "Can connect to any address. Other programs' local sockets stay closed (see Always on).", true},
		{inforce.GroupNetwork, "Can connect anywhere, other programs' local sockets included.", true},
		{inforce.GroupNetwork, "Cannot connect anywhere else.", false},
		{inforce.GroupPrograms, "Can run any program.", true},
		{inforce.GroupPrograms, "Can run any other program.", true},
		{inforce.GroupPrograms, "Cannot run any other program.", false},
		{inforce.GroupEnv, "Gets every variable in your shell, secrets included.", true},
		{inforce.GroupEnv, "Every other variable in your shell, secrets included, is removed before it starts.", false},
		{inforce.GroupRead, "Can read any other file on this computer, except the ones under Never reads and Always on.", false},
	} {
		if got := OpenDefault(c.group, c.def); got != c.open {
			t.Errorf("%s %q: open %v, want %v", c.group, c.def, got, c.open)
		}
	}
}
