// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSpellingShortcutsAgreeOnShape holds the three shortcuts past R15b's walk — the walk cache (cachedTarget),
// fsTargetIsSpelling and fsTargetInRoot — to one shape test (spellingShape). Over one corpus in a real directory
// with no symlink, every query of the shape is answered by all three, and every query outside it by none: a
// shortcut that answered a shape the others send to the walk would say "lands on its spelling" where the walk
// might not.
func TestSpellingShortcutsAgreeOnShape(t *testing.T) {
	d := realDir(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(d, "w"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"f", "w/g"} {
		if err := os.WriteFile(filepath.Join(d, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pid := os.Getpid()
	q := func(p, joined string) pathQuery { return pathQuery{tid: pid, dirfd: atFDCWD, path: p, joined: joined} }
	nf := func(x pathQuery) pathQuery { x.nofollow = true; return x }
	for _, tc := range []struct {
		q     pathQuery
		shape bool
	}{
		{q(d+"/f", d+"/f"), true},
		{q(d+"/w/g", d+"/w/g"), true},
		{nf(q(d+"/w/g", d+"/w/g")), true},
		{q(d+"/./f", d+"/f"), true},
		{q(d+"/none", d+"/none"), true},
		{q("w/g", d+"/w/g"), true},
		{q(d+"/w/../f", d+"/f"), false},
		{q("../"+filepath.Base(d)+"/f", d+"/f"), false},
		{q(d+"/w/", d+"/w"), false},
		{q(d+"/w/.", d+"/w"), false},
		{q(".", d), false},
		{q("", d+"/f"), false},
		{q("f", "f"), false},
		{pathQuery{tid: pid, dirfd: 3, path: "f", joined: d + "/f", empty: true}, false},
		{pathQuery{tid: pid, dirfd: atFDCWD, path: "w/g", joined: d + "/w/g", deletedBase: true}, false},
	} {
		if got := spellingShape(tc.q); got != tc.shape {
			t.Errorf("spellingShape(%+v) = %v, want %v", tc.q, got, tc.shape)
		}
		if got := fsTargetIsSpelling(tc.q); got != tc.shape {
			t.Errorf("fsTargetIsSpelling(%+v) = %v, want %v", tc.q, got, tc.shape)
		}
		if _, ok, err := fsTargetInRoot(tc.q); ok != tc.shape || err != nil {
			t.Errorf("fsTargetInRoot(%+v) = %v, %v; want %v", tc.q, ok, err, tc.shape)
		}
		l, f, _ := cacheLoop(t)
		f.realWalks = true
		if _, ok := l.cachedTarget(tc.q); ok != tc.shape {
			t.Errorf("cachedTarget(%+v) = %v, want %v", tc.q, ok, tc.shape)
		}
	}
}
