// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// statKey is a FileKey producer over os.Stat (symlinks followed, as the Landlock builder opens an entry) or os.Lstat
// (the final component not followed, as HeldExecGrants.Grants asks).
func statKey(stat func(string) (os.FileInfo, error)) func(string) (FileKey, error) {
	return func(p string) (FileKey, error) {
		fi, err := stat(p)
		if err != nil {
			return FileKey{}, err
		}
		st := fi.Sys().(*syscall.Stat_t)
		return FileKey{Dev: uint64(st.Dev), Ino: st.Ino}, nil
	}
}

// TestRunEndsAreAskedWhereTheyLanded: the run asks REFER's no-gain rule and the Landlock floor of the ends the kernel's
// walk landed (the supervisor's walk, the recorder's d_path), with the exec grants by the inodes the builder held. A
// landed end carries a link's declared spelling only once the agent replaced that link with a real directory, which
// holds none of the rules Landlock put on the link's target. The ends were rewritten by the declared spellings, an
// exec.allow directory's and an fs entry's (Canonical), so a move and a link into the directory that
// replaced the link were judged at the link's target and read refused while the kernel allowed them (S4-1 and
// R4-C1), and an unlink there was blamed on Landlock.
func TestRunEndsAreAskedWhereTheyLanded(t *testing.T) {
	w, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := func(rel string) string { return filepath.Join(w, rel) }
	rel := func(p string) string { r, _ := filepath.Rel(w, p); return r }
	for _, d := range []string{"out/realbin", "out/tools", "out/q", "out/q2", "out/q3", "cfg"} {
		if err := os.MkdirAll(at(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"out/x", "cfg/f"} {
		if err := os.WriteFile(at(f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// out/bl: an exec.allow directory declared through a link; out/wl: a write entry declared through a link into
	// another exec.allow directory; out/cl: a watch entry declared through a link out of every write entry.
	for link, target := range map[string]string{"out/bl": "realbin", "out/wl": "tools", "out/cl": "../cfg"} {
		if err := os.Symlink(target, at(link)); err != nil {
			t.Fatal(err)
		}
	}
	rt := &agent.RuleTable{
		Tier:     backend.TierLandlock,
		Contract: &agent.Contract{Name: "landed", Exec: &agent.ExecSection{Allow: []string{"./out/bl/", "./out/tools/"}}},
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: at("out"), Raw: "./out/", Resolved: at("out"), Access: agent.AccessWriteSet},
			{Kind: agent.FSWrite, Path: at("out/wl"), Raw: "./out/wl/", Resolved: at("out/tools"), Access: agent.AccessWriteSet},
			{Kind: agent.FSWatch, Path: at("out/cl"), Raw: "./out/cl/", Resolved: at("cfg")},
		},
		Exec: []agent.ExecRule{
			{Raw: "./out/bl/", Path: at("out/bl"), Resolved: at("out/realbin"), IsDir: true, Verdict: agent.VerdictAllow},
			{Raw: "./out/tools/", Path: at("out/tools"), Resolved: at("out/tools"), IsDir: true, Verdict: agent.VerdictAllow},
		},
	}
	held := HoldExecGrants(rt, statKey(os.Stat))
	ix := NewFSIndex(rt)
	src := at("out/x")
	move := func(name, dst string, refused bool) {
		t.Helper()
		g := held.Grants(rt, statKey(os.Lstat))
		if g == nil {
			t.Fatal("no exec grant was held")
		}
		for _, c := range []struct {
			by  string
			got bool
		}{
			{"RenameGainedBy", ReferRefuses(RenameGainedBy(rt, src, dst, g), false)},
			{"index RenameGainedBy", ReferRefuses(ix.RenameGainedBy(src, dst, g), false)},
			{"LinkGainsBy", LinkGainsBy(rt, src, dst, g)},
			{"index LinkGainsBy", ix.LinkGainsBy(src, dst, g)},
			{"index LandlockRenameRefusalBy", second(ix.LandlockRenameRefusalBy(src, dst, false, g))},
			{"index LandlockLinkRefusalBy", second(ix.LandlockLinkRefusalBy(src, dst, g))},
		} {
			if c.got != refused {
				t.Errorf("%s: %s(out/x, %s) refuses %v, the kernel %v", name, c.by, rel(dst), c.got, refused)
			}
		}
	}
	unlink := func(name, p string, refused bool) {
		t.Helper()
		if _, got := ix.LandlockDeleteRefusal(p); got != refused {
			t.Errorf("%s: index LandlockDeleteRefusal(%s) refuses %v, the kernel %v", name, rel(p), got, refused)
		}
		if _, got := LandlockDeleteRefusal(rt, p); got != refused {
			t.Errorf("%s: LandlockDeleteRefusal(%s) refuses %v, the kernel %v", name, rel(p), got, refused)
		}
	}

	// While the links stand, the walk lands beside the inodes the builder held, and a move or a link gains EXECUTE
	// there (EXDEV); the unlink lands in cfg, which no write entry covers (EACCES).
	move("into the exec link's target", at("out/realbin/x"), true)
	move("into the write link's target", at("out/tools/x"), true)
	unlink("in the watch link's target", at("cfg/f"), true)

	// Each link replaced by a real directory of out: the fresh inode holds no rule, out's grant is all there is.
	for link, fresh := range map[string]string{"out/bl": "out/q", "out/wl": "out/q2", "out/cl": "out/q3"} {
		if err := os.Remove(at(link)); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(at(fresh), at(link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(at("out/cl/f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(at("out/bl/sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	move("into the directory that replaced the exec link", at("out/bl/x"), false)
	move("beneath it", at("out/bl/sub/x"), false)
	// A run that holds no inode asks the table alone (ExecGrantAt): the declared spelling grants nothing there either,
	// the target does.
	for _, c := range []struct {
		dst  string
		want bool
	}{{at("out/bl/x"), false}, {at("out/bl/sub/x"), false}, {at("out/realbin/x"), true}} {
		if got := ReferRefuses(RenameGainedBy(rt, src, c.dst, nil), false); got != c.want {
			t.Errorf("by the table: RenameGainedBy(out/x, %s) refuses %v, the kernel %v", rel(c.dst), got, c.want)
		}
		if got := ix.LinkGainsBy(src, c.dst, nil); got != c.want {
			t.Errorf("by the table: index LinkGainsBy(out/x, %s) refuses %v, the kernel %v", rel(c.dst), got, c.want)
		}
	}
	move("into the directory that replaced the write link", at("out/wl/x"), false)
	unlink("in the directory that replaced the watch link", at("out/cl/f"), false)
	// The targets keep their rules.
	move("into the exec link's target, after", at("out/realbin/x"), true)
	move("into the write link's target, after", at("out/tools/x"), true)
}

func second(_ string, b bool) bool { return b }

// TestCleanDirIsDirOfACleanPath: referGained and the index's canonicalEnd take an end's directory with cleanDir, off
// the indexed evaluator's query path's filepath.Dir; for every clean path it is filepath.Dir's answer.
func TestCleanDirIsDirOfACleanPath(t *testing.T) {
	for _, p := range []string{"/", "/a", "/a/b", "/a/b/c.txt", "/.x/..y", "a", "a/b", ".", ".."} {
		if filepath.Clean(p) != p {
			t.Fatalf("%q is not clean", p)
		}
		if got, want := cleanDir(p), filepath.Dir(p); got != want {
			t.Errorf("cleanDir(%q) = %q, filepath.Dir %q", p, got, want)
		}
	}
}
