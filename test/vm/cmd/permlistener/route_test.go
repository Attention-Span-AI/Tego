// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRouteTable is the listener's decision table: who answers an event, and with what, from the mode, whether
// the opener is this process, and whether the file is the deny target. The two rows that keep the listener from
// deadlocking on itself are the first two of each mode: its own opens (the workers' touches, the reader's
// nothing) are allowed on the reader at once, never handed to a worker that is itself waiting for the answer.
func TestRouteTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mode   mode
		self   bool
		target bool
		want   route
		resp   uint32 // the word an inline route writes
	}{
		{"allow-touch: own open", modeAllowTouch, true, false, routeSelf, unix.FAN_ALLOW},
		{"allow-touch: own open of a path equal to a target", modeAllowTouch, true, true, routeSelf, unix.FAN_ALLOW},
		{"allow-touch: anybody else's open goes to a worker", modeAllowTouch, false, false, routeDecide, 0},
		{"allow-touch: the target flag means nothing", modeAllowTouch, false, true, routeDecide, 0},
		{"deny: own open of the target is not denied", modeDeny, true, true, routeSelf, unix.FAN_ALLOW},
		{"deny: own open", modeDeny, true, false, routeSelf, unix.FAN_ALLOW},
		{"deny: another file is allowed at once", modeDeny, false, false, routeAllow, unix.FAN_ALLOW},
		{"deny: the target is denied at once", modeDeny, false, true, routeDeny, unix.FAN_DENY},
	}
	for _, c := range cases {
		cfg := config{mode: c.mode}
		got := cfg.route(c.self, c.target)
		if got != c.want {
			t.Errorf("%s: route = %v, want %v", c.name, got, c.want)
			continue
		}
		if got != routeDecide && got.response() != c.resp {
			t.Errorf("%s: %v answers %d, want %d", c.name, got, got.response(), c.resp)
		}
	}
}

func TestEveryRouteHasAName(t *testing.T) {
	t.Parallel()
	seen := map[string]route{}
	for _, r := range []route{routeSelf, routeDecide, routeAllow, routeDeny} {
		name := r.String()
		if name == "" || name == "route(?)" {
			t.Errorf("route %d has no name", int(r))
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("routes %d and %d are both %q", int(prev), int(r), name)
		}
		seen[name] = r
	}
}

func fileID(t *testing.T, path string) (dev, ino uint64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return uint64(st.Dev), uint64(st.Ino)
}

// TestTargetIsAFileByNameOrByInode: "the file P" is whatever answers to P's name, which a re-created P does,
// and whatever is P's inode, which a hard link or a bind mount alias is.
func TestTargetIsAFileByNameOrByInode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Link(p, link); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg, err := newTarget(p)
	if err != nil {
		t.Fatalf("newTarget: %v", err)
	}
	pdev, pino := fileID(t, p)
	odev, oino := fileID(t, other)
	ddev, dino := fileID(t, dir)
	cases := []struct {
		name string
		path string
		dev  uint64
		ino  uint64
		want bool
	}{
		{"the file itself", p, pdev, pino, true},
		{"its name with another inode (re-created)", p, odev, oino, true},
		{"its inode under another name (a hard link)", link, pdev, pino, true},
		{"its name once the file is unlinked", p + " (deleted)", pdev, pino, true},
		{"another file", other, odev, oino, false},
		{"a name that only starts like it", p + "2", odev, oino, false},
		{"the directory", dir, ddev, dino, false},
	}
	for _, c := range cases {
		if got := tg.matches(c.path, c.dev, c.ino); got != c.want {
			t.Errorf("%s: matches = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTargetThatDoesNotExistYetIsMatchedByName: the path may be created after the listener starts, so there is
// no inode to know yet, and a zero inode must not match every file whose stat failed.
func TestTargetThatDoesNotExistYetIsMatchedByName(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "later")
	tg, err := newTarget(p)
	if err != nil {
		t.Fatalf("newTarget of a missing path: %v", err)
	}
	if tg.haveID {
		t.Fatal("a missing path has an inode")
	}
	if !tg.matches(p, 5, 6) {
		t.Error("the name does not match")
	}
	if tg.matches(filepath.Join(filepath.Dir(p), "else"), 0, 0) {
		t.Error("an unrelated file with a zero inode matched a target that has none")
	}
}

func TestTargetNeedsAnAbsoluteCleanPath(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "relative/file", "./x"} {
		if _, err := newTarget(bad); err == nil {
			t.Errorf("newTarget(%q) accepted a path that is not absolute", bad)
		}
	}
	tg, err := newTarget("/a/b/../c//d")
	if err != nil {
		t.Fatal(err)
	}
	if tg.path != "/a/c/d" {
		t.Errorf("path = %q, want it cleaned to /a/c/d", tg.path)
	}
}
