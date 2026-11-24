// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"golang.org/x/sys/unix"
)

func metadataFixture(t *testing.T, root, path string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(markerSecret), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMetadataCandidatesAndSettings(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	cwd := filepath.Join(home, "project")
	program := metadataFixture(t, home, "bin/codex", 0700)
	metadataFixture(t, home, ".venv/bin/irrelevant", 0700)
	metadataFixture(t, home, "project/.venv/bin/gemini", 0700)
	metadataFixture(t, home, ".local/share/claude/versions/1", 0700)
	settings := metadataFixture(t, home, ".codex/settings.json", 0600)
	if err := os.Symlink(program, filepath.Join(bin, "claude")); err != nil {
		t.Fatal(err)
	}
	got := collectMetadata(context.Background(), home, cwd, bin, uint32(os.Getuid()), catalog.Rows())
	if len(got.Programs) != 4 || len(got.Settings) != 1 {
		t.Fatalf("programs/settings: %+v", got)
	}
	for _, p := range got.Programs {
		if p.Name == "claude" && p.Path == filepath.Join(bin, "claude") && p.Target != program {
			t.Fatal("lost link target")
		}
	}
	if got.Settings[0].Path != filepath.Dir(settings) || got.Settings[0].FileType != "directory" {
		t.Fatal("settings metadata mismatch")
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), markerSecret) {
		t.Fatal("program or settings content escaped")
	}
}

func TestMetadataRejectsUnsafeObjects(t *testing.T) {
	for _, kind := range []string{"fifo", "directory", "not executable", "link loop", "too many links", "settings link", "parent link", "foreign settings"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			bin := filepath.Join(home, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(bin, "codex")
			bad := p
			switch kind {
			case "fifo":
				if err := unix.Mkfifo(p, 0700); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			case "not executable":
				metadataFixture(t, home, "bin/codex", 0600)
			case "link loop":
				if err := os.Symlink("codex", p); err != nil {
					t.Fatal(err)
				}
			case "too many links":
				metadataFixture(t, home, "target", 0700)
				for i := 9; i >= 0; i-- {
					target := "target"
					if i < 9 {
						target = fmt.Sprint("l", i+1)
					}
					if err := os.Symlink(target, filepath.Join(home, fmt.Sprint("l", i))); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink("../l0", p); err != nil {
					t.Fatal(err)
				}
			case "settings link":
				bad = filepath.Join(home, ".codex")
				if err := os.Symlink(bin, bad); err != nil {
					t.Fatal(err)
				}
			case "parent link":
				bad = filepath.Join(home, ".config/opencode")
				if err := os.Symlink(bin, filepath.Join(home, ".config")); err != nil {
					t.Fatal(err)
				}
			case "foreign settings":
				bad = metadataFixture(t, home, ".codex", 0600)
			}
			uid := uint32(os.Getuid())
			if kind == "foreign settings" {
				uid++
			}
			got := collectMetadata(context.Background(), home, home, bin, uid, catalog.Rows())
			if len(got.Programs) > 0 || len(got.Settings) > 0 {
				t.Fatal("unsafe object became evidence")
			}
			found := false
			for _, s := range got.Sources {
				if s.Path == bad && s.State == "not-read" {
					found = true
				}
			}
			if !found {
				t.Fatalf("unsafe source omitted: %+v", got.Sources)
			}
		})
	}
}

func TestMetadataLinkResolution(t *testing.T) {
	home := t.TempDir()
	target := metadataFixture(t, home, "real/codex", 0700)
	for _, name := range []string{"absolute", "relative", "parent"} {
		link := filepath.Join(home, name)
		to := target
		if name == "relative" {
			to = "real/codex"
		}
		if name == "parent" {
			to = "real/../real/codex"
		}
		if err := os.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
		fd, path, err := metadataPath(context.Background(), link, true)
		if err != nil {
			t.Fatal(err)
		}
		_ = fd.Close()
		if path != target {
			t.Fatalf("resolved %s", path)
		}
		if _, _, err := metadataPath(context.Background(), link, false); !errors.Is(err, unix.ELOOP) {
			t.Fatal("followed metadata link without permission")
		}
	}
	// Exactly eight hops, including a directory link, remain metadata only.
	to := target
	for i := 7; i >= 0; i-- {
		p := filepath.Join(home, fmt.Sprint("hop", i))
		if err := os.Symlink(to, p); err != nil {
			t.Fatal(err)
		}
		to = p
	}
	fd, path, err := metadataPath(context.Background(), to, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = fd.Close()
	if path != target {
		t.Fatal("eight hops did not resolve")
	}
}

func TestMetadataBoundsAndMissing(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	metadataFixture(t, home, "bin/codex", 0700)
	for i := 0; i < 257; i++ {
		metadataFixture(t, home, fmt.Sprintf(".local/share/claude/versions/%03d", i), 0700)
	}
	got := collectMetadata(context.Background(), home, home, strings.Repeat(bin+":", 65)+".:relative", uint32(os.Getuid()), catalog.Rows())
	if len(got.Programs) != 257 {
		t.Fatalf("bounds lost independent candidates: %d", len(got.Programs))
	}
	limits := strings.Join(got.Limits, ",")
	if !strings.Contains(limits, "path-limit") || !strings.Contains(limits, "glob-limit") {
		t.Fatal("limits not disclosed")
	}
	missing := false
	for _, s := range got.Sources {
		if s.State == "missing" {
			missing = true
		}
		if s.Path != "" && !filepath.IsAbs(s.Path) {
			t.Fatal("relative PATH retained as locator")
		}
	}
	if !missing {
		t.Fatal("missing path not reported")
	}
	got = collectMetadata(context.Background(), home, home, ".:relative:", uint32(os.Getuid()), catalog.Rows())
	excluded := 0
	for _, s := range got.Sources {
		if s.State == "excluded" {
			excluded += s.NotRead
		}
	}
	if excluded != 3 {
		t.Fatal("relative/empty PATH entries not counted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = collectMetadata(ctx, home, home, bin, uint32(os.Getuid()), catalog.Rows())
	if len(got.Programs) != 0 || len(got.Settings) != 0 || !strings.Contains(strings.Join(got.Limits, ","), "deadline") {
		t.Fatal("cancelled collection retained evidence")
	}
}

func TestMetadataInputBudget(t *testing.T) {
	home := t.TempDir()
	metadataFixture(t, home, ".codex", 0600)
	got := collectMetadata(context.Background(), home, home, strings.Repeat(":", 65537), uint32(os.Getuid()), catalog.Rows())
	if len(got.Sources) > 40 || len(got.Settings) != 1 || len(got.Programs) != 0 {
		t.Fatal("oversized PATH erased C or exhausted sources")
	}
	got = collectMetadata(context.Background(), home, home, strings.Repeat(":", 60000), uint32(os.Getuid()), catalog.Rows())
	if len(got.Sources) > 40 {
		t.Fatal("empty PATH entries exhausted source budget")
	}
	found := false
	for _, s := range got.Sources {
		if s.State == "excluded" && s.NotRead == 60001 {
			found = true
		}
	}
	if !found {
		t.Fatal("excluded entries lost their count")
	}
}

func TestOversizedPathHasOnlyUnknownRemainder(t *testing.T) {
	home := t.TempDir()
	got := collectMetadata(context.Background(), home, home, strings.Repeat("x", 65537), uint32(os.Getuid()), catalog.Rows())
	for _, s := range got.Sources {
		if s.State == "excluded" {
			t.Fatal("unparsed PATH invented an excluded-entry count")
		}
	}
}

func TestMetadataNeverOpensContents(t *testing.T) {
	home := t.TempDir()
	program := metadataFixture(t, home, "bin/codex", 0700)
	settings := metadataFixture(t, home, ".codex", 0600)
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, p := range []string{program, settings} {
		if _, err := unix.InotifyAddWatch(fd, p, unix.IN_OPEN); err != nil {
			t.Fatal(err)
		}
	}
	collectMetadata(context.Background(), home, home, filepath.Dir(program), uint32(os.Getuid()), catalog.Rows())
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if n > 0 || err != unix.EAGAIN {
		t.Fatalf("metadata collection opened contents: bytes %d error %v", n, err)
	}
	// Check the tripwire itself with one deliberate, fixture-only content read.
	if _, err := os.ReadFile(program); err != nil {
		t.Fatal(err)
	}
	if n, err := unix.Read(fd, buf); err != nil || n <= 0 {
		t.Fatalf("open tripwire did not detect its control: %d %v", n, err)
	}
}

type changingCatalogDirectory struct {
	stats, reads int
	fault        bool
}

func (d *changingCatalogDirectory) names(int) ([]string, error) {
	d.reads++
	return []string{"one"}, nil
}
func (d *changingCatalogDirectory) stat() (unix.Stat_t, error) {
	d.stats++
	if d.fault && d.stats > 1 {
		return unix.Stat_t{}, os.ErrPermission
	}
	return unix.Stat_t{Mode: unix.S_IFDIR | 0700, Ino: 1, Size: int64(d.stats)}, nil
}

func TestCatalogDirectoryChangeDiscardsNames(t *testing.T) {
	for _, fault := range []bool{false, true} {
		d := &changingCatalogDirectory{fault: fault}
		names, err := catalogNames(context.Background(), d)
		if err == nil || len(names) != 0 || d.stats != 2 || d.reads != 1 {
			t.Fatal("changed or unreadable catalog directory retained evidence")
		}
	}
}

type goneCatalogDirectory struct{}

func (goneCatalogDirectory) names(int) ([]string, error) { return []string{"one"}, os.ErrNotExist }
func (goneCatalogDirectory) stat() (unix.Stat_t, error) {
	return unix.Stat_t{Mode: unix.S_IFDIR | 0700, Ino: 1}, nil
}
func TestCatalogEnumerationFailureDiscardsNames(t *testing.T) {
	names, err := catalogNames(context.Background(), goneCatalogDirectory{})
	if len(names) != 0 || !errors.Is(err, errChanged) {
		t.Fatal("disappearing enumeration retained names or became a known missing path")
	}
}
