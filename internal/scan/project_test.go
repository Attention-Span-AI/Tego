// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"golang.org/x/sys/unix"
)

func TestProjectWriteModesUseDiscoveryPolicy(t *testing.T) {
	for _, name := range []string{"package.json", "requirements.txt", "langgraph.json", "crew.jsonc", "config/agents.yaml"} {
		for _, tc := range []struct {
			name    string
			mode    os.FileMode
			primary bool
			read    bool
		}{
			{"0664-own-primary", 0664, true, true},
			{"0664-other-group", 0664, false, false},
			{"0644-other-group", 0644, false, true},
			{"0660-own-primary", 0660, true, true},
			{"0666-own-primary", 0666, true, false},
			{"0646-own-primary", 0646, true, false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				o := commandOptions(t)
				body := "SECRET"
				switch name {
				case "package.json":
					body = `{"dependencies":{"@openai/codex":"SECRET"}}`
				case "requirements.txt":
					body = "langgraph==SECRET\n"
				}
				path := filepath.Join(o.Directory, name)
				writeProcFile(t, filepath.Dir(path), filepath.Base(path), []byte(body))
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
				var st unix.Stat_t
				if err := unix.Stat(path, &st); err != nil {
					t.Fatal(err)
				}
				gid := st.Gid
				if !tc.primary {
					gid = (gid + 1) % 4294967295
				}
				// Vary account fixtures, never host membership or ownership.
				writeProcFile(t, o.Directory, "passwd", []byte(fmt.Sprintf("me:x:%d:%d::%s:/bin/sh\n", o.Caller.UID, gid, o.Directory)))
				// Isolate the file's group check from the selected parent's permissions.
				if err := os.Chmod(o.Directory, 0700); err != nil {
					t.Fatal(err)
				}
				s := Collect(fixtureModePolicy(t, o.Caller.UID, gid, false, false), o).Snapshot
				want := 0
				if tc.read {
					want = 1
				}
				if s.Counts.Project != want {
					t.Fatalf("project count %d; want %d (mode %o, file gid %d, passwd gid %d)", s.Counts.Project, want, st.Mode&0777, st.Gid, gid)
				}
				found := false
				for _, src := range s.Sources {
					if src.Kind != "F" || src.Locator == nil || *src.Locator != path {
						continue
					}
					found = true
					if tc.read && (src.State != "read" || src.Reason != "none") || !tc.read && (src.State != "not-read" || src.Reason != "mode" || s.Status != "partial") {
						t.Fatalf("source %+v; status %s", src, s.Status)
					}
				}
				if !found {
					t.Fatal("missing F source")
				}
				b, err := result.Encode(s)
				if err != nil {
					t.Fatal(err)
				}
				var wire any
				if err := json.Unmarshal(b, &wire); err != nil {
					t.Fatal(err)
				}
				if err := jsonschema.Check("../../spec/scan/v1/schema.json", wire); err != nil {
					t.Fatal(err)
				}
				var footer strings.Builder
				if err := result.Footer(&footer, s, false); err != nil {
					t.Fatal(err)
				}
				if !tc.read && (!strings.Contains(footer.String(), path) || !strings.Contains(footer.String(), "not-read; read 0, not read 1; reason mode")) {
					t.Fatal(footer.String())
				}
				if strings.Contains(string(b)+footer.String(), "SECRET") {
					t.Fatal("manifest value retained")
				}
			})
		}
	}
}

func TestProjectScopeAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		make   func(*testing.T, string)
		reason string
	}{
		{"valid", func(t *testing.T, p string) {
			writeProcFile(t, filepath.Dir(p), filepath.Base(p), []byte(`{"dependencies":{"@openai/codex":"SECRET"}}`))
		}, "none"},
		{"syntax", func(t *testing.T, p string) {
			writeProcFile(t, filepath.Dir(p), filepath.Base(p), []byte(`{"dependencies":{"@openai/codex":"SECRET"}},SECRET`))
		}, "syntax"},
		{"link", func(t *testing.T, p string) {
			if e := os.Symlink("../package.json", p); e != nil {
				t.Fatal(e)
			}
		}, "symlink"},
		{"fifo", func(t *testing.T, p string) {
			if e := unix.Mkfifo(p, 0600); e != nil {
				t.Fatal(e)
			}
		}, "type"},
		{"directory", func(t *testing.T, p string) {
			if e := os.Mkdir(p, 0700); e != nil {
				t.Fatal(e)
			}
		}, "type"},
		{"hardlink", func(t *testing.T, p string) {
			writeProcFile(t, filepath.Dir(p), "other", []byte(`{}`))
			if e := os.Link(filepath.Join(filepath.Dir(p), "other"), p); e != nil {
				t.Fatal(e)
			}
		}, "type"},
		{"writable", func(t *testing.T, p string) {
			writeProcFile(t, filepath.Dir(p), filepath.Base(p), []byte(`{}`))
			if e := os.Chmod(p, 0666); e != nil {
				t.Fatal(e)
			}
		}, "mode"},
		{"large", func(t *testing.T, p string) {
			writeProcFile(t, filepath.Dir(p), filepath.Base(p), []byte(strings.Repeat(" ", manifestBytes+1)))
		}, "size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := unitFixtureRoot(t)
			cwd := filepath.Join(parent, "project")
			if e := os.Mkdir(cwd, 0700); e != nil {
				t.Fatal(e)
			}
			writeProcFile(t, parent, "package.json", []byte(`{"dependencies":{"@google/gemini-cli":"SECRET"}}`))
			tc.make(t, filepath.Join(cwd, "package.json"))
			got := collectProject(t.Context(), cwd, uint32(os.Getuid()), uint32(os.Getgid()))
			if len(got.Sources) != 5 {
				t.Fatalf("sources %+v", got.Sources)
			}
			if got.Sources[0].Reason != tc.reason {
				t.Fatalf("source %+v", got.Sources[0])
			}
			want := 0
			if tc.name == "valid" {
				want = 1
			}
			if len(got.Items) != want {
				t.Fatalf("scope or prefix leaked %+v", got.Items)
			}
		})
	}
}
func TestProjectNoParentChildOrMarkerContent(t *testing.T) {
	root := unitFixtureRoot(t)
	cwd := filepath.Join(root, "project")
	if e := os.Mkdir(cwd, 0700); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{filepath.Join(root, "package.json"), filepath.Join(cwd, "child/package.json"), filepath.Join(cwd, "requirements-dev.txt"), filepath.Join(cwd, "pyproject.toml")} {
		writeProcFile(t, filepath.Dir(p), filepath.Base(p), []byte(`{"dependencies":{"@openai/codex":"SECRET"}}`))
	}
	// A linked directory cannot supply the fixed nested marker.
	if e := os.Symlink(root, filepath.Join(cwd, "config")); e != nil {
		t.Fatal(e)
	}
	got := collectProject(t.Context(), cwd, uint32(os.Getuid()), uint32(os.Getgid()))
	if len(got.Items) != 0 || got.Sources[4].Reason != "symlink" {
		t.Fatalf("walk escaped %+v", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got = collectProject(ctx, cwd, uint32(os.Getuid()), uint32(os.Getgid()))
	if len(got.Items) != 0 || len(got.Sources) != 1 || got.Sources[0].Reason != "deadline" {
		t.Fatalf("cancellation %+v", got)
	}
}
func TestProjectCollectionAndCheck(t *testing.T) {
	o := commandOptions(t)
	o.Check = true
	for name, body := range map[string]string{"package.json": `{"dependencies":{"@openai/codex":"SECRET"}}`, "requirements.txt": "langgraph==SECRET\n"} {
		writeProcFile(t, o.Directory, name, []byte(body))
	}
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.Project != 2 || s.Check != "outside-observed" {
		t.Fatalf("%+v %s", s.Counts, s.Check)
	}
	if _, e := result.Encode(s); e != nil {
		t.Fatal(e)
	}
	writeProcFile(t, o.Directory, "requirements.txt", []byte("langgraph\n--index-url https://SECRET\n"))
	s = Collect(t.Context(), o).Snapshot
	if s.Counts.Project != 1 || s.Status != "partial" || s.Check != "outside-observed" {
		t.Fatalf("%+v %s %s", s.Counts, s.Status, s.Check)
	}
	var out strings.Builder
	if e := result.Footer(&out, s, false); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "requirements.txt") || !strings.Contains(out.String(), "not-read") || !strings.Contains(out.String(), "not walked") {
		t.Fatal(out.String())
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "SECRET") {
		t.Fatal("value retained")
	}
}

func TestContentDeadlinePreservesCompletedProcessCheck(t *testing.T) {
	o := commandOptions(t)
	o.Check = true
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got := collect(ctx, o, func(context.Context, procAccess, string, uint32, []catalog.Row) processSnapshot {
		cancel()
		return processSnapshot{Usable: true}
	}).Snapshot
	if got.Check != "none-observed" || got.Status != "partial" {
		t.Fatalf("unfinished settings or units changed process check: %s %s", got.Check, got.Status)
	}
}

func TestProjectMountPolicy(t *testing.T) {
	root, _, e := metadataPath(t.Context(), unitFixtureRoot(t), false)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = root.Close() }()
	for _, failure := range []error{unix.EXDEV, unix.ENOSYS} {
		fd, e := openProjectPath(root, "config/agents.yaml", func(_ *sys.FD, name string, how *unix.OpenHow) (*sys.FD, error) {
			if name != "config/agents.yaml" || how.Resolve != unix.RESOLVE_BENEATH|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_XDEV || how.Flags&unix.O_PATH == 0 {
				t.Fatal("weakened content-root policy")
			}
			return nil, failure
		})
		if fd != nil || e != failure {
			t.Fatalf("fallback on refusal: %v", e)
		}
		src := projectSource("/project/config/agents.yaml", e)
		want := "mount"
		if failure == unix.ENOSYS {
			want = "unsupported"
		}
		if src.State != "not-read" || src.Reason != want {
			t.Fatalf("hidden refusal: %+v", src)
		}
	}
}
func TestProjectDiscardsChangedOrReplacedFile(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			cwd := unitFixtureRoot(t)
			path := filepath.Join(cwd, "package.json")
			body := []byte(`{"dependencies":{"@openai/codex":"SECRET"}}`)
			writeProcFile(t, cwd, "package.json", body)
			root, _, e := metadataPath(t.Context(), cwd, false)
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = root.Close() }()
			pin, e := projectPath(root, "package.json")
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = pin.Close() }()
			got, e := readProjectPathWith(t.Context(), root, pin, "package.json", path, uint32(os.Getuid()), uint32(os.Getgid()), func(ctx context.Context, r io.Reader) ([]catalog.Dependency, error) {
				deps, e := parseJSONDependencies(ctx, r)
				if e != nil {
					return deps, e
				}
				if replace {
					writeProcFile(t, cwd, "replacement", body)
					if e = os.Rename(filepath.Join(cwd, "replacement"), path); e != nil {
						t.Fatal(e)
					}
				} else {
					if e = os.WriteFile(path, append(body, ' '), 0600); e != nil {
						t.Fatal(e)
					}
				}
				return deps, nil
			})
			if len(got) != 0 || !errors.Is(e, errChanged) {
				t.Fatalf("retained changed file: %+v %v", got, e)
			}
		})
	}
}
