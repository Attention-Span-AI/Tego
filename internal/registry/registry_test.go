// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// layout is a working directory and a user registry under one private temporary directory.
type layout struct {
	t           *testing.T
	dir, user   string
	places      Places
	contractFmt string
}

func newLayout(t *testing.T) *layout {
	t.Helper()
	base := t.TempDir()
	l := &layout{t: t, dir: filepath.Join(base, "proj"), user: filepath.Join(base, "home", ".config", "tego"),
		contractFmt: "version: 0\nname: %s\ncommand: [/bin/true]\n"}
	for _, d := range []string{l.dir, l.user} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	l.places = Places{Dir: l.dir, User: l.user, UID: os.Getuid()}
	return l
}

// write writes a contract named name at rel under root, its directories 0755 and the file 0644.
func (l *layout) write(root, rel, name string) string {
	l.t.Helper()
	path := filepath.Join(root, rel)
	for d := filepath.Dir(path); d != root && strings.HasPrefix(d, root); d = filepath.Dir(d) {
		if err := os.MkdirAll(d, 0o755); err != nil {
			l.t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			l.t.Fatal(err)
		}
	}
	body := strings.ReplaceAll(l.contractFmt, "%s", name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		l.t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		l.t.Fatal(err)
	}
	return path
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestIsNameIsAnAgentIDAndNeverAPath(t *testing.T) {
	for arg, want := range map[string]bool{
		"retriever": true, "my-agent-2": true, "a": true,
		"agent.yaml": false, "./retriever": false, "dir/agent": false, "/abs/agent.yaml": false, "-": false,
		"Retriever": false, "": false, strings.Repeat("a", 41): false, "a_b": false,
	} {
		if got := IsName(arg); got != want {
			t.Errorf("IsName(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestTheProjectFileAnswersForItsOwnName(t *testing.T) {
	l := newLayout(t)
	path := l.write(l.dir, ProjectFile, "retriever")
	e, err := l.places.Resolve("retriever")
	if err != nil {
		t.Fatal(err)
	}
	if e.Path != path || e.Registry != Project || e.Name != "retriever" {
		t.Fatalf("entry = %+v, want %s in the project registry", e, path)
	}
	want, _ := os.ReadFile(path)
	if string(e.Data) != string(want) {
		t.Fatalf("data = %q, want the file's bytes", e.Data)
	}
	// Another name is not the project file's: with nothing else it is not found.
	if _, err := l.places.Resolve("writer"); code(err) != CodeNotFound || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("writer: err = %v, want %s", err, CodeNotFound)
	}
}

func TestTheProjectAgentsDirectoryAnswers(t *testing.T) {
	l := newLayout(t)
	l.write(l.dir, ProjectFile, "other")
	path := l.write(l.dir, filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), "retriever")
	e, err := l.places.Resolve("retriever")
	if err != nil {
		t.Fatal(err)
	}
	if e.Path != path || e.Registry != Project {
		t.Fatalf("entry = %+v, want %s", e, path)
	}
}

func TestTheUserRegistryAnswersWhenTheProjectDoesNot(t *testing.T) {
	l := newLayout(t)
	l.write(l.dir, ProjectFile, "other")
	path := l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
	e, err := l.places.Resolve("retriever")
	if err != nil {
		t.Fatal(err)
	}
	if e.Path != path || e.Registry != User {
		t.Fatalf("entry = %+v, want %s in the user registry", e, path)
	}
}

// A name both registries hold is refused, never answered by the project's entry: an agent run from the user registry
// with a write over its working directory could otherwise plant .tego/agents/<name>.yaml there, and the next
// `tego run <name>` in that directory would run the planted contract in place of the user's. Whatever is at the user
// registry's place counts, an entry that would itself be refused included: which one was meant is the user's to say.
func TestANameBothRegistriesHoldIsAmbiguous(t *testing.T) {
	for _, c := range []struct {
		what string
		proj string
		user func(t *testing.T, path string)
	}{
		{"project agents directory", filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), nil},
		{"project file", ProjectFile, nil},
		{"user entry others could write", ProjectFile, func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
		{"user entry a dangling link", ProjectFile, func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("nowhere.yaml", path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.what, func(t *testing.T) {
			l := newLayout(t)
			proj := l.write(l.dir, c.proj, "retriever")
			user := l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
			if c.user != nil {
				c.user(t, user)
			}
			for range 3 { // deterministic: the same answer every time
				e, err := l.places.Resolve("retriever")
				if code(err) != CodeAmbiguous || e != nil {
					t.Fatalf("entry = %+v, err = %v, want %s", e, err, CodeAmbiguous)
				}
				for _, s := range []string{proj, user, "give the path of the one you mean"} {
					if !strings.Contains(err.Error(), s) {
						t.Fatalf("err = %v, want it to name %q", err, s)
					}
				}
			}
		})
	}
}

// A user registry whose entry cannot even be looked for is no proof the project's entry is the only one: refused.
func TestAUserRegistryThatCannotBeSearchedRefusesAProjectEntry(t *testing.T) {
	l := newLayout(t)
	l.write(l.dir, ProjectFile, "retriever")
	if err := os.Symlink(AgentsDir, filepath.Join(l.user, AgentsDir)); err != nil { // a loop: ELOOP, for root too
		t.Fatal(err)
	}
	if e, err := l.places.Resolve("retriever"); code(err) != CodeEntry || e != nil {
		t.Fatalf("entry = %+v, err = %v, want %s", e, err, CodeEntry)
	}
}

func TestANameTheProjectHoldsTwiceIsAmbiguous(t *testing.T) {
	l := newLayout(t)
	a := l.write(l.dir, ProjectFile, "retriever")
	b := l.write(l.dir, filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), "retriever")
	_, err := l.places.Resolve("retriever")
	if code(err) != CodeAmbiguous || !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) {
		t.Fatalf("err = %v, want %s naming both files", err, CodeAmbiguous)
	}
}

// The project's agent.yaml as a link to its .tego/agents entry is one file, so one contract: it resolves, as
// agent.yaml. A hard link of it is two names, and refused (TestAnEntryWithASecondNameIsRefused).
func TestOneFileTheProjectHoldsTwiceIsNotAmbiguous(t *testing.T) {
	l := newLayout(t)
	l.write(l.dir, filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), "retriever")
	a := filepath.Join(l.dir, ProjectFile)
	if err := os.Symlink(filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), a); err != nil {
		t.Fatal(err)
	}
	if e, err := l.places.Resolve("retriever"); err != nil || e == nil || e.Path != a {
		t.Fatalf("entry = %+v, err = %v, want %s", e, err, a)
	}
}

// An entry with a second name (a hard link) is refused in either registry: R10 compares names, and no write entry is
// compared with the other one, so a run whose write entry holds it could rewrite the entry every later run of the name
// loads (ADR 0059). Its one name back, it resolves.
func TestAnEntryWithASecondNameIsRefused(t *testing.T) {
	for _, c := range []struct{ what, root, rel string }{
		{"user entry", "user", filepath.Join(AgentsDir, "retriever.yaml")},
		{"project entry", "project", filepath.Join(ProjectDir, AgentsDir, "retriever.yaml")},
		{"project file", "project", ProjectFile},
		{"user entry a hard link of the project file", "both", ProjectFile},
	} {
		t.Run(c.what, func(t *testing.T) {
			l := newLayout(t)
			root := l.user
			if c.root != "user" {
				root = l.dir
			}
			path := l.write(root, c.rel, "retriever")
			other := filepath.Join(filepath.Dir(l.dir), "elsewhere.yaml")
			if c.root == "both" {
				if err := os.MkdirAll(filepath.Join(l.user, AgentsDir), 0o755); err != nil {
					t.Fatal(err)
				}
				other = filepath.Join(l.user, AgentsDir, "retriever.yaml")
			}
			if err := os.Link(path, other); err != nil {
				t.Fatal(err)
			}
			_, err := l.places.Resolve("retriever")
			if code(err) != CodeUntrusted || !strings.Contains(err.Error(), "2 names") || !strings.Contains(err.Error(), "hard link") ||
				!errors.Is(err, config.ErrUntrusted) {
				t.Fatalf("err = %v, want %s naming its 2 names and the hard-link fix", err, CodeUntrusted)
			}
			if err := os.Remove(other); err != nil {
				t.Fatal(err)
			}
			if e, err := l.places.Resolve("retriever"); err != nil || e.Path != path {
				t.Fatalf("entry = %+v, err = %v, want %s once it has one name", e, err, path)
			}
		})
	}
}

func TestANameThatIsAlsoAFileInTheWorkingDirectoryIsAmbiguous(t *testing.T) {
	l := newLayout(t)
	l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
	if err := os.WriteFile(filepath.Join(l.dir, "retriever"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := l.places.Resolve("retriever")
	if code(err) != CodeAmbiguous || !strings.Contains(err.Error(), "./retriever") {
		t.Fatalf("err = %v, want %s with the ./retriever fix", err, CodeAmbiguous)
	}
}

func TestAMissingNameIsRefusedWithTheFilesThatWouldHoldIt(t *testing.T) {
	l := newLayout(t)
	l.write(l.dir, ProjectFile, "alpha")
	l.write(l.user, filepath.Join(AgentsDir, "beta.yaml"), "beta")
	_, err := l.places.Resolve("retriever")
	if code(err) != CodeNotFound {
		t.Fatalf("err = %v, want %s", err, CodeNotFound)
	}
	msg := err.Error()
	for _, want := range []string{
		filepath.Join(l.dir, ProjectDir, AgentsDir, "retriever.yaml"), filepath.Join(l.user, AgentsDir, "retriever.yaml"),
		"alpha, beta", "give the contract's path",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not say %q", msg, want)
		}
	}
	// With no user registry configured the refusal says so.
	p := l.places
	p.User = ""
	if _, err := p.Resolve("retriever"); code(err) != CodeNotFound || !strings.Contains(err.Error(), "no user registry") {
		t.Fatalf("err = %v, want not found naming no user registry", err)
	}
}

func TestAnEntryWhoseNameIsNotItsFileNameIsRefused(t *testing.T) {
	l := newLayout(t)
	l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "writer")
	_, err := l.places.Resolve("retriever")
	if code(err) != CodeEntry || !strings.Contains(err.Error(), `"writer"`) {
		t.Fatalf("err = %v, want %s naming writer", err, CodeEntry)
	}
}

// The fix an entry refusal gives writes the name quoted: name is a YAML string (agent-contract R3), so
// following `write name: 2024` would leave a contract agent.Load refuses as "got integer".
func TestAnEntryRefusalsFixQuotesTheName(t *testing.T) {
	for _, tc := range []struct{ what, body string }{
		{"another name", "writer"},
		{"no readable name", ""},
	} {
		t.Run(tc.what, func(t *testing.T) {
			l := newLayout(t)
			p := filepath.Join(l.user, AgentsDir, "2024.yaml")
			if tc.body == "" {
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("name: [unclosed\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				l.write(l.user, filepath.Join(AgentsDir, "2024.yaml"), tc.body)
			}
			_, err := l.places.Resolve("2024")
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeEntry {
				t.Fatalf("err = %v, want %s", err, CodeEntry)
			}
			if !strings.Contains(e.Fix, `write name: "2024" in it`) {
				t.Errorf("fix %q does not quote the name", e.Fix)
			}
		})
	}
}

func TestAProjectFileWhoseNameCannotBeReadIsRefused(t *testing.T) {
	l := newLayout(t)
	l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
	if err := os.WriteFile(filepath.Join(l.dir, ProjectFile), []byte("name: [unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// It may be the one meant: the user registry's entry does not run in its place.
	if _, err := l.places.Resolve("retriever"); code(err) != CodeEntry {
		t.Fatalf("err = %v, want %s", err, CodeEntry)
	}
}

// An agent.yaml in the working directory that is not tego's (another framework's file, or a link out of the
// directory) refuses every name there, the user registry's included, and the refusal says so: the user who typed a
// user-registry name learns why it did not resolve and what to do.
func TestAnUnreadableProjectFileSaysWhyEveryNameIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, l *layout, path string)
	}{
		{"not yaml", func(t *testing.T, _ *layout, path string) {
			if err := os.WriteFile(path, []byte("foo: [\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"link out", func(t *testing.T, l *layout, path string) {
			if err := os.Symlink(l.write(filepath.Dir(l.dir), "shared.yaml", "retriever"), path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLayout(t)
			l.write(l.user, filepath.Join(AgentsDir, "uent.yaml"), "uent")
			tc.make(t, l, filepath.Join(l.dir, ProjectFile))
			_, err := l.places.Resolve("uent")
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeEntry {
				t.Fatalf("err = %v, want %s", err, CodeEntry)
			}
			for _, want := range []string{"no agent name resolves in this directory", "rename or move " + ProjectFile, "give the contract's path"} {
				if !strings.Contains(e.Fix, want) {
					t.Errorf("fix %q does not say %q", e.Fix, want)
				}
			}
		})
	}
}

func TestAnEntryOthersCouldWriteIsRefused(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		l := newLayout(t)
		path := l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
		if err := os.Chmod(path, 0o664); err != nil {
			t.Fatal(err)
		}
		_, err := l.places.Resolve("retriever")
		if code(err) != CodeUntrusted || !strings.Contains(err.Error(), "chmod go-w") {
			t.Fatalf("err = %v, want %s", err, CodeUntrusted)
		}
		// It is a registry entry, not the machine config, and the refusal says what failed.
		want := "registry entry untrusted: " + path + " uid=" + strconv.Itoa(os.Getuid()) + " mode=0664 (group or other writable)"
		if !strings.HasPrefix(err.Error(), want) || strings.Contains(err.Error(), "machine config") {
			t.Fatalf("err = %v, want it to open %q", err, want)
		}
		if !errors.Is(err, config.ErrUntrusted) {
			t.Fatalf("err = %v, want it to wrap config.ErrUntrusted", err)
		}
	})
	t.Run("agents directory", func(t *testing.T) {
		l := newLayout(t)
		l.write(l.dir, filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), "retriever")
		agents := filepath.Join(l.dir, ProjectDir, AgentsDir)
		if err := os.Chmod(agents, 0o775); err != nil {
			t.Fatal(err)
		}
		_, err := l.places.Resolve("retriever")
		if code(err) != CodeUntrusted || !strings.HasPrefix(err.Error(), "registry directory untrusted: "+agents+" ") ||
			strings.Contains(err.Error(), "machine config") {
			t.Fatalf("err = %v, want %s naming the registry directory %s", err, CodeUntrusted, agents)
		}
	})
	t.Run("registry directory", func(t *testing.T) {
		l := newLayout(t)
		l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
		if err := os.Chmod(l.user, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := l.places.Resolve("retriever"); code(err) != CodeUntrusted {
			t.Fatalf("err = %v, want %s", err, CodeUntrusted)
		}
	})
	t.Run("project file of this name", func(t *testing.T) {
		l := newLayout(t)
		path := l.write(l.dir, ProjectFile, "retriever")
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := l.places.Resolve("retriever"); code(err) != CodeUntrusted {
			t.Fatalf("err = %v, want %s", err, CodeUntrusted)
		}
	})
	t.Run("project file of another name is passed over", func(t *testing.T) {
		l := newLayout(t)
		path := l.write(l.dir, ProjectFile, "other")
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		user := l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
		if e, err := l.places.Resolve("retriever"); err != nil || e.Path != user {
			t.Fatalf("entry = %+v, err = %v, want %s", e, err, user)
		}
	})
}

func TestAnEntryThatLeavesItsRegistryOrIsNoFileIsRefused(t *testing.T) {
	t.Run("link out", func(t *testing.T) {
		l := newLayout(t)
		outside := l.write(filepath.Dir(l.user), "outside.yaml", "retriever")
		if err := os.MkdirAll(filepath.Join(l.user, AgentsDir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(l.user, AgentsDir, "retriever.yaml")); err != nil {
			t.Fatal(err)
		}
		if _, err := l.places.Resolve("retriever"); code(err) != CodeEntry {
			t.Fatalf("err = %v, want %s", err, CodeEntry)
		}
	})
	// A link that stays inside the registry but leaves agents/ leads to a file R10 lets any run write: agents/ is the
	// directory no write entry reaches, and the registry around it is not (ADR 0059). Both registries
	// read an entry through agents/ itself.
	for _, reg := range []string{User, Project} {
		t.Run("link out of agents/ within the "+reg+" registry", func(t *testing.T) {
			l := newLayout(t)
			root := l.user
			if reg == Project {
				root = filepath.Join(l.dir, ProjectDir)
			}
			l.write(root, filepath.Join("versions", "retriever.yaml"), "retriever")
			if err := os.MkdirAll(filepath.Join(root, AgentsDir), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join("..", "versions", "retriever.yaml"), filepath.Join(root, AgentsDir, "retriever.yaml")); err != nil {
				t.Fatal(err)
			}
			_, err := l.places.Resolve("retriever")
			if code(err) != CodeEntry || !strings.Contains(err.Error(), "inside "+AgentsDir+"/") {
				t.Fatalf("err = %v, want %s saying an entry stays inside agents/", err, CodeEntry)
			}
		})
	}
	t.Run("relative link inside", func(t *testing.T) {
		l := newLayout(t)
		l.write(l.user, filepath.Join(AgentsDir, "base.yaml"), "retriever")
		if err := os.Symlink("base.yaml", filepath.Join(l.user, AgentsDir, "retriever.yaml")); err != nil {
			t.Fatal(err)
		}
		if e, err := l.places.Resolve("retriever"); err != nil || e.Registry != User {
			t.Fatalf("entry = %+v, err = %v, want the user entry", e, err)
		}
	})
	t.Run("fifo", func(t *testing.T) {
		l := newLayout(t)
		if err := os.MkdirAll(filepath.Join(l.user, AgentsDir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(l.user, AgentsDir, "retriever.yaml"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := l.places.Resolve("retriever"); code(err) != CodeEntry || !strings.Contains(err.Error(), "named pipe") {
			t.Fatalf("err = %v, want %s naming a named pipe", err, CodeEntry)
		}
	})
	t.Run("directory", func(t *testing.T) {
		l := newLayout(t)
		if err := os.MkdirAll(filepath.Join(l.user, AgentsDir, "retriever.yaml"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := l.places.Resolve("retriever"); code(err) != CodeEntry {
			t.Fatalf("err = %v, want %s", err, CodeEntry)
		}
	})
}

func TestNotANameIsRefused(t *testing.T) {
	l := newLayout(t)
	if _, err := l.places.Resolve("agent.yaml"); code(err) != CodeNotFound {
		t.Fatalf("err = %v, want %s", err, CodeNotFound)
	}
}

// An entry inside tego's own files is refused: Compile would lift their read deny for the contract's directory.
func TestAnEntryInsideTegosOwnFilesIsRefused(t *testing.T) {
	l := newLayout(t)
	l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
	l.write(l.dir, filepath.Join(ProjectDir, AgentsDir, "writer.yaml"), "writer")
	p := l.places
	p.Own = []string{filepath.Dir(l.user), filepath.Join(l.dir, ProjectDir)}
	if _, err := p.Resolve("retriever"); code(err) != CodeEntry || !strings.Contains(err.Error(), "R6a") {
		t.Fatalf("user entry: err = %v, want %s naming R6a", err, CodeEntry)
	}
	if _, err := p.Resolve("writer"); code(err) != CodeEntry {
		t.Fatalf("project entry: err = %v, want %s", err, CodeEntry)
	}
	// Through a link to the same directory.
	link := filepath.Join(t.TempDir(), "own")
	if err := os.Symlink(filepath.Dir(l.user), link); err != nil {
		t.Fatal(err)
	}
	p.Own = []string{link}
	if _, err := p.Resolve("retriever"); code(err) != CodeEntry {
		t.Fatalf("own through a link: err = %v, want %s", err, CodeEntry)
	}
	// A sibling is not inside.
	p.Own = []string{l.user + "-other"}
	if _, err := p.Resolve("retriever"); err != nil {
		t.Fatalf("sibling: %v", err)
	}
	// One that holds the working directory too is lifted by the run whatever contract runs: nothing to refuse.
	p.Own = []string{filepath.Dir(l.dir)}
	if _, err := p.Resolve("retriever"); err != nil {
		t.Fatalf("own above the working directory: %v", err)
	}
	if _, err := p.Resolve("writer"); err != nil {
		t.Fatalf("own above the working directory: %v", err)
	}
}

// A directory of the agent's name (its code, often) is no contract a path could mean: the name resolves.
func TestADirectoryOfTheNameIsNotAmbiguous(t *testing.T) {
	l := newLayout(t)
	path := l.write(l.dir, ProjectFile, "retriever")
	if err := os.Mkdir(filepath.Join(l.dir, "retriever"), 0o755); err != nil {
		t.Fatal(err)
	}
	if e, err := l.places.Resolve("retriever"); err != nil || e.Path != path {
		t.Fatalf("entry = %+v, err = %v, want %s", e, err, path)
	}
	// A link to a file is a file.
	if err := os.Symlink(path, filepath.Join(l.dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.places.Resolve("linked"); code(err) != CodeAmbiguous {
		t.Fatalf("a link to a file: err = %v, want %s", err, CodeAmbiguous)
	}
}

// One file the project and the user registry both reach (registry: set to the project's .tego, a link to it, or the
// user's entry a hard link of the project's) is one contract, not two: it resolves, as the project's entry, and is
// not refused as both registries holding the name. Two files of the same bytes stay ambiguous
// (TestANameBothRegistriesHoldIsAmbiguous).
func TestOneFileBothRegistriesReachIsNotAmbiguous(t *testing.T) {
	for _, c := range []struct {
		what  string
		proj  string
		setup func(t *testing.T, l *layout, proj string)
	}{
		{"registry is the project's .tego", filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), func(_ *testing.T, l *layout, _ string) {
			l.places.User = filepath.Join(l.dir, ProjectDir)
		}},
		{"registry links to the project's .tego", filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), func(t *testing.T, l *layout, _ string) {
			link := filepath.Join(filepath.Dir(l.user), "linked")
			if err := os.Symlink(filepath.Join(l.dir, ProjectDir), link); err != nil {
				t.Fatal(err)
			}
			l.places.User = link
		}},
	} {
		t.Run(c.what, func(t *testing.T) {
			l := newLayout(t)
			proj := l.write(l.dir, c.proj, "retriever")
			c.setup(t, l, proj)
			e, err := l.places.Resolve("retriever")
			if err != nil || e == nil || e.Path != proj || e.Registry != Project {
				t.Fatalf("entry = %+v, err = %v, want the project's %s", e, err, proj)
			}
		})
	}
}

// A user registry spelled with ".." after a link (registry: <base>/work/lnk/../tego, lnk -> <base>/home/.config/sub)
// is the directory the kernel's walk of it reaches, <base>/home/.config/tego: its entry is recorded by that file's
// path, and a project entry of the same name is ambiguous with it. The paths were joined with filepath.Join, which
// cleaned them to <base>/work/tego/...: the entry recorded (contract_source.path) named a file that does not exist,
// and the user registry's place was looked for there, so a project entry silently replaced the user's.
func TestAUserRegistryWithDotDotAfterALinkIsTheDirectoryTheKernelReaches(t *testing.T) {
	l := newLayout(t)
	config := filepath.Dir(l.user)
	base := filepath.Dir(filepath.Dir(config))
	for _, d := range []string{filepath.Join(config, "sub"), filepath.Join(base, "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(config, "sub"), filepath.Join(base, "work", "lnk")); err != nil {
		t.Fatal(err)
	}
	l.places.User = base + "/work/lnk/../tego"
	l.write(l.user, filepath.Join(AgentsDir, "retriever.yaml"), "retriever")
	realConfig, err := filepath.EvalSymlinks(config)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(realConfig, "tego", AgentsDir, "retriever.yaml")
	e, err := l.places.Resolve("retriever")
	if err != nil {
		t.Fatal(err)
	}
	if e.Path != want || e.Registry != User {
		t.Fatalf("entry = %s in %s, want %s in the user registry", e.Path, e.Registry, want)
	}
	l.write(l.dir, filepath.Join(ProjectDir, AgentsDir, "retriever.yaml"), "retriever")
	if e, err := l.places.Resolve("retriever"); code(err) != CodeAmbiguous || !strings.Contains(err.Error(), want) {
		t.Fatalf("entry = %+v, err = %v, want %s naming %s", e, err, CodeAmbiguous, want)
	}
}
