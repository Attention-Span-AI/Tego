// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestContractsCatalogPreservesBrokenAndAmbiguousEntries(t *testing.T) {
	l := newLayout(t)
	l.write(l.dir, ProjectFile, "same")
	l.write(l.user, "agents/same.yaml", "same")
	bad := l.write(l.user, "agents/bad.yaml", "bad")
	if err := os.WriteFile(bad, []byte("name: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := l.write(l.dir, "outside.yaml", "escape")
	if err := os.Symlink(outside, filepath.Join(l.user, "agents/escape.yaml")); err != nil {
		t.Fatal(err)
	}
	es, rs := l.places.Catalog()
	if len(es) != 4 || len(rs) != 3 {
		t.Fatalf("entries %v, roots %v", es, rs)
	}
	var same, badSeen, escape int
	for _, e := range es {
		switch filepath.Base(e.Path) {
		case "agent.yaml", "same.yaml":
			if e.Err != nil {
				t.Fatal(e.Err)
			}
			same++
		case "bad.yaml":
			if len(e.Data) == 0 {
				t.Fatal("invalid YAML disappeared before parsing")
			}
			badSeen++
		case "escape.yaml":
			if e.Err == nil || len(e.Data) > 0 {
				t.Fatal("read escaped registry link")
			}
			escape++
		}
	}
	if same != 2 || badSeen != 1 || escape != 1 {
		t.Fatalf("same %d bad %d escape %d", same, badSeen, escape)
	}
}

func TestContractsCatalogMissingUnreadableAndUnsafeRoots(t *testing.T) {
	l := newLayout(t)
	_, rs := l.places.Catalog()
	for _, r := range rs {
		if r.State != "absent" {
			t.Fatalf("missing root: %+v", r)
		}
	}
	// O_DIRECTORY refuses this at every UID. chmod(0) directories remain
	// readable when the package is tested as root.
	if err := os.WriteFile(filepath.Join(l.user, "agents"), []byte("not a registry directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rs = l.places.Catalog()
	found := false
	for _, r := range rs {
		if r.Path == filepath.Join(l.user, "agents") {
			found = r.State == "unreadable" && r.Err != nil
		}
	}
	if !found {
		t.Fatalf("unreadable root hidden: %+v", rs)
	}
	p := l.places
	p.Dir = "relative"
	_, rs = p.Catalog()
	if len(rs) != 1 || rs[0].Err == nil || !strings.Contains(rs[0].Err.Error(), "cannot be placed") {
		t.Fatalf("unsafe root: %+v", rs)
	}
}

func TestContractsCatalogBoundsAndContainedLink(t *testing.T) {
	t.Run("directory entries", func(t *testing.T) {
		l := newLayout(t)
		dir := filepath.Join(l.user, AgentsDir)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxCatalogEntries+1; i++ {
			if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(i)+".txt"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, roots := l.places.Catalog()
		cut := false
		for _, r := range roots {
			if r.Path == dir && r.Err != nil && strings.Contains(r.Err.Error(), "exceeds") {
				cut = true
			}
		}
		if !cut {
			t.Fatal("directory limit hidden")
		}
	})
	t.Run("source bytes", func(t *testing.T) {
		l := newLayout(t)
		data := strings.Repeat("#", agent.MaxContractSize)
		for i := 0; i < MaxCatalogBytes/agent.MaxContractSize+1; i++ {
			path := l.write(l.user, "agents/a"+strconv.Itoa(i)+".yaml", "a")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		entries, _ := l.places.Catalog()
		total, cut := 0, false
		for _, e := range entries {
			total += len(e.Data)
			cut = cut || (e.Err != nil && strings.Contains(e.Err.Error(), "exceed"))
		}
		if !cut || total > MaxCatalogBytes {
			t.Fatalf("byte bound total %d cut %v", total, cut)
		}
	})
	t.Run("relative link inside registry", func(t *testing.T) {
		l := newLayout(t)
		target := l.write(l.user, "agents/body", "inside")
		if err := os.Symlink(filepath.Base(target), filepath.Join(l.user, AgentsDir, "inside.yaml")); err != nil {
			t.Fatal(err)
		}
		entries, _ := l.places.Catalog()
		if len(entries) != 1 || entries[0].Err != nil || len(entries[0].Data) == 0 {
			t.Fatalf("safe registry link changed: %+v", entries)
		}
	})
}
