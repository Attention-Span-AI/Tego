// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func example(t testing.TB) Snapshot {
	t.Helper()
	b, err := os.ReadFile("../../../spec/scan/v1/fixtures/basic.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func stored(t *testing.T) (string, Snapshot, string) {
	t.Helper()
	home := t.TempDir()
	s := example(t)
	s.As = Identity{UID: uint32(os.Getuid()), Recipient: uint32(os.Getuid()), Root: os.Getuid() == 0}
	for n, i := range s.Items {
		if i.Kind == "process" || i.Kind == "other_program" {
			p := i.Process()
			p.UID = s.As.UID
			s.Items[n].Detail = Detail(p)
		}
	}
	if err := Save(home, s.As.UID, s); err != nil {
		t.Fatal(err)
	}
	return home, s, filepath.Join(home, ".tego/scan/last.json")
}

func TestDecodeScan(t *testing.T) {
	s := example(t)
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		bad  []byte
	}{
		{"duplicate", bytes.Replace(b, []byte(`"schema":`), []byte(`"schema":"tego.scan/1","schema":`), 1)},
		{"missing", bytes.Replace(b, []byte(`"other_listed":true,`), nil, 1)},
		{"unknown", bytes.Replace(b, []byte(`"counts":`), []byte(`"secret":"canary","counts":`), 1)},
		{"trailing", append(append([]byte{}, b...), []byte(`{}`)...)},
		{"null scalar", bytes.Replace(b, []byte(`"other_listed":true`), []byte(`"other_listed":null`), 1)},
		{"native rule with wrapper fact", bytes.Replace(b, []byte(`"exe-name"`), []byte(`"argv-pattern"`), 1)},
		{"cgroup without match", bytes.Replace(b, []byte(`"exe-name"`), []byte(`"cgroup"`), 1)},
		{"unknown fact", bytes.Replace(b, []byte(`"exe-name"`), []byte(`"copied-secret"`), 1)},
		{"path control", bytes.Replace(b, []byte(`/home/person/project`), []byte(`/home/\u001bproject`), 1)},
		{"counts", bytes.Replace(b, []byte(`"running":1`), []byte(`"running":2`), 1)},
		{"source ref", bytes.Replace(b, []byte(`"source_id":"s-1"`), []byte(`"source_id":"absent"`), 1)},
		{"foreign uid", bytes.Replace(b, []byte(`"uid":1000`), []byte(`"uid":1001`), 1)},
		{"future catalog", bytes.Replace(b, []byte(`"c1"`), []byte(`"c999"`), 1)},
		{"invalid utf8", append([]byte{0xff}, b...)},
		{"detail unknown", bytes.Replace(b, []byte(`"ppid":`), []byte(`"token":"secret","ppid":`), 1)},
		{"oversize", bytes.Repeat([]byte(" "), MaxBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(b, tc.bad) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := Decode(tc.bad); err == nil {
				t.Fatal("invalid accepted")
			}
		})
	}
}

func TestReadMissing(t *testing.T) {
	if _, err := Read(t.TempDir(), uint32(os.Getuid()), "", time.Now()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}
func TestReadFresh(t *testing.T) {
	home, s, path := stored(t)
	r, err := Read(home, s.As.UID, *s.Boot, s.Finished)
	if err != nil || r.Freshness != "fresh" {
		t.Fatalf("read: %+v %v", r, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("file mode")
	}
	st, err = os.Stat(filepath.Dir(path))
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("directory mode")
	}
}
func TestReadStale(t *testing.T) {
	home, s, _ := stored(t)
	r, err := Read(home, s.As.UID, *s.Boot, s.Finished.Add(6*time.Minute))
	if err != nil || r.Freshness != "stale" {
		t.Fatalf("stale: %s %v", r.Freshness, err)
	}
}
func TestReadAnotherBoot(t *testing.T) {
	home, s, _ := stored(t)
	r, err := Read(home, s.As.UID, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", s.Finished)
	if err != nil || r.Freshness != "another-boot" {
		t.Fatalf("boot: %s %v", r.Freshness, err)
	}
}
func TestReadFuture(t *testing.T) {
	home, s, _ := stored(t)
	r, err := Read(home, s.As.UID, *s.Boot, s.Started.Add(-time.Second))
	if err != nil || r.Freshness != "future" {
		t.Fatalf("future: %s %v", r.Freshness, err)
	}
}
func TestReadOversized(t *testing.T) {
	home, s, path := stored(t)
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), MaxBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, s.As.UID, *s.Boot, s.Finished); !errors.Is(err, ErrSize) {
		t.Fatalf("size: %v", err)
	}
}
func TestReadWrongOwner(t *testing.T) {
	home, s, _ := stored(t)
	if _, err := Read(home, s.As.UID+1, *s.Boot, s.Finished); err == nil {
		t.Fatal("foreign state accepted")
	}
	st := unix.Stat_t{Mode: unix.S_IFREG | 0600, Nlink: 1, Uid: s.As.UID + 1}
	if checkedFile(st, s.As.UID) == nil {
		t.Fatal("foreign file accepted")
	}
}
func TestReadMalformed(t *testing.T) {
	home, s, path := stored(t)
	if err := os.WriteFile(path, []byte(`{"secret":"not a scan"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, s.As.UID, *s.Boot, s.Finished); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed: %v", err)
	}
}
func TestReadSymlink(t *testing.T) {
	home, s, path := stored(t)
	target := filepath.Join(home, "target")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, s.As.UID, *s.Boot, s.Finished); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("link: %v", err)
	}
	if err := Save(home, s.As.UID, s); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		t.Fatal("link not replaced")
	}
	b, err := os.ReadFile(target)
	if err != nil || !bytes.Contains(b, []byte("tego.scan/1")) {
		t.Fatal("target modified")
	}
}
func TestReadFIFO(t *testing.T) {
	home, s, path := stored(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, s.As.UID, *s.Boot, s.Finished); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("fifo: %v", err)
	}
}
func TestStoreUnsafeDirectory(t *testing.T) {
	home, s, path := stored(t)
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := Save(home, s.As.UID, s); !errors.Is(err, ErrMode) {
		t.Fatalf("mode: %v", err)
	}
	if _, err := Read(home, s.As.UID, *s.Boot, s.Finished); !errors.Is(err, ErrMode) {
		t.Fatalf("read mode: %v", err)
	}
}
func TestStoreLinksAndFailure(t *testing.T) {
	home, s, path := stored(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Status = "failed"
	if Save(home, s.As.UID, s) == nil {
		t.Fatal("saved failed snapshot")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("prior snapshot changed")
	}
	s.Status = "ok"
	base := filepath.Join(home, ".tego")
	if err := os.Rename(base, base+"-real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base+"-real", base); err != nil {
		t.Fatal(err)
	}
	if err := Save(home, s.As.UID, s); err != nil {
		t.Fatal("guide-compatible .tego link refused", err)
	}
	scan := filepath.Dir(path)
	if err := os.Rename(scan, scan+"-real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(scan+"-real", scan); err != nil {
		t.Fatal(err)
	}
	if Save(home, s.As.UID, s) == nil {
		t.Fatal("scan link accepted")
	}
}
func TestStoreConcurrent(t *testing.T) {
	home, s, _ := stored(t)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for range 8 {
				if err := Save(home, s.As.UID, s); err != nil {
					t.Error(err)
				}
			}
		})
	}
	for range 16 {
		r, err := Read(home, s.As.UID, *s.Boot, s.Finished)
		if err != nil && !errors.Is(err, ErrChanged) {
			t.Error(err)
		}
		if err == nil && r.Snapshot.Counts != s.Counts {
			t.Error("torn result")
		}
	}
	wg.Wait()
	entries, err := os.ReadDir(filepath.Join(home, ".tego/scan"))
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary entries remain")
	}
}

func FuzzDecodeScan(f *testing.F) {
	s := example(f)
	b, err := Encode(s)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	configured, err := os.ReadFile("../../../spec/scan/v1/fixtures/configured.json")
	if err != nil {
		f.Fatal(err)
	}
	if _, err = Decode(configured); err != nil {
		f.Fatal("invalid configured seed", err)
	}
	f.Add(configured)
	advanced, err := os.ReadFile("../../../spec/scan/v1/fixtures/advanced.json")
	if err != nil {
		f.Fatal(err)
	}
	if _, err = Decode(advanced); err != nil {
		f.Fatal("invalid advanced seed", err)
	}
	f.Add(advanced)
	local, err := Decode(configured)
	if err != nil {
		f.Fatal(err)
	}
	local.Items[0].Name = "claude"
	local.Items[0].Evidence[0].RuleID = "mcp-claude"
	v := local.Items[0].Config()
	v.Client, v.Scope, v.Path = "claude", "local", Path("/home/example/.claude.json")
	local.Items[0].Detail = Detail(v)
	local.Sources[0].Locator = v.Path
	local.Status, local.Check = "partial", "none-observed"
	local.Sources = append(local.Sources, Source{ID: "unresolved-unit", Kind: "E", Locator: Path("/home/example/expand.service"), State: "not-read", NotRead: 1, Reason: "unresolved"})
	localBytes, err := Encode(local)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(localBytes)
	f.Add([]byte(`{"schema":"tego.scan/1","schema":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Decode(b)
		if err != nil {
			return
		}
		out, err := Encode(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(out); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMembershipWords(t *testing.T) {
	id := "r-0123abcd-0000000000000-abcdef"
	p := Process{Membership: "in-run", RunID: &id}
	if got := MembershipWords(p, nil); got != "in a cgroup named for run "+id+"; could not be checked against the record" {
		t.Fatal(got)
	}
	if got := MembershipWords(p, map[string]bool{id: true}); got != "in Tego run "+id {
		t.Fatal(got)
	}
	b, _ := json.Marshal(p)
	if bytes.Contains(b, []byte("recorded")) {
		t.Fatal("live-record assertion persisted")
	}
}

func TestReadWrongMode(t *testing.T) {
	home, s, path := stored(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, s.As.UID, *s.Boot, s.Finished); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("mode: %v", err)
	}
}
func TestReadForeignRecipient(t *testing.T) {
	home, s, path := stored(t)
	uid := s.As.Recipient
	s.As.UID++
	s.As.Recipient++
	s.As.Root = s.As.UID == 0
	for n, i := range s.Items {
		if i.Kind == "process" || i.Kind == "other_program" {
			p := i.Process()
			p.UID = s.As.UID
			s.Items[n].Detail = Detail(p)
		}
	}
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home, uid, *s.Boot, s.Finished); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign recipient: %v", err)
	}
}
func TestReadUnknownBoot(t *testing.T) {
	home, s, _ := stored(t)
	for _, boot := range []string{"", "bad"} {
		r, err := Read(home, s.As.UID, boot, s.Finished)
		if err != nil || r.Freshness != "unknown" {
			t.Fatalf("boot: %s %v", r.Freshness, err)
		}
	}
}

func TestScanDirectoryOwnerDiagnostic(t *testing.T) {
	uid := uint32(os.Getuid())
	if err := checkedDirectory(unix.Stat_t{Uid: uid + 1, Mode: unix.S_IFDIR | 0700}, uid); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("foreign owner got chmod advice: %v", err)
	}
	if err := checkedDirectory(unix.Stat_t{Uid: uid, Mode: unix.S_IFDIR | 0755}, uid); !errors.Is(err, ErrMode) {
		t.Fatalf("mode: %v", err)
	}
}
