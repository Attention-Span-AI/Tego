// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/grouptrust"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
	"golang.org/x/sys/unix"
)

func TestScanPrivateGroupVendorLayouts(t *testing.T) {
	for _, layout := range []string{"file0664", "directory0775", "dropin0775"} {
		t.Run(layout, func(t *testing.T) {
			root := unitFixtureRoot(t)
			uid := uint32(os.Getuid())
			ctx := fixtureModePolicy(t, uid, uint32(os.Getgid()), false, false)
			if layout == "file0664" {
				writeSettings(t, root, ".gemini/settings.json", []byte(`{"mcpServers":{"guest-gemini":{"command":"codex"}}}`))
				if err := os.Chmod(filepath.Join(root, ".gemini/settings.json"), 0664); err != nil {
					t.Fatal(err)
				}
				got := collectMCP(ctx, root, root, uid, &contentBudget{remaining: 6 << 20})
				if len(got.Items) != 1 {
					t.Fatalf("0664 vendor settings: items=%d sources=%+v", len(got.Items), got.Sources)
				}
				return
			}
			writeSettings(t, root, "guest-agent.service", []byte("[Service]\nExecStart=codex\n"))
			target := root
			if layout == "dropin0775" {
				writeSettings(t, root, "guest-agent.service.d/10-reset.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
				target = filepath.Join(root, "guest-agent.service.d")
				if err := os.Chmod(filepath.Join(target, "10-reset.conf"), 0664); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(target, 0775); err != nil {
				t.Fatal(err)
			}
			got := collectUnits(ctx, []string{root}, uid, &contentBudget{remaining: 6 << 20})
			if len(got.Items) != 1 {
				t.Fatalf("0775 vendor unit directory: items=%d sources=%+v", len(got.Items), got.Sources)
			}
		})
	}
}

func fixtureModePolicy(t *testing.T, uid, gid uint32, shared, remote bool) context.Context {
	t.Helper()
	nss := "passwd: files\ngroup: files\n"
	if remote {
		nss = "passwd: files sss\ngroup: files sss\n"
	}
	p := grouptrust.Load(int(uid), func(path string) ([]byte, error) {
		switch path {
		case "/etc/passwd":
			return []byte(fmt.Sprintf("person:x:%d:%d::/:/bin/sh\nother:x:%d:%d::/:/bin/sh\n", uid, gid, uid+1, gid+1)), nil
		case "/etc/group":
			members := "person"
			if shared {
				members += ",other"
			}
			return []byte(fmt.Sprintf("person:x:%d:%s\n", gid, members)), nil
		default:
			return []byte(nss), nil
		}
	})
	return context.WithValue(t.Context(), modePolicyKey{uid}, p)
}

func TestScanModeLayouts(t *testing.T) {
	for _, tc := range []struct {
		name             string
		mode, owner, gid uint32
		shared, remote   bool
		reason, repair   string
	}{
		{name: "file0664", mode: 0664, owner: 1000, gid: 1000},
		{name: "directory0775", mode: 0775, owner: 1000, gid: 1000},
		{name: "second-member", mode: 0664, owner: 1000, gid: 1000, shared: true, reason: "mode", repair: `group "person"`},
		{name: "world-writable", mode: 0666, owner: 1000, gid: 1000, reason: "mode", repair: "chmod o-w"},
		{name: "foreign-owner", mode: 0644, owner: 1001, gid: 1001, reason: "owner", repair: "ask its owner"},
		{name: "root-etc-vendor", mode: 0644, owner: 0, gid: 0},
		{name: "directory-service-primary-refused", mode: 0664, owner: 1000, gid: 1000, remote: true, reason: "mode", repair: "directory-service"},
		{name: "directory-service-other-group", mode: 0664, owner: 1000, gid: 2000, remote: true, reason: "mode", repair: `group "gid 2000"`},
		{name: "directory-service-known-sharing", mode: 0664, owner: 1000, gid: 1000, shared: true, remote: true, reason: "mode", repair: `group "person"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := fixtureModePolicy(t, 1000, 1000, tc.shared, tc.remote)
			err := checkMode(ctx, unix.Stat_t{Mode: tc.mode, Uid: tc.owner, Gid: tc.gid}, 1000)
			if tc.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			src := projectSource("/fixture/source", err)
			if src.Reason != tc.reason || src.Read != 0 || src.NotRead != 1 {
				t.Fatalf("refusal: %+v err=%v", src, err)
			}
			s := result.New(time.Now(), 1000, "test")
			s.Status = "partial"
			s.Sources = append(s.Sources, result.Source{ID: "source-1", Kind: "D", Locator: result.Path(src.Path), State: src.State, Reason: src.Reason, WritableGroup: src.WritableGroup, GroupEvidence: src.GroupEvidence, Read: src.Read, NotRead: src.NotRead})
			var out, errs bytes.Buffer
			if e := result.Render(&out, &errs, s, false, true, nil); e != nil {
				t.Fatal(e)
			}
			text := out.String() + errs.String()
			if !strings.Contains(text, tc.repair) {
				t.Fatalf("missing repair %q in %s", tc.repair, text)
			}
			b, e := result.Encode(s)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = result.Decode(b); e != nil {
				t.Fatal(e)
			}
			var wire any
			if e = json.Unmarshal(b, &wire); e != nil {
				t.Fatal(e)
			}
			if e = jsonschema.Check("../../spec/scan/v1/schema.json", wire); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestScanSharedGroupParentsRefused(t *testing.T) {
	root := unitFixtureRoot(t)
	writeSettings(t, root, ".gemini/settings.json", []byte(`{"mcpServers":{"s":{"command":"codex"}}}`))
	if err := os.Chmod(filepath.Join(root, ".gemini"), 0775); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	ctx := fixtureModePolicy(t, uid, gid, true, false)
	got := collectMCP(ctx, root, root, uid, &contentBudget{remaining: 6 << 20})
	if len(got.Items) != 0 {
		t.Fatal("shared group parent accepted")
	}
	found := false
	for _, s := range got.Sources {
		if s.Reason == "mode" && s.WritableGroup != nil && *s.WritableGroup == "person" && s.Path == filepath.Join(root, ".gemini") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing named-group refusal: %+v", got.Sources)
	}
}

func TestScanSharedUnitModesRefused(t *testing.T) {
	for _, name := range []string{".", "guest.service", "guest.service.d", "guest.service.d/10-reset.conf"} {
		t.Run(name, func(t *testing.T) {
			root := unitFixtureRoot(t)
			writeSettings(t, root, "guest.service", []byte("[Service]\nExecStart=codex\n"))
			writeSettings(t, root, "guest.service.d/10-reset.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
			mode := os.FileMode(0664)
			if name == "." || name == "guest.service.d" {
				mode = 0775
			}
			if e := os.Chmod(filepath.Join(root, name), mode); e != nil {
				t.Fatal(e)
			}
			uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
			got := collectUnits(fixtureModePolicy(t, uid, gid, true, false), []string{root}, uid, &contentBudget{remaining: 6 << 20})
			if len(got.Items) != 0 {
				t.Fatalf("shared group supplied unit evidence: %+v", got.Items)
			}
			found := false
			for _, s := range got.Sources {
				if s.Reason == "mode" && s.WritableGroup != nil && *s.WritableGroup == "person" && s.Path == filepath.Join(root, name) {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing named refusal: %+v", got.Sources)
			}
		})
	}
}

func TestScanModeRejectsNamedAccessACL(t *testing.T) {
	root := unitFixtureRoot(t)
	writeSettings(t, root, "settings.json", []byte(`{"mcpServers":{"s":{"command":"codex"}}}`))
	path := filepath.Join(root, "settings.json")
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, e := range []struct {
		tag, perm uint16
		id        uint32
	}{{1, 6, ^uint32(0)}, {2, 2, uint32(os.Getuid()) + 10001}, {4, 4, ^uint32(0)}, {16, 6, ^uint32(0)}, {32, 4, ^uint32(0)}} {
		at := 4 + i*8
		binary.LittleEndian.PutUint16(acl[at:], e.tag)
		binary.LittleEndian.PutUint16(acl[at+2:], e.perm)
		binary.LittleEndian.PutUint32(acl[at+4:], e.id)
	}
	if e := unix.Setxattr(path, "system.posix_acl_access", acl, 0); e == unix.EOPNOTSUPP {
		t.Log("ACL unavailable; discovery access-ACL check remains owed in a guest")
		return
	} else if e != nil {
		t.Fatal(e)
	}
	uid := uint32(os.Getuid())
	ctx := fixtureModePolicy(t, uid, uint32(os.Getgid()), false, false)
	pin, _, e := metadataPath(ctx, root, false)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = pin.Close() }()
	parsed := false
	e = readContent(ctx, pin, "settings.json", uid, &contentBudget{remaining: 6 << 20}, func(io.Reader) error { parsed = true; return nil })
	if fixedReason(e) != "mode" || parsed {
		t.Fatalf("ACL accepted: parsed=%v err=%v", parsed, e)
	}
}

func TestDiscoveryLazyLocalEvidence(t *testing.T) {
	calls := 0
	fixture := fixtureModePolicy(t, 1000, 1000, false, false)
	ctx := context.WithValue(t.Context(), modePolicyKey{1000}, &discoveryPolicy{load: func() grouptrust.Policy {
		calls++
		return fixture.Value(modePolicyKey{1000}).(grouptrust.Policy)
	}})
	for _, st := range []unix.Stat_t{{Mode: 0644, Uid: 1000, Gid: 1000}, {Mode: 0755, Uid: 0, Gid: 0}, {Mode: 0666, Uid: 1000, Gid: 1000}, {Mode: 0664, Uid: 1001, Gid: 1000}} {
		_ = checkMode(ctx, st, 1000)
	}
	if calls != 0 {
		t.Fatalf("ordinary/refused inode loaded identities %d times", calls)
	}
	for range 2 {
		if e := checkMode(ctx, unix.Stat_t{Mode: 0664, Uid: 1000, Gid: 1000}, 1000); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 1 {
		t.Fatalf("local evidence read %d times, want 1", calls)
	}
}

func TestProjectSharedPrimaryWithoutListedMember(t *testing.T) {
	o := commandOptions(t)
	path := filepath.Join(o.Directory, "package.json")
	writeSettings(t, o.Directory, "package.json", []byte(`{"dependencies":{"@openai/codex":"secret"}}`))
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	uid, gid := o.Caller.UID, st.Gid
	// Match the caller's checked primary gid to the inode: the base must reach
	// its primary-gid allowance, rather than refusing an unrelated gid mismatch.
	writeProcFile(t, o.Directory, "passwd", []byte(fmt.Sprintf("person:x:%d:%d::%s:/bin/sh\nother:x:%d:%d::/:/bin/sh\n", uid, gid, o.Directory, uid+1, gid)))

	p := grouptrust.Load(int(uid), func(path string) ([]byte, error) {
		switch path {
		case "/etc/passwd":
			return []byte(fmt.Sprintf("person:x:%d:%d::/:/bin/sh\nother:x:%d:%d::/:/bin/sh\n", uid, gid, uid+1, gid)), nil
		case "/etc/group":
			return []byte(fmt.Sprintf("staff:x:%d:person\n", gid)), nil
		default:
			return []byte("passwd: files\ngroup: files\n"), nil
		}
	})
	ctx := context.WithValue(t.Context(), modePolicyKey{uid}, p)
	s := Collect(ctx, o).Snapshot
	if s.Counts.Project != 0 {
		t.Fatalf("second primary account supplied F row: %+v", s.Counts)
	}
	for _, src := range s.Sources {
		if src.Kind == "F" && src.Locator != nil && *src.Locator == path {
			if src.Reason != "mode" || src.WritableGroup == nil || *src.WritableGroup != "staff" || src.GroupEvidence != "shared-primary" {
				t.Fatalf("refusal %+v", src)
			}
			return
		}
	}
	t.Fatal("missing F refusal")
}

func TestDiscoveryOrdinaryLayouts(t *testing.T) {
	for _, layout := range []string{"ubuntu-private", "fedora-private", "shared-primary", "domain-joined", "root-vendor-modes"} {
		t.Run(layout, func(t *testing.T) {
			root := unitFixtureRoot(t)
			writeSettings(t, root, ".gemini/settings.json", []byte(`{"mcpServers":{"fixture":{"command":"codex"}}}`))
			writeSettings(t, root, "package.json", []byte(`{"dependencies":{"@openai/codex":"secret"}}`))
			writeSettings(t, root, "fixture.service", []byte("[Service]\nExecStart=codex\n"))
			writeSettings(t, root, "fixture.service.d/10.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
			uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
			mode := os.FileMode(0664)
			if layout == "root-vendor-modes" {
				mode = 0644
			}
			for _, name := range []string{".gemini/settings.json", "package.json", "fixture.service", "fixture.service.d/10.conf"} {
				if e := os.Chmod(filepath.Join(root, name), mode); e != nil {
					t.Fatal(e)
				}
			}
			dirMode := os.FileMode(0775)
			if layout == "root-vendor-modes" {
				dirMode = 0755
			}
			for _, name := range []string{".", ".gemini", "fixture.service.d"} {
				if e := os.Chmod(filepath.Join(root, name), dirMode); e != nil {
					t.Fatal(e)
				}
			}
			p := grouptrust.Load(int(uid), func(path string) ([]byte, error) {
				switch path {
				case "/etc/passwd":
					otherGID := gid + 1
					if layout == "shared-primary" {
						otherGID = gid
					}
					return []byte(fmt.Sprintf("person:x:%d:%d::/:/bin/sh\nother:x:%d:%d::/:/bin/sh\n", uid, gid, uid+1, otherGID)), nil
				case "/etc/group":
					return []byte(fmt.Sprintf("person:x:%d:person\n", gid)), nil
				default:
					if layout == "domain-joined" {
						return []byte("passwd: files sss\ngroup: files sss\n"), nil
					}
					return []byte("passwd: files\ngroup: files\n"), nil
				}
			})
			ctx := context.WithValue(t.Context(), modePolicyKey{uid}, p)
			m := collectMCP(ctx, root, root, uid, &contentBudget{remaining: 6 << 20})
			u := collectUnits(ctx, []string{root}, uid, &contentBudget{remaining: 6 << 20})
			f := collectProject(ctx, root, uid, gid)
			want := 1
			if layout == "shared-primary" || layout == "domain-joined" {
				want = 0
			}
			if len(m.Items) != want || len(u.Items) != want || len(f.Items) != want {
				t.Fatalf("MCP/unit/project=%d/%d/%d want %d each; sources %+v %+v %+v", len(m.Items), len(u.Items), len(f.Items), want, m.Sources, u.Sources, f.Sources)
			}
			// Root ownership is injected separately; no host chown or /etc writes.
			if layout == "root-vendor-modes" {
				if e := checkMode(ctx, unix.Stat_t{Mode: 0644, Uid: 0, Gid: 0}, uid); e != nil {
					t.Fatal(e)
				}
			}
			t.Logf("MCP/unit/project=%d/%d/%d", len(m.Items), len(u.Items), len(f.Items))
		})
	}
}

func TestDiscoveryParentRepair(t *testing.T) {
	for _, kind := range []string{"D", "E", "F"} {
		t.Run(kind, func(t *testing.T) {
			root := unitFixtureRoot(t)
			uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
			ctx := fixtureModePolicy(t, uid, gid, true, false)
			var sources []processSource
			var parent string
			switch kind {
			case "D":
				writeSettings(t, root, ".gemini/settings.json", []byte(`{"mcpServers":{"s":{"command":"codex"}}}`))
				parent = filepath.Join(root, ".gemini")
				if e := os.Chmod(parent, 0775); e != nil {
					t.Fatal(e)
				}
				sources = collectMCP(ctx, root, root, uid, &contentBudget{remaining: 6 << 20}).Sources
			case "E":
				writeSettings(t, root, "fixture.service", []byte("[Service]\nExecStart=codex\n"))
				writeSettings(t, root, "fixture.service.d/10.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
				parent = filepath.Join(root, "fixture.service.d")
				if e := os.Chmod(parent, 0775); e != nil {
					t.Fatal(e)
				}
				sources = collectUnits(ctx, []string{root}, uid, &contentBudget{remaining: 6 << 20}).Sources
			case "F":
				writeSettings(t, root, "config/agents.yaml", []byte("secret"))
				parent = filepath.Join(root, "config")
				if e := os.Chmod(parent, 0775); e != nil {
					t.Fatal(e)
				}
				sources = collectProject(ctx, root, uid, gid).Sources
			}
			for _, src := range sources {
				if src.Reason == "mode" {
					if src.Path != parent || src.WritableGroup == nil || *src.WritableGroup != "person" || src.GroupEvidence != "other-member" {
						t.Fatalf("wrong parent refusal: %+v", src)
					}
					s := result.New(time.Now(), uid, "test")
					s.Status = "partial"
					s.Sources = append(s.Sources, result.Source{ID: "source-1", Kind: kind, Locator: result.Path(src.Path), State: src.State, Reason: src.Reason, WritableGroup: src.WritableGroup, GroupEvidence: src.GroupEvidence, NotRead: 1})
					var out strings.Builder
					if e := result.Footer(&out, s, false); e != nil {
						t.Fatal(e)
					}
					if !strings.Contains(out.String(), "chmod g-w -- "+shellword.Quote(parent)) {
						t.Fatalf("wrong repair: %s", out.String())
					}
					return
				}
			}
			t.Fatalf("missing parent refusal: %+v", sources)
		})
	}
}

func TestAccountPlacementRepairProjection(t *testing.T) {
	repair := "Ask the administrator to repair /etc/group: group or other writable."
	src := procSource("/fixture/settings.json", &grouptrust.ModeError{Group: "person", Evidence: "accounts-unreadable", AccountRepair: repair}, false)
	if src.AccountRepair != repair || src.GroupEvidence != "accounts-unreadable" {
		t.Fatalf("lost account repair: %+v", src)
	}
}

func TestAccountPlacementRepairCollect(t *testing.T) {
	o := commandOptions(t)
	writeProcFile(t, o.Directory, "package.json", []byte(`{"dependencies":{"@openai/codex":"value"}}`))
	if err := os.Chmod(filepath.Join(o.Directory, "package.json"), 0664); err != nil {
		t.Fatal(err)
	}
	p := grouptrust.Load(int(o.Caller.UID), func(path string) ([]byte, error) { return nil, errors.New("group or other writable") })
	ctx := context.WithValue(t.Context(), modePolicyKey{o.Caller.UID}, p)
	s := Collect(ctx, o).Snapshot
	found := false
	for _, src := range s.Sources {
		if src.Kind == "F" && src.GroupEvidence == "accounts-unreadable" {
			found = true
			if !strings.Contains(src.AccountRepair, "/etc/passwd") || !strings.Contains(src.AccountRepair, "group or other writable") {
				t.Fatalf("lost repair in collection: %+v", src)
			}
		}
	}
	if !found {
		t.Fatalf("missing placement refusal: %+v", s.Sources)
	}
	b, err := result.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Decode(b); err != nil {
		t.Fatal(err)
	}
	var wire any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if err := jsonschema.Check("../../spec/scan/v1/schema.json", wire); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := result.Footer(&out, s, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "/etc/passwd") {
		t.Fatal("footer lost account repair")
	}
}

func TestDiscoveryAccountSnapshotAcrossUIDs(t *testing.T) {
	calls := 0
	p := grouptrust.Load(0, func(path string) ([]byte, error) {
		switch path {
		case "/etc/passwd":
			return []byte("root:x:0:0::/:/bin/sh\nfirst:x:200001:200001::/:/bin/sh\nsecond:x:200002:200002::/:/bin/sh\n"), nil
		case "/etc/group":
			return []byte("root:x:0:root\nfirst:x:200001:first\nsecond:x:200002:second\n"), nil
		default:
			return []byte("passwd: files\ngroup: files\n"), nil
		}
	})
	ctx := context.WithValue(t.Context(), collectionPolicyKey{}, &discoveryPolicy{load: func() grouptrust.Policy { calls++; return p }})
	for range 3 {
		for _, uid := range []uint32{0, 200001, 200002} {
			if err := checkMode(ctx, unix.Stat_t{Mode: 0664, Uid: uid, Gid: uid}, uid); err != nil {
				t.Errorf("private group uid %d: %v", uid, err)
			}
			if uid != 0 && checkMode(ctx, unix.Stat_t{Mode: 0664, Uid: uid, Gid: uid}, 0) == nil {
				t.Fatal("snapshot reuse changed the selected owner")
			}
			if checkMode(ctx, unix.Stat_t{Mode: 0664, Uid: uid, Gid: 200001}, uid) == nil && uid != 200001 {
				t.Fatal("snapshot reuse accepted another owner's group")
			}
		}
	}
	if calls != 1 {
		t.Fatalf("account snapshot loaded %d times, want one across UIDs", calls)
	}
}
