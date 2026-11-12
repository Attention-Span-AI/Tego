// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/thishost"
)

const testRun = "r-0123abcd-mabc12-abcdef"

// TestNormalize: every spelling of one block is one value, and what is no block is refused.
func TestNormalize(t *testing.T) {
	for _, c := range []struct {
		kind      Kind
		in, want  string
		wantError bool
	}{
		{KindExec, "curl", "curl", false},
		{KindExec, " /usr/bin/../bin/curl ", "/usr/bin/curl", false},
		{KindExec, "/opt/tools/", "/opt/tools/", false},
		{KindExec, "/opt/tools//", "/opt/tools/", false},
		{KindExec, "./curl", "", true},
		{KindExec, "bin/curl", "", true},
		{KindExec, "two words", "", true},
		{KindExec, "..", "", true},
		{KindNet, "Example.COM:443", "example.com:443", false},
		{KindNet, "example.com.", "example.com", false},
		{KindNet, "tcp://api.example.com:443", "api.example.com:443", false},
		{KindNet, "127.0.0.1:8080", "127.0.0.1:8080", false},
		{KindNet, "::ffff:127.0.0.1", "127.0.0.1", false},
		{KindNet, "[2001:db8::1]:443", "[2001:db8::1]:443", false},
		{KindNet, "2001:db8::1", "2001:db8::1", false},
		{KindNet, "unix:/run/../run/pg.sock", "/run/pg.sock", false},
		{KindNet, "@bus", "@bus", false},
		{KindNet, "example.com:0", "", true},
		{KindNet, "example.com:99999", "", true},
		{KindNet, "example.com:", "", true},
		{KindNet, "127.0.0.1:0", "", true},
		{KindNet, "300.1.2.3", "", true},
		{KindNet, "exa mple.com", "", true},
		{KindNet, "/" + strings.Repeat("s", 120), "", true},
		{KindPath, "/home/u/proj/../proj/.env", "/home/u/proj/.env", false},
		{KindPath, "relative/x", "", true},
		{KindPath, "/a\x00b", "", true},
		{KindPath, "/a\nb", "", true},
		{KindPath, "", "", true},
		{Kind("file"), "/x", "", true},
	} {
		got, err := Normalize(c.kind, c.in)
		if c.wantError {
			if err == nil || !errors.Is(err, ErrInvalid) {
				t.Errorf("Normalize(%s, %q) = %q, %v; want ErrInvalid", c.kind, c.in, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("Normalize(%s, %q) = %q, %v; want %q", c.kind, c.in, got, err, c.want)
		}
	}
}

// TestOverlayAddRemove: an add and a remove each record one change with a rising serial; adding a block twice, by
// any spelling, and removing one that is not there change nothing; Since reports what a reader has not seen.
func TestOverlayAddRemove(t *testing.T) {
	o := New(testRun)
	at := time.Date(2026, 10, 25, 18, 0, 0, 0, time.UTC)
	c, ok, err := o.Add(KindExec, "/usr/bin/curl", "uid:1 pid:2 cli", at)
	if err != nil || !ok || c.Serial != 1 || c.Op != OpAdd || c.Rule() != "live.block[exec:/usr/bin/curl]" {
		t.Fatalf("Add = %+v, %v, %v", c, ok, err)
	}
	if _, ok, err := o.Add(KindExec, "/usr/bin/./curl", "x", at); ok || err != nil {
		t.Fatalf("a second spelling of one block was added again: %v %v", ok, err)
	}
	if _, ok, _ := o.Add(KindNet, "example.com:443", "x", at); !ok {
		t.Fatal("net block not added")
	}
	if _, ok, _ := o.Remove(KindPath, "/nowhere", "x", at); ok {
		t.Fatal("removed a block that was not there")
	}
	c, ok, err = o.Remove(KindExec, "/usr/bin/curl", "uid:1 pid:3 dashboard", at)
	if err != nil || !ok || c.Serial != 3 || c.Op != OpRemove {
		t.Fatalf("Remove = %+v, %v, %v", c, ok, err)
	}
	if len(o.Blocks) != 1 || o.Blocks[0].Key() != "net:example.com:443" {
		t.Fatalf("blocks %+v", o.Blocks)
	}
	got, lost := o.Since(1)
	if lost != 0 || len(got) != 2 || got[0].Serial != 2 || got[1].Serial != 3 {
		t.Fatalf("Since(1) = %+v, lost %d", got, lost)
	}
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(b, testRun)
	if err != nil || back.Serial != 3 || len(back.Blocks) != 1 {
		t.Fatalf("Decode(Encode) = %+v, %v", back, err)
	}
	if _, err := Decode(b, "r-other"); err == nil {
		t.Fatal("an overlay of another run was accepted")
	}
}

// TestOverlayKeepsNewestChanges: past MaxChanges the oldest changes go, and Since says how many a reader missed.
func TestOverlayKeepsNewestChanges(t *testing.T) {
	o := New(testRun)
	for i := 0; i < MaxChanges+10; i++ {
		if _, _, err := o.Add(KindPath, "/p", "x", time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := o.Remove(KindPath, "/p", "x", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if len(o.Changes) != MaxChanges {
		t.Fatalf("%d changes kept, want %d", len(o.Changes), MaxChanges)
	}
	got, lost := o.Since(0)
	if len(got) != MaxChanges || lost != o.Serial-MaxChanges {
		t.Fatalf("Since(0) = %d changes, %d lost; want %d and %d", len(got), lost, MaxChanges, o.Serial-MaxChanges)
	}
	if err := o.Validate(testRun); err != nil {
		t.Fatal(err)
	}
}

// TestDecodeRefusesMalformed: what the launcher would misread is refused, never half-applied.
func TestDecodeRefusesMalformed(t *testing.T) {
	for name, body := range map[string]string{
		"not json":          "{",
		"wrong version":     `{"v":6,"run":"` + testRun + `"}`,
		"unknown kind":      `{"v":1,"run":"` + testRun + `","blocks":[{"kind":"file","value":"/x"}]}`,
		"not normalized":    `{"v":1,"run":"` + testRun + `","blocks":[{"kind":"path","value":"/x/../y"}]}`,
		"twice":             `{"v":1,"run":"` + testRun + `","blocks":[{"kind":"path","value":"/y"},{"kind":"path","value":"/y"}]}`,
		"serial past":       `{"v":1,"run":"` + testRun + `","serial":1,"changes":[{"serial":2,"op":"add","kind":"path","value":"/y"}]}`,
		"bad op":            `{"v":1,"run":"` + testRun + `","serial":1,"changes":[{"serial":1,"op":"allow","kind":"path","value":"/y"}]}`,
		"trailing document": `{"v":1,"run":"` + testRun + `"}{}`,
	} {
		if _, err := Decode([]byte(body), testRun); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Decode = %v, want ErrInvalid", name, err)
		}
	}
}

// TestSetMatches: each kind matches what it names and nothing else; a nil Set blocks nothing.
func TestSetMatches(t *testing.T) {
	o := New(testRun)
	for _, b := range []struct {
		k Kind
		v string
	}{
		{KindExec, "/usr/bin/curl"}, {KindExec, "wget"}, {KindExec, "/opt/tools/"},
		{KindNet, "example.com:443"}, {KindNet, "10.1.2.3"}, {KindNet, "[2001:db8::1]:22"},
		{KindNet, "/run/pg.sock"}, {KindNet, "@bus"},
		{KindPath, "/home/u/proj/secret"},
	} {
		if _, _, err := o.Add(b.k, b.v, "t", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	curlID := FileID{Dev: 7, Ino: 42}
	s := Compile(o, Resolved{
		Addrs: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("93.184.216.34")}},
		Files: map[string]FileID{"/usr/bin/curl": curlID},
	})
	exec := func(id FileID, idOK bool, names ...string) string {
		e, ok := s.MatchExec(names, id, idOK, nil)
		if !ok {
			return ""
		}
		return e.Rule()
	}
	for _, c := range []struct {
		got, want string
	}{
		{exec(FileID{}, false, "/usr/bin/curl"), "live.block[exec:/usr/bin/curl]"},
		{exec(curlID, true, "/tmp/hardlink"), "live.block[exec:/usr/bin/curl]"},
		{exec(FileID{}, false, "/usr/local/bin/wget"), "live.block[exec:wget]"},
		{exec(FileID{}, false, "/opt/tools/x/y"), "live.block[exec:/opt/tools/]"},
		{exec(FileID{}, false, "/usr/bin/git"), ""},
		{exec(FileID{}, false, "/usr/bin/curlx"), ""},
		{exec(FileID{}, false, "/opt/toolsx"), ""},
	} {
		if c.got != c.want {
			t.Errorf("exec match %q, want %q", c.got, c.want)
		}
	}
	inet := func(ap, host string) string {
		e, ok := s.MatchInet(netip.MustParseAddrPort(ap), host, nil)
		if !ok {
			return ""
		}
		return e.Rule()
	}
	for _, c := range []struct{ got, want string }{
		{inet("93.184.216.34:443", ""), "live.block[net:example.com:443]"},
		{inet("[::ffff:93.184.216.34]:443", ""), "live.block[net:example.com:443]"},
		{inet("203.0.113.5:443", "EXAMPLE.com."), "live.block[net:example.com:443]"},
		{inet("93.184.216.34:80", ""), ""},
		{inet("10.1.2.3:9999", ""), "live.block[net:10.1.2.3]"},
		{inet("[2001:db8::1]:22", ""), "live.block[net:[2001:db8::1]:22]"},
		{inet("[2001:db8::1]:23", ""), ""},
		{inet("10.1.2.4:9999", ""), ""},
	} {
		if c.got != c.want {
			t.Errorf("inet match %q, want %q", c.got, c.want)
		}
	}
	if _, ok := s.MatchUnix("/run/pg.sock", nil); !ok {
		t.Error("unix pathname not matched")
	}
	if _, ok := s.MatchUnix("", []byte("bus")); !ok {
		t.Error("abstract name not matched")
	}
	if _, ok := s.MatchUnix("/run/other.sock", nil); ok {
		t.Error("another socket matched")
	}
	for p, want := range map[string]bool{
		"/home/u/proj/secret": true, "/home/u/proj/secret/a/b": true, "/home/u/proj/secrets": false,
		"/home/u/proj": false, "relative": false,
	} {
		if _, ok := s.MatchPath(p, AccessRead|AccessWrite); ok != want {
			t.Errorf("MatchPath(%q) = %v, want %v", p, ok, want)
		}
	}
	var none *Set
	if none.HasExec() || none.HasNet() || none.HasPath() {
		t.Error("a nil Set blocks something")
	}
	if _, ok := none.MatchPath("/x", AccessRead|AccessWrite); ok {
		t.Error("a nil Set matched")
	}
	if Compile(New(testRun), Resolved{}) != nil {
		t.Error("an empty overlay compiled to a Set")
	}
	if got := s.Hosts(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("Hosts = %v", got)
	}
}

// TestUpdateAndRead: Update creates, changes and keeps the overlay by an atomic rename; Read gives it back; an
// unreadable overlay is never replaced; concurrent writers lose no change.
func TestUpdateAndRead(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := Read(dir, testRun); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read of no file = %v, want ErrNotExist", err)
	}
	if sig := Stat(dir); sig.Exists {
		t.Fatalf("Stat of no file = %+v", sig)
	}
	o, err := Update(ctx, dir, testRun, func(o *Overlay) (bool, error) {
		_, ok, err := o.Add(KindExec, "curl", By("cli"), time.Now())
		return ok, err
	})
	if err != nil || len(o.Blocks) != 1 {
		t.Fatalf("Update = %+v, %v", o, err)
	}
	sig := Stat(dir)
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || fi.Mode().Perm() != 0o600 || !sig.Exists {
		t.Fatalf("overlay file %v, %v, %+v", fi, err, sig)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Update(ctx, dir, testRun, func(o *Overlay) (bool, error) {
				_, ok, err := o.Add(KindPath, "/p"+string(rune('a'+i)), "w", time.Now())
				return ok, err
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, err := Read(dir, testRun)
	if err != nil || len(got.Blocks) != 9 || got.Serial != 9 {
		t.Fatalf("after concurrent writers: %d blocks, serial %d, %v; want 9, 9", len(got.Blocks), got.Serial, err)
	}
	if Stat(dir) == sig {
		t.Error("the signature did not change across writes")
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(ctx, dir, testRun, func(*Overlay) (bool, error) { return true, nil }); err == nil {
		t.Fatal("an unreadable overlay was replaced")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, FileName)); string(b) != "{broken" {
		t.Fatalf("the unreadable overlay was changed: %q", b)
	}
}

// TestReadRefusesUntrusted: a symlink and a file others may write are not read.
func TestReadRefusesUntrusted(t *testing.T) {
	dir := t.TempDir()
	b, _ := New(testRun).Encode()
	other := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(other, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, testRun); !errors.Is(err, ErrUntrusted) {
		t.Errorf("Read through a symlink = %v, want ErrUntrusted", err)
	}
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, FileName), 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, testRun); !errors.Is(err, ErrUntrusted) {
		t.Errorf("Read of a group-writable file = %v, want ErrUntrusted", err)
	}
}

// FuzzDecode: no input makes Decode panic, and whatever it accepts encodes and decodes back to itself.
func FuzzDecode(f *testing.F) {
	b, _ := New(testRun).Encode()
	f.Add(b)
	f.Add([]byte(`{"v":1,"run":"` + testRun + `","serial":1,"blocks":[{"kind":"net","value":"example.com:443"}],"changes":[{"serial":1,"op":"add","kind":"net","value":"example.com:443"}]}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		o, err := Decode(in, "")
		if err != nil {
			return
		}
		out, err := o.Encode()
		if err != nil {
			t.Fatalf("an accepted overlay does not encode: %v", err)
		}
		if _, err := Decode(out, o.Run); err != nil {
			t.Fatalf("an encoded overlay does not decode: %v", err)
		}
		_ = Compile(o, Resolved{})
	})
}

// TestMatchInetNamesThisHostInEverySpelling: a block is on a destination, not a spelling. One that names this host, by a
// loopback address, an unspecified one, one of the host's own, a localhost name or a host that resolved to one of those,
// refuses every other way to reach the host on its port, and one on another host refuses none of them.
func TestMatchInetNamesThisHostInEverySpelling(t *testing.T) {
	lan := netip.MustParseAddr("192.0.2.10")
	own := testHost{own: lan, bcast: netip.MustParseAddr("192.0.2.255")}
	o := New("r-1")
	for _, v := range []string{"127.0.0.1:5000", "[::1]:5001", "localhost:5002", "box.example:5003", "0.0.0.0:5004",
		"192.0.2.10:5005", "::ffff:127.0.0.1", "203.0.113.7:5006"} {
		if _, _, err := o.Add(KindNet, v, "t", time.Now()); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
	s := Compile(o, Resolved{Addrs: map[string][]netip.Addr{"box.example": {lan}}})
	spellings := []string{"127.0.0.1", "127.0.0.2", "127.255.255.254", "::1", "0.0.0.0", "::", "::ffff:0.0.0.0",
		"::ffff:127.0.0.1", "::ffff:127.0.0.2", "::1%1", "192.0.2.10", "::ffff:192.0.2.10"}
	match := func(addr string, port uint16, h thishost.Addrs) string {
		e, ok := s.MatchInet(netip.AddrPortFrom(netip.MustParseAddr(addr), port), "", h)
		if !ok {
			return ""
		}
		return e.Value
	}
	for port, value := range map[uint16]string{5000: "127.0.0.1:5000", 5001: "[::1]:5001", 5002: "localhost:5002",
		5003: "box.example:5003", 5004: "0.0.0.0:5004", 5005: "192.0.2.10:5005", 9: "127.0.0.1"} {
		for _, a := range spellings {
			if got := match(a, port, own); got != value {
				t.Errorf("%s port %d matched %q, want %q", a, port, got, value)
			}
		}
		if got := match("203.0.113.7", port, own); got != "" {
			t.Errorf("another host on port %d matched %q", port, got)
		}
	}
	for _, a := range spellings {
		if got := match(a, 5006, own); got != "127.0.0.1" {
			t.Errorf("%s on a remote block's port matched %q, want the portless loopback block alone", a, got)
		}
	}
	// Without the host's own addresses the class is what a pure reading can tell.
	if got := match("192.0.2.10", 5000, nil); got != "" {
		t.Errorf("own nil: a LAN address matched %q", got)
	}
	if got := match("0.0.0.0", 5000, nil); got != "127.0.0.1:5000" {
		t.Errorf("own nil: 0.0.0.0 matched %q", got)
	}
}

// testHost is a host with one address on one subnet and, when set, one IPv6 anycast address it joined.
type testHost struct{ own, bcast, anycast netip.Addr }

func (h testHost) Own(a netip.Addr) bool       { return a == h.own }
func (h testHost) Broadcast(a netip.Addr) bool { return a == h.bcast }
func (h testHost) Anycast(a netip.Addr) bool   { return h.anycast.IsValid() && a == h.anycast }

// TestMatchInetABlockOnThisHostRefusesWhatReachesIt: a datagram to a multicast group, a broadcast address or an IPv6
// anycast address this host joined is delivered to a local server bound to all interfaces, so a block naming this host
// refuses it on the block's port. The reading is the destination's alone: such an address names no host, so a block on
// one refuses that address and nothing else, and a block on another machine does not follow a datagram that machine may
// also hear.
func TestMatchInetABlockOnThisHostRefusesWhatReachesIt(t *testing.T) {
	h := testHost{own: netip.MustParseAddr("192.0.2.10"), bcast: netip.MustParseAddr("192.0.2.255"),
		anycast: netip.MustParseAddr("2001:db8:1::")}
	reaching := []string{"224.0.0.1", "239.255.255.250", "ff02::1", "ff02::1%3", "ff01::1", "::ffff:224.0.0.1",
		"255.255.255.255", "::ffff:255.255.255.255", "192.0.2.255", "::ffff:192.0.2.255", "2001:db8:1::", "2001:db8:1::%3"}
	compile := func(t *testing.T, values ...string) *Set {
		t.Helper()
		o := New("r-1")
		for _, v := range values {
			if _, _, err := o.Add(KindNet, v, "t", time.Now()); err != nil {
				t.Fatalf("%s: %v", v, err)
			}
		}
		return Compile(o, Resolved{Addrs: map[string][]netip.Addr{"box.example": {h.own}}})
	}
	at := func(a string, port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr(a), port) }

	for _, block := range []string{"127.0.0.1:5000", "[::1]:5000", "localhost:5000", "box.example:5000", "0.0.0.0:5000", "192.0.2.10:5000"} {
		s := compile(t, block)
		for _, a := range reaching {
			if e, ok := s.MatchInet(at(a, 5000), "", h); !ok || e.Value != block {
				t.Errorf("block %s: %s on its port matched %q, %v", block, a, e.Value, ok)
			}
			if e, ok := s.MatchInet(at(a, 5001), "", h); ok {
				t.Errorf("block %s: %s on another port matched %q", block, a, e.Value)
			}
		}
	}

	s := compile(t, "203.0.113.7:5000", "example.com:5000")
	for _, a := range reaching {
		if e, ok := s.MatchInet(at(a, 5000), "", h); ok {
			t.Errorf("a block on another machine matched %s: %q", a, e.Value)
		}
	}

	// A block on a group, a broadcast or an anycast address is on that address: this host, spelled any way, stays open.
	for _, block := range []string{"224.0.0.1:5000", "255.255.255.255:5000", "192.0.2.255:5000", "[2001:db8:1::]:5000"} {
		s := compile(t, block)
		for _, a := range []string{"127.0.0.1", "::1", "0.0.0.0", "192.0.2.10"} {
			if e, ok := s.MatchInet(at(a, 5000), "", h); ok {
				t.Errorf("block %s matched %s", e.Value, a)
			}
		}
		if _, ok := s.MatchInet(netip.MustParseAddrPort(block), "", h); !ok {
			t.Errorf("block %s does not refuse its own address", block)
		}
	}

	// Without the running host's reading, a group and the limited broadcast still say what they are; a subnet's does not.
	s = compile(t, "127.0.0.1:5000")
	if _, ok := s.MatchInet(at("224.0.0.1", 5000), "", nil); !ok {
		t.Error("no snapshot: a group send was not refused")
	}
	if _, ok := s.MatchInet(at("255.255.255.255", 5000), "", nil); !ok {
		t.Error("no snapshot: the limited broadcast was not refused")
	}
	if e, ok := s.MatchInet(at("192.0.2.255", 5000), "", nil); ok {
		t.Errorf("no snapshot: a subnet's broadcast matched %q", e.Value)
	}
}

// TestMatchInetRemoteBlockStaysRemote: a block on another host does not reach this one. A connect to 0.0.0.0 or to
// loopback on the blocked port is another destination, and a portless block on a name does not refuse them on every port.
func TestMatchInetRemoteBlockStaysRemote(t *testing.T) {
	o := New("r-1")
	for _, v := range []string{"203.0.113.7:443", "example.com"} {
		if _, _, err := o.Add(KindNet, v, "t", time.Now()); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
	}
	s := Compile(o, Resolved{Addrs: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("93.184.216.34")}}})
	for _, a := range []string{"0.0.0.0", "::", "127.0.0.1", "::1"} {
		if e, ok := s.MatchInet(netip.AddrPortFrom(netip.MustParseAddr(a), 443), "", nil); ok {
			t.Errorf("%s matched %s", a, e.Value)
		}
	}
}
