// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package sysaudit

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Environment the traced child reads its fixture from.
const (
	envEtc  = "TEGO_AUDIT_ETC"
	envUser = "TEGO_AUDIT_USER"
	envFile = "TEGO_AUDIT_ENVFILE"
	envHome = "TEGO_AUDIT_HOME"
	envUID  = "TEGO_AUDIT_UID"
)

// layerFixture writes the three file layers, each in its own 0700 directory, and returns their paths.
func layerFixture(t *testing.T) (etc, user, envf, home string) {
	t.Helper()
	root := t.TempDir()
	mk := func(dir, body string) string {
		d := filepath.Join(root, dir)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "config.yaml")
		if err := os.WriteFile(p, []byte("version: 0\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	home = filepath.Join(root, "home")
	return mk("etc", "stop_grace: 9s\n"), mk("home/.tego", ""), mk("envconfig", ""), home
}

// walkLook reports whether c is R14's procfs walk (config.ThroughProc) looking at p, a strict ancestor of one of the
// layer paths, by Lstat or Readlink: the walk resolves a layer path a component at a time, as the kernel's open of
// that layer does, so it looks at no directory the open does not pass through anyway. An open, a stat that follows
// links, a read or a write of an ancestor is not such a look and stays outside the layers (I10).
func walkLook(c testutil.Syscall, p string, layers ...string) bool {
	switch c.Name {
	case "newfstatat":
		if c.Args[3]&unix.AT_SYMLINK_NOFOLLOW == 0 {
			return false
		}
	case "lstat", "readlinkat", "readlink":
	default:
		return false
	}
	for _, l := range layers {
		if p != l && (p == "/" || strings.HasPrefix(l, p+"/")) {
			return true
		}
	}
	return false
}

// TestConfigLoadSourcesOpensOnlyItsLayers is identity-config.md I10, syscall-audited: loading the three file
// layers opens, stats and reads each layer file and its directory and no other path: no $HOME, nothing
// outside the layer paths but the procfs walk's Lstat and Readlink of their ancestors (walkLook), nothing written.
func TestConfigLoadSourcesOpensOnlyItsLayers(t *testing.T) {
	if testutil.InSysTraceChild() {
		src := config.Sources{Etc: os.Getenv(envEtc), User: os.Getenv(envUser), EnvFile: os.Getenv(envFile)}
		testutil.MarkBegin()
		m, _, err := config.LoadSources(src, os.Getenv(envHome), os.Getuid(), config.TrustAbort)
		testutil.MarkEnd()
		if err != nil {
			t.Fatal(err)
		}
		if m.StopGrace.Value.String() != "9s" {
			t.Fatalf("the etc layer was not applied: stop_grace %v", m.StopGrace.Value)
		}
		return
	}
	etc, user, envf, home := layerFixture(t)
	calls := testutil.SysTrace(t, t.Name(), envEtc+"="+etc, envUser+"="+user, envFile+"="+envf, envHome+"="+home)
	allowed := map[string]bool{}
	for _, p := range []string{etc, user, envf} {
		allowed[p], allowed[filepath.Dir(p)] = true, true
	}
	seen := map[string]bool{}
	for _, c := range calls {
		if c.Written() {
			t.Errorf("config.LoadSources wrote: %v", c)
		}
		for _, p := range c.Paths {
			if throughALink(p) {
				t.Errorf("config.LoadSources named %s, which the prefixes below cannot judge: %v", p, c)
				continue
			}
			if strings.HasPrefix(p, "/proc/self/fd/") || strings.HasPrefix(p, "/proc/"+strconv.Itoa(c.TID)+"/fd/") {
				continue // checkDirectory names the open file's directory from its descriptor (R20)
			}
			if !allowed[p] && !walkLook(c, p, etc, user, envf) {
				t.Errorf("config.LoadSources touched %s outside its layers: %v", p, c)
			}
			seen[p] = true
		}
	}
	for _, p := range []string{etc, user, envf} {
		if !seen[p] || !seen[filepath.Dir(p)] {
			t.Errorf("the audit did not see %s and its directory opened; the trace is not what it audits: %v", p, calls)
		}
	}
}

// systemPath is where a passwd lookup may look (R19 names the passwd database, never $HOME): Go's own read of
// /etc/passwd when the test binary is built without cgo, as the shipped binary is, and glibc's NSS modules
// when it is not, which reach into /etc, /run, /usr, /lib and /var (nss_systemd's userdb directories, nscd's
// socket, the boot id, the modules themselves). None of them is a user's file.
var systemPath = regexp.MustCompile(`^/($|(etc|run|usr|lib|lib32|lib64|libx32|var)(/|$)|proc/(self|sys)/)`)

// procLink matches a path that reaches the whole file system through a /proc link: a process's or thread's root
// or cwd, or a path below a descriptor's link (fd/N/...).
var procLink = regexp.MustCompile(`^/proc/(self|thread-self|[0-9]+)(/task/[0-9]+)?/((root|cwd)(/|$)|fd/[^/]+/)`)

// throughALink reports whether p is a path the audits' prefix checks cannot judge: one through a /proc link
// (procLink), or one with a "." or ".." element or a doubled slash, which can leave the directory a prefix names
// (a single trailing slash, as glibc's NSS opens its directories with, is none). The audits refuse such a path
// before they look at its prefix (the class).
func throughALink(p string) bool {
	q := p
	if len(q) > 1 {
		q = strings.TrimSuffix(q, "/")
	}
	return filepath.Clean(q) != q || procLink.MatchString(p)
}

// TestConfigLoadReadsNoHome is I10's other half for config.Load itself: for a uid the passwd database does not
// name, Load looks it up there, finds no per-user layer (E9) and touches nothing under $HOME, and outside the
// passwd database opens only the /etc layer and $TEGO_CONFIG with their directories, and looks at their ancestors
// only by the procfs walk (walkLook: $HOME is one only when the fixture's temporary directory lies under it).
func TestConfigLoadReadsNoHome(t *testing.T) {
	if testutil.InSysTraceChild() {
		uid, err := strconv.Atoi(os.Getenv(envUID))
		if err != nil {
			t.Fatal(err)
		}
		testutil.MarkBegin()
		_, _, _ = config.Load(uid, false) // the fixture file is not the unknown uid's, so the trust check refuses it
		testutil.MarkEnd()
		return
	}
	_, _, envf, _ := layerFixture(t)
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/" {
		t.Skip("no $HOME to audit against")
	}
	const noSuchUID = 2147483000
	calls := testutil.SysTrace(t, t.Name(), config.EnvConfigVar+"="+envf, envUID+"="+strconv.Itoa(noSuchUID))
	sawEnv := false
	for _, c := range calls {
		if c.Written() {
			t.Errorf("config.Load wrote: %v", c)
		}
		for _, p := range c.Paths {
			switch {
			case throughALink(p):
				t.Errorf("config.Load named %s, which the prefixes below cannot judge: %v", p, c)
			case strings.HasPrefix(p, "/proc/self/fd/") || strings.HasPrefix(p, "/proc/"+strconv.Itoa(c.TID)+"/fd/"):
			case p == envf || p == filepath.Dir(envf):
				sawEnv = true
			case walkLook(c, p, envf, config.EtcPath):
			case strings.HasPrefix(p, home+"/") && !strings.HasPrefix(envf, home+"/"), p == home:
				t.Errorf("config.Load touched $HOME: %v", c)
			case !systemPath.MatchString(p):
				t.Errorf("config.Load touched %s, which is neither a layer nor where the passwd database is: %v", p, c)
			}
		}
	}
	if !sawEnv {
		t.Errorf("the audit never saw $TEGO_CONFIG opened: %v", calls)
	}
}

// TestThroughALinkCatchesTheWaysOut pins throughALink: what the config audits admit by prefix (/proc/self/fd/N, a
// /proc/self entry, /etc) stays admitted, and a path that leaves through a /proc link or a ".." does not.
func TestThroughALinkCatchesTheWaysOut(t *testing.T) {
	for _, tc := range []struct {
		p    string
		want bool
	}{
		{"/proc/self/fd/3", false},
		{"/proc/1234/fd/3", false},
		{"/proc/self/status", false},
		{"/proc/sys/kernel/random/boot_id", false},
		{"/etc/passwd", false},
		{"/", false},
		{"/run/systemd/userdb/", false},
		{"/proc/self/", false},

		{"/proc/self/root/home/u/.tego/machine.yaml", true},
		{"/proc/self/root/", true},
		{"/etc//", true},
		{"/proc/self/root", true},
		{"/proc/thread-self/cwd/x", true},
		{"/proc/1234/task/1235/root/etc", true},
		{"/proc/self/fd/3/x", true},
		{"/etc/../home/u/.tego", true},
		{"/etc//passwd", true},
		{"/etc/./passwd", true},
	} {
		if got := throughALink(tc.p); got != tc.want {
			t.Errorf("throughALink(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}
