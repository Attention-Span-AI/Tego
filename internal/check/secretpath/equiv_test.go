// SPDX-License-Identifier: Apache-2.0

package secretpath

import (
	"math/rand/v2"
	"path"
	"strings"
	"testing"
)

// refIs is Is as it was before it stopped allocating: path.Clean, p+"/" per certificate folder and
// strings.Split. Is must answer as it does for every path.
func refIs(p string) bool {
	if p == "" {
		return false
	}
	p = path.Clean(p)
	for _, d := range publicCertDirs {
		if strings.HasPrefix(p+"/", d) {
			return false
		}
	}
	segs := strings.Split(p, "/")
	base := segs[len(segs)-1]
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	for i, s := range segs {
		if secretDirs[s] || s == "gcloud" && i > 0 && segs[i-1] == ".config" {
			return true
		}
	}
	switch {
	case secretFiles[base], strings.HasPrefix(base, ".env."):
		return true
	case base == "cert.pem" || base == "cacert.pem":
		return false
	case base == "token":
		for i, s := range segs[:len(segs)-1] {
			if s == ".config" {
				return i < len(segs)-2
			}
		}
		return false
	}
	for _, ext := range keyExts {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// pathParts are the names the classifier looks for and some it must not mistake for them.
var pathParts = []string{"", ".", "..", "home", "u", ".ssh", ".aws", ".config", "gcloud", "gh", "token", "id_rsa",
	"id_rsa.pub", ".env", ".env.local", ".envrc", "cert.pem", "cacert.pem", "server.key", "a.pem", "etc", "ssl",
	"certs", "usr", "lib", "pki", "ca-certificates", "confidential", "secrets", "x.jks", "notes.md", "credentials"}

// TestIsMatchesTheReference: on 200,000 random paths built from the names the classifier knows (absolute and
// relative, with empty, "." and ".." segments, the certificate folders, .config/<app>/token at every depth), Is
// answers as the code it replaced.
func TestIsMatchesTheReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 1))
	for range 200_000 {
		var b strings.Builder
		if rng.IntN(4) > 0 {
			b.WriteByte('/')
		}
		for i, n := 0, rng.IntN(7); i < n; i++ {
			if i > 0 {
				b.WriteByte('/')
			}
			b.WriteString(pathParts[rng.IntN(len(pathParts))])
		}
		if rng.IntN(10) == 0 {
			b.WriteByte('/')
		}
		p := b.String()
		if got, want := Is(p), refIs(p); got != want {
			t.Fatalf("Is(%q) = %v, the reference says %v", p, got, want)
		}
		if clean(p) && path.Clean(p) != p {
			t.Fatalf("clean(%q) says Clean leaves it, Clean gives %q", p, path.Clean(p))
		}
	}
	for _, d := range publicCertDirs {
		for _, p := range []string{d, d[:len(d)-1], d + "a.pem", d[:len(d)-1] + "x/a.pem"} {
			if got, want := Is(p), refIs(p); got != want {
				t.Errorf("Is(%q) = %v, the reference says %v", p, got, want)
			}
		}
	}
}

// FuzzIsMatchesTheReference is TestIsMatchesTheReference on any string.
func FuzzIsMatchesTheReference(f *testing.F) {
	for _, s := range []string{"/home/u/.ssh/id_rsa", "/etc/ssl/certs/a.pem", "a/.config/gh/token", ".config/token",
		"//x/../.aws", "/usr/lib/ssl"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if got, want := Is(p), refIs(p); got != want {
			t.Fatalf("Is(%q) = %v, the reference says %v", p, got, want)
		}
		if clean(p) && path.Clean(p) != p {
			t.Fatalf("clean(%q) says Clean leaves it, Clean gives %q", p, path.Clean(p))
		}
	})
}

// TestIsAllocatesNothingForACleanPath: the dashboard calls Is for every path of every line it reads.
func TestIsAllocatesNothingForACleanPath(t *testing.T) {
	for _, p := range []string{"/home/u/proj/src/main.go", "/home/u/.config/gh/token", "/etc/ssl/certs/a.pem"} {
		if n := testing.AllocsPerRun(100, func() { Is(p) }); n != 0 {
			t.Errorf("Is(%q) allocates %v times", p, n)
		}
	}
}

// BenchmarkIs is Is over a mix of project, library, config and secret paths.
func BenchmarkIs(b *testing.B) {
	ps := []string{"/home/u/proj/src/f123.go", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/home/u/.codex/cache/c1.json",
		"/home/u/.ssh/id_rsa", "/etc/ssl/certs/ca-certificates.crt", "/home/u/proj/node_modules/a/b/c/index.js"}
	for b.Loop() {
		for _, p := range ps {
			Is(p)
		}
	}
}
