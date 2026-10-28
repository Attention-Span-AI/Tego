// SPDX-License-Identifier: Apache-2.0

package secretpath

import (
	"path"
	"strings"
)

// NearSeconds and NearLines are how close a send must come to a secret touch to count as next to it: within both 5 s
// and 16 ledger lines. A send right after (or right before) a key read is how an exfiltration looks in the ledger; the
// line bound keeps a busy agent's start-up traffic, which shares a second with its own config reads, from all looking
// near. One rule for both sides: the dashboard's verdict (internal/control/ledgerview) and tego learn's.
const (
	NearSeconds = 5
	NearLines   = 16
)

// ReadOpen reports whether a file line that went through can have handed the run the file's contents: an open that
// asks to read, that did not fail, and that did not make the file. Anything else on a file line (a write-only open, a
// create, an unlink, a rename) read nothing. The line's rule is the caller's to check: a refused or held line never
// went through. A watched line carries no return, so true there means the run opened the file or tried to.
func ReadOpen(op string, flags, errno int, created bool) bool {
	const accMode, writeOnly = 0o3, 0o1
	return op == "open" && flags&accMode != writeOnly && errno == 0 && !created
}

// publicCertDirs hold certificate bundles every program reads; a .pem there is public, not a secret.
var publicCertDirs = []string{"/etc/ssl/", "/usr/lib/ssl/", "/usr/local/ssl/", "/usr/share/ca-certificates/",
	"/etc/pki/", "/etc/ca-certificates/"}

// secretDirs are directory names whose contents are a person's credentials or marked confidential.
var secretDirs = map[string]bool{".ssh": true, ".aws": true, ".gnupg": true, ".kube": true, ".azure": true,
	".password-store": true, "confidential": true, "secrets": true, ".secrets": true}

// secretFiles are file names that hold a credential wherever they sit.
var secretFiles = map[string]bool{"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true, ".netrc": true,
	".pypirc": true, ".pgpass": true, ".git-credentials": true, "credentials": true,
	"credentials.json": true, ".credentials.json": true, "auth.json": true, "kubeconfig": true, ".env": true,
	"secrets.yaml": true, "secrets.yml": true, "secrets.json": true}

// keyExts are the file extensions of private keys and key stores.
var keyExts = []string{".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore", ".jks"}

// Is reports whether p names a file or directory that holds secrets: SSH, cloud and GPG credentials, private keys,
// .env files, token files (.config/<app>/token), and directories named confidential or secrets. It looks at the name
// only, so it is a guess a person reads, not a verdict; a path the run's own rules guard (fs.deny_read, fs.ask_read)
// is a secret to that run whatever its name (GuardRule).
//
// It allocates nothing for a path already clean, and looks up only the names that could be one of its lists: the
// dashboard asks it for every path of every line it reads.
func Is(p string) bool {
	if p == "" {
		return false
	}
	if !clean(p) {
		p = path.Clean(p)
	}
	for _, d := range publicCertDirs {
		if strings.HasPrefix(p, d) || p == d[:len(d)-1] { // p+"/" under d, without building p+"/"
			return false
		}
	}
	base := p[strings.LastIndexByte(p, '/')+1:]
	if strings.HasSuffix(base, ".pub") {
		return false // a public key
	}
	// The segments of p as strings.Split(p, "/") gives them, walked in place; configAt is the index of the first
	// ".config" among all but the last, last the index of the last.
	configAt, last, prev := -1, 0, ""
	for i, rest := 0, p; ; i++ {
		seg, tail, more := strings.Cut(rest, "/")
		if seg != "" && (seg[0] == '.' || seg[0] == 'c' || seg[0] == 's' || seg[0] == 'g') { // every name below
			if secretDirs[seg] || seg == "gcloud" && i > 0 && prev == ".config" {
				return true
			}
			if seg == ".config" && configAt < 0 && more {
				configAt = i
			}
		}
		if !more {
			last = i
			break
		}
		prev, rest = seg, tail
	}
	switch {
	case secretFiles[base], strings.HasPrefix(base, ".env."):
		return true
	case base == "cert.pem" || base == "cacert.pem":
		return false
	case base == "token":
		// .config/<app>/.../token holds an app's login token; .config/token is not an app's.
		return configAt >= 0 && configAt < last-1
	}
	for _, ext := range keyExts {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// clean reports whether path.Clean would leave p as it is, by the patterns Clean rewrites: a doubled slash, a "."
// or ".." element, a trailing slash. It may say no for a clean path (a leading "../"), which only costs a Clean. One
// pass, looking only after each slash.
func clean(p string) bool {
	if p == "" || p == "." || p == ".." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") {
		return false
	}
	for i := strings.IndexByte(p, '/'); i >= 0; {
		j := i + 1
		switch {
		case j == len(p):
			return len(p) == 1 // a trailing slash, unless p is the root
		case p[j] == '/':
			return false
		case p[j] == '.':
			if k := j + 1; k == len(p) || p[k] == '/' || p[k] == '.' && (k+1 == len(p) || p[k+1] == '/') {
				return false // a "." or ".." element
			}
		}
		n := strings.IndexByte(p[j:], '/')
		if n < 0 {
			break
		}
		i = j + n
	}
	return true
}

// GuardRule reports whether the rule that decided a file line guards a secret: the run's contract says a read of it
// is refused or needs a person. An fs.ask entry asks before a change, not a read: it names a folder the agent may
// write to, not a secret.
func GuardRule(rule string) bool {
	return strings.HasPrefix(rule, "fs.deny_read[") || strings.HasPrefix(rule, "fs.ask_read[")
}
