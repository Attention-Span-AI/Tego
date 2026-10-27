// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The source satisfies the agent's interfaces by shape, though this package never imports pkg/spec/agent.
var (
	_ agent.ProfileSource = Source{}
	_ agent.ProfileNamer  = Source{}
)

// TestResolveNamesAndPins: tego/<preset> is the newest revision, tego/<preset>@<n> revision n, and every other name
// (an unknown preset, a revision that does not exist, a spelling of a pin with a leading zero, a name outside tego/)
// is not found, wrapping fs.ErrNotExist so the chain names the ones there are.
func TestResolveNamesAndPins(t *testing.T) {
	for _, p := range List() {
		latest, err := os.ReadFile(filepath.Join(fmt.Sprintf("v%d", p.Revision), p.Name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		where, data, err := Source{}.Resolve(p.Ref())
		if err != nil || string(data) != string(latest) || where != PathPrefix+fmt.Sprintf("v%d/%s.yaml", p.Revision, p.Name) {
			t.Errorf("%s: %s, %v", p.Ref(), where, err)
		}
		for n := 1; n <= p.Revision; n++ {
			want, err := os.ReadFile(filepath.Join(fmt.Sprintf("v%d", n), p.Name+".yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if _, data, err := (Source{}).Resolve(p.Pinned(n)); err != nil || string(data) != string(want) {
				t.Errorf("%s: %v", p.Pinned(n), err)
			}
		}
	}
	for _, name := range []string{
		"tego/no-secret", "tego/no-secrets@0", "tego/no-secrets@01", "tego/no-secrets@2", "tego/no-secrets@",
		"tego/no-secrets@1@1", "no-secrets", "base/no-secrets", "tego/", "tego/v1/no-secrets", "tego/hosts", "",
	} {
		if _, _, err := (Source{}).Resolve(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Resolve(%q) = %v, want not found", name, err)
		}
	}
	want := []string{
		"tego/no-secrets", "tego/no-secrets@1", "tego/no-prod", "tego/no-prod@1",
		"tego/repo-only-writes", "tego/repo-only-writes@1",
	}
	if got := (Source{}).Names(); !slices.Equal(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}
	if p := List(); len(p) != 3 || p[0].Name != "no-secrets" || p[1].Name != "no-prod" || p[2].Name != "repo-only-writes" {
		t.Errorf("List() = %+v", p)
	}
}

// TestEveryRevisionHasItsFile: the catalog and the embedded files name the same revisions, so no file ships that no
// name reaches and no name has no file.
func TestEveryRevisionHasItsFile(t *testing.T) {
	want := map[string]bool{}
	for _, p := range catalog {
		for n := 1; n <= p.Revision; n++ {
			want[revisionFile(p.Name, n)] = true
		}
	}
	got := map[string]bool{}
	err := fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && p != "hosts.yaml" {
			got[p] = true
		}
		return err
	})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("embedded %v, catalog %v (%v)", got, want, err)
	}
	disk, _ := filepath.Glob("v*/*.yaml")
	if len(disk) != len(want) {
		t.Errorf("on disk %v, catalog %v: a revision file the embed pattern misses", disk, want)
	}
}

// TestReleasedRevisionsAreFrozen: a released revision's bytes never change (README.md, the freeze rule). Every entry
// of released names a revision the catalog has, and its file still hashes to the sha256 recorded at its release.
// At a release cut (TEGO_RELEASE_VERSION set, as make preset-freeze sets it for scripts/release.sh tag and
// release.yml), every revision the catalog has must be listed: what the tag carries is released, so the freeze
// holds from that tag on, never from whenever someone remembers to fill the table.
func TestReleasedRevisionsAreFrozen(t *testing.T) {
	if version := os.Getenv("TEGO_RELEASE_VERSION"); version != "" {
		for _, line := range unreleased(released) {
			t.Errorf("release %s carries a preset revision released does not list; add to released in presets.go:\n\t%s", version, line)
		}
	}
	for pinned, sum := range released {
		_, data, err := Source{}.Resolve(Prefix + pinned)
		if err != nil {
			t.Errorf("released %s: %v", pinned, err)
			continue
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("released revision %s changed (sha256 %x, released as %s): a change to a released preset is a new revision", pinned, got, sum)
		}
	}
}

// unreleased is the released entry, as a line of Go to paste, of every catalog revision the given table does not
// list, in catalog order.
func unreleased(table map[string]string) []string {
	var out []string
	for _, p := range catalog {
		for n := 1; n <= p.Revision; n++ {
			pinned := strings.TrimPrefix(p.Pinned(n), Prefix)
			if _, ok := table[pinned]; ok {
				continue
			}
			data, err := files.ReadFile(revisionFile(p.Name, n))
			if err != nil {
				out = append(out, fmt.Sprintf("%q: unreadable (%v),", pinned, err))
				continue
			}
			sum := sha256.Sum256(data)
			out = append(out, fmt.Sprintf("%q: %q,", pinned, hex.EncodeToString(sum[:])))
		}
	}
	return out
}

// TestUnreleasedNamesEveryMissingRevision: the release-cut check names each revision released lacks, with the line
// to add, and none it lists.
func TestUnreleasedNamesEveryMissingRevision(t *testing.T) {
	all := unreleased(map[string]string{})
	if len(all) != len(Source{}.Names())-len(catalog) {
		t.Fatalf("unreleased of an empty table: %v", all)
	}
	sum := sha256.Sum256(must(files.ReadFile(revisionFile("no-prod", 1))))
	if want := fmt.Sprintf("%q: %q,", "no-prod@1", hex.EncodeToString(sum[:])); !slices.Contains(all, want) {
		t.Errorf("unreleased %v lacks %s", all, want)
	}
	full := map[string]string{}
	for _, p := range catalog {
		for n := 1; n <= p.Revision; n++ {
			full[strings.TrimPrefix(p.Pinned(n), Prefix)] = "x"
		}
	}
	if got := unreleased(full); len(got) != 0 {
		t.Errorf("unreleased of a full table: %v", got)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// TestRevisionOneContents: revision 1 is what ADR 0068 says it is, key for key.
func TestRevisionOneContents(t *testing.T) {
	pass := []any{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
		"TERM", "COLORTERM", "TZ", "NO_COLOR", "GOPATH", "GOROOT", "GOCACHE", "GOMODCACHE", "CARGO_HOME", "RUSTUP_HOME",
		"JAVA_HOME", "NVM_DIR", "PYENV_ROOT", "VIRTUAL_ENV", "CONDA_PREFIX"}
	for name, want := range map[string]map[string]any{
		"no-secrets":       {"env": map[string]any{"pass": pass}},
		"no-prod":          {"net": map[string]any{"allow": []any{}}},
		"repo-only-writes": {"fs": map[string]any{"write": []any{"/dev/null"}}},
	} {
		if got := decode(t, revisionFile(name, 1)); !reflect.DeepEqual(got, want) {
			t.Errorf("%s@1 = %#v, want %#v", name, got, want)
		}
	}
}

// loosening is every value that widens what a run may do, by key path: a preset that set one would loosen the
// contracts that extend it. A key a preset sets that is not in allowedKeys fails too, so a new kind of entry is
// a decision made here and in ADR 0068, never a file edit alone.
var loosening = map[string]func(any) bool{
	"revision":       func(any) bool { return true }, // a preset's rules version is run_start.profiles plus its pin
	"host_sockets":   isTrue,
	"fs.reads":       equals("direct"),
	"fs.deny_read":   func(v any) bool { l, ok := v.([]any); return ok && len(l) == 0 }, // [] switches the built-in list off
	"fs.assurance":   equals("best-effort"),
	"exec.assurance": equals("best-effort"),
	"io_uring":       isTrue,
	"keyring":        isTrue,
	"ipc":            isTrue,
	"setuid":         isTrue,
	"exec.anonymous": isTrue,
	"record":         equals("off"),
	"capture":        equals("off"),
}

// allowedKeys is every key path a preset may set, with what it may hold: no-prod's empty net.allow, the
// repo-only-writes /dev/null entry and no-secrets' allow-list of names, none of them credential-shaped. env.pass is
// the one key through which a preset widens a contract (the lists concatenate, R5, so a name a preset passes is
// passed whatever narrower list the contract writes), so each name is held to credentialShaped here and each later
// revision's list to the one before it (TestEnvPassNeverWidens).
var allowedKeys = map[string]func(any) bool{
	"env.pass": func(v any) bool {
		l, ok := v.([]any)
		for _, n := range l {
			if s, _ := n.(string); s == "" || credentialShaped(s) {
				return false
			}
		}
		return ok && len(l) > 0
	},
	"net.allow": func(v any) bool { l, ok := v.([]any); return ok && len(l) == 0 },
	"fs.write":  func(v any) bool { return reflect.DeepEqual(v, []any{"/dev/null"}) },
}

// TestPresetsNeverLoosen: no revision of any preset sets revision, host_sockets: true, fs.reads: direct or any
// other loosening value, and none sets a key outside allowedKeys or a value its check refuses (an allowed host, a
// write entry, a pattern in env.pass). Each also loads alone with no warning, so no value is one Load ignores as
// profile-cannot-loosen.
func TestPresetsNeverLoosen(t *testing.T) {
	for _, p := range catalog {
		for n := 1; n <= p.Revision; n++ {
			file := revisionFile(p.Name, n)
			for key, v := range flatten("", decode(t, file)) {
				if bad, ok := loosening[key]; ok && bad(v) {
					t.Errorf("%s sets %s: %v, which loosens every contract extending it", file, key, v)
				}
				if ok, known := allowedKeys[key]; !known || !ok(v) {
					t.Errorf("%s sets %s: %v, which no preset may (allowedKeys, ADR 0068)", file, key, v)
				}
			}
			chain := (&agent.ProfileChain{}).WithBuiltin(Source{})
			c, ds, err := agent.LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: "+p.Pinned(n)+"\ncommand: [x]\n"), chain)
			if err != nil || c == nil || len(ds) != 0 {
				t.Errorf("%s loads with %v:\n%v", p.Pinned(n), err, ds)
			}
		}
	}
	// The check itself: each loosening value it names is caught.
	for key, v := range map[string]any{"revision": "1", "host_sockets": true, "fs.reads": "direct", "fs.deny_read": []any{}} {
		if !loosening[key](v) {
			t.Errorf("loosening[%s] passes %v", key, v)
		}
	}
	if _, ok := allowedKeys["net.allow"]; !ok || allowedKeys["net.allow"]([]any{"example.com:443"}) {
		t.Error("allowedKeys lets a preset allow a host")
	}
	for _, name := range []string{
		"GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
		"NPM_TOKEN", "PGPASSWORD", "MYSQL_PWD", "SSH_AUTH_SOCK", "DOCKER_HOST", "DOCKER_CONFIG", "KUBECONFIG",
		"GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET", "VAULT_ADDR", "GPG_AGENT_INFO", "DATABASE_URL",
		"CLAUDE_CODE_OAUTH_TOKEN", "SENTRY_DSN", "HTTPS_PROXY", "CI_JOB_JWT", "SESSION_COOKIE", "PRIVATE_KEY",
	} {
		if allowedKeys["env.pass"]([]any{"PATH", name}) {
			t.Errorf("allowedKeys lets a preset pass %s", name)
		}
	}
}

// credentialShaped is a variable name that may carry a credential, or a way to one: a name with a credential word
// in it, a cloud or secret-store family, an agent socket, a container or cluster endpoint, a database or error
// reporting URL, or a proxy (whose URL may carry a password). It errs wide: a name it catches that a toolchain needs
// is passed by the contract that needs it, never by a preset.
func credentialShaped(name string) bool {
	n := strings.ToUpper(name)
	for _, w := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL", "AUTH", "KEY", "COOKIE",
		"SESSION", "JWT", "CERT", "DSN", "_URL", "PROXY", "SOCK", "PRIVATE"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	for _, p := range []string{"AWS_", "AZURE_", "GOOGLE_", "GCLOUD_", "GCP_", "VAULT_", "DOCKER_", "KUBE", "SSH_",
		"GPG_", "GNUPG", "GH_", "GITHUB_", "GITLAB_", "NPM_CONFIG_", "PIP_", "TWINE_", "CARGO_REGISTR", "HF_"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// envPassReviewed is every name a later revision of a preset passes that the revision before it did not, keyed by
// <preset>@<revision> and then by the name, each with the review that admitted it (an ADR or its amendment). A
// name absent here is a widening TestEnvPassNeverWidens refuses: a new revision may drop names freely, but a name it
// adds reaches every contract that moves to it, so adding one is a decision on record, never a file edit alone.
var envPassReviewed = map[string]map[string]string{}

// envPassWidening is each name of cur that prev does not hold and reviewed does not admit.
func envPassWidening(prev, cur []string, reviewed map[string]string) []string {
	var out []string
	for _, n := range cur {
		if !slices.Contains(prev, n) && reviewed[n] == "" {
			out = append(out, n)
		}
	}
	return out
}

// TestEnvPassNeverWidens: revision n+1 of a preset passes no variable revision n did not, unless envPassReviewed
// names the review that admitted it.
func TestEnvPassNeverWidens(t *testing.T) {
	names := func(file string) []string {
		var out []string
		if env, ok := decode(t, file)["env"].(map[string]any); ok {
			for _, v := range env["pass"].([]any) {
				out = append(out, v.(string))
			}
		}
		return out
	}
	for _, p := range catalog {
		for n := 2; n <= p.Revision; n++ {
			if w := envPassWidening(names(revisionFile(p.Name, n-1)), names(revisionFile(p.Name, n)), envPassReviewed[p.Name+"@"+strconv.Itoa(n)]); len(w) > 0 {
				t.Errorf("%s passes %v, which revision %d did not; record the review in envPassReviewed or drop them", p.Pinned(n), w, n-1)
			}
		}
	}
	// The check itself.
	if w := envPassWidening([]string{"PATH", "HOME"}, []string{"PATH", "EDITOR"}, nil); !slices.Equal(w, []string{"EDITOR"}) {
		t.Errorf("widening %v", w)
	}
	if w := envPassWidening([]string{"PATH"}, []string{"PATH", "EDITOR"}, map[string]string{"EDITOR": "ADR 0068 amendment"}); len(w) != 0 {
		t.Errorf("a reviewed name refused: %v", w)
	}
}

// hostGroupsOf is HostGroups, failing the test on its error.
func hostGroupsOf(t *testing.T) []HostGroup {
	t.Helper()
	gs, err := HostGroups()
	if err != nil {
		t.Fatal(err)
	}
	return gs
}

// TestHostGroups: the seven groups, in the file's order, each with entries.
func TestHostGroups(t *testing.T) {
	var names []string
	for _, g := range hostGroupsOf(t) {
		names = append(names, g.Name)
		if len(g.Hosts) == 0 {
			t.Errorf("group %s has no host", g.Name)
		}
	}
	if want := []string{"github", "npm", "pypi", "crates", "go-proxy", "rubygems", "maven-central"}; !slices.Equal(names, want) {
		t.Errorf("groups %v, want %v", names, want)
	}
	gs := hostGroupsOf(t)
	gs[0].Hosts[0] = "changed.example:1"
	if hostGroupsOf(t)[0].Hosts[0] == "changed.example:1" {
		t.Error("HostGroups returns the package's own slices")
	}
	for _, bad := range []string{
		"", "a:\n", "  - x.example:443\n", "a:\n  - x:443\n", "a:\n  - x.example:0\n", "a:\n  - x.example:443\nb:\n",
		"a:\n  - x.example:443\na:\n  - y.example:443\n", "A:\n  - x.example:443\n", "a:\n - x.example:443\n",
		"a:\n  - X.example:443\n", "a:\n  - x.example:443 # c\n", "a: [x.example:443]\n", "a:\n  - -x.example:443\n",
	} {
		if _, err := parseHostGroups([]byte(bad)); err == nil {
			t.Errorf("parseHostGroups(%q) accepted", bad)
		}
	}
}

// TestHostsFileIsYAML: what parseHostGroups reads from hosts.yaml is what a YAML parser reads, so the file means
// one thing to init and to anyone reading it.
func TestHostsFileIsYAML(t *testing.T) {
	data, err := os.ReadFile("hosts.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var got []HostGroup
	m := doc.Content[0]
	for i := 0; i < len(m.Content); i += 2 {
		var hosts []string
		if err := m.Content[i+1].Decode(&hosts); err != nil {
			t.Fatal(err)
		}
		got = append(got, HostGroup{Name: m.Content[i].Value, Hosts: hosts})
	}
	if !reflect.DeepEqual(got, hostGroupsOf(t)) {
		t.Errorf("yaml reads %v, parseHostGroups %v", got, hostGroupsOf(t))
	}
}

func decode(t *testing.T, file string) map[string]any {
	t.Helper()
	data, err := files.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// flatten is every leaf of a decoded mapping by its dotted key path; a list is a leaf.
func flatten(prefix string, m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			for kk, vv := range flatten(prefix+k+".", sub) {
				out[kk] = vv
			}
			continue
		}
		out[prefix+k] = v
	}
	return out
}

func isTrue(v any) bool { b, ok := v.(bool); return ok && b }

func equals(s string) func(any) bool { return func(v any) bool { return v == s } }
