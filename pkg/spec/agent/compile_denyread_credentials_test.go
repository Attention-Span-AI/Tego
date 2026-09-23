// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// credentialFiles plants one file per credential class the built-in deny_read list must cover,
// under the fixture's home. builtIn() skips an entry that does not exist, so a row is only testable
// once something is there.
func credentialFiles(t *testing.T, home string) []string {
	t.Helper()
	files := map[string]string{
		".npmrc":                        "//registry.npmjs.org/:_authToken=tok",
		".git-credentials":              "https://u:tok@github.com",
		".config/gh/hosts.yml":          "github.com:\n  oauth_token: tok\n",
		".docker/config.json":           `{"auths":{"ghcr.io":{"auth":"dG9r"}}}`,
		".kube/config":                  "users:\n- user:\n    token: tok\n",
		".config/gcloud/credentials.db": "sqlite",
	}
	var planted []string
	for rel, content := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		planted = append(planted, p)
	}
	return planted
}

// TestBuiltInDenyReadCoversPublishedCredentialClasses pins the built-in list against the credential
// classes the nx "s1ngularity" compromise actually stole (August 2025): it drove the developer's own
// agent CLI to collect SSH keys, GitHub tokens via `gh auth token`, npm credentials from ~/.npmrc
// and .env files, and pushed them to public repositories. Reads are allowed by default
// (SEMANTICS §1), so this list is the entire defence against that recon step; before this the list
// stopped at ~/.ssh, ~/.aws, ~/.netrc and ~/.gnupg plus browser profiles, covering one of that
// attack's four credential classes.
//
// Both halves are asserted: the rule is in the table, and the read is actually refused in every
// enforcing tier — a rule that compiles but evaluates to allow would protect nothing.
func TestBuiltInDenyReadCoversPublishedCredentialClasses(t *testing.T) {
	f := newFixture(t)
	planted := credentialFiles(t, f.home)

	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))

	for _, secret := range planted {
		// ~/.config/gh and ~/.config/gcloud are denied as directories (the credential is one
		// file among several); the rest are denied as the file itself.
		covered := findFS(rt, FSDenyRead, secret) != nil ||
			findFS(rt, FSDenyRead, filepath.Dir(secret)) != nil
		if !covered {
			t.Errorf("no built-in deny_read entry covers %s:\n%s", secret, render(ds))
			continue
		}
		for _, tier := range enforcingTiers() {
			got := rt.Evaluate(Action{Kind: ActionFSRead, Path: secret}, tier)
			if got.Verdict != VerdictRefused {
				t.Errorf("tier %s: read of %s is %q (rule %s), want refused", tier, secret, got.Verdict, got.Rule)
			}
		}
	}
}

// TestPopulatedDenyReadKeepsTheBuiltInList is the tri-state's third arm, and the fail-open half of
// this change. R6 says "only the explicit `deny_read: []` disables it" and R5 makes deny_read the
// one list that never loses entries, but a populated list used to *replace* the built-in one: a
// contract that added a single project path silently stopped denying ~/.ssh, ~/.aws, ~/.netrc,
// ~/.gnupg, every credential file and the .env scan, with no diagnostic. That is a worse fail-open
// than the one TestBuiltInDenyReadAppliesWithoutFSSection guards, because it is reached by a
// contract an author writes on purpose.
func TestPopulatedDenyReadKeepsTheBuiltInList(t *testing.T) {
	f := newFixture(t)
	credentialFiles(t, f.home)

	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [\"secrets/\"]\n"))

	// The declared entry is compiled.
	if r := findFS(rt, FSDenyRead, filepath.Join(f.project, "secrets")); r == nil {
		t.Fatalf("declared deny_read entry missing:\n%s", render(ds))
	}
	// And so is the built-in list, in full.
	for _, want := range []string{".ssh", ".aws", ".netrc", ".npmrc", ".config/gh"} {
		p := filepath.Join(f.home, want)
		r := findFS(rt, FSDenyRead, p)
		if r == nil {
			t.Errorf("a populated deny_read dropped the built-in entry %s:\n%s", p, render(ds))
			continue
		}
		if !r.BuiltIn {
			t.Errorf("%s: BuiltIn = false", p)
		}
	}
	if r := findFS(rt, FSDenyRead, filepath.Join(f.project, ".env")); r == nil {
		t.Errorf("a populated deny_read dropped the built-in .env scan:\n%s", render(ds))
	}
	// No deny-read-disabled warning: nothing was disabled.
	if hasCode(ds, CodeDenyReadDisabled) {
		t.Errorf("populated deny_read reported as disabling the list:\n%s", render(ds))
	}
}

// TestDeclaredDenyReadIsNotDuplicatedByTheBuiltInList keeps the union from producing two rules for
// one path: an author who spells out a path the built-in list also covers should get one entry, not
// a doubled row in the print and in the ledger's rule field.
func TestDeclaredDenyReadIsNotDuplicatedByTheBuiltInList(t *testing.T) {
	f := newFixture(t)
	ssh := filepath.Join(f.home, ".ssh")

	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [\"" + ssh + "\"]\n"))

	n := 0
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.Path == ssh {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d deny_read rules for %s, want 1", n, ssh)
	}
}

// TestExplicitEmptyDenyReadStillDisablesEverything re-checks the disabling arm after the union
// change: `deny_read: []` must still switch the whole built-in list off, credential rows included,
// and it is the loud route (deny-read-disabled at Load).
func TestExplicitEmptyDenyReadStillDisablesEverything(t *testing.T) {
	f := newFixture(t)
	planted := credentialFiles(t, f.home)

	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: []\n"))

	for _, secret := range append(planted, filepath.Join(f.home, ".ssh")) {
		if r := findFS(rt, FSDenyRead, secret); r != nil {
			t.Errorf("deny_read: [] kept the built-in entry %s", r.Path)
		}
		if r := findFS(rt, FSDenyRead, filepath.Dir(secret)); r != nil {
			t.Errorf("deny_read: [] kept the built-in entry %s", r.Path)
		}
	}
}

// TestBuiltInDenyReadCoversPackagedBrowserProfiles: SEMANTICS §1 promises "browser profile directories",
// and on Ubuntu Firefox and Chromium are snaps (profiles under ~/snap), flatpak browsers keep theirs under
// ~/.var/app, and Chrome's beta and unstable channels have their own directory. Each is refused in every
// enforcing tier.
func TestBuiltInDenyReadCoversPackagedBrowserProfiles(t *testing.T) {
	f := newFixture(t)
	profiles := []string{
		"snap/firefox/common/.mozilla/firefox/x.default/cookies.sqlite",
		"snap/chromium/common/chromium/Default/Cookies",
		".var/app/org.mozilla.firefox/.mozilla/firefox/x.default/logins.json",
		".var/app/com.google.Chrome/config/google-chrome/Default/Cookies",
		".config/google-chrome-beta/Default/Cookies",
		".config/google-chrome-unstable/Default/Cookies",
	}
	for _, rel := range profiles {
		p := filepath.Join(f.home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	for _, rel := range profiles {
		p := filepath.Join(f.home, rel)
		for _, tier := range enforcingTiers() {
			got := rt.Evaluate(Action{Kind: ActionFSRead, Path: p}, tier)
			if got.Verdict != VerdictRefused {
				t.Errorf("tier %s: read of ~/%s is %q, want refused\n%s", tier, rel, got.Verdict, render(ds))
			}
		}
	}
}

// tokenStoreRows are the rows ADR 0067 adds, each with a file planted where the tool keeps its secret: the row
// itself for a file row, a file beneath it for a directory row (docs/spec/builtin-deny-read.md cites each).
var tokenStoreRows = []struct {
	row, secret string
	dir         bool
}{
	{".claude/.credentials.json", "", false},
	{".claude.json", "", false},
	{".claude/backups", ".claude.json.backup.1761400000000", true},
	{".codex/auth.json", "", false},
	{".gemini/oauth_creds.json", "", false},
	{".gemini/.env", "", false},
	{".gemini/mcp-oauth-tokens.json", "", false},
	{".copilot/config.json", "", false},
	{".copilot/mcp-oauth-config", "server.tokens.json", true},
	{".copilot/mcp-secrets", "index.json", true},
	{".azure", "msal_token_cache.json", true},
	{".config/op", "config", true},
	{".password-store", "github.com/me.gpg", true},
	{".pypirc", "", false},
	{".cargo/credentials", "", false},
	{".cargo/credentials.toml", "", false},
	{".terraform.d/credentials.tfrc.json", "", false},
	{".vault-token", "", false},
	{".pgpass", "", false},
}

// TestBuiltInDenyReadCoversAgentTokenStores (ADR 0067): an agent under tego must not read the token stores of the
// harnesses and tools that run beside it, its own harness's included. Each row is in the table, built-in, at the
// granularity the secret lives at (the file, or the directory that holds it among other files), and a read of the
// secret is refused in every enforcing tier.
func TestBuiltInDenyReadCoversAgentTokenStores(t *testing.T) {
	f := newFixture(t)
	for _, r := range tokenStoreRows {
		p := filepath.Join(f.home, r.row, r.secret)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("tok"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	for _, r := range tokenStoreRows {
		row := filepath.Join(f.home, r.row)
		rule := findFS(rt, FSDenyRead, row)
		if rule == nil {
			t.Errorf("no built-in deny_read entry for ~/%s:\n%s", r.row, render(ds))
			continue
		}
		if !rule.BuiltIn {
			t.Errorf("~/%s: BuiltIn = false", r.row)
		}
		secret := filepath.Join(row, r.secret)
		for _, tier := range enforcingTiers() {
			got := rt.Evaluate(Action{Kind: ActionFSRead, Path: secret}, tier)
			if got.Verdict != VerdictRefused {
				t.Errorf("tier %s: read of %s is %q (rule %s), want refused", tier, secret, got.Verdict, got.Rule)
			}
		}
	}
	// A file row names the file, not its directory: the rest of ~/.claude, ~/.codex and ~/.gemini (the settings
	// and sessions a harness keeps) stays readable.
	for _, keep := range []string{".claude/settings.json", ".codex/config.toml", ".gemini/settings.json"} {
		p := filepath.Join(f.home, keep)
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: p}, backend.TierLandlock); got.Verdict == VerdictRefused {
			t.Errorf("read of ~/%s is refused (rule %s); only the token file is a row", keep, got.Rule)
		}
	}
}

// TestAbsentTokenStoreRowsCostNothing: a row whose path does not exist adds no rule and no diagnostic, so a machine
// without these tools prints and records the rules it did before ADR 0067 (only RuleTable.AbsentDenyRead, which the
// Landlock ruleset reads, names the row).
func TestAbsentTokenStoreRowsCostNothing(t *testing.T) {
	f := newFixture(t)
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	for _, r := range tokenStoreRows {
		if rule := findFS(rt, FSDenyRead, filepath.Join(f.home, r.row)); rule != nil {
			t.Errorf("absent ~/%s compiled a rule", r.row)
		}
		for _, d := range ds {
			if strings.Contains(d.Message, r.row) {
				t.Errorf("absent ~/%s produced a diagnostic: %s", r.row, d.Message)
			}
		}
	}
}

// TestTokenStoreRowsJoinTheAlternatePatterns (ADR 0057 D2, ADR 0067): every new row is in RuleTable.DenyReadPatterns
// whether it exists or not, so a person's alternate naming it, for a held read or a held write, is refused by name, and
// the rule names the row. The patterns refuse alternates only; a direct read of a row created during the run is
// refused by the Landlock ruleset (TestAbsentRowsAreRecordedForLandlock).
func TestTokenStoreRowsJoinTheAlternatePatterns(t *testing.T) {
	f := newFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	for _, r := range tokenStoreRows {
		row := filepath.Join(f.home, r.row)
		p := row
		if r.dir {
			p = filepath.Join(row, "created-later")
		}
		d, ok := rt.DenyReadPatternOf(p)
		if !ok {
			t.Errorf("%s matches no deny_read pattern", p)
			continue
		}
		if want := "fs.deny_read[" + row + "]"; d.Rule != want {
			t.Errorf("%s: rule %q, want %q", p, d.Rule, want)
		}
	}
	if d, ok := rt.DenyReadPatternOf(filepath.Join(f.home, ".claude", "settings.json")); ok {
		t.Errorf("~/.claude/settings.json matches %s; only ~/.claude/.credentials.json is a row", d.Rule)
	}
}

// TestWriteEntryAtATokenStoreRow pins a consequence ADR 0067 states: the new
// file rows follow R6's existing rules for a write entry. A write entry equal to one (fs.write ~/.claude.json, as Claude
// Code was run without CLAUDE_CONFIG_DIR) is a contradiction and the contract does not compile; a write entry above one
// (fs.write ~/.claude/) leaves it unenforced by the Landlock ruleset, with a warning: since ADR 0069 the held reads
// refuse it at tier landlock (held-reads). The way out is CLAUDE_CONFIG_DIR (or
// the launcher's CODEX_HOME), not a write entry in the home directory.
func TestWriteEntryAtATokenStoreRow(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.home, ".claude.json"), "{}", 0o600)
	f.file(filepath.Join(f.home, ".claude", ".credentials.json"), "{}", 0o600)
	_, ds, err := Compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\""+filepath.Join(f.home, ".claude.json")+"\"]\n"), f.machine, f.opts()...)
	if err == nil {
		t.Errorf("fs.write ~/.claude.json compiled")
	}
	contradiction := false
	for _, d := range ds {
		if d.Code == CodeContradiction && d.IsError() && strings.Contains(d.Message, ".claude.json") {
			contradiction = true
		}
	}
	if !contradiction {
		t.Errorf("fs.write ~/.claude.json compiled without the contradiction:\n%s", render(ds))
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"" + filepath.Join(f.home, ".claude") + "/\"]\n"))
	r := findFS(rt, FSDenyRead, filepath.Join(f.home, ".claude", ".credentials.json"))
	if r == nil || !r.Unenforced {
		t.Fatalf("~/.claude/.credentials.json under fs.write ~/.claude/: rule %+v, want an unenforced deny_read", r)
	}
	warned := false
	for _, d := range ds {
		if (d.Code == CodeUnenforced || d.Code == CodeHeldReads) && !d.IsError() && strings.Contains(d.Message, ".credentials.json") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no unenforced or held-reads warning for ~/.claude/.credentials.json under fs.write ~/.claude/:\n%s", render(ds))
	}
}

// TestAbsentRowsAreRecordedForLandlock (ADR 0067 D3): a row that does not exist
// compiles no rule, but RuleTable.AbsentDenyRead names it, so the Landlock ruleset leaves its name ungranted and a file
// created there during the run is refused (TestTokenStoreCreatedDuringRunIsRefused in internal/runtime proves the
// refusal). A row that exists is a rule and not in the list; a row at or below a write entry is left out, since the
// write grant reaches it whatever the ruleset enumerates; deny_read: [] records none.
func TestAbsentRowsAreRecordedForLandlock(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.home, ".pgpass"), "*:*:*:me:pw", 0o600)
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	has := func(rt *RuleTable, rel string) bool {
		return slices.ContainsFunc(rt.AbsentDenyRead, func(a AbsentRow) bool { return a.Path == filepath.Join(f.home, rel) })
	}
	for _, r := range tokenStoreRows {
		if r.row != ".pgpass" && !has(rt, r.row) {
			t.Errorf("absent ~/%s is not in AbsentDenyRead (%d paths)\n%s", r.row, len(rt.AbsentDenyRead), render(ds))
		}
	}
	for _, rel := range []string{".pgpass", ".ssh", ".aws"} {
		if has(rt, rel) {
			t.Errorf("~/%s exists and is a rule, yet AbsentDenyRead names it", rel)
		}
	}

	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + filepath.Join(f.home, ".claude") + "/\"]\n"))
	if has(rt, ".claude/.credentials.json") {
		t.Errorf("~/.claude/.credentials.json lies inside the write entry ~/.claude/, yet AbsentDenyRead names it")
	}
	if !has(rt, ".codex/auth.json") {
		t.Errorf("~/.codex/auth.json is absent and outside the write entry, yet AbsentDenyRead does not name it")
	}

	rt, _ = f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: []\n"))
	if len(rt.AbsentDenyRead) != 0 {
		t.Errorf("deny_read: [] still records absent rows %v", rt.AbsentDenyRead)
	}
}

// TestAbsentRowsNameTheNameLandlockLeavesOut: each absent row
// carries the name the Landlock ruleset leaves ungranted for it (AbsentRow.At), which the tier models refuse a read
// beneath: the row itself where its directory exists, the first missing directory on its way where that is missing
// too. A row that is a symlink leading nowhere is recorded by where the link leads, since that is the file a login
// writing through the link makes; a row beneath a regular file is not recorded, since nothing can be made there; a
// row an exec.allow directory covers is not recorded, since the grant's read reaches it.
func TestAbsentRowsNameTheNameLandlockLeavesOut(t *testing.T) {
	f := newFixture(t)
	h := func(rel ...string) string { return filepath.Join(append([]string{f.home}, rel...)...) }
	for _, d := range []string{".claude", "dotfiles", ".terraform.d"} {
		if err := os.MkdirAll(h(d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.file(h(".cargo"), "not a directory", 0o600)
	if err := os.Symlink(h("dotfiles", "claude.json"), h(".claude.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h("nowhere", "vault-token"), h(".vault-token")); err != nil {
		t.Fatal(err)
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [\"" + h(".terraform.d") + "/\"]\n"))
	row := func(rel string) (AbsentRow, bool) {
		for _, a := range rt.AbsentDenyRead {
			if a.Path == h(rel) {
				return a, true
			}
		}
		return AbsentRow{}, false
	}
	for _, c := range []struct{ rel, resolved, at string }{
		{".claude/.credentials.json", h(".claude", ".credentials.json"), h(".claude", ".credentials.json")},
		{".codex/auth.json", h(".codex", "auth.json"), h(".codex")},
		{".pgpass", h(".pgpass"), h(".pgpass")},
		{".claude.json", h("dotfiles", "claude.json"), h("dotfiles", "claude.json")},
		{".vault-token", h("nowhere", "vault-token"), h("nowhere")},
	} {
		a, ok := row(c.rel)
		if !ok {
			t.Errorf("absent ~/%s is not in AbsentDenyRead\n%s", c.rel, render(ds))
			continue
		}
		if a.Resolved != c.resolved || a.At != c.at {
			t.Errorf("~/%s: Resolved %q At %q, want %q and %q", c.rel, a.Resolved, a.At, c.resolved, c.at)
		}
		if want := "fs.deny_read[" + h(c.rel) + "]"; a.RuleName() != want {
			t.Errorf("~/%s: rule %q, want %q", c.rel, a.RuleName(), want)
		}
	}
	for _, rel := range []string{".cargo/credentials", ".cargo/credentials.toml", ".terraform.d/credentials.tfrc.json"} {
		if a, ok := row(rel); ok {
			t.Errorf("~/%s is recorded (At %q), though nothing the ruleset leaves out can hold it", rel, a.At)
		}
	}
	// The lookup the tier models ask: beneath the name left out, named by the row whose own path covers it, else by
	// the first row sharing the name.
	for _, c := range []struct{ p, rule string }{
		{h(".codex", "auth.json"), "fs.deny_read[" + h(".codex", "auth.json") + "]"},
		{h(".codex", "config.toml"), "fs.deny_read[" + h(".codex", "auth.json") + "]"},
		{h("dotfiles", "claude.json"), "fs.deny_read[" + h(".claude.json") + "]"},
		{h(".claude", "backups", "x.json"), "fs.deny_read[" + h(".claude", "backups") + "]"},
	} {
		a, ok := rt.AbsentRowOf(c.p)
		if !ok || a.RuleName() != c.rule {
			t.Errorf("AbsentRowOf(%s) = %q, %v; want %q", c.p, a.RuleName(), ok, c.rule)
		}
	}
	for _, p := range []string{h("dotfiles", "other"), h(".claude", "settings.json"), h(".cargo"), h(".terraform.d", "credentials.tfrc.json")} {
		if a, ok := rt.AbsentRowOf(p); ok {
			t.Errorf("AbsentRowOf(%s) = %s; the ruleset grants that path", p, a.RuleName())
		}
	}
	// The link's target is an alternate pattern too (ADR 0057 D2).
	if d, ok := rt.DenyReadPatternOf(h("dotfiles", "claude.json")); !ok || d.Rule != "fs.deny_read["+h(".claude.json")+"]" {
		t.Errorf("the dangling ~/.claude.json's target matches pattern %q, %v", d.Rule, ok)
	}
}
