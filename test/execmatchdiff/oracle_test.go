// SPDX-License-Identifier: Apache-2.0

package execmatchdiff_test

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	compare "github.com/attention-span-ai/tego/test/execmatchdiff"
	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
)

func TestExceptionOracleRejectsAWSGlobalRebinding(t *testing.T) {
	tokens := []string{"--", "s3", "--profile", "rm", "ls"}
	// Freeze the wrong binding the previous oracle accepted. Using only the
	// current normalizer would stop testing the oracle once that parser is fixed.
	r := old.NewNormalizer(oldrows.Builtin().Lookup("aws"), nil).Normalize([]string{"s3", "--profile", "rm", "ls"})
	if compare.AllowSpelling("aws s3 ls", "aws", tokens, r) {
		t.Fatal("oracle accepted a spelling that aws's service parser can read as rm")
	}
}

func TestExceptionOracleAcceptsIdenticalVerb(t *testing.T) {
	for _, tc := range []struct {
		tool, entry string
		tokens      []string
	}{
		{"aws", "aws s3 ls", []string{"--", "s3", "ls"}},
		{"go", "go version", []string{"--", "version"}},
		{"npm", "npm install", []string{"--", "install", "x"}},
		{"pip", "pip install", []string{"--", "install", "x"}},
		{"systemctl", "systemctl status", []string{"--", "status", "x"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			r := execmatch.NewNormalizer(rows.Builtin().Lookup(tc.tool), nil).Normalize(tc.tokens)
			if !compare.AllowSpelling(tc.entry, tc.tool, tc.tokens, r) {
				t.Fatal("oracle rejected an unchanged verb, options and operands")
			}
		})
	}
}

func TestPatternExceptionOraclePreservesLiteralBoundary(t *testing.T) {
	for _, tc := range []struct {
		entry  string
		tokens []string
		want   bool
	}{
		{"tool --", nil, true},
		{"tool a -- -r", []string{"a", "-r"}, true},
		{"tool a -- -r", []string{"a", "--", "-r"}, true},
		{"tool a -- -r", []string{"-r", "a"}, false},
		{"tool -- --", []string{"--"}, false},
		{"tool -- --", []string{"--", "--"}, true},
		{"tool -- *.go", []string{"a.go"}, true},
		{"tool -- *.go", []string{"a.txt"}, false},
		{"tool -- -v*", []string{"--", "-verbose"}, true},
	} {
		if got := compare.PatternSeparatorClass(tc.entry, "tool", tc.tokens, nil) != ""; got != tc.want {
			t.Errorf("%q %q: exception=%v, want %v", tc.entry, tc.tokens, got, tc.want)
		}
	}
}

func TestExceptionOracleRejectsDifferentVerb(t *testing.T) {
	for _, tc := range []struct{ tool, entry, other string }{
		{"go", "go build", "run"}, {"npm", "npm install", "publish"}, {"pip", "pip list", "install"}, {"systemctl", "systemctl status", "reboot"},
	} {
		tokens := []string{"--", tc.other}
		readings := execmatch.NewNormalizer(rows.Builtin().Lookup(tc.tool), nil).Normalize(tokens)
		if compare.AllowSpelling(tc.entry, tc.tool, tokens, readings) {
			t.Errorf("oracle admits %s under %q", tc.other, tc.entry)
		}
	}
}

func TestExceptionOracleChecksEndedOptions(t *testing.T) {
	tokens := []string{"--", "install", "--global"}
	readings := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tokens)
	if got := compare.AllowSpellingClass("npm install", "npm", tokens, readings); got != "ended-options" {
		t.Fatalf("class=%q, want independently checked ended-options", got)
	}
}

func TestPatternExceptionOracleRejectsAWSGlobalRebinding(t *testing.T) {
	tokens := []string{"s3", "--profile", "rm", "ls"}
	wrong := old.NewNormalizer(oldrows.Builtin().Lookup("aws"), nil).Normalize(tokens)
	if compare.PatternSeparatorClass("aws -- s3 --profile rm ls", "aws", tokens, wrong) != "" {
		t.Fatal("pattern oracle accepted rm under an ls binding")
	}
}

func TestNpmValueExceptionNamesSameVerbAndBindings(t *testing.T) {
	for _, tokens := range [][]string{{"--tag", "--global", "install", "x"}, {"---tag", "--global", "install", "x"}, {"----tag", "--global", "install", "x"}, {"---tag=--global", "install", "x"}, {"----tag=--global", "install", "x"}, {"--c=--global", "install", "x"}, {"---c=--global", "install", "x"}, {"-cc=--global", "install", "x"}, {"--cc=--global", "install", "x"}, {"--tag=--global", "install", "x"}, {"--tag=--tag=--global", "install", "x"}} {
		readings := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tokens)
		if compare.NpmValueClass("npm install --global", tokens, readings) == "" {
			t.Errorf("independent String parser did not certify %q", tokens)
		}
		if compare.NpmValueClass("npm publish --global", tokens, readings) != "" {
			t.Errorf("independent parser certified a different verb for %q", tokens)
		}
		for i := range readings {
			readings[i].Operands = append(readings[i].Operands, "wrong-operand")
		}
		if compare.NpmValueClass("npm install --global", tokens, readings) != "" {
			t.Errorf("independent parser ignored changed operands for %q", tokens)
		}
	}
}

func TestNpmEndedOptionsExceptionPreservesVerbAndPredicates(t *testing.T) {
	for _, list := range []string{"deny", "ask"} {
		for _, tc := range []struct {
			tokens []string
			want   bool
		}{
			{[]string{"--tag=---", "install", "--global"}, true},
			{[]string{"--tag=---", "publish", "--global"}, false},
			{[]string{"--global", "--tag=---", "install", "--global"}, false},
		} {
			r := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tc.tokens)
			got := compare.NpmRefusalCorrectionClass("npm install --global", list, tc.tokens, r, "none", "") != ""
			if got != tc.want {
				t.Errorf("%s %q: exception=%v want %v", list, tc.tokens, got, tc.want)
			}
			if tc.want {
				for i := range r {
					r[i].Operands = append(r[i].Operands, "wrong")
				}
				if compare.NpmRefusalCorrectionClass("npm install --global", list, tc.tokens, r, "none", "") != "" {
					t.Error("changed operands certified")
				}
			}
		}
	}
}

func TestNpmBrowserOracleUsesBooleanStringType(t *testing.T) {
	for _, tc := range []struct {
		tokens []string
		entry  string
	}{
		{[]string{"--browser", "--global", "access"}, "npm access"},
		{[]string{"--browser", "--", "access", "--global"}, "npm access --global"},
		{[]string{"--browser", "-g", "access"}, "npm access --global"},
	} {
		r := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tc.tokens)
		if compare.NpmValueClass(tc.entry, tc.tokens, r) == "" {
			t.Errorf("browser type not certified for %q", tc.tokens)
		}
		if compare.NpmValueClass("npm publish", tc.tokens, r) != "" {
			t.Errorf("different verb certified for %q", tc.tokens)
		}
		for i := range r {
			r[i].Operands = append(r[i].Operands, "wrong")
		}
		if compare.NpmValueClass(tc.entry, tc.tokens, r) != "" {
			t.Errorf("changed operands certified for %q", tc.tokens)
		}
	}
}

func TestNpmRefusalCorrectionsRequireExactBindings(t *testing.T) {
	for _, tc := range []struct {
		tokens       []string
		entry, class string
	}{
		{[]string{"--browser", "--global", "access"}, "npm access --global", "npm-browser-value"},
		{[]string{"--force=--global", "access"}, "npm access --force=--global", "npm-token-splice"},
	} {
		for _, list := range []string{"deny", "ask"} {
			r := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tc.tokens)
			if got := compare.NpmRefusalCorrectionClass(tc.entry, list, tc.tokens, r, "none", ""); got != tc.class {
				t.Errorf("%s %q class=%q want %q", list, tc.tokens, got, tc.class)
			}
			if compare.NpmRefusalCorrectionClass("npm publish --global", list, tc.tokens, r, "none", "") != "" {
				t.Error("wrong verb certified")
			}
			for i := range r {
				r[i].Operands = append(r[i].Operands, "wrong")
			}
			if compare.NpmRefusalCorrectionClass(tc.entry, list, tc.tokens, r, "none", "") != "" {
				t.Error("changed operand certified")
			}
		}
	}
}

func TestNpmPatternValueOracleRejectsOtherBindings(t *testing.T) {
	for _, entry := range []string{"npm --tag -- install", "npm --fetch-retries -- install"} {
		tokens := []string{"--tag", "--", "install"}
		if entry == "npm --fetch-retries -- install" {
			tokens[0] = "--fetch-retries"
		}
		r := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tokens)
		if got := compare.PatternSeparatorClass(entry, "npm", tokens, r); got != "npm-pattern-value" {
			t.Errorf("%s class=%q", entry, got)
		}
		if compare.PatternSeparatorClass("npm --tag -- publish", "npm", tokens, r) != "" {
			t.Error("different verb certified")
		}
		for i := range r {
			r[i].Operands = append(r[i].Operands, "wrong")
		}
		if compare.PatternSeparatorClass(entry, "npm", tokens, r) != "" {
			t.Error("different invocation bindings certified")
		}
	}
}

func TestPatternRefusalCorrectionUsesIndependentPredicates(t *testing.T) {
	for _, tc := range []struct {
		tool, entry string
		tokens      []string
		want        bool
	}{
		{"systemctl", "systemctl -- reboot", []string{"start", "reboot"}, true},
		{"systemctl", "systemctl -- reboot", []string{"reboot"}, false},
		{"git", "git stash -- drop", []string{"stash", "drop"}, true},
		{"git", "git stash -- drop", []string{"stash", "push", "--", "drop"}, false},
		{"npm", "npm -- publish --force", []string{"publish", "--force"}, true},
		{"npm", "npm -- publish --force", []string{"publish", "--", "--force"}, false},
		{"gh", "gh --", []string{"version"}, true},
		{"gh", "gh --", nil, false},
		{"unknown", "unknown a -- -r", []string{"a", "-rf"}, true},
		{"unknown", "unknown a -- -r", []string{"a", "-r"}, false},
		{"unknown", "unknown a -- b", []string{"x", "a", "b"}, false},
		{"unknown", "unknown pre -- post", []string{"post", "pre"}, false},
		{"unknown", "unknown pre -- post", []string{"pre", "post", "--"}, true},
		{"unknown", "unknown --force -- --force", []string{"--force", "--"}, true},
		{"unknown", "unknown --force -- --force", []string{"--force", "--", "--force"}, false},
		{"gh", "gh repo --", []string{"repo", "clone"}, false},
	} {
		var readings []execmatch.Reading
		if row := rows.Builtin().Lookup(tc.tool); row != nil {
			readings = execmatch.NewNormalizer(row, nil).Normalize(tc.tokens)
		}
		if got := compare.SeparatorPatternDoesNotMatch(tc.entry, tc.tool, tc.tokens, readings); got != tc.want {
			t.Errorf("%s %q correction=%v want%v", tc.entry, tc.tokens, got, tc.want)
		}
		if tc.want && len(readings) > 0 {
			for i := range readings {
				readings[i].Operands = append(readings[i].Operands, "wrong")
			}
			if compare.SeparatorPatternDoesNotMatch(tc.entry, tc.tool, tc.tokens, readings) {
				t.Errorf("altered bindings certified: %s", tc.entry)
			}
		}
	}
}

func TestNpmCommandlessOracleDeclinesCommandsAndUnsupportedForms(t *testing.T) {
	for _, tc := range []struct {
		tokens []string
		want   bool
	}{
		{[]string{"-abc", "-c", "", "-0", "-c"}, true},
		{[]string{"--call", "--tag", ""}, true},
		{[]string{"-abc", "-c", "", "-0", "-c", "--", "install"}, false},
		{[]string{"install"}, false},
		{[]string{"--tag=--global"}, false},
		{[]string{"--quiet"}, false},
	} {
		r := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tc.tokens)
		if got := compare.NpmCommandless(tc.tokens, r); got != tc.want {
			t.Errorf("%q commandless=%v want%v", tc.tokens, got, tc.want)
		}
	}
	if compare.NpmCommandless([]string{"--future"}, []execmatch.Reading{{Unlocatable: true}}) {
		t.Error("generic unlocatable reading certified")
	}
	if compare.NpmCommandless([]string{"--future"}, []execmatch.Reading{{Path: []string{"install"}}}) {
		t.Error("named current command certified")
	}
}

func TestComparisonHeldReadCannotCertifyAdmission(t *testing.T) {
	refused := compare.DecisionState{Outcome: "refused", List: "deny", Final: true}
	held := compare.DecisionState{Outcome: "none", Final: false}
	if !compare.HeldRefusal(false, refused, held) {
		t.Fatal("incomplete held read not recognized")
	}
	for _, tc := range []struct {
		complete bool
		after    compare.DecisionState
	}{
		{true, held},
		{false, compare.DecisionState{Outcome: "none", Final: true}},
		{false, compare.DecisionState{Outcome: "allowed", List: "allow", Final: false}},
	} {
		if compare.HeldRefusal(tc.complete, refused, tc.after) {
			t.Errorf("admission certified as held: %+v", tc)
		}
		if !compare.PotentialLoosening(refused, tc.after) {
			t.Errorf("refusal floor lost: %+v", tc)
		}
	}
	pending := compare.DecisionState{Outcome: "none", Final: false}
	final := compare.DecisionState{Outcome: "none", Final: true}
	if compare.HeldRefusal(false, pending, final) || !compare.PotentialLoosening(pending, final) {
		t.Error("pending-to-final non-refusal escaped floor")
	}
}

func TestNpmEndedRootOraclePreservesOpaqueDashCommand(t *testing.T) {
	tokens := []string{"--searchexclude=x", "-a", "--ci-name=x", "--searchexclude", "--", "--init-author-url=x", "audit", "--audit=x", "--install-strategy=x"}
	for _, tc := range []struct {
		entry string
		want  bool
	}{
		{"npm audit", true}, {"npm", false}, {"npm --all", false}, {"npm --searchexclude=x", false},
	} {
		r := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tokens)
		if got := compare.NpmEndedRootDoesNotMatch(tc.entry, tokens, r); got != tc.want {
			t.Errorf("%s correction=%v want%v", tc.entry, got, tc.want)
		}
		if tc.want {
			for i := range r {
				r[i].Operands = append(r[i].Operands, "wrong")
			}
			if compare.NpmEndedRootDoesNotMatch(tc.entry, tokens, r) {
				t.Error("changed operand certified")
			}
		}
	}
	if compare.NpmEndedRootDoesNotMatch("npm audit", tokens, []execmatch.Reading{{Unlocatable: true}}) {
		t.Error("unlocatable reading certified")
	}
}

func TestAllowBindingOracleChecksEveryConstrainedInvocation(t *testing.T) {
	read := func(tool string, tokens []string) []execmatch.Reading {
		return execmatch.NewNormalizer(rows.Builtin().Lookup(tool), nil).Normalize(tokens)
	}
	good := compare.AllowInvocation{Tool: "go", Tokens: []string{"--", "version"}, Entries: []string{"go version"}}
	good.Readings = read(good.Tool, good.Tokens)
	bad := compare.AllowInvocation{Tool: "go", Tokens: []string{"--", "run"}, Entries: []string{"go version"}}
	bad.Readings = read(bad.Tool, bad.Tokens)
	other := compare.AllowInvocation{Tool: "git", Tokens: []string{"--", "version"}, Entries: []string{"git status"}}
	other.Readings = read(other.Tool, other.Tokens)
	for _, invs := range [][]compare.AllowInvocation{{good, bad}, {good, other}} {
		if compare.AllowBindings("go version", "go", true, true, invs) != "" {
			t.Errorf("unlisted authority hidden by good reading: %+v", invs)
		}
	}
	if compare.AllowBindings("go version", "go", true, true, []compare.AllowInvocation{good}) == "" {
		t.Error("valid identical verb rejected")
	}
}

func TestHeldNpmValueExceptionPreservesBindingAndHold(t *testing.T) {
	tokens := []string{"--searchexclude=x", "-a", "--ci-name=x", "--searchexclude", "--init-author-url=x", "--", "audit", "--audit=x", "--install-strategy=x"}
	nz := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil)
	inv := compare.AllowInvocation{Tool: "npm", Tokens: tokens, Readings: nz.NormalizeOpen(tokens, true), Entries: []string{"npm audit"}}
	if got := compare.AllowBindings("npm audit", "npm", false, false, []compare.AllowInvocation{inv}); got != "held-allow-value/npm-value-binding" {
		t.Fatalf("held source binding class=%q", got)
	}
	if got := compare.AllowBindings("npm audit", "npm", false, true, []compare.AllowInvocation{inv}); got != "" {
		t.Errorf("incomplete final admission certified: %s", got)
	}
	complete := inv
	complete.Readings = nz.Normalize(tokens)
	if got := compare.AllowBindings("npm audit", "npm", true, true, []compare.AllowInvocation{complete}); got != "allow-value/npm-value-binding" {
		t.Errorf("complete class=%q", got)
	}
	for _, alter := range []func(*compare.AllowInvocation){
		func(v *compare.AllowInvocation) { v.Entries = []string{"npm install"} },
		func(v *compare.AllowInvocation) {
			r := nz.NormalizeOpen(tokens, true)
			for i := range r {
				r[i].Operands = append(r[i].Operands, "wrong")
			}
			v.Readings = r
		},
		func(v *compare.AllowInvocation) {
			r := nz.NormalizeOpen(tokens, true)
			for i := range r {
				r[i].Path = []string{"install"}
			}
			v.Readings = r
		},
	} {
		bad := inv
		alter(&bad)
		if got := compare.AllowBindings("npm audit", "npm", false, false, []compare.AllowInvocation{bad}); got != "" {
			t.Errorf("changed entry or binding certified: %s", got)
		}
	}
	bad := compare.AllowInvocation{Tool: "npm", Tokens: []string{"install"}, Readings: nz.NormalizeOpen([]string{"install"}, true), Entries: []string{"npm audit"}}
	if got := compare.AllowBindings("npm audit", "npm", false, false, []compare.AllowInvocation{inv, bad}); got != "" {
		t.Errorf("held value binding hid another authority: %s", got)
	}
}

func TestPipEndedOptionsOraclePreservesVerbAndBindings(t *testing.T) {
	tokens := []string{"--trusted-host", "config", "-q", "--", "cache", "x", "--no-cache-dir=x", "--disable-pip-version-check", "--client-cert"}
	nz := execmatch.NewNormalizer(rows.Builtin().Lookup("pip"), nil)
	readings := nz.Normalize(tokens)
	plain := append(append([]string(nil), tokens[:3]...), tokens[4:]...)
	p, err := old.Parse("pip cache", old.ListAllow, oldrows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	ix := old.NewIndex(oldrows.Builtin(), []*old.Pattern{p}, old.IndexOptions{})
	f := old.Facts{Requested: "pip", Image: "pip", Argv0: "pip", Argv: append([]string{"pip"}, plain...), ArgvComplete: true}
	if b := ix.Decide(&f); b.Outcome != old.OutcomeAllowed || b.Pattern == nil || b.Pattern.Entry != "pip cache" {
		t.Fatalf("stripped released same-entry admission lost: %+v", b)
	}
	if got := compare.AllowSpellingClass("pip cache", "pip", tokens, readings); got != "ended-options" {
		t.Fatalf("retained marker class=%q", got)
	}
	if got := compare.AllowSpellingClass("pip install", "pip", tokens, readings); got != "" {
		t.Errorf("wrong verb certified: %s", got)
	}
	wrong := nz.Normalize(tokens)
	for i := range wrong {
		wrong[i].Operands = append(wrong[i].Operands, "wrong")
	}
	if got := compare.AllowSpellingClass("pip cache", "pip", tokens, wrong); got != "" {
		t.Errorf("changed operands certified: %s", got)
	}
	if got := compare.PatternSeparatorClass("pip -- cache x *", "pip", tokens, readings); got != "pip" {
		t.Errorf("pattern retained marker class=%q", got)
	}
}

func TestAWSChildVocabularyOraclePreservesServiceScope(t *testing.T) {
	tokens := []string{"--cli-read-timeout=x", "--cli-auto-prompt=x", "--", "operation", "false", "--no-sign-request=x", "--dryrun=x", "operation", "--query"}
	p, err := old.Parse("aws operation", old.ListAllow, oldrows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	ix := old.NewIndex(oldrows.Builtin(), []*old.Pattern{p}, old.IndexOptions{})
	plain := append(append([]string(nil), tokens[:2]...), tokens[3:]...)
	f := old.Facts{Requested: "aws", Image: "aws", Argv0: "aws", Argv: append([]string{"aws"}, plain...), ArgvComplete: true}
	b := ix.Decide(&f)
	if b.Outcome != old.OutcomeAllowed || b.Pattern == nil || b.Pattern.Entry != "aws operation" {
		t.Fatalf("stripped released admission=%+v; readings=%+v", b, old.NewNormalizer(oldrows.Builtin().Lookup("aws"), nil).Normalize(plain))
	}
	readings := execmatch.NewNormalizer(rows.Builtin().Lookup("aws"), nil).Normalize(tokens)
	if got := compare.AllowSpellingClass("aws operation", "aws", tokens, readings); got != "child-vocabulary" {
		t.Fatalf("child vocabulary class=%q; readings=%+v", got, readings)
	}
}

func TestAWSChildVocabularyOracleRejectsChangedBindings(t *testing.T) {
	tokens := []string{"--", "s3", "ls", "--profile", "rm"}
	nz := execmatch.NewNormalizer(rows.Builtin().Lookup("aws"), nil)
	readings := nz.Normalize(tokens)
	for _, entry := range []string{"aws s3 rm", "aws s3 ls --profile"} {
		if got := compare.AllowSpellingClass(entry, "aws", tokens, readings); got != "" {
			t.Errorf("wrong command or main-parser option certified for %s: %s", entry, got)
		}
	}
	for i := range readings {
		readings[i].Operands = append(readings[i].Operands, "wrong")
	}
	if got := compare.AllowSpellingClass("aws s3 ls", "aws", tokens, readings); got != "" {
		t.Errorf("changed service operands certified: %s", got)
	}
}

func TestNpmPostCommandMarkerCorrectionPreservesBindings(t *testing.T) {
	tokens := []string{"explain", "init", "--browser=x", "--if-present=x", "--fetch-retry-mintimeout", "--", "-q", "exec", "--all=x"}
	nz := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil)
	r := nz.Normalize(tokens)
	if !compare.NpmOptionalDoesNotMatch("npm explain --all", "deny", tokens, r) {
		t.Fatalf("source optional reading union rejected: %+v", r)
	}
	if got := compare.NpmValueClass("npm explain", tokens, r); got != "npm-optional-value-binding" {
		t.Errorf("same-entry union class=%q", got)
	}
	for _, entry := range []string{"npm explain", "npm explain --browser", "npm explain --fetch-retry-mintimeout"} {
		if compare.NpmOptionalDoesNotMatch(entry, "deny", tokens, r) {
			t.Errorf("true predicate removed: %s", entry)
		}
	}
	for _, entry := range []string{"", "npm", "git status", "npm -- explain"} {
		if compare.NpmOptionalDoesNotMatch(entry, "deny", tokens, r) {
			t.Errorf("unsupported entry certified: %q", entry)
		}
	}
	unlocatable := nz.Normalize(tokens)
	for i := range unlocatable {
		unlocatable[i].Unlocatable = true
	}
	if compare.NpmOptionalDoesNotMatch("npm explain --all", "deny", tokens, unlocatable) {
		t.Error("current unlocatable reading certified")
	}
	if compare.NpmOptionalDoesNotMatch("npm explain --all", "allow", tokens, r) {
		t.Error("allow predicate omitted")
	}
	if compare.NpmOptionalDoesNotMatch("npm explain --all", "deny", tokens, r[:1]) {
		t.Error("missing conservative alternative certified")
	}
	wrong := nz.Normalize(tokens)
	for i := range wrong {
		wrong[i].Operands = append(wrong[i].Operands, "wrong")
	}
	if compare.NpmOptionalDoesNotMatch("npm explain --all", "deny", tokens, wrong) {
		t.Error("changed operand certified")
	}
	if got := compare.NpmValueClass("npm install", tokens, r); got != "" {
		t.Errorf("wrong verb certified: %s", got)
	}
	changedHit := nz.Normalize(tokens)
	for i := range changedHit {
		changedHit[i].Hits[0].Value = "wrong"
	}
	if compare.NpmOptionalDoesNotMatch("npm explain --all", "deny", tokens, changedHit) {
		t.Error("changed option hit certified")
	}
	extraArm := append(nz.Normalize(tokens), changedHit[0])
	if compare.NpmOptionalDoesNotMatch("npm explain --all", "deny", tokens, extraArm) {
		t.Error("extra unknown alternative certified")
	}

	over := []string{"explain"}
	for range 5 {
		over = append(over, "--browser=x")
	}
	over = append(over, "--tag", "--global", "--", "--all")
	if compare.NpmOptionalDoesNotMatch("npm explain --all", "deny", over, nz.Normalize(over)) {
		t.Error("over-budget union certified")
	}
}

func TestNpmValueOracleRestoresPresenceBeforeMatching(t *testing.T) {
	for _, tokens := range [][]string{
		{"--tag", "--global", "install", "x"},
		{"install", "--browser=x", "--tag", "--global"},
	} {
		r := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil).Normalize(tokens)
		for _, entry := range []string{"npm install --tag=*", "npm install --browser=*"} {
			if got := compare.NpmValueClass(entry, tokens, r); got != "" {
				t.Errorf("placeholder made a valueless option present under %s: %s", entry, got)
			}
		}
	}
}

func TestSeparatorOracleDoesNotMoveOptionValues(t *testing.T) {
	for _, tc := range []struct {
		tool, entry, want string
		tokens            []string
	}{
		{"systemctl", "systemctl help", "ended-options", []string{"--no-reload", "--firmware-setup=x", "--timestamp", "--", "--help", "--", "help", "--lines", "disable"}},
		{"pip", "pip cache", "ended-options", []string{"--log", "--", "--", "cache", "x", "--timeout", "y"}},
		{"go", "go version", "identical-binding", []string{"-C", "--", "--", "version", "-v"}},
		{"aws", "aws s3 ls", "", []string{"--profile", "--", "--", "s3", "ls", "--profile", "rm"}},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			nz := execmatch.NewNormalizer(rows.Builtin().Lookup(tc.tool), nil)
			r := nz.Normalize(tc.tokens)
			if got := compare.AllowSpellingClass(tc.entry, tc.tool, tc.tokens, r); got != tc.want {
				t.Fatalf("marker/value class=%q want%q; readings=%+v", got, tc.want, r)
			}
			for i := range r {
				r[i].Operands = append(r[i].Operands, "wrong")
			}
			if got := compare.AllowSpellingClass(tc.entry, tc.tool, tc.tokens, r); got != "" {
				t.Errorf("changed operands certified: %s", got)
			}
		})
	}
}

func TestAllowBindingOracleRejectsUnsafeReadingFlags(t *testing.T) {
	for _, flag := range []string{"unlocatable", "unknown-before", "unknown-args", "pending"} {
		tokens, entry := []string{"--", "version"}, "go version"
		if flag == "unknown-args" {
			tokens, entry = []string{"--", "build", "-v"}, "go build -v"
		}
		r := execmatch.NewNormalizer(rows.Builtin().Lookup("go"), nil).Normalize(tokens)
		for i := range r {
			switch flag {
			case "unlocatable":
				r[i].Unlocatable = true
			case "unknown-before":
				r[i].UnknownBefore = true
			case "unknown-args":
				r[i].Unknown = true
			case "pending":
				r[i].Pending = true
			}
		}
		inv := compare.AllowInvocation{Tool: "go", Tokens: tokens, Readings: r, Entries: []string{entry}}
		if got := compare.AllowBindings(entry, "go", true, true, []compare.AllowInvocation{inv}); got != "" {
			t.Errorf("%s reading certified: %s", flag, got)
		}
	}
}

func TestAWSSeparatorOraclePreservesGlobalPredicates(t *testing.T) {
	tokens := []string{"--debug", "--no-cli-auto-prompt=x", "--ca-bundle=x", "--no-sign-request", "--dryrun", "--color=x", "--", "operation", "false"}
	nz := execmatch.NewNormalizer(rows.Builtin().Lookup("aws"), nil)
	r := nz.Normalize(tokens)
	if got := compare.AllowSpellingClass("aws operation --debug", "aws", tokens, r); got != "identical-binding" {
		t.Fatalf("prefix global predicate rejected: %s", got)
	}
	post := append(append([]string(nil), tokens[1:]...), "--debug")
	if got := compare.AllowSpellingClass("aws operation --debug", "aws", post, nz.Normalize(post)); got != "" {
		t.Errorf("postmarker unknown global satisfied a predicate: %s", got)
	}
}

func TestNpmAllDashOraclePreservesEndedVocabulary(t *testing.T) {
	nz := execmatch.NewNormalizer(rows.Builtin().Lookup("npm"), nil)
	for _, marker := range []string{"---", "----", strings.Repeat("-", 64)} {
		tokens := []string{marker, "publish", "--force"}
		r := nz.Normalize(tokens)
		if got := compare.AllowSpellingClass("npm publish", "npm", tokens, r); got != "ended-options" {
			t.Errorf("%q ended vocabulary class=%q", marker, got)
		}
		if got := compare.AllowSpellingClass("npm install", "npm", tokens, r); got != "" {
			t.Errorf("%q wrongverb certified: %s", marker, got)
		}
		if got := compare.NpmRefusalCorrectionClass("npm publish --force", "deny", tokens, r, "none", ""); got != "npm-ended-options" {
			t.Errorf("%q marker-only false predicate class=%q", marker, got)
		}
	}
	tokens := []string{"--tag", "---", "publish", "--force"}
	if got := compare.NpmValueClass("npm publish", tokens, nz.Normalize(tokens)); got != "npm-value-binding" {
		t.Errorf("String beforemarker class=%q", got)
	}
	consumed := []string{"--tag", "---x", "publish", "--force"}
	if got := compare.AllowSpellingClass("npm publish", "npm", consumed, nz.Normalize(consumed)); got != "" {
		t.Errorf("String value ---x treated as separator: %s", got)
	}
}

func TestAllowBindingOraclePreservesArgumentHold(t *testing.T) {
	tokens := []string{"--", "run", "main.go"}
	r := execmatch.NewNormalizer(rows.Builtin().Lookup("go"), nil).Normalize(tokens)
	inv := compare.AllowInvocation{Tool: "go", Tokens: tokens, Readings: r, Entries: []string{"go run main.go"}}
	if got := compare.AllowBindings("go run main.go", "go", false, true, []compare.AllowInvocation{inv}); got != "" {
		t.Errorf("argument-constrained prefix became final: %s", got)
	}
	if got := compare.AllowBindings("go run main.go", "go", false, false, []compare.AllowInvocation{inv}); got == "" {
		t.Error("held prefix lost independent binding certificate")
	}
	inv.Entries = []string{"go run"}
	for i := range r {
		r[i].Pending = true
	}
	if got := compare.AllowBindings("go run", "go", false, true, []compare.AllowInvocation{inv}); got != "" {
		t.Errorf("pending plain command became final: %s", got)
	}
	if got := compare.AllowBindings("go run", "go", false, false, []compare.AllowInvocation{inv}); got == "" {
		t.Error("nonfinal pending spelling lost certificate")
	}
}

func TestFalseCorrectionOraclesRejectUnlocatableReadings(t *testing.T) {
	for _, tc := range []struct {
		name, tool string
		tokens     []string
		check      func([]execmatch.Reading) bool
	}{
		{"npm value", "npm", []string{"--browser", "--global", "access"}, func(r []execmatch.Reading) bool {
			return compare.NpmRefusalCorrectionClass("npm access --global", "deny", []string{"--browser", "--global", "access"}, r, "none", "") != ""
		}},
		{"npm marker", "npm", []string{"---", "publish", "--force"}, func(r []execmatch.Reading) bool {
			return compare.NpmRefusalCorrectionClass("npm publish --force", "deny", []string{"---", "publish", "--force"}, r, "none", "") != ""
		}},
		{"separator predicate", "systemctl", []string{"start", "reboot"}, func(r []execmatch.Reading) bool {
			return compare.SeparatorPatternDoesNotMatch("systemctl -- reboot", "systemctl", []string{"start", "reboot"}, r)
		}},
		{"commandless", "npm", []string{"--tag", "--global"}, func(r []execmatch.Reading) bool { return compare.NpmCommandless([]string{"--tag", "--global"}, r) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := execmatch.NewNormalizer(rows.Builtin().Lookup(tc.tool), nil).Normalize(tc.tokens)
			if !tc.check(r) {
				t.Fatal("lost positive source witness")
			}
			for i := range r {
				r[i].Unlocatable = true
			}
			if tc.check(r) {
				t.Error("unlocatable refusal certified as a nonrefusal")
			}
		})
	}
}
