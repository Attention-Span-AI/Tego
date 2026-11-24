// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// plant writes files into a fresh git checkout and returns its root.
func plant(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	for name, src := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// names is the found tests as "dir test kind".
func names(found []Found) []string {
	out := []string{}
	for _, f := range found {
		out = append(out, f.Dir+" "+f.Test+" "+f.Kind)
	}
	return out
}

const gates = `package p

import (
	"os"
	"testing"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

// twoDeep skips through requireRoot: the helpers are found to a fixed point, whatever the order they are written in.
func twoDeep(t *testing.T, name string) string {
	t.Helper()
	requireRoot(t)
	return name
}

func TestDirect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func TestDirectUid(t *testing.T) {
	if os.Getuid() > 0 {
		t.Skipf("uid %d", os.Getuid())
	}
}

func TestOrChain(t *testing.T) {
	if os.Getenv("X") != "kvm" || os.Geteuid() != 0 {
		t.Skip("only in a guest")
	}
}

func TestNegatedRootTest(t *testing.T) {
	if !(os.Geteuid() == 0) {
		t.Skip("needs root")
	}
}

func TestViaHelper(t *testing.T) {
	requireRoot(t)
}

func TestViaTwoHelpers(t *testing.T) {
	c := twoDeep(t, "x")
	_ = c
}

func TestAndChain(t *testing.T) {
	if os.Getenv("X") == "" && os.Geteuid() != 0 {
		t.Skip("skips only when both hold")
	}
}

func TestSkipsWhenRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the dashboard refuses to run as root")
	}
}

func TestNeedsCapability(t *testing.T) {
	if os.Getenv("CAPS") == "" {
		t.Skip("loading the objects needs cap_bpf; run as root")
	}
}

func TestRootCanDoIt(t *testing.T) {
	if os.Getenv("Y") == "" {
		t.Skip("root can search a mode-000 directory")
	}
}

func TestInASubtest(t *testing.T) {
	t.Run("x", func(t *testing.T) {
		requireRoot(t)
	})
}

func TestConditionalCall(t *testing.T) {
	if os.Getenv("Z") != "" {
		requireRoot(t)
	}
}

func TestInAClosureOnly(t *testing.T) {
	f := func() { requireRoot(t) }
	_ = f
}

func Testlower(t *testing.T) {
	requireRoot(t)
}

func TestPlain(t *testing.T) {}
`

// TestScanFindsTheRootGatedTests: each form of a skip for want of root is found, each look-alike is not. A test that
// skips for a non-root process only when another term holds, or that holds the gate in a branch, a loop or a closure,
// is "sub" (it may skip): the tool prefers a candidate to a silent pass.
func TestScanFindsTheRootGatedTests(t *testing.T) {
	root := plant(t, map[string]string{"p/gates_test.go": gates})
	found, err := Scan(root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"p TestAndChain sub", // the && chain: it skips for a non-root process whenever its other term holds, so it may
		"p TestConditionalCall sub",
		"p TestDirect test",
		"p TestDirectUid test",
		"p TestInAClosureOnly sub",
		"p TestInASubtest sub",
		"p TestNeedsCapability test",
		"p TestNegatedRootTest test",
		"p TestOrChain test",
		"p TestViaHelper test",
		"p TestViaTwoHelpers test",
	}
	if got := names(found); !reflect.DeepEqual(got, want) {
		t.Fatalf("found\n  %q\nwant\n  %q", got, want)
	}
}

// TestScanReadsTheBuildItIsGiven: a file's //go:build line and name suffix decide whether the build reads it, so a
// test that only the tegobpf build compiles is no candidate of the integration step, and the integration build's own
// file is one of its.
func TestScanReadsTheBuildItIsGiven(t *testing.T) {
	gate := "package p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) {\n\tif os.Geteuid() != 0 {\n\t\tt.Skip(\"needs root\")\n\t}\n}\n"
	root := plant(t, map[string]string{
		"a/integ_test.go":         "//go:build integration\n\n" + gate,
		"b/bpf_test.go":           "//go:build integration && tegobpf\n\n" + gate,
		"c/plain_test.go":         gate,
		"d/windows_test.go":       gate, // not _windows_test.go: read
		"d/other_windows_test.go": gate,
		"e/testdata/x_test.go":    gate,
		"_f/x_test.go":            gate,
	})
	for _, c := range []struct {
		tags []string
		want []string
	}{
		{nil, []string{"c TestX test", "d TestX test"}},
		{[]string{"integration"}, []string{"a TestX test", "c TestX test", "d TestX test"}},
		{[]string{"integration", "tegobpf"}, []string{"a TestX test", "b TestX test", "c TestX test", "d TestX test"}},
	} {
		found, err := Scan(root, c.tags, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := names(found); !reflect.DeepEqual(got, c.want) {
			t.Errorf("tags %v: found %q, want %q", c.tags, got, c.want)
		}
	}
}

// TestScanKeepsAnExternalTestPackageApart: a helper of package p_test is not the helper of package p's tests.
func TestScanKeepsAnExternalTestPackageApart(t *testing.T) {
	root := plant(t, map[string]string{
		"p/ext_test.go": "package p_test\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc need(t *testing.T) {\n\tif os.Geteuid() != 0 {\n\t\tt.Skip(\"needs root\")\n\t}\n}\n",
		"p/in_test.go":  "package p\n\nimport \"testing\"\n\nfunc need(t *testing.T) {}\n\nfunc TestIn(t *testing.T) { need(t) }\n",
	})
	found, err := Scan(root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("found %q, want none", names(found))
	}
}

// TestScanSurvivesAFileDeletedFromTheTree: git lists a tracked file that was deleted in the working tree.
func TestScanSurvivesAFileDeletedFromTheTree(t *testing.T) {
	root := plant(t, map[string]string{"p/gone_test.go": gates, "p/kept_test.go": "package p\n"})
	if out, err := exec.Command("git", "-C", root, "add", "p/gone_test.go").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	if err := os.Remove(filepath.Join(root, "p", "gone_test.go")); err != nil {
		t.Fatal(err)
	}
	found, err := Scan(root, nil, false)
	if err != nil || len(found) != 0 {
		t.Fatalf("found %q, err %v; want none", names(found), err)
	}
}

// TestScanFailsOnABrokenFile: a file it cannot parse is an error, not a silently shorter list.
func TestScanFailsOnABrokenFile(t *testing.T) {
	root := plant(t, map[string]string{"p/bad_test.go": "func TestNoPackage(t *testing.T) {}\n"})
	if _, err := Scan(root, nil, false); err == nil {
		t.Fatal("a file with no package clause was read")
	}
}

// shapes is a probe tree: five needs-root skips that the plain
// `euid != 0` read missed, each with a message that says nothing of root. check-skiplists.sh exited 0 on a tree that
// held them all. A sixth test, TestQuietMessage, is the shape the first version caught; the controls beside them must
// not be named.
var shapes = map[string]string{
	"go.mod": "module example.test/shapes\n\ngo 1.21\n",
	"zzhelp/help.go": `package zzhelp

import (
	"os"
	"testing"
)

// RequireRoot is a helper of another package, in a non-test file.
func RequireRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping")
	}
}
`,
	"zzprobe/probe_test.go": `package zzprobe

import (
	"os"
	"testing"

	"example.test/shapes/zzhelp"
)

type env struct{}

func (env) requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping")
	}
}

func TestQuietMessage(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not enough privilege")
	}
}

func TestElseBranch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping")
	} else {
		t.Log("root")
	}
}

func TestViaMethod(t *testing.T) {
	env{}.requireRoot(t)
}

func TestCrossPkg(t *testing.T) {
	zzhelp.RequireRoot(t)
}

func TestInSwitch(t *testing.T) {
	switch {
	case os.Geteuid() != 0:
		t.Skip("skipping")
	}
}

func TestSubtestVar(t *testing.T) {
	f := func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("skipping")
		}
	}
	t.Run("a", f)
}

// The controls: a skip for a tool, a skip for root, a helper of no skip, a test with no skip.
func TestControlTool(t *testing.T) {
	if os.Getenv("NO_TOOL") != "" {
		t.Skip("no tool")
	}
}

func TestControlRootRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the dashboard refuses to run as root")
	}
}

func TestControlHelperWithoutSkip(t *testing.T) {
	env{}.plain(t)
}

func (env) plain(t *testing.T) { t.Helper() }
`,
}

// TestScanFindsTheFiveShapesTheFirstVersionMissed: if-else, a method helper, a helper of another package, a switch
// case and a subtest function kept in a variable, none with a message that says root. Fails against the tool of
// 31104d6d8.
func TestScanFindsTheFiveShapesTheFirstVersionMissed(t *testing.T) {
	root := plant(t, shapes)
	found, err := Scan(root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"zzprobe TestCrossPkg test",
		"zzprobe TestElseBranch test",
		"zzprobe TestInSwitch test",
		"zzprobe TestQuietMessage test",
		"zzprobe TestSubtestVar sub",
		"zzprobe TestViaMethod test",
	}
	if got := names(found); !reflect.DeepEqual(got, want) {
		t.Fatalf("found\n  %q\nwant\n  %q", got, want)
	}
}

// TestScanFollowsAnIdThroughNamesAndValues: the id read into a local, a package variable or a function's result and
// tested later, a helper that is a function variable, a helper called with the id; and the look-alikes, where the
// id is only an argument of a call that gives no root flag, sits in a literal, or is shadowed by a local name.
func TestScanFollowsAnIdThroughNamesAndValues(t *testing.T) {
	root := plant(t, map[string]string{"go.mod": "module example.test/vals\n", "p/vals_test.go": `package p

import (
	"os"
	"testing"
)

var amRoot = os.Geteuid() == 0

func isPrivileged() bool { return os.Geteuid() == 0 }

var needRoot = func(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping")
	}
}

func skipUnless(t *testing.T, ok bool, why string) {
	if !ok {
		t.Skip(why)
	}
}

func place(euid int) (int, error) { return euid, nil }

func run() int { return os.Geteuid() }

func TestLocal(t *testing.T) {
	euid := os.Geteuid()
	if euid != 0 {
		t.Skip("skipping")
	}
}

func TestPackageVar(t *testing.T) {
	if !amRoot {
		t.Skip("skipping")
	}
}

func TestFunctionResult(t *testing.T) {
	if !isPrivileged() {
		t.Skip("skipping")
	}
}

func TestFunctionVariable(t *testing.T) {
	needRoot(t)
}

func TestIdAsArgument(t *testing.T) {
	skipUnless(t, os.Geteuid() == 0, "skipping")
}

func TestRootVariableSkipsInTheRootRun(t *testing.T) {
	root := os.Geteuid() == 0
	if root {
		t.Skip("the root run does not take this branch")
	}
}

func TestZeroTestOfALocal(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("refuses root")
	}
}

func TestErrorOfAnIdCall(t *testing.T) {
	_, err := place(os.Geteuid())
	if err != nil {
		t.Skip("no place")
	}
}

func TestLiteralHoldingAnId(t *testing.T) {
	cfg := struct{ uid int }{uid: os.Geteuid()}
	_ = cfg
	if os.Getenv("X") != "" {
		t.Skip("no x")
	}
}

func TestLocalNameShadowsAFunctionOfTheSameName(t *testing.T) {
	run := func() bool { return false }
	if run() {
		t.Skip("never")
	}
}
`})
	found, err := Scan(root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"p TestFunctionResult sub",
		"p TestFunctionVariable test",
		"p TestIdAsArgument sub",
		"p TestLocal sub",
		"p TestPackageVar sub",
	}
	if got := names(found); !reflect.DeepEqual(got, want) {
		t.Fatalf("found\n  %q\nwant\n  %q", got, want)
	}
}

// TestScanReadsAReleaseTaggedFile: a //go:build go1.N line is true for the toolchain that builds the tree, so the
// file is read (F2: the release tags were nil and such a file was left out without a word).
func TestScanReadsAReleaseTaggedFile(t *testing.T) {
	root := plant(t, map[string]string{
		"p/old_test.go":   "//go:build go1.21\n\npackage p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestRel(t *testing.T) {\n\tif os.Geteuid() != 0 {\n\t\tt.Skip(\"skipping\")\n\t}\n}\n",
		"p/new_test.go":   "//go:build go1.99999\n\npackage p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestFuture(t *testing.T) {\n\tif os.Geteuid() != 0 {\n\t\tt.Skip(\"skipping\")\n\t}\n}\n",
		"p/mixed_test.go": "//go:build unix && !windows\n\npackage p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestUnix(t *testing.T) {\n\tif os.Geteuid() != 0 {\n\t\tt.Skip(\"skipping\")\n\t}\n}\n",
	})
	found, err := Scan(root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"p TestRel test", "p TestUnix test"}
	if got := names(found); !reflect.DeepEqual(got, want) {
		t.Fatalf("found %q, want %q (TestFuture needs a toolchain that does not exist)", got, want)
	}
}

// TestScanHonoursAnIgnoreComment: a skip the tool cannot tell from a needs-root one is cleared by a comment that gives
// its reason, on the line of the skip or the line before it, and a comment with no reason is an error.
func TestScanHonoursAnIgnoreComment(t *testing.T) {
	src := func(comment string) map[string]string {
		return map[string]string{"p/x_test.go": "package p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) {\n\tif os.Geteuid() != 0 && os.Getenv(\"CAPS\") != \"\" {\n" + comment + "\t\tt.Skip(\"skipping\")\n\t}\n}\n"}
	}
	for _, c := range []struct {
		name, comment string
		want          []string
		fails         bool
	}{
		{"no comment", "", []string{"p TestX sub"}, false},
		{"a reason on the line before", "\t\t// rootskips:ignore it skips with capabilities, not for want of root\n", []string{}, false},
		{"no reason", "\t\t// rootskips:ignore\n", nil, true},
		{"another comment", "\t\t// this is not a root skip\n", []string{"p TestX sub"}, false},
	} {
		found, err := Scan(plant(t, src(c.comment)), nil, false)
		if c.fails {
			if err == nil {
				t.Errorf("%s: a directive with no reason was taken", c.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := names(found); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: found %q, want %q", c.name, got, c.want)
		}
	}
}

const rootRun = `package p

import (
	"os"
	"testing"
)

// skipIfRoot is a helper that skips the test of a root process; the tests that call it skip as root.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a folder whatever its mode")
	}
}

func requireRootToo(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root") // a skip of the other half: not this tool's
	}
}

func TestSkipsAsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
}

func TestSkipsAsRootInTheElse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Log("not root")
	} else {
		t.Skip("root can open it")
	}
}

func TestSkipsAsRootUnderAnAnd(t *testing.T) {
	if os.Getenv("X") == "" && os.Geteuid() == 0 {
		t.Skip("may skip as root")
	}
}

func TestSkipsAsRootInASwitch(t *testing.T) {
	switch os.Geteuid() {
	case 0:
		t.Skip("root")
	}
}

func TestSkipsAsRootInASubtest(t *testing.T) {
	t.Run("a file that cannot be written is exit 125 [io]", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes into a folder whatever its mode")
		}
	})
	t.Run("this one runs", func(t *testing.T) {})
}

func TestSkipsAsRootInATable(t *testing.T) {
	for _, name := range []string{"a", "b"} {
		t.Run(name, func(t *testing.T) {
			skipIfRoot(t)
		})
	}
}

func TestSkipsAsRootViaAHelper(t *testing.T) {
	skipIfRoot(t)
}

func TestSkipsAsRootThroughAName(t *testing.T) {
	root := os.Geteuid() == 0
	if root {
		t.Skip("root")
	}
}

func TestRunsAsRoot(t *testing.T) {
	if os.Getenv("X") == "" {
		t.Skip("no X")
	}
}

func TestSkipsOnlyWhenNotRoot(t *testing.T) {
	requireRootToo(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func TestClearedByAComment(t *testing.T) {
	// rootskips:ignore skips only where the kernel lacks the feature, which the root run's has
	if os.Geteuid() == 0 {
		t.Skip("no feature")
	}
}
`

// TestScanAsRootFindsTheTestsThatSkipWhenRoot: the root run's own skips, which Scan does not read (a process that is
// not root never takes them): the strict gate named five of them UNLISTED only after a three-hour guest run.
func TestScanAsRootFindsTheTestsThatSkipWhenRoot(t *testing.T) {
	root := plant(t, map[string]string{"go.mod": "module example.test/m\n", "p/p_test.go": rootRun})
	found, err := ScanAsRoot(root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"p TestSkipsAsRoot test",
		"p TestSkipsAsRootInASubtest/a_file_that_cannot_be_written_is_exit_125_[io] sub",
		"p TestSkipsAsRootInASwitch test",
		"p TestSkipsAsRootInATable/* sub",
		"p TestSkipsAsRootInTheElse test",
		"p TestSkipsAsRootThroughAName test",
		"p TestSkipsAsRootUnderAnAnd test",
		"p TestSkipsAsRootViaAHelper test",
	}
	if got := names(found); !reflect.DeepEqual(got, want) {
		t.Errorf("found\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The other half is unchanged: Scan still reads a root run's skip as no candidate.
	other, err := Scan(root, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range other {
		if strings.HasPrefix(f.Test, "TestSkipsAsRoot") {
			t.Errorf("Scan lists %s, a skip of the root run", f.Test)
		}
	}
}
