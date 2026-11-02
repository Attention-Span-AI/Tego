// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestControlLicensesPrintsWhatTheBinaryCarries (docs/GAPS.md B12): `tego-control licenses` prints every licence file
// of the tree whole under its name, the Apache-2.0 text and every module of THIRD_PARTY_NOTICES.txt among them, as
// the user and with exit 0; an argument or an unknown flag is a usage error. It was an unknown command, and an
// installed tego-control carried no notice at all.
func TestControlLicensesPrintsWhatTheBinaryCarries(t *testing.T) {
	code, out, errs := run(t, user, "licenses")
	if code != identity.ExitOK || errs != "" {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	root := filepath.Join("..", "..", "..")
	full, err := filepath.Glob(filepath.Join(root, "LICENSES", "*.txt"))
	if err != nil || len(full) == 0 {
		t.Fatalf("the licence texts under LICENSES/: %v %v", full, err)
	}
	for _, path := range append([]string{filepath.Join(root, "LICENSE"), filepath.Join(root, "NOTICE"),
		filepath.Join(root, "THIRD_PARTY_NOTICES.txt")}, full...) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name, _ := filepath.Rel(root, path)
		if !strings.Contains(out, "==> "+filepath.ToSlash(name)+" <==\n"+string(b)) {
			t.Errorf("tego-control licenses does not print %s whole under its name", name)
		}
	}
	notices, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY_NOTICES.txt"))
	if err != nil {
		t.Fatal(err)
	}
	modules := 0
	for _, l := range strings.Split(string(notices), "\n") {
		if strings.HasPrefix(l, "===== ") {
			modules++
			if !strings.Contains(out, "\n"+l+"\n") {
				t.Errorf("tego-control licenses lacks the notices of %s", l)
			}
		}
	}
	if modules < 2 {
		t.Fatalf("THIRD_PARTY_NOTICES.txt names %d modules; the test read the wrong file", modules)
	}
	if !strings.Contains(out, "Apache License") || !strings.Contains(out, "Version 2.0, January 2004") {
		t.Fatalf("tego-control licenses prints no Apache-2.0 text:\n%.300s", out)
	}
	for _, argv := range [][]string{{"licenses", "extra"}, {"licenses", "--json"}} {
		if code, out, errs := run(t, user, argv...); code != identity.ExitUsage || out != "" || errs == "" {
			t.Errorf("%v: exit %d stdout %q stderr %q, want a usage error", argv, code, out, errs)
		}
	}
}
