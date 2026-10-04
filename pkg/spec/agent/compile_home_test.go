// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os/user"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestCompileNamesAMissingPasswdHome pins defaults()'s error for a passwd entry with no home field (common in
// container images): user.Current succeeds with HomeDir "", and the error used to wrap that nil error as
// `%!w(<nil>)`, naming neither the cause nor WithHome. A failing lookup still wraps its cause.
func TestCompileNamesAMissingPasswdHome(t *testing.T) {
	c, _, err := LoadBytes("a.yaml", []byte("version: 0\nname: a\ncommand: [x]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := currentUser
	t.Cleanup(func() { currentUser = saved })

	currentUser = func() (*user.User, error) { return &user.User{Uid: "4242"}, nil }
	_, _, err = Compile(c, &config.Machine{}, WithCwd(t.TempDir()))
	if err == nil {
		t.Fatal("Compile with no home succeeded")
	}
	if msg := err.Error(); strings.Contains(msg, "%!") || !strings.Contains(msg, "4242") || !strings.Contains(msg, "WithHome") {
		t.Errorf("error = %q, want the uid and WithHome named, no formatting residue", msg)
	}

	cause := errors.New("passwd unreadable")
	currentUser = func() (*user.User, error) { return nil, cause }
	if _, _, err = Compile(c, &config.Machine{}, WithCwd(t.TempDir())); !errors.Is(err, cause) {
		t.Errorf("error = %v, want it to wrap %v", err, cause)
	}
}
