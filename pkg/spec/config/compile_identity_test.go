// SPDX-License-Identifier: Apache-2.0

//go:build (!cgo && !darwin) || osusergo

package config_test

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Keep the compiler's default lookup intact. Only the database file is a fixture,
// so reverting the compiler to user.Current cannot hide behind an injected result.
// A uid the database does not list has no implicit home, whatever USER and HOME
// say: a library compile refuses with the lookup's error and takes a home only
// from WithHome, and a command's captured caller compiles a contract that needs
// no home without one.
func TestCompilePasswdLookupEnvironment(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	config.SetPasswdFileForTest(t, passwd)
	uid, _ := config.InvokingUID()
	var unknown user.UnknownUserIdError
	if _, err := config.LookupPasswd(uid); !errors.As(err, &unknown) || int(unknown) != uid {
		t.Fatalf("fixture lookup for uid %d: %v, want UnknownUserIdError", uid, err)
	}
	for _, tc := range []struct {
		name, username, home string
	}{
		{name: "no-env"},
		{name: "user", username: "container"},
		{name: "home", home: "/untrusted-home"},
		{name: "user-home", username: "container", home: "/untrusted-home"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range map[string]string{"USER": tc.username, "HOME": tc.home} {
				t.Setenv(key, value)
				if value == "" {
					if err := os.Unsetenv(key); err != nil {
						t.Fatal(err)
					}
				}
			}
			c, _, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), []byte("version: 0\nname: numeric\ncommand: [/bin/true]\n"), nil)
			if err != nil {
				t.Fatal(err)
			}
			m := config.Builtin()
			m.LedgerRoot.Value = filepath.Join(dir, "runs")
			rt, ds, err := agent.Compile(c, m, agent.WithCwd(dir), agent.Offline())
			var missing user.UnknownUserIdError
			if rt != nil || !errors.As(err, &missing) || int(missing) != uid {
				t.Fatalf("library compile for uid %d absent from passwd = %v, %v\n%v; want the passwd lookup refusal", uid, rt, err, ds)
			}
			caller := config.CaptureCaller()
			caller.Cwd, caller.CwdError = dir, ""
			if caller.Home != "" || caller.HomeError != "" {
				t.Fatalf("captured caller for uid %d absent from passwd: home %q, error %q; want neither", uid, caller.Home, caller.HomeError)
			}
			rt, ds, err = agent.Compile(c, m, agent.WithCallerContext(caller), agent.Offline())
			if err != nil || rt.Home != "" {
				t.Fatalf("caller compile for uid %d absent from passwd = %v, %v\n%v; want a compiled contract with no home", uid, rt, err, ds)
			}
			home := t.TempDir()
			rt, ds, err = agent.Compile(c, m, agent.WithCwd(dir), agent.WithHome(home), agent.Offline())
			if err != nil || rt.Home != home {
				t.Fatalf("explicit-home compile = %v, %v\n%v; want home %q", rt, err, ds, home)
			}
		})
	}
}
