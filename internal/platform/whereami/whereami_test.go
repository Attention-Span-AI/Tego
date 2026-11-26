// SPDX-License-Identifier: Apache-2.0

package whereami

import (
	"errors"
	"strings"
	"testing"
)

// facts describes one machine: the paths that exist (a trailing "/" says a directory), process 1's environment (nil
// says it cannot be read) and how many WSL marks hold.
func facts(paths []string, env []byte, readable bool, wsl int) Facts {
	has := func(p string) (found, dir bool) {
		for _, q := range paths {
			if q == p {
				return true, false
			}
			if q == p+"/" {
				return true, true
			}
		}
		return false, false
	}
	return Facts{
		Present: func(p string) bool { f, _ := has(p); return f },
		IsDir:   func(p string) bool { f, d := has(p); return f && d },
		InitEnviron: func() ([]byte, error) {
			if !readable {
				return nil, errors.New("open /proc/1/environ: permission denied")
			}
			return env, nil
		},
		WSLMarks: func() int { return wsl },
	}
}

func TestDetectEveryPlace(t *testing.T) {
	env := func(kv ...string) []byte { return []byte(strings.Join(kv, "\x00") + "\x00") }
	cases := []struct {
		name  string
		facts Facts
		want  Kind
	}{
		{"Docker's mark", facts([]string{"/.dockerenv"}, nil, false, 0), Container},
		{"Podman's mark", facts([]string{"/run/.containerenv"}, nil, false, 0), Container},
		{"the container variable of process 1", facts(nil, env("PATH=/bin", "container=podman"), true, 0), Container},
		{"the container variable beside others", facts(nil, env("container=lxc", "HOME=/root"), true, 0), Container},
		{"no mark at all", facts(nil, env("PATH=/bin"), true, 0), Host},
		{"nothing readable", facts(nil, nil, false, 0), Host},
		{"an empty container variable is no mark", facts(nil, env("container="), true, 0), Host},
		{"a variable that only ends in container", facts(nil, env("not_container=x", "xcontainer=y"), true, 0), Host},
		{"WSL by one of its marks", facts(nil, env("PATH=/bin"), true, 1), WSL},
		{"WSL by all of them", facts(nil, env("PATH=/bin"), true, 3), WSL},
		{"a container on a WSL kernel is a container", facts([]string{"/.dockerenv"}, nil, false, 1), Container},
		{"systemd at process 1 keeps the host words, with a mark", facts([]string{"/.dockerenv", "/run/systemd/system/"}, nil, false, 0), Host},
		{"systemd at process 1, nspawn's variable", facts([]string{"/run/systemd/system/"}, env("container=systemd-nspawn"), true, 0), Host},
		{"a file where the systemd folder should be is no systemd", facts([]string{"/.dockerenv", "/run/systemd/system"}, nil, false, 0), Container},
		{"systemd at process 1 on a WSL kernel", facts([]string{"/.dockerenv", "/run/systemd/system/"}, nil, false, 2), WSL},
	}
	for _, c := range cases {
		if got := Detect(c.facts); got != c.want {
			t.Errorf("%s: Detect = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAMarkThatCannotBeLookedAtIsNotAContainer: the machine's own reads count a path as present only when they saw it,
// so a refused or failed look never turns a host into a container.
func TestAMarkThatCannotBeLookedAtIsNotAContainer(t *testing.T) {
	dir := t.TempDir()
	if Machine.Present(dir + "/absent") {
		t.Errorf("an absent path is present")
	}
	if !Machine.Present(dir) || !Machine.IsDir(dir) {
		t.Errorf("the temporary directory is not seen")
	}
	if Machine.IsDir(dir + "/absent") {
		t.Errorf("an absent path is a directory")
	}
}

func TestWordsAndCureOnlyChangeInAContainer(t *testing.T) {
	was := Here
	t.Cleanup(func() { Here = was })
	for _, c := range []struct {
		kind      Kind
		container bool
	}{{Host, false}, {WSL, false}, {Container, true}} {
		Here = func() Kind { return c.kind }
		w := Words()
		if got := w.NotAtTop != ""; got != c.container {
			t.Errorf("%v: Words().NotAtTop set = %v, want %v", c.kind, got, c.container)
		}
		cure := CgroupCure("the host's cure")
		if c.container && cure != ContainerCgroupCure || !c.container && cure != "the host's cure" {
			t.Errorf("%v: CgroupCure = %q", c.kind, cure)
		}
	}
}

// TestTheContainerWordsSayWhatTheGuideSays: every thing docs/user/container.md names is named, and no systemd, WSL or
// privileged advice is.
func TestTheContainerWordsSayWhatTheGuideSays(t *testing.T) {
	for _, words := range []string{ContainerCgroupCure, ContainerNotAtTop} {
		for _, want := range []string{"examples/container/compose.yaml", "docs/user/container.md", "examples/container",
			"delegated cgroup subtree", "SYS_ADMIN", "apparmor=unconfined", "/run/tego-lsm/lsm-list"} {
			if !strings.Contains(words, want) {
				t.Errorf("%q does not name %q", words, want)
			}
		}
		for _, bad := range []string{"Delegate=", "user@.service", "daemon-reload", "re-login", "wsl.conf", "wsl --update",
			"[boot]", "privileged"} {
			if strings.Contains(words, bad) {
				t.Errorf("%q gives the advice %q, which does not apply in a container", words, bad)
			}
		}
	}
	if !strings.Contains(ContainerNotAtTop, "tego run") {
		t.Errorf("the not-at-the-top words do not say what a container runs: %q", ContainerNotAtTop)
	}
}
