// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// builtinAllowContract is a contract whose net: section allows the one unix: entry given, on its line 4.
func builtinAllowContract(entry string) string {
	return "version: 0\nname: t\ncommand: [\"python\"]\nnet: {allow: [\"" + entry + "\"]}\n"
}

// contradictions are the diagnostics of code contradiction in ds.
func contradictions(ds []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Code == CodeContradiction {
			out = append(out, d)
		}
	}
	return out
}

// TestBuiltinRefusedAllowIsAContradiction is ADR 0113 at compile: a net.allow unix: entry that a built-in refusal
// refuses, by its path or by the place it resolves to, admits nothing in any enforcing run, since the built-ins are
// decided before net.allow. Compile refuses it as a contradiction naming the entry, the built-in rule and the ADR,
// with a fix that names the supported way. The SSH-agent exception, an exact container-daemon socket (its own warning)
// and a socket no built-in covers compile without it.
func TestBuiltinRefusedAllowIsAContradiction(t *testing.T) {
	f := newSocketFixture(t, "project/link")
	link := filepath.Join(f.project, "link")
	if err := os.Symlink("/run/user/4242/bus", link); err != nil {
		t.Fatal(err)
	}
	const hostIPCFix = "remove the entry; to let the agent cause one operation through that socket, such as restarting one " +
		"service, run a helper outside the run that does that one operation and nothing else, listening on a socket at a " +
		"path no built-in refuses (outside /run/user/4242), and allow that socket instead (docs/user/built-in-refusals.md)"
	for _, tc := range []struct {
		name, entry, rule, message, fix string
	}{
		{"the session bus", "unix:/run/user/4242/bus", BuiltinHostIPC,
			"net[unix:/run/user/4242/bus] is refused by builtin.host_ipc in every enforcing run, before net.allow is read: no contract entry lifts a built-in refusal (ADR 0113), so this entry admits nothing; the socket is the D-Bus session bus, through which systemd-run --user starts a command outside the run",
			hostIPCFix},
		{"the user manager", "unix:/run/user/4242/systemd/private", BuiltinHostIPC,
			"net[unix:/run/user/4242/systemd/private] is refused by builtin.host_ipc in every enforcing run, before net.allow is read: no contract entry lifts a built-in refusal (ADR 0113), so this entry admits nothing; the socket is the systemd user manager",
			hostIPCFix},
		{"another server in the runtime directory", "unix:/run/user/4242/pulse/native", BuiltinHostIPC,
			"net[unix:/run/user/4242/pulse/native] is refused by builtin.host_ipc in every enforcing run, before net.allow is read: no contract entry lifts a built-in refusal (ADR 0113), so this entry admits nothing",
			hostIPCFix},
		{"the system bus", "unix:/run/dbus/system_bus_socket", BuiltinHostIPC, "", hostIPCFix},
		{"a link to the bus", "unix:" + link, BuiltinHostIPC,
			"net[unix:" + link + "] (resolves to /run/user/4242/bus) is refused by builtin.host_ipc in every enforcing run, before net.allow is read: no contract entry lifts a built-in refusal (ADR 0113), so this entry admits nothing; the socket is the D-Bus session bus, through which systemd-run --user starts a command outside the run",
			hostIPCFix},
		{"tego's own socket", "unix:~/.tego/api.sock", BuiltinTegoSurface,
			"net[unix:~/.tego/api.sock] is refused by builtin.tego_surface in every enforcing run, before net.allow is read: no contract entry lifts a built-in refusal (ADR 0113), so this entry admits nothing",
			"remove the entry: no run reaches Tego's own sockets (docs/user/built-in-refusals.md)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, ds, err := f.compileErr(f.load(builtinAllowContract(tc.entry)))
			got := contradictions(ds)
			if err == nil || rt != nil || len(got) != 1 {
				t.Fatalf("want one %s error, got err %v and:\n%s", CodeContradiction, err, render(ds))
			}
			d := got[0]
			if !d.IsError() || d.Line != 4 || d.Col == 0 || !strings.Contains(d.Message, tc.rule) || !strings.Contains(d.Message, "ADR 0113") {
				t.Errorf("want an error at the entry naming %s and ADR 0113: %+v", tc.rule, d)
			}
			if tc.message != "" && d.Message != tc.message {
				t.Errorf("message changed:\n got %s\nwant %s", d.Message, tc.message)
			}
			if d.Fix != tc.fix {
				t.Errorf("fix changed:\n got %s\nwant %s", d.Fix, tc.fix)
			}
		})
	}

	for _, tc := range []struct{ name, entry, warn string }{
		{"the SSH agent", "unix:/run/user/4242/openssh_agent", ""},
		{"gpg-agent's SSH socket", "unix:/run/user/4242/gnupg/S.gpg-agent.ssh", ""},
		{"an exact container socket", "unix:/run/docker.sock", CodeContainerSocketEscape},
		{"rootless docker", "unix:/run/user/4242/docker.sock", CodeContainerSocketEscape},
		{"an unrelated socket outside", "unix:/srv/ops/restart-app.sock", ""},
		{"another user's runtime directory", "unix:/run/user/4243/bus", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds := f.compile(f.load(builtinAllowContract(tc.entry)))
			if got := contradictions(ds); len(got) != 0 {
				t.Errorf("%s is not refused by a built-in, so it is no contradiction:\n%s", tc.entry, render(ds))
			}
			if tc.warn != "" && !hasCode(ds, tc.warn) {
				t.Errorf("want its %s warning:\n%s", tc.warn, render(ds))
			}
		})
	}
}

// TestBuiltinRefusedAllowRecordOnly: a record-only run (--observe, and tego watch with no --boundary) installs no
// built-in and refuses nothing, so an entry a built-in would refuse is no contradiction there.
func TestBuiltinRefusedAllowRecordOnly(t *testing.T) {
	f := newFixture(t)
	for _, entry := range []string{"unix:/run/user/4242/bus", "unix:/run/user/4242/systemd/private"} {
		_, ds := f.compile(f.load(builtinAllowContract(entry)), WithObserve())
		if got := contradictions(ds); len(got) != 0 {
			t.Errorf("%s under --observe:\n%s", entry, render(ds))
		}
	}
}

// TestHostSocketsBesideNetIsANote: host_sockets: true has no effect beside a net: section, which decides every unix
// destination by its own entries (ADR 0070), so compile says so in an informational note at the key; nothing is noted
// without a net: section, where the key is the opt-out, or in a record-only run.
func TestHostSocketsBesideNetIsANote(t *testing.T) {
	f := newFixture(t)
	notes := func(ds []Diagnostic) []Diagnostic {
		var out []Diagnostic
		for _, d := range ds {
			if d.Code == CodeRedundantRule && strings.Contains(d.Message, "host_sockets") {
				out = append(out, d)
			}
		}
		return out
	}
	const want = "host_sockets: true has no effect beside a net: section, which decides every unix destination by its own " +
		"entries (ADR 0070); no contract key lifts the built-in refusals either (ADR 0113)"
	for _, yaml := range []string{
		"version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\nnet: {}\n",
		"version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\nnet:\n  allow: [\"unix:/run/user/4242/openssh_agent\"]\n",
	} {
		_, ds := f.compile(f.load(yaml))
		got := notes(ds)
		if len(got) != 1 {
			t.Fatalf("want one note:\n%s\n%s", yaml, render(ds))
		}
		d := got[0]
		if d.IsError() || !d.Informational() || d.Line != 4 || d.Message != want ||
			d.Fix != "remove host_sockets: true; a net.allow unix: entry names each socket the agent needs" {
			t.Errorf("want an informational note at the key: %+v", d)
		}
		if _, ds := f.compile(f.load(yaml), WithObserve()); len(notes(ds)) != 0 {
			t.Errorf("a record-only run notes nothing:\n%s", render(ds))
		}
	}
	if _, ds := f.compile(f.load("version: 0\nname: t\ncommand: [\"python\"]\nhost_sockets: true\n")); len(notes(ds)) != 0 {
		t.Errorf("without a net: section host_sockets: true is the opt-out, not a no-op:\n%s", render(ds))
	}
}
