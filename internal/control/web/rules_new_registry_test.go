// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// withRegistry gives the fixture's rule service a machine config whose user registry is a new folder under the
// fixture's home, as tego learn --save would write to, and returns that folder.
func (f *rulesFix) withRegistry(t *testing.T) string {
	t.Helper()
	rs := f.withSetup(t)
	reg := filepath.Join(f.home, ".config", "tego")
	rs.Machine = &config.Machine{Home: f.home}
	rs.Machine.Registry.Value = reg
	return reg
}

// fromRunForm is the Create form of a draft from run id, saved to the user registry (to) with refused reads recorded
// (reads), as the page sends it back.
func fromRunForm(f *rulesFix, id, name, base string, reads bool) url.Values {
	v := url.Values{"csrf": {f.s.csrf}, "mode": {"run"}, "from": {id}, "dir": {f.proj}, "name": {name}, "to": {"registry"}, "base": {base}}
	if reads {
		v.Set("reads", "on")
	}
	return v
}

// TestMakeAContractFromThisRunSavesWhereLearnSaves (docs/DASHBOARD.md, From a run): the run page's Tighten tab links
// to New contract from that run, which previews at once, saving to the user registry with refused reads recorded,
// as tego learn --save does. Create writes <registry>/agents/<name>.yaml through registry.Save, mode 0600, with
// reason: reads: on, and the registry then resolves the name from the run's folder to that file, as tego run <name>
// typed there does. A second Create of the name is refused and the file kept; with the switch off the draft has no
// reason: block.
func TestMakeAContractFromThisRunSavesWhereLearnSaves(t *testing.T) {
	f := newRulesFix(t)
	reg := f.withRegistry(t)

	_, tab := f.get(t, "/runs/"+rulesRunA+"/least-privilege")
	link := `href="/rules/new?mode=run&amp;from=` + rulesRunA + `"`
	if !strings.Contains(tab, link) || !strings.Contains(tab, "Make a contract from this run") || !strings.Contains(tab, "--save &lt;name&gt;") {
		t.Fatalf("the Tighten tab has no Make a contract from this run link")
	}
	// A watched run's own "Make a contract", in the head of every tab, goes there in one click, not to the Tighten tab
	// first (acceptance B, 2026-11-11).
	const watched = "r-aaaaaaaa-0000000000034-watchd"
	dir := filepath.Join(f.root, watched)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-time.Hour).UTC()
	var ev strings.Builder
	for n, l := range []string{`"kind":"run_start","source":"supervisor","tier":"observe","command":["sh"],"cwd":"` + f.proj + `"`,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`} {
		fmt.Fprintf(&ev, `{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"sh","pid":10,"tid":10,"cgroup":1,%s}`+"\n",
			n, n+1, t0.Add(time.Duration(n)*time.Millisecond).Format(time.RFC3339Nano), n+1, watched, l)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(ev.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tab := range []string{"", "/refusals"} {
		_, top := f.get(t, "/runs/"+watched+tab)
		if want := `<a class="link" href="/rules/new?mode=run&amp;from=` + watched + `">Make a contract</a>`; !strings.Contains(top, want) {
			i := strings.Index(top, "Watched only")
			t.Errorf("tab %q: the head's Make a contract does not link to New contract from this run: %q", tab, top[max(0, i):min(len(top), i+300)])
		}
	}
	code, body := f.get(t, "/rules/new?mode=run&from="+rulesRunA)
	file := filepath.Join(reg, "agents", "proj.yaml")
	for _, want := range []string{
		`name="to" value="registry" checked`, `name="to" value="project">`,
		`name="reads" value="on" aria-describedby="nw-reads-cost" checked`, "Show refused reads (slower)", agent.ReasonReadCost,
		"Writes <span class=\"code-i\">" + file + "</span>", "Save proj</button>",
		"cd " + f.proj + " &amp;&amp; tego run proj</code>", "reads: on",
		`<input type="hidden" name="to" value="registry"><input type="hidden" name="reads" value="on">`,
	} {
		if code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("the preview from the run lacks %q (%d)", want, code)
		}
	}
	m := newBase.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no Create form:\n%s", body)
	}
	if _, err := os.Stat(file); err == nil {
		t.Fatal("a preview wrote the file")
	}

	w := post(f.s, "/rules/new", fromRunForm(f, rulesRunA, "proj", m[1], true), own, "", f.c)
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/rules/new?created=") {
		t.Fatalf("Create went to %q: %d %s", loc, w.Code, w.Body)
	}
	page := follow(t, f.s, f.c, w)
	for _, want := range []string{"proj · contract saved", "Saved proj: " + file, "cd " + f.proj + " &amp;&amp; tego run proj</code>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the saved page lacks %q", want)
		}
	}
	fi, err := os.Stat(file)
	saved, _ := os.ReadFile(file)
	if err != nil || fi.Mode().Perm() != 0o600 || !strings.Contains(string(saved), "reason:\n") || !strings.Contains(string(saved), "  reads: on\n") {
		t.Fatalf("the saved file: %v %v\n%s", err, fi, saved)
	}
	uid, _ := config.InvokingUID()
	e, err := registry.Places{Dir: f.proj, User: reg, UID: uid}.Resolve("proj")
	if err != nil || e.Path != file || e.Registry != registry.User {
		t.Fatalf("tego run proj from %s would not find it: %+v, %v", f.proj, e, err)
	}

	again := follow(t, f.s, f.c, post(f.s, "/rules/new", fromRunForm(f, rulesRunA, "proj", m[1], true), own, "", f.c))
	if !strings.Contains(again, html.EscapeString(`The agent name "proj" is already the contract `+file+`: give another name.`)) {
		t.Errorf("a second save of the name:\n%s", again)
	}
	if b, _ := os.ReadFile(file); string(b) != string(saved) {
		t.Error("the saved file was written over")
	}

	q := url.Values{"mode": {"run"}, "from": {rulesRunA}, "dir": {f.proj}, "name": {"quiet"}, "to": {"registry"}, "preview": {"1"}}
	_, off := f.get(t, "/rules/new?"+q.Encode())
	if strings.Contains(off, "reads: on") || strings.Contains(off, `value="on" aria-describedby="nw-reads-cost" checked`) || !strings.Contains(off, "Save quiet</button>") {
		t.Errorf("with the switch off the draft still records refused reads")
	}
}

// TestSaveFromARunRefusesWhatLearnSaveRefuses: a name that is no agent name, a name tego run would find ambiguous in
// the run's folder (a file of that name there), and a registry whose agents/ is a link out of it are each a problem
// on the preview, and a Create of them writes nothing.
func TestSaveFromARunRefusesWhatLearnSaveRefuses(t *testing.T) {
	f := newRulesFix(t)
	reg := f.withRegistry(t)
	preview := func(name string) string {
		q := url.Values{"mode": {"run"}, "from": {rulesRunA}, "dir": {f.proj}, "name": {name}, "to": {"registry"}, "reads": {"on"}, "preview": {"1"}}
		_, body := f.get(t, "/rules/new?"+q.Encode())
		return body
	}
	if b := preview("../evil"); !strings.Contains(b, "is not an agent id") || strings.Contains(b, `name="base"`) {
		t.Errorf("a path as the name is not refused")
	}
	if err := os.WriteFile(filepath.Join(f.proj, "tool"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b := preview("tool"); !strings.Contains(b, html.EscapeString(`The agent name "tool" is taken in `+f.proj)) || strings.Contains(b, `name="base"`) {
		t.Errorf("a name that is also a file in the run's folder is not refused")
	}
	if err := os.MkdirAll(reg, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(reg, "agents")); err != nil {
		t.Fatal(err)
	}
	if b := preview("bot"); !strings.Contains(b, "The registry cannot say whether the agent name") || strings.Contains(b, `name="base"`) {
		t.Errorf("an agents/ link out of the registry is not refused")
	}
	// Create straight from a form (no preview) is checked again and writes nothing.
	for _, name := range []string{"../evil", "tool", "bot", ".hidden"} {
		w := post(f.s, "/rules/new", fromRunForm(f, rulesRunA, name, strings.Repeat("0", 64), true), own, "", f.c)
		if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/rules/new?") || strings.Contains(loc, "created=") {
			t.Errorf("%q: Create went to %q", name, loc)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("written through the link: %v", ents)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.proj), "evil.yaml")); err == nil {
		t.Error("a name from the form reached the file system")
	}
}

// TestSaveFromARunTakesOnlyTheDashboardsOwnPost: the save is a state change, so it passes postAllowed like New
// policy's Create: a POST without the form's token, one from another origin, one whose browser says it is
// cross-site, and one with neither Origin nor Referer are refused 403, and none writes the registry entry.
func TestSaveFromARunTakesOnlyTheDashboardsOwnPost(t *testing.T) {
	f := newRulesFix(t)
	reg := f.withRegistry(t)
	_, body := f.get(t, "/rules/new?mode=run&from="+rulesRunA)
	m := newBase.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no Create form")
	}
	form := fromRunForm(f, rulesRunA, "proj", m[1], true)
	noToken := url.Values{}
	for k, v := range form {
		if k != "csrf" {
			noToken[k] = v
		}
	}
	if w := post(f.s, "/rules/new", noToken, own, "", f.c); w.Code != http.StatusForbidden {
		t.Errorf("no token: %d", w.Code)
	}
	if w := post(f.s, "/rules/new", form, "http://evil.example", "", f.c); w.Code != http.StatusForbidden {
		t.Errorf("another origin: %d", w.Code)
	}
	if w := post(f.s, "/rules/new", form, "", "", f.c); w.Code != http.StatusForbidden {
		t.Errorf("no Origin, no Referer: %d", w.Code)
	}
	r := httptest.NewRequest("POST", "/rules/new", strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:8484"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", own)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(f.c)
	cross := httptest.NewRecorder()
	f.s.ServeHTTP(cross, r)
	if cross.Code != http.StatusForbidden {
		t.Errorf("Sec-Fetch-Site cross-site: %d", cross.Code)
	}
	if _, err := os.Lstat(filepath.Join(reg, "agents", "proj.yaml")); err == nil {
		t.Fatal("a refused post wrote the registry entry")
	}
	if w := post(f.s, "/rules/new", form, own, "", f.c); !strings.Contains(w.Header().Get("Location"), "created=") {
		t.Fatalf("the dashboard's own post: %d %q", w.Code, w.Header().Get("Location"))
	}
	if _, err := os.Stat(filepath.Join(reg, "agents", "proj.yaml")); err != nil {
		t.Fatalf("the dashboard's own post wrote nothing: %v", err)
	}
}

// TestADraftFromARunSaysBesideEachAddressToWriteTheName (docs/DASHBOARD.md, From a run): each network entry of a draft
// from a run that is an address carries the note that Tego saw an address, not a name; an entry the run's record named by
// its host name, in the same draft, does not.
func TestADraftFromARunSaysBesideEachAddressToWriteTheName(t *testing.T) {
	f := newRulesFix(t)
	f.withRegistry(t)
	f.run(t, "r-aaaaaaaa-0000000000040-netrun", filepath.Join(f.proj, "net.yaml"), "version: 0\nname: net-agent\ncommand: [sh]\n",
		time.Now().Add(-30*time.Minute).UTC().Truncate(time.Millisecond), false,
		`"kind":"net","source":"supervisor","rule":"unmatched","verdict":"allow","authority":"observe","dst":"104.20.23.154:443","proto":"tcp"`,
		`"kind":"net","source":"supervisor","rule":"net[tcp://svc.example.net:443]","verdict":"allow","authority":"rule","dst":"93.184.216.34:443","proto":"tcp","host":"svc.example.net"`,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	q := url.Values{"mode": {"run"}, "from": {"r-aaaaaaaa-0000000000040-netrun"}, "dir": {f.proj}, "name": {"net"}, "to": {"registry"}, "preview": {"1"}}
	_, body := f.get(t, "/rules/new?"+q.Encode())
	var address, named []string
	for _, li := range regexp.MustCompile(`(?s)<li>.*?</li>`).FindAllString(body, -1) {
		switch {
		case strings.Contains(li, "104.20.23.154"):
			address = append(address, li)
		case strings.Contains(li, "svc.example.net"):
			named = append(named, li)
		}
	}
	if len(address) != 1 || len(named) != 1 {
		t.Fatalf("the draft's rules: %d rows name the address and %d the host name, want one each:\n%s", len(address), len(named), body)
	}
	if !strings.Contains(address[0], rules.AddressNote) {
		t.Errorf("the address's row has no note: %s", address[0])
	}
	if strings.Contains(named[0], rules.AddressNote) {
		t.Errorf("the host name's row carries the address note: %s", named[0])
	}
	if n := strings.Count(body, rules.AddressNote); n != 1 {
		t.Errorf("the address note shows %d times, want once beside the one address", n)
	}
}

// TestAFailedSaveSaysNotSavedOnce: a registry save the file system refuses (agents/ that cannot be written) goes back
// to the preview with one line that leads "Not saved" (the button said Save), names what failed and where, and stacks
// no other lead (Not created, refused, a second Not saved). Nothing is written.
func TestAFailedSaveSaysNotSavedOnce(t *testing.T) {
	f := newRulesFix(t)
	reg := f.withRegistry(t)
	agents := filepath.Join(reg, "agents")
	if err := os.MkdirAll(agents, 0o700); err != nil {
		t.Fatal(err)
	}
	cause := unwritableFolder(t, agents)
	_, body := f.get(t, "/rules/new?mode=run&from="+rulesRunA)
	m := newBase.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no Save form:\n%s", body)
	}
	page := follow(t, f.s, f.c, post(f.s, "/rules/new", fromRunForm(f, rulesRunA, "proj", m[1], true), own, "", f.c))
	file := filepath.Join(agents, "proj.yaml")
	if want := html.EscapeString("Not saved: Tego could not create " + file + ": "); !strings.Contains(page, want) || !strings.Contains(page, cause) {
		t.Errorf("the page lacks %q and the cause %q:\n%s", want, cause, page)
	}
	for _, stacked := range []string{"Not created", "refused: ", "Not saved: Not saved"} {
		if strings.Contains(page, stacked) {
			t.Errorf("the line stacks %q", stacked)
		}
	}
	if ents, _ := os.ReadDir(agents); len(ents) != 0 {
		t.Errorf("a refused save wrote %v", ents)
	}
}

// fsImmutableFL is FS_IMMUTABLE_FL of linux/fs.h, the inode flag chattr +i sets; golang.org/x/sys/unix names the
// ioctls that read and set it (FS_IOC_GETFLAGS, FS_IOC_SETFLAGS) but not the flag.
const fsImmutableFL = 0x00000010

// unwritableFolder makes dir refuse a new file to this process, and returns the cause the file system gives, as its
// errno's text. As a user the folder's mode refuses it (0500: permission denied). Root writes past a mode
// (CAP_DAC_OVERRIDE; acceptance 2C, 2026-11-11, where the test skipped as root), so as root the folder is made
// immutable instead (FS_IMMUTABLE_FL, which root's CAP_LINUX_IMMUTABLE sets and no capability writes past: operation
// not permitted). A file system that does not keep the flag skips the test. The cause is read from a create this
// function tries first, so it is what this machine says.
func unwritableFolder(t *testing.T, dir string) string {
	t.Helper()
	if os.Geteuid() != 0 {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	} else {
		setFlags := func(set bool) error {
			fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(fd) }()
			flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
			if err != nil {
				return err
			}
			if set {
				flags |= fsImmutableFL
			} else {
				flags &^= fsImmutableFL
			}
			return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(flags))
		}
		if err := setFlags(true); err != nil {
			t.Skipf("root writes past a folder's mode, and this file system does not keep the immutable flag: %v", err)
		}
		t.Cleanup(func() {
			if err := setFlags(false); err != nil {
				t.Errorf("clear the immutable flag of %s: %v", dir, err)
			}
		})
	}
	probe := filepath.Join(dir, ".unwritable-probe")
	fh, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		_ = fh.Close()
		_ = os.Remove(probe)
		t.Fatalf("%s still takes a new file", dir)
	}
	var errno unix.Errno
	if !errors.As(err, &errno) {
		t.Fatalf("the probe create failed without an errno: %v", err)
	}
	return errno.Error()
}

// TestPresetsDraftTakesTheRefusedReadsSwitch (docs/DASHBOARD.md, From a run): New contract from presets offers "Show refused reads
// (slower)" too, off by default as tego init writes no reason: block. Ticked, the draft has reason: {reads: on} and
// Create writes it; the Create form carries the switch back; unticked, there is no reason: block. The switch's
// accessible name is its label alone and its cost the description, so a screen reader says each once.
func TestPresetsDraftTakesTheRefusedReadsSwitch(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	dir := filepath.Join(filepath.Dir(f.proj), "reads-proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, fresh := f.get(t, "/rules/new")
	if !strings.Contains(fresh, `aria-labelledby="nw-reads-name" name="reads" value="on" aria-describedby="nw-reads-cost">`) ||
		!strings.Contains(fresh, `<strong id="nw-reads-name">Show refused reads (slower)</strong>`) {
		t.Fatalf("a fresh presets form has no switch, or it is on:\n%s", fresh)
	}
	q := url.Values{"dir": {dir}, "preset": {"no-secrets"}, "cmd": {"sh"}, "preview": {"1"}}
	_, off := f.get(t, "/rules/new?"+q.Encode())
	if strings.Contains(off, "reads: on") || strings.Contains(off, `<input type="hidden" name="reads"`) {
		t.Error("with the switch off the presets draft records refused reads")
	}
	q.Set("reads", "on")
	_, on := f.get(t, "/rules/new?"+q.Encode())
	for _, want := range []string{"reason:\n  # A read this contract refuses is recorded at tier landlock too, under every record level (" + agent.ReasonReadCost + ").\n  reads: on\n",
		`<input type="hidden" name="askread" value=""><input type="hidden" name="reads" value="on">`, `value="on" aria-describedby="nw-reads-cost" checked>`} {
		if !strings.Contains(on, html.EscapeString(want)) && !strings.Contains(on, want) {
			t.Errorf("the presets draft with the switch on lacks %q", want)
		}
	}
	m := newBase.FindStringSubmatch(on)
	if m == nil {
		t.Fatalf("no Create form:\n%s", on)
	}
	form := url.Values{"csrf": {f.s.csrf}, "dir": {dir}, "name": {"reads-proj"}, "preset": {"no-secrets"}, "cmd": {"sh"}, "mode": {"presets"},
		"reads": {"on"}, "base": {m[1]}}
	if loc := post(f.s, "/rules/new", form, own, "", f.c).Header().Get("Location"); !strings.HasPrefix(loc, "/rules/new?created=") {
		t.Fatalf("Create went to %q", loc)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "agent.yaml")); err != nil || !strings.Contains(string(b), "\nreason:\n") || !strings.Contains(string(b), "  reads: on\n") {
		t.Errorf("the written file: %v\n%s", err, b)
	}
}
