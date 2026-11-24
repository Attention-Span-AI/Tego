// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// installerPathLine and installerFishLine are the lines scripts/install.sh adds to a shell's start-up file on a Mac
// (and that an older Linux install may have added): the exact text, so only those lines are ever removed.
const (
	installerPathLine = `export PATH="$HOME/.local/bin:$PATH" # added by the Tego installer`
	installerFishLine = `fish_add_path "$HOME/.local/bin" # added by the Tego installer`
)

var (
	agentUnit   = regexp.MustCompile(`^tego-agent@[A-Za-z0-9_.:\\-]+\.service$`)
	restartUnit = regexp.MustCompile(`^tego-agent-restart@[A-Za-z0-9_.:\\-]+\.(timer|service)$`)
)

// exampleUnits are the unit files Tego's examples/systemd folder ships, and the Description line each begins with: a
// copy a person made in ~/.config/systemd/user is theirs, and is removed (with their say-so) only while it still reads
// as Tego's.
var exampleUnits = map[string]string{
	"tego-agent@.service":         "Description=Tego agent ",
	"tego-agent-restart@.service": "Description=Planned restart of Tego agent ",
	"tego-agent-restart@.timer":   "Description=Daily planned restart of Tego agent ",
	unitGCService:                 "Description=Tego retention pass",
	unitGCTimer:                   "Description=Daily Tego retention pass",
}

// guideDropIns are the drop-in files Tego's own guide (docs/user/run-as-a-service.md) tells the person to create beside
// a copied example unit, and the exact text it tells them to put in each: <unit>.d/<file>. Only these, byte for byte,
// are removed; any other file in such a folder is the person's.
var guideDropIns = map[string]map[string]string{
	"tego-agent@.service": {"10-delegate.conf": "[Service]\nDelegate=yes\n"},
}

// scanUninstall looks at what is here and says what removing it would do. It changes nothing.
func scanUninstall(ctx context.Context, e *uninstallEnv) *uninstallPlan {
	p := &uninstallPlan{}
	e.scanUnits(ctx, p)
	e.scanShellLines(p)
	e.scanState(p)
	e.scanRecords(ctx, p)
	e.scanPrograms(p)
	e.scanSystem(p)
	return p
}

func (e *uninstallEnv) tilde(path string) string { return tildeHome(path, e.home) }

// ---- user units ------------------------------------------------------------------------------------------------

// unitNames is every unit whose name starts tego- that the user manager knows, loaded or only on disk.
func (e *uninstallEnv) unitNames(ctx context.Context) (map[string]bool, error) {
	if e.systemctl == nil {
		return nil, errors.New("systemctl is not available")
	}
	names := map[string]bool{}
	var firstErr error
	got := false
	for _, argv := range [][]string{
		{"list-units", "--all", "--plain", "--no-legend", "--no-pager", "tego-*"},
		{"list-unit-files", "--plain", "--no-legend", "--no-pager", "tego-*"},
	} {
		out, err := e.systemctl(ctx, argv...)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		got = true
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			for len(f) > 0 && (f[0] == "●" || f[0] == "*" || f[0] == "×" || f[0] == "○") {
				f = f[1:]
			}
			if len(f) > 0 {
				names[f[0]] = true
			}
		}
	}
	if !got {
		return nil, firstErr
	}
	return names, nil
}

func (e *uninstallEnv) userUnitFile(name string) string {
	return filepath.Join(e.home, ".config", "systemd", "user", name)
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// isTemplateUnit reports whether name is a template (tego-agent@.service): it names no instance, so it cannot run.
func isTemplateUnit(name string) bool {
	i := strings.IndexByte(name, '@')
	return i >= 0 && strings.HasPrefix(name[i+1:], ".")
}

// stopUnit stops name and clears a failed state; a unit that is already gone is not an error. It never stops a
// template: no caller asks it to, and systemd would refuse.
func (e *uninstallEnv) stopUnit(ctx context.Context, name string, disable bool) error {
	if isTemplateUnit(name) {
		return fmt.Errorf("%s is a template, not a running unit", name)
	}
	gone := func(out string, err error) bool {
		t := strings.ToLower(out)
		return err == nil || strings.Contains(t, "not loaded") || strings.Contains(t, "not found") || strings.Contains(t, "does not exist")
	}
	if out, err := e.systemctl(ctx, "stop", name); !gone(out, err) {
		return fmt.Errorf("systemctl --user stop %s: %v: %s", name, err, strings.TrimSpace(out))
	}
	if disable {
		if out, err := e.systemctl(ctx, "disable", name); !gone(out, err) && !strings.Contains(strings.ToLower(out), "no installation config") {
			return fmt.Errorf("systemctl --user disable %s: %v: %s", name, err, strings.TrimSpace(out))
		}
	}
	_, _ = e.systemctl(ctx, "reset-failed", name)
	return nil
}

func (e *uninstallEnv) scanUnits(ctx context.Context, p *uninstallPlan) {
	names, err := e.unitNames(ctx)
	if err != nil {
		p.notes = append(p.notes, "Could not ask your user service manager ("+oneLine(err.Error())+"), so units were not checked. If Tego's dashboard is running: systemctl --user stop tego-dashboard")
		return
	}
	// What Tego itself started: the dashboard, and the retention timer (transient, so it leaves with a stop).
	for _, u := range []struct{ name, what string }{
		{unitGCTimer, "stop Tego's daily clean-up timer (tego-gc.timer)"},
		{unitGCService, "stop Tego's clean-up job (tego-gc.service)"},
		{unitDashboard, "stop the dashboard (tego-dashboard)"},
	} {
		if !names[u.name] || fileExists(e.userUnitFile(u.name)) {
			continue // a copy the person put in ~/.config/systemd/user is theirs: below
		}
		name := u.name
		p.appendStep(groupTego, u.what, func(ctx context.Context) error { return e.stopUnit(ctx, name, false) })
	}
	// What the person set up: agent services, their planned restarts, and the example unit files they copied.
	var timers, instances []string
	for n := range names {
		switch {
		case restartUnit.MatchString(n):
			timers = append(timers, n)
		case agentUnit.MatchString(n):
			instances = append(instances, n)
		}
	}
	sort.Strings(timers)
	sort.Strings(instances)
	reload := false
	for _, n := range append(timers, instances...) {
		name := n
		what := "stop and remove " + strings.TrimSuffix(name, ".service") + " (an agent service of yours)"
		if strings.HasPrefix(name, "tego-agent-restart@") {
			what = "stop and remove " + name + " (the planned restart of one of your agent services)"
		}
		p.appendStep(groupServices, what, func(ctx context.Context) error { return e.stopUnit(ctx, name, true) })
	}
	var files []string
	for n := range exampleUnits {
		files = append(files, n)
	}
	sort.Strings(files)
	for _, n := range files {
		path := e.userUnitFile(n)
		if !e.copyOfExample(n, path) {
			continue
		}
		name := n
		// A copy of a template is a file: the instances of it that run are stopped above, each by its full name, and
		// the template itself is never stopped (systemd refuses a name with no instance).
		if names[name] && !isTemplateUnit(name) {
			p.appendStep(groupServices, "stop and remove "+name+" (your copy of Tego's example unit)", func(ctx context.Context) error {
				return e.stopUnit(ctx, name, true)
			})
		}
		p.appendStep(groupServices, "remove "+e.tilde(path)+" (your copy of Tego's example unit)", func(context.Context) error {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		})
		reload = true
	}
	for _, n := range files {
		if e.scanDropInDir(p, n) {
			reload = true
		}
	}
	if reload || len(instances) > 0 || len(timers) > 0 {
		p.appendStep(groupServices, "reload your user service manager", func(ctx context.Context) error {
			_, err := e.systemctl(ctx, "daemon-reload")
			return err
		})
	}
}

// scanDropInDir plans the removal of the drop-in folder <unit>.d that the guide has the person make beside a copy of an
// example unit: the files the guide names (with the text it gives), then the folder if that leaves it empty. Anything
// else in the folder is left, and named. It reports whether it planned a removal.
func (e *uninstallEnv) scanDropInDir(p *uninstallPlan, unit string) bool {
	dir := e.userUnitFile(unit + ".d")
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return false // absent, or a link or file the person put there: not ours to touch
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		p.notes = append(p.notes, "Could not read "+e.tilde(dir)+" ("+oneLine(err.Error())+"), so it was left.")
		return false
	}
	var ours []string
	var left []string
	for _, en := range entries {
		path := filepath.Join(dir, en.Name())
		want, named := guideDropIns[unit][en.Name()]
		if named && en.Type().IsRegular() {
			if b, err := os.ReadFile(path); err == nil && string(b) == want {
				ours = append(ours, path)
				continue
			}
		}
		left = append(left, e.tilde(path))
	}
	for _, l := range left {
		p.notes = append(p.notes, "Left "+l+": Tego's guide did not tell you to create it, so it is yours.")
	}
	if len(ours) == 0 {
		return false
	}
	what := "remove " + e.tilde(dir) + " (the drop-in folder from Tego's service guide)"
	if len(left) > 0 {
		what = "remove " + strings.Join(tildes(e, ours), ", ") + " (the drop-in from Tego's service guide; the folder stays, it holds other files)"
	}
	p.appendStep(groupServices, what, func(context.Context) error {
		for _, f := range ours {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		// os.Remove refuses a folder that still holds anything: that is the check that it is empty.
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) && !fileExistsNonEmpty(dir) {
			return err
		}
		return nil
	})
	return true
}

func tildes(e *uninstallEnv, paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = e.tilde(p)
	}
	return out
}

// fileExistsNonEmpty reports whether dir is a folder that still holds something (left behind on purpose).
func fileExistsNonEmpty(dir string) bool {
	en, err := os.ReadDir(dir)
	return err == nil && len(en) > 0
}

// copyOfExample reports whether path is a regular file that still begins as the example unit name does.
func (e *uninstallEnv) copyOfExample(name, path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, exampleUnits[name]) {
			return true
		}
	}
	return false
}

// ---- shell start-up lines ---------------------------------------------------------------------------------------

type shellLine struct {
	rel, line string
	pathLine  bool // the installer's PATH line: kept while ~/.local/bin holds anything else
	fish      bool // a file of Tego's own: removed when nothing else is in it
	why       string
}

func (e *uninstallEnv) scanShellLines(p *uninstallPlan) {
	targets := []shellLine{
		{rel: ".bashrc", line: bashrcLine, why: "the line `tego start` added to load your saved agent sign-ins"},
		{rel: ".zshrc", line: installerPathLine, pathLine: true},
		{rel: ".bash_profile", line: installerPathLine, pathLine: true},
		{rel: ".bash_login", line: installerPathLine, pathLine: true},
		{rel: ".profile", line: installerPathLine, pathLine: true},
		{rel: ".config/fish/conf.d/tego.fish", line: installerFishLine, pathLine: true, fish: true},
	}
	others := e.otherLocalBinEntries()
	for _, t := range targets {
		rcHome, rcRel, ok := e.resolveRC(t.rel)
		if !ok {
			continue
		}
		data, err := readGuideData(rcHome, rcRel, false)
		if err != nil || !hasLine(data, t.line) {
			continue
		}
		if t.pathLine && others > 0 {
			p.notes = append(p.notes, fmt.Sprintf("Left the PATH line in %s: ~/.local/bin still holds %d other file(s) that may need it.", e.tilde(filepath.Join(e.home, t.rel)), others))
			continue
		}
		what := "the line the installer added to " + e.tilde(filepath.Join(e.home, t.rel))
		if t.why != "" {
			what = t.why + " in " + e.tilde(filepath.Join(e.home, t.rel))
		}
		t := t
		p.appendStep(groupTego, "remove "+what+" (only that line; a backup is kept beside the file)", func(context.Context) error {
			return editShellFile(rcHome, rcRel, t.line, t.fish)
		})
	}
}

// resolveRC is the folder and name a start-up file really lives under, following a link the way saveLogin does.
func (e *uninstallEnv) resolveRC(rel string) (home, name string, ok bool) {
	full := filepath.Join(e.home, rel)
	if _, err := os.Lstat(full); err != nil {
		return "", "", false
	}
	target, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", "", false
	}
	if target == full {
		return e.home, rel, true
	}
	return filepath.Dir(target), filepath.Base(target), true
}

// otherLocalBinEntries counts what else is in ~/.local/bin besides Tego's two programs.
func (e *uninstallEnv) otherLocalBinEntries() int {
	ents, err := os.ReadDir(filepath.Join(e.home, ".local", "bin"))
	if err != nil {
		return 0
	}
	n := 0
	for _, d := range ents {
		if d.Name() != "tego" && d.Name() != "tego-control" && !strings.HasPrefix(d.Name(), ".tego") {
			n++
		}
	}
	return n
}

func hasLine(data []byte, line string) bool {
	for _, l := range strings.Split(string(data), "\n") {
		if l == line {
			return true
		}
	}
	return false
}

// editShellFile removes every line equal to line from the file, after a backup beside it. Every other byte stays. A file
// that is Tego's own (fish) and holds nothing else afterwards is removed.
func editShellFile(home, rel, line string, removeIfEmpty bool) error {
	data, err := readGuideData(home, rel, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !hasLine(data, line) {
		return nil
	}
	full := filepath.Join(home, rel)
	st, err := os.Stat(full)
	if err != nil {
		return err
	}
	mode := st.Mode().Perm()
	backup := rel + ".tego-backup"
	for i := 1; fileExists(filepath.Join(home, backup)); i++ {
		backup = fmt.Sprintf("%s.tego-backup-%d", rel, i)
	}
	bf, err := publishGuideFile(home, backup, data, mode)
	if err != nil {
		return fmt.Errorf("could not write the backup, so %s is unchanged: %w", full, err)
	}
	_ = bf.Close()
	var kept []string
	for _, l := range strings.Split(string(data), "\n") {
		if l != line {
			kept = append(kept, l)
		}
	}
	out := strings.Join(kept, "\n")
	if removeIfEmpty && strings.TrimSpace(out) == "" {
		return os.Remove(full)
	}
	return replaceGuideFile(home, rel, []byte(out), mode)
}

// ---- state, records, programs ---------------------------------------------------------------------------------

// stateFiles are the files Tego keeps under the home that are not the person's proof: the dashboard's log (it holds
// the sign-in link), the guide's installer log, the saved agent sign-ins and the last project.
var stateFiles = []struct{ rel, what string }{
	{".tego/dashboard.log", "the dashboard's log and sign-in link"},
	{".tego/setup-install.log", "the setup guide's installer log"},
	{".config/tego/agent.env", "your saved agent sign-ins"},
	{".config/tego/last-project", "the project `tego start` set up last"},
}

func (e *uninstallEnv) scanState(p *uninstallPlan) {
	for _, s := range stateFiles {
		path := filepath.Join(e.home, s.rel)
		if !fileExists(path) {
			continue
		}
		s := s
		p.appendStep(groupTego, "remove "+e.tilde(path)+" ("+s.what+")", func(context.Context) error {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			_ = os.Remove(filepath.Dir(path)) // only when it is now empty
			return nil
		})
	}
}

// remainder counts what dir holds besides the state files this command removes.
func (e *uninstallEnv) remainder(dir string) (entries []os.DirEntry, present bool) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fileExists(dir)
	}
	skip := map[string]bool{}
	for _, s := range stateFiles {
		if filepath.Join(e.home, filepath.Dir(s.rel)) == dir {
			skip[filepath.Base(s.rel)] = true
		}
	}
	for _, d := range ents {
		if !skip[d.Name()] {
			entries = append(entries, d)
		}
	}
	return entries, true
}

func (e *uninstallEnv) scanRecords(ctx context.Context, p *uninstallPlan) {
	records := filepath.Join(e.home, ".tego")
	contracts := filepath.Join(e.home, ".config", "tego")
	var dirs []string
	var kept []string
	if ents, present := e.remainder(records); present && (len(ents) > 0 || !isDir(records)) {
		dirs = append(dirs, records)
		// the runs `tego status` lists: run-shaped directories only, not the dot files the folder holds beside them
		ids, _ := runIDsNewestFirst(filepath.Join(records, "runs"))
		runs := len(ids)
		kept = append(kept, fmt.Sprintf("your records in %s (%d run%s, the chain and the logs)", e.tilde(records), runs, plural(runs)))
	}
	if ents, present := e.remainder(contracts); present && (len(ents) > 0 || !isDir(contracts)) {
		dirs = append(dirs, contracts)
		n := 0
		if r, err := os.ReadDir(filepath.Join(contracts, "agents")); err == nil {
			n = len(r)
		}
		kept = append(kept, fmt.Sprintf("your contracts in %s (%d agent contract%s)", e.tilde(contracts), n, plural(n)))
	}
	if len(dirs) == 0 {
		return
	}
	p.kept = append(p.kept, "Kept: "+strings.Join(kept, " and ")+".")
	for _, d := range dirs {
		d := d
		p.appendStep(groupRecords, "delete "+e.tilde(d)+" (cannot be undone)", func(ctx context.Context) error { return e.deleteRecordsDir(ctx, d) })
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// deleteRecordsDir removes one of the records' folders. It refuses while a run is going (its record is being
// written), when it cannot tell, and for a folder this user does not own.
func (e *uninstallEnv) deleteRecordsDir(ctx context.Context, dir string) error {
	if e.liveRuns == nil {
		return errors.New("could not check whether a session is running, so nothing was deleted")
	}
	n, err := e.liveRuns(ctx)
	if err != nil {
		return fmt.Errorf("could not check whether a session is running (%v), so nothing was deleted", err)
	}
	if n > 0 {
		return fmt.Errorf("%d session%s still running: stop it (tego session stop), then run tego uninstall again", n, plural(n))
	}
	st, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if uid, ok := ownerOf(st); ok && uid != e.euid {
		return errors.New("not owned by you")
	}
	if dir != filepath.Join(e.home, ".tego") && dir != filepath.Join(e.home, ".config", "tego") {
		return errors.New("not one of Tego's folders")
	}
	return os.RemoveAll(dir)
}

// scanPrograms finds the installed tego and the tego-control beside it, and removes them only when they are Tego's
// and the user's to remove.
func (e *uninstallEnv) scanPrograms(p *uninstallPlan) {
	if e.self == "" || filepath.Base(e.self) != "tego" {
		return
	}
	dir := filepath.Dir(e.self)
	if fileExists(filepath.Join(dir, "go.mod")) || fileExists(filepath.Join(dir, "..", "go.mod")) {
		p.notes = append(p.notes, "Left "+e.tilde(e.self)+": it sits in a source checkout (a go.mod is beside it), so it is a build, not an install.")
		return
	}
	var items []string // control first: the installer moves it first, and tego refuses a mismatched pair
	ctl := filepath.Join(dir, "tego-control")
	if st, err := os.Lstat(ctl); err == nil {
		switch {
		case !st.Mode().IsRegular():
			p.notes = append(p.notes, "Left "+e.tilde(ctl)+": it is not a plain file.")
		case !e.isPinnedControl(ctl):
			p.notes = append(p.notes, "Left "+e.tilde(ctl)+": it is not the tego-control this tego was built with.")
		default:
			items = append(items, ctl)
		}
	}
	items = append(items, e.self)
	writable := unix.Access(dir, unix.W_OK) == nil
	for _, it := range items {
		it := it
		st, err := os.Lstat(it)
		if err != nil {
			continue
		}
		if uid, ok := ownerOf(st); !writable || (ok && uid != e.euid) {
			p.sudo = append(p.sudo, "sudo rm "+shellQuote(it))
			continue
		}
		what := "remove " + e.tilde(it) + " (the program Tego's installer put there)"
		p.appendStep(groupTego, what, func(context.Context) error {
			if err := os.Remove(it); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		})
	}
}

// isPinnedControl reports whether path holds the tego-control this build pins by SHA-256.
func (e *uninstallEnv) isPinnedControl(path string) bool {
	if e.pin == nil {
		return false
	}
	pin, ok := e.pin()
	if !ok {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<30)); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == pin
}

// scanSystem names what a system-wide install leaves: files only root can remove. It touches none of them.
func (e *uninstallEnv) scanSystem(p *uninstallPlan) {
	var self os.FileInfo
	if e.self != "" {
		self, _ = os.Stat(e.self)
	}
	reload := false
	for _, pat := range e.systemPaths {
		matches, _ := filepath.Glob(pat)
		sort.Strings(matches)
		for _, m := range matches {
			if st, err := os.Stat(m); err == nil && self != nil && os.SameFile(st, self) {
				continue // the running program: scanPrograms names it
			}
			if strings.Contains(m, "/etc/systemd/system/") && (strings.HasSuffix(m, ".service") || strings.HasSuffix(m, ".timer")) {
				if !strings.Contains(filepath.Base(m), "@.") { // a template has no instance to stop; its instances are listed by name
					p.sudo = append(p.sudo, "sudo systemctl disable --now "+unitWord(filepath.Base(m)))
				}
				p.sudo = append(p.sudo, "sudo rm "+shellQuote(m))
				reload = true
				continue
			}
			if isDir(m) {
				p.sudo = append(p.sudo, "sudo rm -r "+shellQuote(m))
				continue
			}
			p.sudo = append(p.sudo, "sudo rm "+shellQuote(m))
		}
	}
	if reload {
		p.sudo = append(p.sudo, "sudo systemctl daemon-reload")
	}
}

// unitWord is a unit file's name as one shell word: as it is when systemd's own alphabet spells it (the glob's matches
// are named by whoever made the file, and the line is typed as printed), quoted otherwise.
func unitWord(name string) string {
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@._:-", r)) {
			return shellQuote(name)
		}
	}
	if name == "" || name[0] == '-' {
		return shellQuote(name)
	}
	return name
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ownerOf is the uid that owns the file info describes.
func ownerOf(st os.FileInfo) (int, bool) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok && s != nil {
		return int(s.Uid), true
	}
	return 0, false
}

// ---- the real environment ---------------------------------------------------------------------------------------

func newRealUninstallEnv(stdout, stderr io.Writer) (*uninstallEnv, error) {
	euid := os.Geteuid()
	home, err := config.PasswdHome(euid)
	if err != nil || !filepath.IsAbs(home) {
		home = os.Getenv("HOME")
		if !filepath.IsAbs(home) {
			return nil, errors.New("your home folder is not known")
		}
	}
	self, _ := os.Executable()
	if r, err := filepath.EvalSymlinks(self); err == nil {
		self = r
	}
	tty := guideInteractive(stdout)
	return &uninstallEnv{
		home: home, self: self, euid: euid,
		in: os.Stdin, out: stdout, errOut: stderr, interactive: tty, color: tty,
		systemctl: userSystemctl, pin: handoff.PinnedSum, liveRuns: realLiveRuns,
		systemPaths: []string{
			"/etc/tego", "/etc/systemd/system/tego*.service", "/etc/systemd/system/tego*.timer",
			"/usr/local/bin/tego", "/usr/local/bin/tego-control", "/usr/bin/tego", "/usr/bin/tego-control", "/opt/tego",
		},
	}, nil
}

// userSystemctl runs `systemctl --user args...` through the guide's reviewed process start (setup_guide.go).
func userSystemctl(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	c := proc.Command("systemctl", append([]string{"--user"}, args...)...)
	c.Stdout, c.Stderr = &out, &out
	err := runGuideCommand(ctx, c)
	return out.String(), err
}

// realLiveRuns counts the sessions still going, as tego session list reads them.
func realLiveRuns(ctx context.Context) (int, error) {
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		return 0, err
	}
	_, snaps, err := allSessions(ctx, m)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range snaps {
		if sessionRunning(s) {
			n++
		}
	}
	return n, nil
}
