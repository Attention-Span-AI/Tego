// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/registry"
	rtcgroup "github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The guidance lines (docs/OPERATIONS.md, after `tego learn`; ADR 0142's slice 1): after its own output, a command a newcomer follows says the
// one step that comes next, on stderr and last, in one format:
//
//	(an empty line)
//	next: <one plain sentence>
//	  <one command, verbatim>
//
// A block always starts with a line that begins "next: ", and its command, when it has one, is the line after it,
// indented two spaces; the sentence never wraps, so that holds. A part Tego cannot know is written in angle brackets.
// The other guidance lines (doctor's Ready or Not ready line, watch's stop: line) follow the same rule as the block:
// on when stderr is a terminal, TEGO_HINTS=on turns them on where it is not and TEGO_HINTS=off off everywhere, and
// never inside a governed run. A command leaves them out with --json, --no-summary, --follow and on its usage and
// own errors (exit 2 and 125), whose line already names the fix: each command prints them only on the paths that
// reach its end. One exit 125 has its block: tego run, watch and test refused only because this shell is outside the
// user manager's cgroup (outsideHint), whose error line names no command that opens a shell inside it. One exception: watch's stop: line is part of its notice and is said with it, before the run's own
// checks, which can still refuse the run. A fact is not guidance: the reads line after a run (readsLine) prints
// whatever TEGO_HINTS says. No stdout line changes: every guidance line is on stderr, after the lines that were there
// before.

// hintsEnv is the variable that turns the guidance lines on or off. There is no config key for it: an older tego
// refuses a machine config with a key it does not know.
const hintsEnv = "TEGO_HINTS"

// stderrTerminal reports whether w, a command's stderr, is a terminal. Tests replace it.
var stderrTerminal = func(w io.Writer) bool {
	if o, ok := w.(*outputWriter); ok {
		w = o.dst
	}
	f, ok := w.(*os.File)
	return ok && isTerminalFile(f)
}

// isTerminalFile reports whether f is a terminal, under the File's own lease (ADR 0023). It lives here, beside its
// first public caller, because vault.go, its other caller, stays private (tools/oss/manifest.txt).
func isTerminalFile(f *os.File) bool {
	term := false
	_ = sys.FileDo(f, func(fd int) error { _, err := unix.IoctlGetTermios(fd, unix.TCGETS); term = err == nil; return nil }) // TCGETS answers only a terminal
	return term
}

// hintsOn reports whether the guidance lines go to stderr: TEGO_HINTS=off never, TEGO_HINTS=on or a terminal yes,
// and never from inside a governed run, whose agent reads them as its own output (selfInRun fails closed).
func hintsOn(stderr io.Writer) bool {
	switch os.Getenv(hintsEnv) {
	case "off":
		return false
	case "on":
	default:
		if !stderrTerminal(stderr) {
			return false
		}
	}
	in, _ := selfInRun()
	return !in
}

// hintBlock is the "next:" block of text and command ("" for none).
func hintBlock(text, command string) string {
	s := "\nnext: " + text + "\n"
	if command != "" {
		s += "  " + command + "\n"
	}
	return s
}

// writeHint writes the "next:" block when the guidance lines are on.
func writeHint(stderr io.Writer, text, command string) {
	if hintsOn(stderr) {
		_, _ = io.WriteString(stderr, hintBlock(text, command)) // guidance never changes an exit
	}
}

// writeGuide writes one guidance line (text ends with its newline) when the guidance lines are on.
func writeGuide(stderr io.Writer, text string) {
	if hintsOn(stderr) {
		_, _ = io.WriteString(stderr, text)
	}
}

// scopeOpener is guide.OpenScope: the command that opens a shell in the user manager's cgroup from this one, or why
// none does, and the user it opens it as when the person who reads it is another. A variable so a test describes a
// shell without reading this one's environment.
var scopeOpener = guide.OpenScope

// outsideHint is the next: block of a command that found no tier here, or could not start a run, only because this
// shell is outside the user manager's cgroup (doctor.Report.OutsideUserManager, cgroup.ErrBesideSubtree): open a
// shell inside it, then do there what then says ("run tego setup there", "run this again there"). Its command never
// starts a run, and is never the command that printed it. tego run, watch and test say it on exit 125 too: the one
// exception to exit 125's rule of no hint, since their error line names the cgroup but not the command that opens a
// shell in it, which acceptance B (2026-11-11) found a newcomer cannot guess. Where no command opens one from
// here (guide.OpenScope's reason), a guidance line says why and the block has no command. Where tego was started from
// another user's shell through sudo or su (guide.Opening.As), a guidance line says whose shell the command opens and
// that it is typed in the person's own shell, and the block says so too (acceptance 3, 2026-11-11).
func outsideHint(stderr io.Writer, then string) {
	o := scopeOpener()
	text := "open a shell in your user manager's cgroup, then " + then + ":"
	switch {
	case o.Command == "":
		writeGuide(stderr, "\nsystemd-run --user cannot open a shell in your user manager's cgroup here: "+
			record.Printable(o.Missing)+"; a terminal on your desktop is in it.\n")
		text = strings.TrimSuffix(text, ":") + "."
	case o.As != "":
		writeGuide(stderr, "\ntego ran as "+o.As+", started from another user's shell through sudo or su. Type the command "+
			"below in your own login shell, not in one sudo or su opened: it opens a shell as "+o.As+", in "+o.As+"'s user manager's cgroup, not in yours.\n")
		text = "from your own shell, open a shell as this user; " + strings.Replace(then, " there", " in it", 1) + ":"
	}
	writeHint(stderr, text, o.Command)
}

// besideUserManager reports whether a run started from this process would be refused only for its place: FS.CanPlace's
// cgroup.ErrBesideSubtree, the refusal tego run, watch and test exit 125 with from a shell beside the user manager's
// cgroup (an SSH or console login). It reads /proc/self/cgroup and the cgroup mount and makes nothing. Any other answer
// is false: a refusal for another cause is not cured by that shell, so the command a hint names then says itself why
// it cannot run. Root (sudo tego agents) asks it for the invoking user, who types the command without sudo
// (rootBeside). A variable so a test describes a place without being in it.
var besideUserManager = func() bool {
	uid, _ := config.InvokingUID()
	if config.InitNSRoot() {
		return rootBeside(uid, cgroupChain(os.Getpid()), isDir(rtcgroup.UserSubtree(uid)))
	}
	fs, err := rtcgroup.Detect(uid)
	return err == nil && errors.Is(fs.CanPlace(), rtcgroup.ErrBesideSubtree)
}

// rootBeside is besideUserManager for a root process: whether the command its hint names, typed without sudo by the
// invoking user uid in the shell sudo was typed in (typedIn), is outside that user's manager's cgroup. chain is the
// /proc/<pid>/cgroup of this process and its ancestors, nearest first (cgroupChain), and managed whether
// user@<uid>.service's cgroup exists. Root itself, a cgroup that cannot be read or told, and a user with no manager
// running are not beside: the command says itself why it cannot run there, and no shell opens one for it.
func rootBeside(uid int, chain [][]byte, managed bool) bool {
	if uid == 0 || !managed {
		return false
	}
	cg := typedIn(chain)
	return cg != nil && strings.Contains(string(cg), "0::") && !guide.InUserManager(cg, uid)
}

// typedIn is the cgroup of the shell sudo was typed in, from chain (rootBeside's): this process's own, since sudo
// moves no process into another cgroup, unless that is a session of root's own (/user.slice/user-0.slice/...). Where
// the caller has no logind session (a systemd-run --user scope, a desktop terminal), sudo's PAM stack (pam_systemd,
// included through system-auth on Fedora 44) opens one for root and moves sudo into it, so the process says nothing
// of the shell (acceptance 2B, 2026-11-11: session-c3.scope, from inside the scope, sent the person to open the scope
// they were in). Then it is the nearest ancestor's outside root's slice: the shell, or the sudo that shell started.
// nil when none can be read.
func typedIn(chain [][]byte) []byte {
	for _, cg := range chain {
		path, ok := unifiedLine(cg)
		if !ok {
			return nil
		}
		if !strings.HasPrefix(path, rootSlice) {
			return cg
		}
	}
	return nil
}

// rootSlice is the cgroup of root's own logind sessions: a session pam_systemd opens for sudo lies under it.
const rootSlice = "/user.slice/user-0.slice/"

// unifiedLine is the path of the unified "0::" line of a /proc/<pid>/cgroup file.
func unifiedLine(procCgroup []byte) (string, bool) {
	for _, line := range strings.Split(string(procCgroup), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return path, true
		}
	}
	return "", false
}

// maxAncestors bounds cgroupChain's walk: sudo, its monitor and the shell are three steps up.
const maxAncestors = 16

// cgroupChain is the /proc/<pid>/cgroup of pid and of its ancestors, nearest first, up to maxAncestors and pid 1; it
// stops at the first it cannot read. It only reads /proc.
func cgroupChain(pid int) [][]byte {
	var chain [][]byte
	for range maxAncestors {
		cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			break
		}
		chain = append(chain, cg)
		ppid, ok := parentOf(pid)
		if !ok || ppid <= 1 {
			break
		}
		pid = ppid
	}
	return chain
}

// parentOf is pid's parent from /proc/<pid>/stat: the fourth field, after the command name in parentheses, which may
// itself hold spaces and parentheses, so the fields are read after its last ')'.
func parentOf(pid int) (int, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(f[1])
	return ppid, err == nil
}

// isDir reports whether path is a directory.
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// runHint writes the next: block of text and command, a step whose command may start a run (guide.StartsRun). From a
// shell beside the user manager's cgroup (besideUserManager), where that command exits 125, a guidance line says the
// command and the block opens a shell inside the cgroup instead (outsideHint): tego learn --save named tego run there,
// which failed (acceptance B, 2026-11-11, and its review). Its command is never one that starts a run, and never
// the command that printed it. Root's block names guide.DefaultScope, which the person types as themselves: this
// process's environment is root's, not the shell's the person returns to.
func runHint(stderr io.Writer, text, command string) {
	if !guide.StartsRun(command) || !hintsOn(stderr) || !besideUserManager() {
		writeHint(stderr, text, command)
		return
	}
	writeGuide(stderr, "\ntego starts no run from this shell, which is outside your user manager's cgroup. In a shell inside it, "+
		text+" "+command+"\n")
	const then = "run that command there"
	if config.InitNSRoot() {
		writeHint(stderr, "open a shell in your user manager's cgroup, then "+then+":", guide.DefaultScope)
		return
	}
	outsideHint(stderr, then)
}

// shortRun is how a hint names run id: its last part, which every command takes for the run (resolveRunDir), when
// that names this run alone among the runs under root now; else the whole id.
func shortRun(root, id string) string {
	i := strings.LastIndexByte(id, '-')
	if root == "" || i < 0 || i == len(id)-1 {
		return record.Printable(id)
	}
	short := id[i+1:]
	if got, err := expandRunAbbrev(short, root); err == nil && got == id {
		return short
	}
	return record.Printable(id)
}

// namePlaceholder is what a hint writes for an agent name only the person can choose.
const namePlaceholder = "<name>"

// nameFromFolder is the agent name a hint could propose for a run that worked in dir: the folder's base name when
// learn --save takes it (saveableName), else namePlaceholder, which the person fills in.
func nameFromFolder(dir string) string {
	if dir != "" {
		if base := filepath.Base(dir); base != "/" && saveableName(base) {
			return base
		}
	}
	return namePlaceholder
}

// saveableName reports whether learn --save takes name: an agent name ([a-z0-9-]{1,40}) that does not start with
// "-", which tego run <name> would read as a flag.
func saveableName(name string) bool {
	return registry.IsName(name) && !strings.HasPrefix(name, "-")
}

// proposedName is the name a hint proposes to --save a run that worked in runDir under: nameFromFolder's, when the
// registries of m resolve it to nothing from the working directory, where the hint is typed, and from runDir, where
// learn's own hint then runs tego run <name> (saveDirs); else namePlaceholder. A name a registry holds already, or one tego run
// finds ambiguous there (a file of that name in the folder, such as the binary go build makes in it), would make one
// of the next commands fail as written. m nil, or a lookup that cannot be made, gives namePlaceholder too.
func proposedName(m *config.Machine, runDir string) string {
	name := nameFromFolder(runDir)
	if name == namePlaceholder || m == nil {
		return namePlaceholder
	}
	places, perr := registryPlaces(m)
	if perr != nil {
		return namePlaceholder
	}
	for _, dir := range saveDirs(places.Dir, runDir) {
		places.Dir = dir
		if _, err := places.Resolve(name); !nameNotFound(err) {
			return namePlaceholder
		}
	}
	return name
}

// folderHere reports whether dir, a run's recorded working directory, is a directory on this machine: "" and a folder
// of a record made elsewhere are not, and a hint never sends the person there.
func folderHere(dir string) bool {
	if dir == "" {
		return false
	}
	fi, err := os.Stat(dir)
	return err == nil && fi.IsDir()
}

// nameNotFound reports whether err is a registry's answer that it holds no agent of the name.
func nameNotFound(err error) bool {
	var re *registry.Error
	return errors.As(err, &re) && re.Code == registry.CodeNotFound
}

// startPlaceholder is what a hint writes for a command only the person knows.
const startPlaceholder = "<the command you start it with>"
