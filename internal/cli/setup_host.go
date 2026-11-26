// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	pathpkg "path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// guideHost changes presentation only, never the capabilities doctor measures.
type guideHost string

const (
	hostLinux   guideHost = "linux"
	hostMac     guideHost = "mac"
	hostWindows guideHost = "windows"
)

// setupHost accepts the old Mac command too. An old engine ignores the new
// variable and uses its ordinary Linux wording.
func setupHost() guideHost {
	switch os.Getenv("TEGO_HOST_KIND") {
	case "mac":
		return hostMac
	case "windows":
		return hostWindows
	}
	if os.Getenv("TEGO_ON_MAC") == "1" {
		return hostMac
	}
	// WSL still supplies the distribution name when interop and Windows PATH
	// import are disabled. A shell opened with wsl.exe must use Windows wording
	// and the same dashboard refusal as the native command.
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return hostWindows
	}
	return hostLinux
}

func (h guideHost) returnTo() string {
	if h == hostWindows {
		return "Windows"
	}
	return "your Mac"
}

// windowsLinuxPath accepts File Explorer's own spelling for an existing project.
func windowsLinuxPath(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	for _, prefix := range []string{`\\wsl$\tego\`, `\\wsl.localhost\tego\`} {
		if strings.HasPrefix(strings.ToLower(s), prefix) {
			return "/" + strings.ReplaceAll(s[len(prefix):], `\`, "/")
		}
	}
	return s
}

func windowsProjectPath(s string) bool {
	if strings.HasPrefix(s, "//") {
		if _, err := os.Stat(s); err == nil {
			return false
		}
		return true
	}
	drive := len(s) >= 2 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':'
	return strings.HasPrefix(s, `\\`) || drive && (len(s) == 2 || s[2] == '\\' || s[2] == '/')
}

// windowsCopyFolder is Tego's Linux home folder as File Explorer names it: where a person copies a file or a project
// to, so that Tego's Linux sees it (the guide's project question says the same).
const windowsCopyFolder = `\\wsl$\tego\home\tego`

// windowsForm is how a path argument names a place that only Windows sees.
type windowsForm int

const (
	notWindows   windowsForm = iota
	windowsDrive             // C:\work\x, C:/work/x or C:
	windowsOwn               // \\wsl$\tego\... or \\wsl.localhost\tego\...: Tego's Linux, as Windows names it
	windowsShare             // any other \\server\share path, another Linux's \\wsl$\Ubuntu\... included
	windowsMount             // /mnt/c/...: where a Linux with the drives mounted would see one
)

// mountPresent says whether path is a mount point here: a folder on another device than its parent. A /mnt/c that is
// only an empty folder (Tego's distribution has one, with automount off) is no drive. The stat is given two seconds (a
// dead drive in another WSL distribution can hang it for much longer), and a stat that has not answered counts as a
// mount: nothing is then said about its absence. A variable so a test names either answer.
var mountPresent = func(path string) bool {
	answer := make(chan bool, 1)
	go func() {
		var a, b unix.Stat_t
		if unix.Stat(path, &a) != nil {
			answer <- false
			return
		}
		if unix.Stat(pathpkg.Dir(path), &b) != nil {
			answer <- true
			return
		}
		answer <- a.Dev != b.Dev
	}()
	select {
	case present := <-answer:
		return present
	case <-time.After(2 * time.Second):
		return true
	}
}

// classifyWindowsPath says which Windows form arg is and, for Tego's Linux seen from Windows, the path Tego's Linux
// reads it as. The forms are those the guide's project question refuses (windowsProjectPath) and /mnt/<letter>/...,
// which only counts when no such mount exists here (automount is off in Tego's distribution).
func classifyWindowsPath(arg string) (windowsForm, string) {
	arg = strings.TrimSpace(arg)
	if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		arg = arg[1 : len(arg)-1]
	}
	slashed := strings.ReplaceAll(arg, `\`, "/")
	if strings.HasPrefix(slashed, "//") {
		parts := strings.SplitN(slashed[2:], "/", 3)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			host := strings.ToLower(parts[0])
			if (host == "wsl$" || host == "wsl.localhost") && strings.EqualFold(parts[1], "tego") {
				rest := ""
				if len(parts) == 3 {
					rest = parts[2]
				}
				return windowsOwn, pathpkg.Clean("/" + rest)
			}
		}
		return windowsShare, ""
	}
	if len(arg) >= 2 && (arg[0] >= 'A' && arg[0] <= 'Z' || arg[0] >= 'a' && arg[0] <= 'z') && arg[1] == ':' &&
		(len(arg) == 2 || arg[2] == '\\' || arg[2] == '/') {
		return windowsDrive, ""
	}
	if len(arg) >= 6 && strings.HasPrefix(arg, "/mnt/") && (arg[5] >= 'A' && arg[5] <= 'Z' || arg[5] >= 'a' && arg[5] <= 'z') &&
		(len(arg) == 6 || arg[6] == '/') && !mountPresent(arg[:6]) {
		return windowsMount, ""
	}
	return notWindows, ""
}

// ownDistribution reports whether this process runs in Tego's own Windows-managed distribution, the one the
// installer provisions and the Windows command enters: the guest entry sets TEGO_HOST_KIND=windows only for the
// commands that command runs, and the distribution is named tego. Neither is a proof (the words are all they decide: a
// caller who sets them gets the words of Tego's distribution); another WSL distribution (setupHost says hostWindows
// for it too, for the guide's wording) has neither and keeps its own drives.
func ownDistribution() bool {
	return os.Getenv("TEGO_HOST_KIND") == "windows" || os.Getenv("WSL_DISTRO_NAME") == "tego"
}

// windowsPathWords is what is true about a file or folder that arg names, for the refusal of a command that takes a
// rules file or a project folder: "" unless this is a WSL distribution (setupHost) and arg is a Windows form
// (classifyWindowsPath).
//
// In Tego's own distribution no Windows drive is mounted by design, so a file there has to be copied in: the same
// instruction the guide's project question gives, with Tego's distribution and home named. In another WSL distribution
// (Tego installed in an Ubuntu) neither name is true: the words say only that a Windows path is not a Linux path
// there, and where the file is if the drive is mounted (/mnt/c/...); a form with nothing true to add adds nothing.
func windowsPathWords(arg string, folder bool) string {
	if setupHost() != hostWindows {
		return ""
	}
	form, linux := classifyWindowsPath(arg)
	if !ownDistribution() {
		switch form {
		case windowsDrive:
			a := strings.Trim(strings.TrimSpace(arg), `"`)
			mount := "/mnt/" + strings.ToLower(a[:1])
			rest := strings.TrimLeft(strings.ReplaceAll(a[2:], `\`, "/"), "/")
			if mountPresent(mount) {
				return "that is a Windows path, not a Linux path; with the drive mounted here the file is at " + pathpkg.Join(mount, rest)
			}
			return "that is a Windows path, not a Linux path, and " + mount + " is not mounted here"
		case windowsMount:
			return "that drive is not mounted in this Linux (" + arg[:6] + " is no mount point)"
		case notWindows, windowsOwn, windowsShare:
		}
		return ""
	}
	switch form {
	case windowsOwn:
		return "that is Tego's Linux as Windows names it; type its Linux path here: " + linux
	case windowsDrive, windowsMount, windowsShare:
		what := "file"
		if folder {
			what = "folder"
		}
		return "Tego's Linux, inside Windows, does not see your Windows drives or network folders. In File Explorer, paste " +
			windowsCopyFolder + " in the address bar and copy the " + what + " there, then type its Linux path here, for example " +
			"/home/tego/" + windowsBase(arg)
	case notWindows:
	}
	return ""
}

// windowsBase is the last name of a path written with either slash; "rules.yaml" when it names nothing.
func windowsBase(arg string) string {
	arg = strings.Trim(strings.TrimSpace(arg), `"`)
	arg = strings.TrimRight(strings.ReplaceAll(arg, `\`, "/"), "/")
	base := arg[strings.LastIndex(arg, "/")+1:]
	if base == "" || strings.HasSuffix(base, ":") || base == "." || base == ".." {
		return "rules.yaml"
	}
	return base
}

// missingFileWhy is err's text for a refusal about the rules file arg, with windowsPathWords(arg) added after a
// semicolon when err says arg is not there. Every other error, and every host but Windows, gives err's own text.
func missingFileWhy(err error, arg string) string {
	why := err.Error()
	if !errors.Is(err, os.ErrNotExist) {
		return why
	}
	if words := windowsPathWords(arg, false); words != "" {
		return why + "; " + words
	}
	return why
}
