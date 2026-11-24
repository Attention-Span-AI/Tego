// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"strings"
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
