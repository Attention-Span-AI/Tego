// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"errors"

	"golang.org/x/sys/unix"
)

// SystemdRunPath is the executable used both to check whether a user scope can be opened and to open it. PATH cannot
// redirect the automatic handoff to another program (ADR 0142's automatic-scope amendment).
func SystemdRunPath() (string, error) {
	return systemdRunPath([]string{"/usr/bin/systemd-run", "/bin/systemd-run"})
}

func systemdRunPath(paths []string) (string, error) {
	for _, path := range paths {
		var st unix.Stat_t
		if unix.Stat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && unix.Access(path, unix.X_OK) == nil {
			return path, nil
		}
	}
	return "", errors.New("systemd-run is missing from /usr/bin and /bin")
}

var scopeRunner = SystemdRunPath
