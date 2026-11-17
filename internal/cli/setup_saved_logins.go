// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// readSavedLogins reads data only: the shell file is never evaluated as a program.
func readSavedLogins(home string, out io.Writer) map[string]string {
	values := make(map[string]string)
	b, err := readGuideFile(home, agentEnvRel)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && out != nil {
			fmt.Fprintf(out, "Ignored saved logins: %v\n", err)
		}
		return values
	}
	for _, line := range strings.Split(string(b), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if !ok || len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' {
			continue
		}
		value = value[1 : len(value)-1]
		if validToken(value) != nil {
			continue
		}
		for _, a := range guideAgents {
			for _, login := range a.logins {
				if name == login.envVar {
					values[name] = value
				}
			}
		}
	}
	return values
}

// loadRunSavedLogins makes the first session independent of whether the parent shell loaded bashrc.
func loadRunSavedLogins(o runOptions, home string, out io.Writer) {
	if o.adopted || o.generated {
		return
	}
	for name, value := range readSavedLogins(home, out) {
		if _, set := os.LookupEnv(name); !set {
			_ = os.Setenv(name, value)
		}
	}
}
