// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// multicallCheck is doctor's line on how this host lays out its core utilities: the file `ls` leads to, when it has
// more than one hard link (uutils coreutils on Ubuntu 25.10 and later) or is named busybox, toybox or coreutils
// (agent.MulticallOf). An exec.allow entry for one name of such a file admits more than that name (SEMANTICS §4,
// docs/GAPS.md), and compile notes each such entry [exec-multicall]; this line says it of the host before any
// contract is written. It is a fact about the host, never a tier's condition and never doctor's exit. It is read by
// stat alone: doctor runs no program to learn whether the file honours a foreign argv[0].
type multicallCheck struct {
	// Name is the command looked up on PATH ("ls"), and Path where PATH found it.
	Name string `json:"name"`
	Path string `json:"path"`
	agent.MulticallFile
}

// multicallProbeName is the command whose file doctor reads: every coreutils build has an ls, and on a multi-call host
// it leads to the shared file.
const multicallProbeName = "ls"

// errNotOnPath is lookMulticallProbe's answer when no absolute PATH directory holds an executable ls.
var errNotOnPath = errors.New("not on PATH")

// lookMulticallProbe finds multicallProbeName on doctor's PATH as a shell would: the first absolute directory holding
// an executable file of that name. It stats the candidates and runs none of them. A relative PATH entry names a
// directory relative to wherever doctor was started, which says nothing of the host, and is skipped.
func lookMulticallProbe() (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, multicallProbeName)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", errNotOnPath
}

// checkMulticall is the line's answer: nil when ls is not found, or leads to a file with one link and another name.
func checkMulticall() *multicallCheck {
	p, err := lookMulticallProbe()
	if err != nil {
		return nil
	}
	m, ok := agent.MulticallOf(p)
	if !ok {
		return nil
	}
	return &multicallCheck{Name: multicallProbeName, Path: p, MulticallFile: m}
}

// writeMulticallCheck writes the check as one line in the probe lines' shape (doctor.WriteResults), under the state
// "note", since it says how this host's files are laid out and is neither a probe's pass nor a failure. A nil check
// writes nothing. It goes before the dashboard line, which stays the report's last line (docs/INSTALL.md).
func writeMulticallCheck(w io.Writer, c *multicallCheck) error {
	if c == nil {
		return nil
	}
	var line string
	if c.Dispatcher {
		line = fmt.Sprintf("\nnote multicall: %s leads to %s, a multi-call program, which runs the program argv[0] or argv[1] "+
			"names: an exec.allow entry for any of its names admits every program it holds, at every tier; tego compile "+
			"notes such entries [exec-multicall]", c.Path, c.Resolved)
	} else {
		line = fmt.Sprintf("\nnote multicall: %s leads to %s, one program file with %d names (hard links): an exec.allow "+
			"entry for one of them admits that name's link at tiers cgroup and bpflsm, and the file by any name at tier "+
			"landlock to an agent that wins the exec race; a build that reads argv[0] runs any program it holds through a "+
			"listed name; tego compile notes such entries [exec-multicall]",
			c.Path, c.Resolved, c.Links)
	}
	if _, err := fmt.Fprintln(w, line); err != nil {
		return fmt.Errorf("doctor: write multicall: %w", err)
	}
	return nil
}
