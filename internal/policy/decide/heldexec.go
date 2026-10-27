// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// FileKey is a file's identity: its device and inode numbers, as stat(2) gives them.
type FileKey struct{ Dev, Ino uint64 }

// HeldExecGrants is the rights the run's Landlock ruleset binds to each inode an exec.allow entry named when the run
// started (the builder's execGrants, enforce-landlock R5): EXECUTE and READ_FILE, and READ_DIR for a directory entry.
// A Landlock rule is on the inode the builder held, not on the name: an exec.allow directory renamed inside a write
// entry takes its EXECUTE to its new name, and a fresh directory made at the declared name has none. The table alone
// cannot see that; a producer that can stat the run's files holds the inodes before the agent
// runs (HoldExecGrants) and asks REFER's no-gain rule by them (Grants).
type HeldExecGrants map[FileKey]agent.AccessSet

// HoldExecGrants stats each exec entry of rt as the Landlock builder opens it, symlinks followed, and records what its
// grant gives that inode. It must run before the agent does, when the builder's inodes are the entries' own. An entry
// that cannot be stat'ed holds nothing here; the table still answers for it (ExecGrantAt) wherever an end cannot be
// stat'ed.
func HoldExecGrants(rt *agent.RuleTable, stat func(string) (FileKey, error)) HeldExecGrants {
	if rt == nil {
		return nil
	}
	var h HeldExecGrants
	for i := range rt.Exec {
		r := &rt.Exec[i]
		if r.Path == "" {
			continue
		}
		k, err := stat(r.Path)
		if err != nil {
			continue
		}
		a := agent.AccessExecute | agent.AccessReadFile
		if r.IsDir {
			a |= agent.AccessReadDir
		}
		if h == nil {
			h = HeldExecGrants{}
		}
		h[k] |= a
	}
	return h
}

// Grants is ExecGrants by identity: the rights the held inodes give at the end p, matched against p itself and each
// of its directories up to "/", each stat'ed by lstat with its final component not followed (a symlink holds no
// grant: the builder opened the entry through it). An end lstat cannot stat all the way (a name the syscall will not
// find) is answered by the table (ExecGrantAt). nil, the table's answer throughout, when nothing is held or
// rt's images are unrestricted: every write entry then grants EXECUTE, so an exec grant adds no right the no-gain rule
// compares.
func (h HeldExecGrants) Grants(rt *agent.RuleTable, lstat func(string) (FileKey, error)) ExecGrants {
	if len(h) == 0 || rt == nil || rt.ExecUnrestricted() {
		return nil
	}
	return func(p string) agent.AccessSet {
		var a agent.AccessSet
		for cur := p; ; cur = path.Dir(cur) {
			k, err := lstat(cur)
			if err != nil {
				return ExecGrantAt(rt, p)
			}
			a |= h[k]
			if cur == "/" || cur == "." {
				return a
			}
		}
	}
}
