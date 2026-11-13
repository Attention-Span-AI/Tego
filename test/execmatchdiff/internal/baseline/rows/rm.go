// SPDX-License-Identifier: Apache-2.0

package rows

import "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"

// Rm is the rm row, probed against GNU coreutils 9.5's rm (Ubuntu 25.10 installs it as /usr/bin/gnurm, which
// /usr/bin/rm links to): getopt_long, so options permute past operands until `--`, long options take unique
// prefixes, and short options cluster. uutils' rm takes the same options. Without a tty, plain `rm -r` removes what
// `rm -rf` would (measured), which is why a deny names -r, not -rf.
func Rm() *execmatch.Row {
	return &execmatch.Row{
		Tool:    "rm",
		Names:   []string{"gnurm"},
		Version: "GNU coreutils 9.5",
		Docs:    "rm(1), coreutils src/remove.c",
		Source:  execmatch.SourceProbed,
		Root: leaf(gnu,
			flag("force", "f"),
			flag("interactive-each", "i"),
			flag("interactive-once", "I"),
			opt("interactive", ""),
			flag("one-file-system", ""),
			flag("no-preserve-root", ""),
			opt("preserve-root", ""),
			flag("recursive", "rR"),
			flag("dir", "d"),
			flag("verbose", "v"),
			flag("help", ""),
			flag("version", ""),
		),
		Coverage: map[string]string{
			"rm -rf": "does not cover rm -r, rm -R or rm -dr, which remove the same tree without a tty; deny rm -r",
			"rm -fr": "does not cover rm -r, rm -R or rm -dr, which remove the same tree without a tty; deny rm -r",
		},
	}
}
