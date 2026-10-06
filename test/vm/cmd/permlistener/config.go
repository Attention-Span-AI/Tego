// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

type mode string

const (
	// modeAllowTouch is ADR 0021's third-party listener: it allows everything, and each decision opens files on
	// the marked mount the way a real listener's does.
	modeAllowTouch mode = "allow-touch"
	// modeDeny is ADR 0017's space 6: it refuses the opens of one file.
	modeDeny mode = "deny"
)

const (
	defaultWorkers  = 4
	defaultDelay    = 2 * time.Millisecond
	defaultDeadline = 10 * time.Second
	defaultTouch    = "/etc/os-release"
	defaultStat     = "/usr/bin"
)

// config is what the flags say, validated and with the mode's defaults filled in. The fields of the other
// mode are zero: allow-touch has no path, deny has no workers.
type config struct {
	mode     mode
	marks    []string // paths whose mounts are marked
	path     string   // deny: the file whose opens are refused
	workers  int
	touch    []string // files each decision opens and reads
	stat     []string // paths each decision stats
	delay    time.Duration
	deadline time.Duration
}

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

const usageText = `usage: permlistener [-mode allow-touch|deny] [flags]

A third-party fanotify permission listener for the pairs runs (ADR 0021) and the conformance suite (ADR 0017).
It needs CAP_SYS_ADMIN. It prints PERMLISTENER-READY once its marks are placed, and on SIGTERM or SIGINT it
removes them, answers what is still queued and prints PERMLISTENER-STATS.

  allow-touch (default)  marks the mount of / for FAN_OPEN_PERM and FAN_OPEN_EXEC_PERM. Each open or exec by
                         another process is decided by a worker that opens and reads the -touch files and
                         stats the -stat paths, as a real listener's decision does, and then answers
                         FAN_ALLOW. Its own opens are allowed at once.
  deny -path P           marks the mount of P's directory for FAN_OPEN_PERM. An open of P is answered
                         FAN_DENY (EPERM to the opener); every other open is allowed at once. It opens
                         nothing itself.

Flags:
`

// parseConfig reads the command line. A mistake in it is an error whose message names the flag; -h is
// flag.ErrHelp, after the usage went to out.
func parseConfig(args []string, out io.Writer) (config, error) {
	fs := flag.NewFlagSet("permlistener", flag.ContinueOnError)
	fs.SetOutput(out)
	modeFlag := fs.String("mode", string(modeAllowTouch), "allow-touch or deny")
	path := fs.String("path", "", "deny: the `file` whose opens are refused, by name or inode (absolute)")
	workers := fs.Int("workers", defaultWorkers, "allow-touch: deciding goroutines")
	delay := fs.Duration("decide-delay", defaultDelay, "allow-touch: how long a decision waits before it opens anything, to widen the window")
	deadline := fs.Duration("deadline", defaultDeadline, "allow-touch: an event no worker has answered by then is answered FAN_ALLOW and counted late")
	var marks, touch, stat listFlag
	fs.Var(&marks, "mark", "a `path` whose mount is marked; repeatable (default /, or the directory of -path in deny mode)")
	fs.Var(&touch, "touch", "allow-touch: a `file` each decision opens and reads; repeatable (default "+defaultTouch+")")
	fs.Var(&stat, "stat", "allow-touch: a `path` each decision stats; repeatable (default "+defaultStat+")")
	fs.Usage = func() {
		fmt.Fprint(out, usageText)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfg := config{mode: mode(*modeFlag)}
	var err error
	switch cfg.mode {
	case modeAllowTouch:
		if set["path"] {
			return config{}, errors.New("-path applies to -mode deny only")
		}
		if *workers < 1 {
			return config{}, fmt.Errorf("-workers must be at least 1, not %d", *workers)
		}
		if *deadline <= 0 {
			return config{}, fmt.Errorf("-deadline must be positive, not %v", *deadline)
		}
		if *delay < 0 {
			return config{}, fmt.Errorf("-decide-delay must not be negative, not %v", *delay)
		}
		cfg.workers, cfg.delay, cfg.deadline = *workers, *delay, *deadline
		if cfg.touch, err = absolute("-touch", touch, defaultTouch); err != nil {
			return config{}, err
		}
		if cfg.stat, err = absolute("-stat", stat, defaultStat); err != nil {
			return config{}, err
		}
		if cfg.marks, err = absolute("-mark", marks, "/"); err != nil {
			return config{}, err
		}
	case modeDeny:
		for _, name := range []string{"workers", "touch", "stat", "decide-delay", "deadline"} {
			if set[name] {
				return config{}, fmt.Errorf("-%s applies to -mode allow-touch only", name)
			}
		}
		if *path == "" {
			return config{}, errors.New("-mode deny needs -path")
		}
		if !filepath.IsAbs(*path) {
			return config{}, fmt.Errorf("-path %q is not absolute", *path)
		}
		cfg.path = filepath.Clean(*path)
		if cfg.marks, err = absolute("-mark", marks, filepath.Dir(cfg.path)); err != nil {
			return config{}, err
		}
	default:
		return config{}, fmt.Errorf("-mode must be %s or %s, not %q", modeAllowTouch, modeDeny, *modeFlag)
	}
	return cfg, nil
}

// absolute checks and cleans a repeatable path flag, or gives the default when the flag was not set.
func absolute(flagName string, given listFlag, def string) ([]string, error) {
	if len(given) == 0 {
		return []string{def}, nil
	}
	out := make([]string, 0, len(given))
	for _, p := range given {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("%s %q is not absolute", flagName, p)
		}
		out = append(out, filepath.Clean(p))
	}
	return out, nil
}

// preflight checks, before any group exists, that what the configuration names is there: a decision that
// opened nothing would leave the cycle ADR 0021 names untested without saying so. The files are touched here
// with no mark in place, so they cannot wait on this process's own group.
func preflight(cfg config) error {
	for _, m := range cfg.marks {
		if err := statPath(m); err != nil {
			return fmt.Errorf("-mark %s: %w", m, err)
		}
	}
	if cfg.mode != modeAllowTouch {
		return nil
	}
	for _, p := range cfg.touch {
		if err := touchFile(p); err != nil {
			return fmt.Errorf("-touch %s: %w", p, err)
		}
	}
	for _, p := range cfg.stat {
		if err := statPath(p); err != nil {
			return fmt.Errorf("-stat %s: %w", p, err)
		}
	}
	return nil
}
