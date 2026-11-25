// SPDX-License-Identifier: Apache-2.0

// Command ledger-attacker is the agent of a held run that tries to change what an earlier run of its own agent recorded,
// so that a budget counted over a window would be lower: it removes, renames, truncates and appends to an earlier
// run's events.jsonl and to chain.log, makes a decoy in the ledger root, and takes the file's mode and dates. $ATTACK_EVENTS
// is the earlier run's events.jsonl, $ATTACK_CHAIN_LOG the account's chain.log, and $ATTACK_WINDOW_LOCK, when set, the
// agent's window lock in the ledger root, whose mode it takes too. Each attempt prints one line
//
//	ATTEMPT <name> <outcome>
//
// where the outcome is OK (the call succeeded), an errno name, or the kind of control. It always ends 0: the test judges
// the lines, and the files, afterwards. Two controls say the denials are the run's and not a wrong path: the agent can
// stat the file it attacks (CONTROL stat) and write where its contract lets it (CONTROL write-out).
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func outcome(err error) string {
	if err == nil {
		return "OK"
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		switch errno {
		case unix.EACCES:
			return "EACCES"
		case unix.EPERM:
			return "EPERM"
		case unix.EROFS:
			return "EROFS"
		case unix.ENOENT:
			return "ENOENT"
		}
		return "errno-" + errno.Error()
	}
	return "error-" + err.Error()
}

// control does each destructive operation on files the agent may write, and prints CONTROL allowed-<op> with the outcome.
func control() {
	say := func(name string, err error) { fmt.Println("CONTROL allowed-"+name, outcome(err)) }
	dir := "out/ctl"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		say("mkdir", err)
		return
	}
	mk := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("a line\n"), 0o600); err != nil {
			say("create-"+name, err)
		}
		return p
	}
	say("unlink", unix.Unlink(mk("u")))
	say("rename", unix.Rename(mk("r"), filepath.Join(dir, "r.moved")))
	say("truncate", unix.Truncate(mk("t"), 0))
	fd, err := unix.Open(mk("o"), unix.O_WRONLY|unix.O_TRUNC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	say("open-trunc", err)
	fd, err = unix.Open(mk("a"), unix.O_WRONLY|unix.O_APPEND, 0)
	if err == nil {
		_, err = unix.Write(fd, []byte("more\n"))
		_ = unix.Close(fd)
	}
	say("append", err)
}

func attempt(name string, err error) { fmt.Printf("ATTEMPT %s %s\n", name, outcome(err)) }

func main() {
	events, chain := os.Getenv("ATTACK_EVENTS"), os.Getenv("ATTACK_CHAIN_LOG")
	if events == "" || chain == "" {
		fmt.Println("ledger-attacker: ATTACK_EVENTS and ATTACK_CHAIN_LOG are required")
		os.Exit(3)
	}
	dir := filepath.Dir(events)
	root := filepath.Dir(dir)

	if err := os.WriteFile("out/control.txt", []byte("the agent writes where it may\n"), 0o600); err != nil {
		fmt.Println("CONTROL write-out", outcome(err))
	} else {
		fmt.Println("CONTROL write-out OK")
	}
	var st unix.Stat_t
	fmt.Println("CONTROL stat-events", outcome(unix.Stat(events, &st)))
	fmt.Println("CONTROL stat-chain", outcome(unix.Stat(chain, &st)))
	lock := os.Getenv("ATTACK_WINDOW_LOCK")
	if lock != "" {
		fmt.Println("CONTROL stat-lock", outcome(unix.Stat(lock, &st)))
	}

	// The same operations on copies in the agent's own write directory succeed: each denial below is the run's holding
	// the record, not a call that cannot work.
	control()

	// The destructive attempts, on the earlier run's events file and on chain.log.
	attempt("unlink-events", unix.Unlink(events))
	attempt("rename-events", unix.Rename(events, events+".moved"))
	attempt("rename-run-dir", unix.Rename(dir, dir+".moved"))
	attempt("rmdir-run-dir", unix.Rmdir(dir))
	attempt("truncate-events", unix.Truncate(events, 0))
	fd, err := unix.Open(events, unix.O_WRONLY|unix.O_TRUNC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	attempt("open-trunc-events", err)
	fd, err = unix.Open(events, unix.O_WRONLY|unix.O_APPEND, 0)
	if err == nil {
		_, err = unix.Write(fd, []byte("{}\n"))
		_ = unix.Close(fd)
	}
	attempt("append-events", err)
	attempt("unlink-chain", unix.Unlink(chain))
	attempt("rename-chain", unix.Rename(chain, chain+".moved"))
	attempt("truncate-chain", unix.Truncate(chain, 0))
	fd, err = unix.Open(chain, unix.O_WRONLY|unix.O_APPEND, 0)
	if err == nil {
		_, err = unix.Write(fd, []byte("r-forged 0000\n"))
		_ = unix.Close(fd)
	}
	attempt("append-chain", err)
	fd, err = unix.Open(filepath.Join(root, "r-decoy"), unix.O_CREAT|unix.O_WRONLY, 0o600)
	if err == nil {
		_ = unix.Close(fd)
	}
	attempt("create-in-root", err)
	attempt("mkdir-decoy-run", unix.Mkdir(filepath.Join(root, "r-3f9c2a1b-0000000000000-decoy0"), 0o700))

	// Not destructive to the record, and not denied by any tier: the mode and the dates of a file the agent can name.
	// The count never reads a date, and tego run puts a taken mode back; the test checks both.
	attempt("chmod-events", unix.Chmod(events, 0))
	if lock != "" {
		// The file that keeps two runs of one agent apart: its name follows from the agent's identity, and no tier denies
		// chmod. tego run puts the mode back; the test checks it.
		attempt("chmod-window-lock", unix.Chmod(lock, 0))
	}
	old := unix.Timeval{Sec: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()}
	attempt("utimes-events", unix.Utimes(events, []unix.Timeval{old, old}))
}
