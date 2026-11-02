// SPDX-License-Identifier: Apache-2.0

// Command isocheck checks that no test harness in the tree can write the invoking user's own ~/.tego.
//
// tego resolves its home from the passwd database, and from $HOME only for an account that has no passwd home
// (identity-config.md R21), so a harness that sets HOME isolates nothing: the chain anchor (~/.tego/chain.log), the own log (~/.tego/tego.log) and the
// built-in ledger root are the developer's own unless the harness points them elsewhere. The one way to do that
// is a binary built with -tags tegotesthooks started with TEGO_CONFIG naming a ledger_root, TEGO_TEST_CHAIN_ANCHOR
// and TEGO_TEST_OWN_LOG_HOME (internal/cli/anchor_testhook.go, ownlog_testhook.go; identity-config.md R27). On
// 2026-10-06, 61 lines of runs whose ledgers were temporary directories were found in the developer's chain.log: an
// integration test took os.Environ() before the call that set those variables. This check holds the harness code to
// the rules that keep that from happening again; the test hooks build refuses to run without the variables, which
// holds the rest.
//
// Go (any .go file outside the skipped directories):
//
//	GO-1  in a function, an os.Environ() inside a statement that builds a "TEGO_CONFIG=" entry comes after every
//	      call of writeMachineConfig or writeMachineConfigWith (those call t.Setenv for the two variables; an
//	      os.Environ() taken first, in the same statement included, holds neither).
//	GO-2  a file with a "TEGO_CONFIG=" environment entry also names TEGO_TEST_CHAIN_ANCHOR, testutil.TegoEnv or
//	      writeMachineConfig: the environment a tego subprocess gets carries the isolation.
//	GO-3  a file that builds cmd/tego builds it with tegotesthooks (a string literal naming the tag), except the
//	      three listed in goBuildExempt, which name it without running it.
//	GO-4  a package (a directory's test binary) whose tests can start a run, a sweep, a gc, a reaper or the tego
//	      binary, or write tego's state below a tego home (stateWriters: internal/govlog's governance ledger), has,
//	      in every build that compiles such a test, a TestMain whose exit code is a guarded run's: in
//	      its own top-level statements (not in a closure or another statement's block) either
//	      os.Exit(testutil.GuardedMain(m)) (or GuardedLeakCheckMain), or code := testutil.GuardedMain(m) and, as the
//	      first statement after it that exits, os.Exit(code), with nothing between that assigns code, takes its
//	      address, calls os.Exit, panics or returns, at any depth. m is used nowhere else (no test runs before or
//	      outside the guard) and no top-level return, os.Exit or panic comes before it. So the binary fails when the
//	      invoking user's real ~/.tego or ~/.bash_history changed while it ran. A hand-written check of
//	      testutil.GuardRealTego does not count: the rule holds one exact shape, where each review of the
//	      hand-written forms found another that exited 0 whatever the tests wrote. Such a package is
//	      internal/runtime or internal/cli, or has a file (a test, or its own code, which a test can call: a
//	      main_test.go that calls main()) that imports one of them or a package of the module whose own code
//	      imports one, directly or through others (taken over every build); or has a file that builds cmd/tego,
//	      runs the tego binary, holds a "TEGO_CONFIG=" or "TEGO_TEST_CHAIN_ANCHOR=" entry, or calls TegoEnv,
//	      writeMachineConfig or writeMachineConfigWith. A run of the binary is a command GO-5 knows as one, whatever
//	      environment it gets, or one given its arguments as a list (exec.Command(bin, args...)) whose program is a
//	      literal ending in tego or a name, field or pointer holding "tego" or ending in "bin", or whose list is a
//	      []string literal, an append to one, or a name of the file assigned one, starting with a subcommand. A list
//	      given to a program spelled otherwise (argv[0] of a list built elsewhere, a copy of the binary under
//	      another name) is out of this signal's reach. Builds are every combination of the tags the package's
//	      //go:build lines name, on linux/amd64; the rule needs the module path and applies only where root has a
//	      go.mod.
//	GO-5  in a function, an exec.Command or exec.CommandContext that runs the tego binary (the program is not a
//	      string literal, or is a literal ending in tego, and the first argument is a string literal naming one of
//	      SH-5's subcommands; a list passed as args... is not followed) is
//	      either passed straight to a call that runs it (the callee is not followed), or assigned to a name or field
//	      and given an Env of its own before it leaves view: the statements after the assignment, in its block, set
//	      that name's Env to something other than the bare inherited environment (nil, os.Environ(), or an append to
//	      it or to an Env that holds it, naming neither a TEGO_CONFIG= nor a TEGO_TEST_CHAIN_ANCHOR= entry)
//	      before one of them starts it (Run, Start, Output, CombinedOutput), passes it to a call, uses it as a value
//	      (c2 := cmd, return cmd) or puts another command in the name. An Env set inside an if or a closure does not
//	      count, and one set there to the inherited environment, a truncation of the Env (cmd.Env[:0]) and
//	      os.Environ() appended after the isolation (exec keeps the last entry of a name) undo it. Run straight from
//	      the call, returned, or never given an Env of its own before it starts, it meets the test build's refusal
//	      of the built-in ~/.tego/runs and fails on that, not on what it tests (the cgroup suite's `doctor
//	      --require cgroup` skipped about 18 root tests so), and a product build reads and writes the real ~/.tego.
//	      An environment built in a local variable or a helper (env := os.Environ(); cmd.Env = env) is not
//	      followed: GO-5 is a check against slips, and the runtime guard (GO-4) and the test build's refusal hold
//	      the rest.
//
// Shell and Python (.sh, .bash, .py, comment lines removed; test/vm is exempt: its scripts run inside the KVM guests,
// whose home is the guest's):
//
//	SH-1  a file that assigns TEGO_CONFIG also sets TEGO_TEST_CHAIN_ANCHOR and TEGO_TEST_OWN_LOG_HOME, or calls
//	      a helper that does (kt_config, lib_init).
//	SH-2  a Python file that opens a pseudo-terminal sets HISTFILE to /dev/null: a shell on it writes its history
//	      to ~/.bash_history when it exits.
//	SH-3  a script that starts an interactive shell (-i) sets HISTFILE to /dev/null.
//	SH-4  a script that builds cmd/tego (go build, install or run) builds it with tegotesthooks.
//	SH-5  a script that runs a tego binary sets TEGO_TEST_CHAIN_ANCHOR and TEGO_TEST_OWN_LOG_HOME, or calls kt_config
//	      or lib_init: running tego does not depend on assigning TEGO_CONFIG. A run is a path ending in tego, or a
//	      $var that is one letter or has tego, bin or exe in its name, at the start of a command (after ; & | ( { $(,
//	      then, do, else, if, while, until, !, or sudo, env, exec, timeout, nohup, time, setsid, script, xargs, command
//	      or a shell and its options) and followed by run, watch, gc, stop, events, status, ask, approve, deny,
//	      alternate, doctor, drift, learn, adopt, agents, measure, detect, compile, dns or init (every command
//	      internal/cli registers but version and licenses, which read no config, ledger, anchor or log: notRuns),
//	      on a line joined at its trailing backslashes; or, in a Python
//	      file that names tego, an argument list that starts with a name, call or subscript (or a literal ending in
//	      tego) and a subcommand in quotes.
//	SH-6  a script that runs a tego binary and takes it from its caller (TEGO_BIN, --tego) refuses a binary that is
//	      not a test build: kt_require_testhooks or kt_ensure_tego, or a search of the file for
//	      TEGO_TEST_CHAIN_ANCHOR, the one name only a test build contains (a product build ignores the variable).
//	SH-7  a script that starts a run (run, watch, adopt or agents, in a run SH-5 knows) assigns XDG_RUNTIME_DIR (a
//	      shell assignment, a Python keyword argument, dict key or item assignment; in Python also the name required
//	      by a check that refuses /run/user/<uid>) or calls kt_config or lib_init, and never assigns it the inherited
//	      value ($XDG_RUNTIME_DIR, os.environ, os.getenv) or a path under /run/user/, directly or copied through
//	      other names: a launch makes <XDG_RUNTIME_DIR>/tego and removes the directories the invoking user's crashed
//	      runs left there (identity-config.md R27 clause b4).
//
// Usage: go run ./tools/isocheck [root]   (root defaults to the working directory)
// Exit: 0 when every rule holds; 1 when one does not; 2 on a read or parse error.
//
// Imports: standard library only.
package main

import (
	"fmt"
	"os"
	"sort"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	findings, err := check(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "isocheck: %v\n", err)
		os.Exit(2)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	for _, f := range findings {
		fmt.Println(f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "isocheck: %d finding(s): a harness here could write the invoking user's own ~/.tego, ~/.bash_history or runtime directory\n", len(findings))
		os.Exit(1)
	}
}
