// SPDX-License-Identifier: Apache-2.0

// Package testutil holds helpers that the tree's own tests share. Only _test.go files import it, so
// nothing here reaches a shipped binary.
//
// LeakCheckMain is a TestMain body that fails a package's test binary when, after every test has run,
// the runtime can prove a goroutine is leaked: blocked on a channel, a sync.Cond, a sync.WaitGroup or
// another concurrency primitive that nothing still running can ever reach (Go 1.27's goroutineleak
// profile). The long-lived goroutines of a run (the recorder and uprobe drains, the DNS refresher, the
// limits watcher, the supervisor's workers) must all end with the run, and a drain that outlives a
// `tego run` pins its ring, its descriptors and its memory for as long as the process lives.
//
// NoFDLeak is the descriptor table's check (ADR 0023 A8): it fails a test whose descriptor table grew between
// its call and the test's Cleanup, and refuses a parallel test, where the delta would mean nothing.
//
// GuardedMain, GuardedLeakCheckMain and GuardedStdioLeakCheckMain (which also fails the binary on a standard
// descriptor a test closed or replaced) are the other TestMain gate (over GuardRealTego): they fail a package
// whose tests can start a run, a sweep, a gc, a reaper or the tego binary when anything in the invoking user's
// real ~/.tego or ~/.bash_history (found through passwd, as tego finds its home, and through $HOME as the binary
// started only for an account passwd names no home for, where tego falls back to it) changed while they ran, or
// when the invoking user's runtime parent (/run/user/<uid>/tego, and <XDG_RUNTIME_DIR>/tego for the variable the
// binary started with) was made, removed or replaced, holds a new entry no live run locks, or lost a crashed run's
// entry. PrivateRuntimeDir is what such a package's TestMain calls first, so its runs keep their runtime
// directories under its own temporary parent.
// tools/isocheck GO-4 names the packages that must exit with their code. Started as go test starts a test binary,
// they run the tests in a re-executed child and check once it ended, so a test that panics or runs into the test
// timeout after a write is reported too.
//
// TegoEnv is the environment a test gives a tego binary built with -tags tegotesthooks that it starts as a
// subprocess: the chain anchor, the own-log home and XDG_RUNTIME_DIR in the test's own directory, never the
// invoking user's.
//
// TimingMode, Mode.Measure, Mode.Judge and Mode.JudgeRatio are how a test holds code to an absolute timing budget
// (docs/BENCHMARKS.md, "Timing budgets in the test suites"): Measure takes the fastest of many interleaved rounds,
// less the clock's own cost, on the wall clock alone in budget mode (MinOf) and in the unit gate on the calling
// thread's figures from the same samples (MinOfThread: the wall clock, the thread's own time and its CPU time), and
// Judge (JudgeRatio, for a ratio to a fixed workload) holds the Figure to the budget's Limit and Target as its spec
// writes them in budget mode (BudgetsEnv=1, which scripts/timing-budgets.sh sets where the machine is quiet). In
// every other run, the unit gate, it holds the own time to CeilingFactor times the Limit and the same samples' wall
// clock to WallCeilingFactor times it; a pace across threads and processes, which no one thread's figures are, is
// held on the wall clock to CeilingFactor times its Limit. A sample's own time is its wall clock less the thread's
// run-queue delay over it (/proc/thread-self/schedstat) beyond the CPU time the process's other threads had over it,
// where the thread never blocked, and its whole wall clock where it did: it keeps the code's work, the work it hands
// to other goroutines and the waits the code makes, and leaves out the waits for a CPU that other processes fill,
// which nothing bounds. A wait can still hide in it where another process's work fills it and the thread never
// blocks (a thread that process preempts just as it parks, or a wait that yields its CPU instead of sleeping), which
// takes another process wanting the thread's CPU, and the fastest sample can be one where it did; the wall clock
// never hides one, so a wait past a hundred Limits fails on any machine, and one past ten fails wherever it cannot
// hide.
// CPU time alone would never see a regression that only waits. MinOf on ThreadCPU alone is for relative bounds, two
// sizes of the same code.
//
// Imports: the standard library and internal/realtego (which imports only the standard library, and is where
// the test build of tego finds the same homes). Must not import anything else under internal/ or pkg/: a helper
// every package's tests import cannot depend on any of them without an import cycle.
// The separate contracttest and ledgertest subpackages depend on the public
// compiler and record schema respectively; importing either never changes this
// package's dependency graph.
package testutil
