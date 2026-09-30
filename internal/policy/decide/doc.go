// SPDX-License-Identifier: Apache-2.0

// Package decide is the decision core (ADR 0028): the one package that owns the verdict model of every tier,
// so compile --test, the tier-1 and tier-2 records, tier 2's fanotify listener and tier 3's plane cannot
// disagree about a contract. The kernel still judges; the core predicts and attributes what it judges.
//
// Models, each built from the compiled agent.RuleTable alone:
//
//   - landlock (tier 1; landlock.go): Landlock's union of the grants over the rule plan, plus the rules the
//     supervisor enforces itself (deny_write, exec, net). The plan's pure half (plan.go) is what the
//     enforce/landlock builder applies: which deny_read targets are unenforced (R4, checked against compile's
//     mark by I5), which are enumerated (E29) and the ancestor levels it holds (R3).
//   - cgroup (tier 2; cgroup.go): the inherited Landlock ruleset plus the fanotify listener's open and exec
//     decisions, on the listener's indexes (ListenerOpen, ListenerExec over PathIndex, index.go) and on a walk
//     of the table (ListenerOpenRefused) that Evaluate and the supervisor ask; the two are held to one answer.
//   - root (tier 3; root.go, rootrows.go): SEMANTICS §2's nearest-wins walk (FSDecider), and the same model as
//     the inode-keyed rows (RootRow, RootIndex) with the walk over them that bpf/decide.bpf.c makes
//     (RootIndex.Walk), checked against Evaluate's bpflsm column by the oracle in rootoracle_test.go; and the plane's row compiler (planerows.go,
//     CompilePlane): complete rows, exec rows, keyed inodes, ADR 0025's neutral Landlock rules and the cap.
//   - observe: the nearest entry names the action and everything is allowed.
//
// Consumers: Evaluate answers compile --test (internal/cli calls it through agent.TestTable.RunBy);
// AdvisoryFS is the seccomp supervisor's advisory fs verdict (advisory.go); FSMatch, InferFS and MatchNetLPM
// are tier 2's recorder's attribution (recorder.go, ADR 0016); ListenerOpen and ListenerExec are the fanotify
// listener's decisions. pkg/spec/agent's RuleTable.Evaluate, FSDecider, ListenerOpenRefused and
// ExecReadGrant are deprecated shims over this package, which registers itself with agent.RegisterDecider
// to keep pkg/spec independent of internal implementation packages (ADR 0019, ADR 0031 (1)). External
// callers use the experimental pkg/policy/evaluate facade, which delegates directly to this core.
//
// Several models are still separate functions that ADR 0028 S5 merges once their consumers converge (ADR
// 0016 step 2, ADR 0024 step A): the supervisor's advisory tables beside the root walk, the listener's index
// beside ListenerOpenRefused, MatchNetLPM (the kernel rows' attribution) beside Evaluate's net matcher, both
// composing overlapping entries by SEMANTICS §5's one rule. They live here together so that a semantic fix is
// one edit in one package, and the cross-checks that hold them to one answer (cgroup_test.go, rootrows_test.go,
// and internal/runtime/enforce/cgroup's TestCrossCheckTiers and TestNetPrecedenceMatchesEvaluate) run on it.
//
// The package is pure: no I/O, no goroutines, no clock, no lock (.golangci.yml decide-is-pure), and its
// runtime query paths — FSDecider, AdvisoryFS, ListenerOpen, ListenerExec, MatchNetLPM, RootIndex.Walk, and
// PlaneRows' Decide, KindAt, RuleAt and ExecMatch — allocate nothing (TestQueryPathsAllocateNothing,
// TestPlaneQueriesAllocateNothing).
//
// Imports: standard library (pure packages), pkg/spec/agent, pkg/spec/backend, pkg/spec/record.
// Must not import: anything else under internal/, os, syscall, golang.org/x/sys, time, sync.
package decide
