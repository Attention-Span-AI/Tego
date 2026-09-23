// SPDX-License-Identifier: Apache-2.0

// Command cpu is the overhead benchmark's control workload (docs/BENCHMARKS.md): a fixed amount of
// SHA-256 chaining and nothing else. It opens no file beyond the FDs the runtime hands it, execs
// nothing, and dials no socket, so none of the syscalls a tier's seccomp filter notifies on
// (openat with write flags, execve, connect, unlink/rename/mkdir) ever fire. Landlock's own
// decision is made once, at ruleset attach, off this workload's hot path entirely. If this
// workload's overhead is not ~0%, the cost is coming from somewhere enforcement was not supposed to
// touch (process launch, the notify listener's fixed setup, or the cgroup itself) and the benchmark
// has found something worth chasing rather than a rounding error in a build workload.
//
// Iterations is fixed (not time-based) so every run does the same work: a wall-clock target would
// let scheduler noise change the work done rather than the time taken, which is exactly the
// variance this workload exists to be free of.
package main

import (
	"crypto/sha256"
	"fmt"
)

// iterations is calibrated (see docs/BENCHMARKS.md) to run a few hundred milliseconds on the
// benchmark machine: long enough that process-start fixed costs do not dominate the measurement,
// short enough that hyperfine's default run count finishes in seconds.
const iterations = 1_800_000

func main() {
	h := sha256.Sum256([]byte("tego overhead control"))
	for i := 0; i < iterations; i++ {
		h = sha256.Sum256(h[:])
	}
	fmt.Printf("cpu: %d rounds, final=%x\n", iterations, h)
}
