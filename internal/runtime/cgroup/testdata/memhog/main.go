// SPDX-License-Identifier: Apache-2.0

// Command memhog is a standalone helper built and run by the cgroup package's OOM integration test
// (docs/p0/runtime-launch.md R10; §10 "OOM detection"). It grows its own resident memory without
// bound, one small chunk at a time, writing every byte so the kernel actually commits the page
// rather than leaving it a lazily-faulted zero page. Run inside a cgroup whose memory.max is set
// low, it exists to be OOM-killed by the kernel — it never stops on its own, so the test's
// enclosing timeout catches the case where the limit failed to bite (a hang is the failure signal,
// not a false pass).
package main

func main() {
	const chunk = 256 * 1024
	var blocks [][]byte
	for {
		b := make([]byte, chunk)
		for i := range b {
			b[i] = byte(i)
		}
		blocks = append(blocks, b)
	}
}
