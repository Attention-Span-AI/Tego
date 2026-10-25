// SPDX-License-Identifier: Apache-2.0

package runlock

// pathDir is the run directory at path, looked up by path: the name internal/runtime's tests, moved here with the
// proofs, call it by.
func pathDir(path string) Dir { return Dir{Path: path} }

// OpenStopTarget is OpenStopTargetFor (whose doc is the contract) on a lock line's two values.
func OpenStopTarget(runDir string, pid int, wantStartBootNS uint64) (*StopTarget, error) {
	return OpenStopTargetFor(runDir, LockInfo{PID: pid, StartBootNS: wantStartBootNS})
}
