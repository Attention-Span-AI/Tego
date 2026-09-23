// SPDX-License-Identifier: Apache-2.0

// Package ask coordinates local human approvals. It authenticates each packet's
// kernel credentials and records a decision before returning it to the caller.
// It never continues a trapped syscall or performs the approved operation: the
// supervisor retains the original notification and completes it safely.
package ask
