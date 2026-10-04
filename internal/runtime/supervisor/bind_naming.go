// SPDX-License-Identifier: Apache-2.0

package supervisor

// BindNaming is bounded metadata captured while a bind notification is held.
// It is naming only; the kernel supplies the copied object and terminal result.
type BindNaming struct {
	Path            string
	Abstract        bool
	Rule            string
	AttemptMonoNS   uint64
	SupervisorOwned bool
}

// ListenNaming captures a trapped listen attempt. It carries no authority over
// the bound socket: the kernel validates the actual socket and supplies its
// terminal result, independently of this original pathname spelling.
type ListenNaming = BindNaming
