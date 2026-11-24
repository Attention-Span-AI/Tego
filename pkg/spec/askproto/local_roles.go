// SPDX-License-Identifier: Apache-2.0

package askproto

import "fmt"

// InitialUserNamespace is Linux's initial user namespace inode (PROC_USER_INIT_INO).
const InitialUserNamespace uint64 = 4026531837

// LocalApprovalActor is the authenticated OS process that gave one root answer.
// It is data returned by the broker, never an identity accepted in a command.
type LocalApprovalActor struct {
	UID           uint32 `json:"uid"`
	PID           int    `json:"pid"`
	StartBootNS   uint64 `json:"start_boot_ns"`
	UserNamespace uint64 `json:"user_namespace"`
	Source        string `json:"source"`
	Role          string `json:"role"`
}

// AnswerAuthority carries the actor or a typed system cause. Its zero value
// omits both fields and preserves personal protocol and record bytes.
type AnswerAuthority struct {
	Actor       *LocalApprovalActor `json:"actor,omitempty"`
	SystemCause string              `json:"system_cause,omitempty"`
}

// Validate checks the closed local root actor vocabulary, without doing I/O
// or establishing the truth of any field. Kernel checks belong to the broker.
func (a LocalApprovalActor) Validate() error {
	if a.UID != 0 || a.PID <= 0 || a.StartBootNS == 0 || a.UserNamespace != InitialUserNamespace || a.Source != "kernel-local-uid" || a.Role != "owner" {
		return fmt.Errorf("local approval actor: invalid identity fields")
	}
	return nil
}
