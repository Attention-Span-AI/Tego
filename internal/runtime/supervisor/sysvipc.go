// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

// ruleSysVIPC names a refused System V IPC syscall. Like ruleKeyring it is a rule name, not a reason: the
// reason is read-denied, a store outside the run the run is denied, and the syscall is the refused op.
const ruleSysVIPC = "sysv-ipc"

// gapWhySysVIPC prefixes the why of the gap line a continued System V IPC syscall leaves: "sysv-ipc-" and the
// syscall's name. Record v1 has no IPC action kind, as it has no keyring one (gapWhyKeyring).
const gapWhySysVIPC = "sysv-ipc-"

// answerSysVIPC answers one System V IPC syscall: shmget, shmat, shmctl, semget, semop, semtimedop, semctl,
// msgget, msgsnd, msgrcv or msgctl (enforce-landlock R11). The IPC namespace is the host's at tiers 1 and 2,
// its ids are small integers anyone can guess, and a segment or queue another process made is reached by id
// alone: no fs, net or exec rule sees it and Landlock has no right for it. A segment made outside the run was
// attached read-write inside it with no line in the ledger (R34). By default the syscall is
// refused with EPERM, as the keyring's are, and the refusal recorded. A contract that declares `ipc: true`, and
// an observe run, has it continued, and each binary's first use of each syscall recorded as gap what=record
// why=sysv-ipc-<syscall>. The answer depends on the contract alone: the arguments are keys, ids and flags,
// nothing a rule of the contract names.
func (l *Loop) answerSysVIPC(n *notif, op string) {
	l.answerOptIn(n, op, l.table.Load().ipcAllowed, &l.ipcSeen, gapWhySysVIPC, ruleSysVIPC)
}
