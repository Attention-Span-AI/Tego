// SPDX-License-Identifier: Apache-2.0

// Package selfbin checks the running tego binary's absolute path for re-entry and for a line Tego prints to paste
// after sudo.
//
// sudo replaces PATH with its secure_path, which has no ~/.local/bin (the installer's folder) and, on AlmaLinux 9.8, no
// /usr/local/bin, so `sudo tego ...` is "command not found" there, and a lookup in the reader's shell
// (`sudo "$(command -v tego)"`) selects the reader's installed copy. That form is appropriate in static docs,
// which cannot know an install location, but a product hint must name the binary that is running.
// The printed line quotes its absolute path. Because it runs as root or as another account, a path that cannot be vouched for gives no command and a reason (Named): the path cannot be read, was
// replaced since the process started (the name no longer identifies the running file), does not print safely (a
// control character in it could forge a second command on the administrator's screen), cannot be executed, or fails
// the owner and write-authority check below. The executable and
// every resolved ancestor up to / must be owned by root or this process's effective uid. Files refuse group/world
// write; non-sticky directories refuse world write. Directory group write permits a private primary group or an
// empty local group (no passwd primary users or group members). Bounded reads of the local passwd, group and NSS
// files supply the account facts, the caller's primary group included; no name service is asked, the reads share a
// two-second deadline (accountEvidenceWait), and they are made only when a folder of the path is group-writable. Incomplete membership refuses even the primary gid: a directory source or an unreadable,
// truncated, oversized or malformed file cannot rule out another principal sharing it. A group that can be joined
// with a password (a usable password field in /etc/group, or in /etc/gshadow when the caller can read it) refuses
// too: newgrp admits accounts no file lists. A normal user cannot read /etc/gshadow, so a password set only there is
// not seen (ADR 0142, 2026-11-18, group passwords). Access ACLs or unavailable
// ACL metadata refuse the non-sticky
// group-write exception. Sticky directories protect trusted children from rename (as in /tmp), irrespective of
// group membership, but never protect file contents. Missing stat metadata fails closed. A refusal says to install
// in a folder only root or you can write. This is a point-in-time check; root and this account remain trusted.
// Path is the separate identity check for immediate re-entry and does not impose this printed-command trust rule.
//
// Imports: the standard library, golang.org/x/sys/unix, internal/shellword, pkg/spec/record.
// Must not import: the rest of internal.
package selfbin
