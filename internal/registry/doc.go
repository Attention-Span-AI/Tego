// SPDX-License-Identifier: Apache-2.0

// Package registry resolves agent names and owns contract file publication.
//
// OpenDirectory walks every absolute directory component, including agents, with
// O_NOFOLLOW beneath the previous descriptor. Ancestors are opened O_PATH, which
// needs search permission and never read; only the destination is opened for
// reading. The destination descriptor remains open through Write. WriteFileAt is
// the single publisher used by Save and by rulefile's guarded create and replace
// paths. It writes a random exclusive 0600 temporary file beneath that descriptor
// after checking the reviewed directory identity. It sets the requested final
// mode, syncs and closes the file, repeats the owning review check, verifies the
// temporary inode and digest, and verifies the old file identity and digest for a
// replacement, then publishes and syncs the directory. New files never replace an
// existing name; replacement checks the old device, inode and SHA-256 immediately
// before atomic rename. Failures remove the temporary name and name their failing
// step.
// A directory-sync failure after publication reports that the complete file exists.
// Save removes an entry refused by its post-publication resolution check and syncs
// that removal. A cleanup failure reports whether the complete file may remain or
// whether its removal could not be synced; callers must not claim nothing was written.
// A process interrupted before publication can leave an unreferenced dot-file;
// it cannot leave an empty or partial contract under the final name.
// The final rechecks and path publication syscalls are separate operations. An
// authorized writer to the same directory can race them; this is not an atomic
// compare-and-swap against hostile directory mutations.
//
// Save creates directories 0700 and contract files 0600. rulefile creates project
// contracts 0644 and preserves permission bits on replacement. New files belong
// to the effective user and inherit the filesystem's group selection. Replaced
// contracts likewise belong to the writer, which rulefile restricts to the old
// file's owner. Neither path changes owner with chown.
//
// Imports: internal/platform/sys, pkg/spec/agent, pkg/spec/config, pkg/spec/identity, golang.org/x/sys/unix,
// yaml.v3 and the standard library.
// Must not import: internal/control, internal/rulefile, internal/runtime, internal/policy.
package registry
