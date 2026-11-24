// SPDX-License-Identifier: Apache-2.0

// Package grouptrust checks bounded local account evidence for discovery reads
// and caller identification. ReadAccountFileAt uses the same two-pass collector
// for a single account file, with exactly the same placement policy.
// System reads all three files, then reads all again through fresh opens.
// Each file must have equal bytes in both passes. Descriptor and path device,
// inode, size, mtime and ctime must also match within and across passes;
// metadata comparisons are additional refusals, never proof of equal contents.
// Differences or errors refuse without retry; no name service is invoked.
// This rule asks whether another, non-root user can write a discovery source.
// Its account evidence comes from verified system files that only root can change.
// The premise is checked, not assumed: in both passes, passwd, group and
// nsswitch.conf must be regular root-owned files with no group/other write bits.
// Every path component must be root-owned and exclude group/other writes,
// including sticky writable ancestors. Root-owned symlinks are resolved by the
// shared config placement resolver; their targets and target paths must pass the
// same checks. Symlink mode 0777 itself grants no write authority. File bytes are
// read through the verified descriptors; file and ancestor descriptors stay held
// through both passes and are rechecked after reads. Unverifiable placement
// refuses accounts-unreadable with the account file, failed check and an
// administrator repair. Link text is bounded at 128 KiB per file per pass,
// using fixed 4 KiB probes. Placement has at most 512 checked steps after its root
// and 4096 bytes of resolved path text. The shared resolver also requires readable account files
// and searchable directories. System uses fixed /etc paths; test injection is
// through Go collection functions, never an environment variable or flag.
// The scan does not defend its account evidence against root editing account
// files while it reads.
// Account tools replace these files by rename; replacement between or during
// passes changes file identity and is refused. An in-place change that alters
// bytes read in either pass, size or observed timestamps is refused. Root's
// in-place writes that leave both passes reading the same bytes are not detected:
// a change undone between passes, or writes interleaved with one file's reads
// inside one timestamp tick. Under the assumption that each file is replaced
// only by rename during collection, the combined evidence was true at the
// moment between the two passes.
// Membership changed after the scan remains a limit.
// This only supports showing discovery rows, never exclusive write authority:
// running processes can retain removed groups, membership can change after
// the scan, and a container's databases can omit members of a mounted host group.
// The separate install-path policy is in selfbin (ADR 0142).
// Imports: standard library, x/sys/unix and pkg/spec/config (shared placement resolver).
// Must not import: other internal packages, runtime, CLI, scan or policy.
package grouptrust
