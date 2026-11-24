// SPDX-License-Identifier: Apache-2.0

package contracts

import "strings"

// What a blocked helper waits for. When a helper's location budget runs out and one of its threads is in state D,
// the kernel says in /proc/<pid>/task/<tid>/wchan which function the thread sleeps in. The names below, and only
// these, say the thread waits for this computer's own disk or journal, so the refusal can say so (CheckDisk) instead of
// "a disconnected or stuck mount". The table is plain data, kept to the one in ADR 0144 ("A blocked helper's wait"):
// a name is matched exactly (or exactly followed by ".", the suffix the compiler gives a split function, such as
// ".part.0" or ".constprop.0") or by a fixed prefix, and a name that is not in it, is empty, is "0" (the kernel
// hides it) or could not be read is not known to be a disk and keeps the mount words. There is no other test.

// wchanFamily is what a wchan name belongs to.
type wchanFamily int

const (
	// wchanUnknown: not in the table, empty, "0", or unreadable. The mount words.
	wchanUnknown wchanFamily = iota
	// wchanDisk: a local disk, a journal or the block layer. The disk words.
	wchanDisk
	// wchanNetwork: a network or user-space filesystem. The mount words, as for an unknown name; listed so the table
	// says what was considered.
	wchanNetwork
)

// wchanRule is one row of the table: name is matched exactly, or as a prefix when prefix is set.
type wchanRule struct {
	name   string
	prefix bool
	family wchanFamily
}

// wchanTable is the table. It is data to be reviewed, and its rows are held to ADR 0144's by a test.
var wchanTable = []wchanRule{
	// Local disk or journal.
	{"jbd2_", true, wchanDisk}, // jbd2_log_wait_commit, jbd2_journal_*
	{"xfs_log_force", true, wchanDisk},
	{"btrfs_commit_transaction", true, wchanDisk},
	{"io_schedule", true, wchanDisk},
	{"folio_wait_bit", true, wchanDisk},
	{"wait_on_page_bit", true, wchanDisk},
	{"blk_mq_", true, wchanDisk},
	{"ext4_", true, wchanDisk},
	// Network or user-space filesystem.
	{"fuse_", true, wchanNetwork},
	{"request_wait_answer", false, wchanNetwork},
	{"nfs_", true, wchanNetwork},
	{"rpc_", true, wchanNetwork},
	{"cifs_", true, wchanNetwork},
	{"smb", true, wchanNetwork},
	{"ceph_", true, wchanNetwork},
	{"p9_", true, wchanNetwork},
}

// classifyWchan says which family a wchan name belongs to. The network rows come first only so that a name that could
// be read as either is never a disk: no row of the two overlaps today.
func classifyWchan(name string) wchanFamily {
	if name == "" || name == "0" {
		return wchanUnknown
	}
	for _, family := range []wchanFamily{wchanNetwork, wchanDisk} {
		for _, r := range wchanTable {
			if r.family != family {
				continue
			}
			if r.prefix && strings.HasPrefix(name, r.name) || !r.prefix && (name == r.name || strings.HasPrefix(name, r.name+".")) {
				return family
			}
		}
	}
	return wchanUnknown
}

// onlyDiskWaits reports whether at least one thread is in state D and every thread in state D waits in the disk
// family: one thread that waits for anything else (a network or user-space filesystem, an unknown name, an unreadable
// one) keeps the mount words.
func onlyDiskWaits(threads map[int]Thread) bool {
	disk := false
	for _, t := range threads {
		if t.State != 'D' {
			continue
		}
		if classifyWchan(t.WChan) != wchanDisk {
			return false
		}
		disk = true
	}
	return disk
}
