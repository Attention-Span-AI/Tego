// SPDX-License-Identifier: Apache-2.0

package hostaddr

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// sizeofFibRuleHdr is struct fib_rule_hdr (linux/fib_rules.h): family, dst_len, src_len, tos, table, res1, res2,
// action and a 32-bit flags word.
const sizeofFibRuleHdr = 12

// maxUID is the highest uid a rule can name (the kernel reserves 2^32-1 as "no uid").
const maxUID = 0xfffffffe

// userSet is the users whose traffic a policy rule's `uidrange` can select: the run's own. A supervisor running as root
// (the root tiers) does not know which user its agent runs as, so every user is possible there; any rule with a
// `uidrange` then can select it.
type userSet struct {
	uids []uint32
	any  bool
}

// runUsers is the users this process's runs generate traffic as: its real and effective user, or every user when it is
// root.
func runUsers() userSet {
	uid, euid := os.Getuid(), os.Geteuid()
	if uid == 0 || euid == 0 {
		return userSet{any: true}
	}
	return userSet{uids: []uint32{uint32(uid), uint32(euid)}} //nolint:gosec // a uid fits 32 bits
}

// holds reports whether a user of the set is in [start, end], and whether every user of the set is.
func (u userSet) holds(start, end uint32) (some, all bool) {
	if u.any {
		return true, start == 0 && end >= maxUID
	}
	all = len(u.uids) > 0
	for _, id := range u.uids {
		if id >= start && id <= end {
			some = true
		} else {
			all = false
		}
	}
	return some, all
}

// reachable is the non-standard tables, by family, that a policy rule the run's own traffic can match leads to. The
// tables the default rules look up (local, main and default) always count (lookedUp).
type reachable struct{ v4, v6 map[uint32]bool }

// has reports whether the routes of table, in family, are looked up for the run's own traffic.
func (r *reachable) has(family uint8, table uint32) bool {
	if lookedUp(table) {
		return true
	}
	if family == unix.AF_INET6 {
		return r.v6[table]
	}
	return r.v4[table]
}

func (r *reachable) add(family uint8, table uint32) {
	m := &r.v4
	if family == unix.AF_INET6 {
		m = &r.v6
	}
	if *m == nil {
		*m = map[uint32]bool{}
	}
	(*m)[table] = true
}

// parseRules reads one datagram of the RTM_GETRULE dump of family under sequence number seq, and adds the table of each
// rule that can match the run's own traffic (ruleReaches) to reach. done says the dump ended. Errors are walkDump's,
// and a rule message shorter than its header or with a malformed attribute is one too: the tables read so far are not
// the rules' answer, and the caller returns no table.
func parseRules(b []byte, seq uint32, family uint8, users userSet, reach *reachable) (done bool, err error) {
	return walkDump(b, seq, func(mtype uint16, body []byte) error {
		if mtype != unix.RTM_NEWRULE {
			return nil
		}
		table, ok, err := ruleReaches(body, family, users)
		if err != nil {
			return err
		}
		if ok {
			reach.add(family, table)
		}
		return nil
	})
}

// ruleReaches reads one rule message and reports the table it leads to and whether the run's own traffic can match it.
// The kernel matches a rule's selectors all together and, for a rule marked `not`, takes the opposite (fib_rule_match);
// the run's traffic is locally generated, with mark 0, an output interface of the agent's choosing (it can bind its
// sockets to one, VRF devices included), the loopback as input interface, and the user the run has. Each selector is told by whether the traffic can match it and whether it can
// miss it; a selector the traffic's own choices decide (`from`, `to`, `tos`, `ipproto`, the ports) is taken as able to
// do both, which only counts more tables as this host's. A rule that does not look a table up (`goto`, `blackhole`,
// `unreachable`, `prohibit`, `nop`) leads to none.
func ruleReaches(m []byte, family uint8, users userSet) (table uint32, reaches bool, err error) {
	ne := binary.NativeEndian
	if len(m) < sizeofFibRuleHdr {
		return 0, false, fmt.Errorf("a rule message of %d bytes", len(m))
	}
	if m[0] != family {
		return 0, false, nil // another family's rule in an unfiltered dump
	}
	dstLen, srcLen, tos, hdrTable, action, flags := m[1], m[2], m[3], m[4], m[7], ne.Uint32(m[8:])
	table = uint32(hdrTable)
	// canMatch is every selector able to match the run's traffic; canMiss, some selector able to miss it.
	canMatch, canMiss := true, false
	var mark uint32
	mask := uint32(0xffffffff) // a rule with a mark and no FRA_FWMASK in the message matches all its bits
	selector := func(match, miss bool) {
		canMatch = canMatch && match
		canMiss = canMiss || miss
	}
	if dstLen != 0 || srcLen != 0 || tos != 0 {
		selector(true, true)
	}
	for attrs := m[sizeofFibRuleHdr:]; len(attrs) > 0; {
		if len(attrs) < unix.SizeofRtAttr {
			return 0, false, fmt.Errorf("%d bytes after the last rule attribute", len(attrs))
		}
		l, at := int(ne.Uint16(attrs[0:])), ne.Uint16(attrs[2:])&^(unix.NLA_F_NESTED|unix.NLA_F_NET_BYTEORDER)
		if l < unix.SizeofRtAttr || l > len(attrs) {
			return 0, false, fmt.Errorf("rule attribute length %d of %d bytes", l, len(attrs))
		}
		data := attrs[unix.SizeofRtAttr:l]
		switch at {
		case unix.FRA_TABLE:
			if len(data) != 4 {
				return 0, false, fmt.Errorf("a rule table attribute of %d bytes", len(data))
			}
			table = ne.Uint32(data)
		case unix.FRA_FWMARK:
			if len(data) != 4 {
				return 0, false, fmt.Errorf("a rule mark attribute of %d bytes", len(data))
			}
			mark = ne.Uint32(data)
		case unix.FRA_FWMASK:
			if len(data) != 4 {
				return 0, false, fmt.Errorf("a rule mark mask attribute of %d bytes", len(data))
			}
			mask = ne.Uint32(data)
		case unix.FRA_OIFNAME:
			// An unprivileged agent can bind a socket to an interface (SO_BINDTODEVICE, Linux 5.7), which sets the flow's
			// output interface, so this selector can match and can miss (an unbound send misses it).
			selector(true, true)
		case unix.FRA_L3MDEV:
			if len(data) != 1 {
				return 0, false, fmt.Errorf("a rule l3mdev attribute of %d bytes", len(data))
			}
			if data[0] != 0 {
				selector(true, true) // the same setsockopt binds a VRF device, which this rule selects
			}
		case unix.FRA_IIFNAME:
			if strings.TrimRight(string(data), "\x00") == "lo" {
				selector(true, false) // a locally generated flow comes in on the loopback
			} else {
				selector(false, true)
			}
		case unix.FRA_UID_RANGE:
			if len(data) != 8 {
				return 0, false, fmt.Errorf("a rule uid range attribute of %d bytes", len(data))
			}
			some, all := users.holds(ne.Uint32(data[0:]), ne.Uint32(data[4:]))
			selector(some, !all)
		case unix.FRA_SRC, unix.FRA_DST, unix.FRA_IP_PROTO, unix.FRA_SPORT_RANGE, unix.FRA_DPORT_RANGE, unix.FRA_TUN_ID:
			selector(true, true)
		}
		attrs = attrs[min(align4(l), len(attrs)):]
	}
	if mark != 0 {
		// The kernel misses a rule when (flow mark ^ rule mark) & mask is not 0 (fib4_rule_match); the run's traffic has mark
		// 0 (setting one needs CAP_NET_ADMIN), so the rule is missed exactly when mark & mask is not 0.
		if mark&mask != 0 {
			selector(false, true)
		} else {
			selector(true, false)
		}
	}
	if action != unix.FR_ACT_TO_TBL || table == unix.RT_TABLE_UNSPEC {
		return table, false, nil
	}
	if flags&unix.FIB_RULE_INVERT != 0 {
		return table, canMiss, nil
	}
	return table, canMatch, nil
}

// UnreadWords says which tables hold `local`, `broadcast` or `anycast` routes this reading did not count, and why, for
// `tego doctor` and the snapshot's note; "" when there are none.
func (t LocalTable) UnreadWords() string {
	if len(t.Unread) == 0 {
		return ""
	}
	names := make([]string, len(t.Unread))
	for i, n := range t.Unread {
		names[i] = strconv.FormatUint(uint64(n), 10)
	}
	more := ""
	if len(t.Unread) >= maxUnread {
		more = " and possibly more"
	}
	return "routing table " + strings.Join(names, ", ") + more + " holds local, broadcast or anycast routes that Tego does not read as this host's: " +
		"no policy rule that the run's own traffic can match leads to it (a mark selects it, or nothing does), " +
		"so a net rule or block for this host does not cover a destination only those routes deliver here"
}
