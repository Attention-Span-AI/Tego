// SPDX-License-Identifier: Apache-2.0

package record

import (
	"fmt"
	"net/netip"
	"strings"
)

// LearnNote is the top-level contract's account of destinations learn withheld
// after a secret read near a send (ADR 0016). It grants no permission and proves
// neither a leak nor that the contract has stayed as learn wrote it.
type LearnNote struct {
	Run      string   `json:"run" yaml:"run"`
	Withheld []string `json:"withheld" yaml:"withheld"`
}

// Validate checks learn history before a contract or run record can carry it.
// Only exact TCP/UDP addresses are retained, never host names or broad rules.
func (n *LearnNote) Validate() error {
	if n == nil {
		return nil
	}
	const at = "run_start.contract_source.learn"
	if !runIDRe.MatchString(n.Run) {
		return fieldErr("learn", at+".run", "not a run id")
	}
	if len(n.Withheld) == 0 || len(n.Withheld) > 100000 {
		return fieldErr("learn", at+".withheld", "need 1 to 100000 endpoints")
	}
	for i, s := range n.Withheld {
		if canonical, ok := LearnEndpoint(s); !ok || canonical != s {
			return fieldErr("learn", fmt.Sprintf("%s.withheld.%d", at, i), "not a canonical TCP or UDP address and port")
		}
		if i > 0 && s <= n.Withheld[i-1] {
			return fieldErr("learn", fmt.Sprintf("%s.withheld.%d", at, i), "endpoints must be sorted and distinct")
		}
	}
	return nil
}

// LearnEndpoint validates an exact endpoint held by LearnNote. The result is its
// canonical protocol://address:port spelling, with mapped IPv4 addresses unmapped.
func LearnEndpoint(s string) (string, bool) {
	proto, addr, ok := strings.Cut(s, "://")
	if !ok || (proto != "tcp" && proto != "udp") {
		return "", false
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
		return "", false
	}
	canonical := proto + "://" + netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	return canonical, true
}
