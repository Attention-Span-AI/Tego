// SPDX-License-Identifier: Apache-2.0

// Command ifaces is a workload for ADR 0128: it asks Go's own net package for the host's interfaces and their
// addresses and writes what it got to the file its first argument names, as JSON. Go never goes through the C library
// here: net.Interfaces opens a netlink socket of its own (syscall.NetlinkRIB: bind, sendto, getsockname, recvfrom).
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: ifaces <out.json>")
		os.Exit(2)
	}
	var res struct {
		Names []string `json:"names"`
		Addrs []string `json:"addrs"`
		Err   string   `json:"err,omitempty"`
	}
	ifs, err := net.Interfaces()
	if err == nil {
		for _, i := range ifs {
			res.Names = append(res.Names, i.Name)
		}
		var addrs []net.Addr
		if addrs, err = net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				res.Addrs = append(res.Addrs, a.String())
			}
		}
	}
	if err != nil {
		res.Err = err.Error()
	}
	b, err := json.Marshal(res)
	if err == nil {
		err = os.WriteFile(os.Args[1], b, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ifaces:", err)
		os.Exit(1)
	}
}
