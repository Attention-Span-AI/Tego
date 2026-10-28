// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/attention-span-ai/tego/internal/platform/peer"
)

// dashboardCheck is doctor's answer to whether the kernel can tell which run a dashboard connection comes from:
// tego-control asks sock_diag for every request's client socket (peer.TCPSocketCgroup) and refuses any request it
// cannot attribute (docs/DASHBOARD.md, docs/adr/0123-dashboard-threat-model.md). Without the inet_diag and tcp_diag
// modules every sign-in and POST is refused, and the 403 was the first sign of it (Root-suite fixes, 2026-10-27).
// It is a dashboard dependency, not a tier's: a failing check is a warning, never doctor's exit.
type dashboardCheck struct {
	// OK is true when the lookup answered for the probe's own loopback connection.
	OK bool `json:"ok"`
	// Missing is true when the kernel answers no TCP socket lookup at all (peer.ErrNoTCPDiag).
	Missing bool `json:"missing,omitempty"`
	// Detail is what doctor prints after "dashboard: ".
	Detail string `json:"detail"`
	// Fix is the command that makes it work, "" when OK or when no fix is known.
	Fix string `json:"fix,omitempty"`
}

// The words of dashboardCheck, held here so the test reads the same strings the reader does.
const (
	dashboardOK      = "the dashboard can tell which run a connection comes from"
	dashboardMissing = "the kernel answers no TCP socket lookup (the inet_diag and tcp_diag modules are not loaded): " +
		"tego-control refuses every dashboard action until it is loaded"
	dashboardFix = "load the tcp_diag module: sudo modprobe tcp_diag (and add it to /etc/modules-load.d)"
)

// errDashboardUnchecked wraps a probe that could not make its own loopback connection: nothing was asked of sock_diag,
// so the line says it did not check rather than that the dashboard refuses (a doctor run where loopback is closed).
var errDashboardUnchecked = errors.New("the probe's own loopback connection failed")

// probeTCPDiag is the probe classifyTCPDiag reads, a variable so a test hands it an answer.
var probeTCPDiag = loopbackTCPDiag

// checkDashboard runs the probe and classifies its answer.
func checkDashboard() dashboardCheck { return classifyTCPDiag(probeTCPDiag()) }

// classifyTCPDiag reads the probe's error: nil is a working lookup, peer.ErrNoTCPDiag the missing modules, anything
// else a lookup that failed for another reason, said as it is (an older kernel's ErrNoCgroupID refuses the dashboard
// too, but no module load fixes it).
func classifyTCPDiag(err error) dashboardCheck {
	switch {
	case err == nil:
		return dashboardCheck{OK: true, Detail: dashboardOK}
	case errors.Is(err, peer.ErrNoTCPDiag):
		return dashboardCheck{Missing: true, Detail: dashboardMissing, Fix: dashboardFix}
	case errors.Is(err, errDashboardUnchecked):
		return dashboardCheck{Detail: "not checked: " + err.Error()}
	}
	return dashboardCheck{Detail: "cannot tell which run a connection comes from (" + err.Error() +
		"): tego-control refuses every dashboard action on this machine"}
}

// loopbackTCPDiag opens a loopback TCP connection of its own and asks peer's lookup, the one tego-control makes,
// for the client half. The listener is on an ephemeral port of 127.0.0.1 and is closed before it returns.
func loopbackTCPDiag() error {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("loopback listener: %w: %w", errDashboardUnchecked, err)
	}
	defer func() { _ = ln.Close() }() // the probe's own listener: closing it loses nothing
	accepted := make(chan net.Conn, 1)
	go func() { // owned here: Accept returns on the dial below, or on ln.Close when the dial fails
		c, aerr := ln.Accept()
		if aerr != nil {
			c = nil
		}
		accepted <- c
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		_ = ln.Close() // ends the Accept above
		<-accepted
		return fmt.Errorf("loopback dial: %w: %w", errDashboardUnchecked, err)
	}
	defer func() { _ = conn.Close() }() // the probe's own connection
	if srv := <-accepted; srv != nil {
		defer func() { _ = srv.Close() }() // the probe's own connection
	}
	client, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("loopback client address: %w: %w", errDashboardUnchecked, err)
	}
	server, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("loopback server address: %w: %w", errDashboardUnchecked, err)
	}
	_, err = peer.TCPSocketCgroup(client, server)
	return err
}

// writeDashboardCheck writes the check as one line in the probe lines' shape (doctor.WriteResults): "ok", or "warn"
// where a probe would say FAIL, since this check never decides doctor's exit, then "dashboard: <detail>" and the fix.
func writeDashboardCheck(w io.Writer, c dashboardCheck) error {
	state := "warn"
	if c.OK {
		state = "ok  "
	}
	line := "\n" + state + " dashboard: " + c.Detail
	if c.Fix != "" {
		line += "; fix: " + c.Fix
	}
	if _, err := fmt.Fprintln(w, line); err != nil {
		return fmt.Errorf("doctor: write dashboard: %w", err)
	}
	return nil
}
