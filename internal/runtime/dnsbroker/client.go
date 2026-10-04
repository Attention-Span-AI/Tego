// SPDX-License-Identifier: Apache-2.0

package dnsbroker

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Exchange is a cooperating DNS client, not a system resolver override. The
// expected launcher PID is required and checked against the kernel socket peer.
func Exchange(ctx context.Context, runDir string, serverPID int, query []byte) ([]byte, error) {
	q, err := queryMessage(query)
	if err != nil {
		return nil, err
	}
	if serverPID <= 0 {
		return nil, ErrUnauthorized
	}
	dir, path, err := openSocketDir(runDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	// A governed connect is resolved by the supervisor. Literal short paths
	// preserve its no-magic-link boundary; long standalone fixture paths use
	// the held directory but cannot be promised as a governed runtime endpoint.
	literal := filepath.Join(dir.Name(), SocketName)
	if len(literal) < len(unix.RawSockaddrUnix{}.Path) {
		path = literal
	}
	d := net.Dialer{}
	connection, err := d.DialContext(ctx, "unixpacket", path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = connection.Close() }()
	c, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, ErrProtocol
	}
	peer, err := socketPeer(c)
	if err != nil || peer.PID != serverPID {
		return nil, ErrUnauthorized
	}
	pidfd, err := unix.PidfdOpen(serverPID, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(pidfd) }()
	if !pidfdAlive(pidfd) {
		return nil, ErrUnauthorized
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if _, err = c.Write(query); err != nil {
		return nil, err
	}
	raw := make([]byte, MaxPacket+1)
	// Ordinary read cannot import SCM_RIGHTS and remains usable under the
	// strict agent filter's recvmsg/recvmmsg ban. The extra byte detects any
	// packet exceeding the protocol bound even when seqpacket truncates it.
	n, err := c.Read(raw)
	if err != nil {
		return nil, err
	}
	if n > MaxPacket || !pidfdAlive(pidfd) {
		return nil, ErrProtocol
	}
	raw = raw[:n]
	if _, _, err = responseMessage(raw, q.ID, q.Questions[0]); err != nil {
		return nil, fmt.Errorf("broker response: %w", err)
	}
	return raw, nil
}
