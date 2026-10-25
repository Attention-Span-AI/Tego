// SPDX-License-Identifier: Apache-2.0

package askclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// OpenSocketDir opens the run directory path without following a symlink at its last component, and returns it with
// the socket's address under /proc/self/fd, which keeps socket addresses short even for deeply nested configured
// ledger roots. The caller closes the directory once the socket is dialled or bound: the client dials by it and the
// broker in internal/runtime/ask binds by it, so both ends name the socket one way. Its two raw descriptor sites
// moved here from internal/runtime/ask with it (tools/fdcheck/baseline.txt).
func OpenSocketDir(path string) (*os.File, string, error) { return socketDir(path) }

// socketDir is OpenSocketDir's body under the name it had in internal/runtime/ask: ADR 0023 A9's ratchet against the
// base lets a raw site arrive in a package only with the declaration it is in, matched by name.
func socketDir(path string) (*os.File, string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	dir := os.NewFile(uintptr(fd), path)
	return dir, fmt.Sprintf("/proc/self/fd/%d/%s", fd, askproto.SocketName), nil
}

// PeerCred is the kernel's credentials of c's peer as of the connect (SO_PEERCRED).
func PeerCred(c *net.UnixConn) (*unix.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) { cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return nil, err
	}
	if controlErr != nil {
		return nil, controlErr
	}
	return cred, nil
}

// Descriptor is a file a command passes beside its packet (SCM_RIGHTS): Control runs fn with its descriptor, held
// open against a concurrent Close for fn's duration.
type Descriptor interface {
	Control(fn func(fd int) error) error
}

// Call sends cmd to the broker of the run directory dir and reads the reply. expectedPID must come from a verified
// live launcher pidfd and run lock (Launcher), retained until the call returns: a server whose SO_PEERCRED pid is
// another is refused (ErrUnauthorized), so a replacement pathname socket cannot pose as the run's broker. rights,
// when not nil, is the descriptor the packet passes (Command.Alternate).
func Call(ctx context.Context, dir string, expectedPID int, cmd askproto.Command, rights Descriptor) (askproto.Response, error) {
	if expectedPID <= 0 {
		return askproto.Response{}, askproto.ErrUnauthorized
	}
	f, path, err := OpenSocketDir(dir)
	if err != nil {
		return askproto.Response{}, err
	}
	defer func() { _ = f.Close() }()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unixpacket", path)
	if err != nil {
		return askproto.Response{}, err
	}
	c := conn.(*net.UnixConn)
	defer func() { _ = c.Close() }()
	p, err := PeerCred(c)
	if err != nil {
		return askproto.Response{}, err
	}
	if int(p.Pid) != expectedPID {
		return askproto.Response{}, askproto.ErrUnauthorized
	}
	deadline := time.Now().Add(askproto.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	ready, err := ReadResponse(c)
	if err != nil {
		return askproto.Response{}, err
	}
	if len(ready.Ready) != askproto.NonceLen {
		return askproto.Response{}, askproto.ErrProtocol
	}
	cmd.Nonce = ready.Ready
	data, err := json.Marshal(cmd)
	if err != nil {
		return askproto.Response{}, err
	}
	if rights != nil {
		err = rights.Control(func(fd int) error {
			_, _, err := c.WriteMsgUnix(data, unix.UnixRights(fd), nil)
			return err
		})
	} else {
		_, err = c.Write(data)
	}
	if err != nil {
		return askproto.Response{}, err
	}
	return ReadResponse(c)
}

// ReadResponse reads one broker packet from c (askproto.DecodeResponse); a truncated packet is ErrProtocol.
func ReadResponse(c *net.UnixConn) (askproto.Response, error) {
	buf := make([]byte, askproto.MaxResponse)
	n, _, flags, _, err := c.ReadMsgUnix(buf, nil)
	if err != nil {
		return askproto.Response{}, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return askproto.Response{}, askproto.ErrProtocol
	}
	return askproto.DecodeResponse(buf[:n])
}

// List lists held requests.
func List(ctx context.Context, dir string, expectedPID int) ([]askproto.Summary, error) {
	r, e := Call(ctx, dir, expectedPID, askproto.Command{Action: askproto.ActionList}, nil)
	return r.Pending, e
}

// Detail is one held request, its target whole.
func Detail(ctx context.Context, dir string, expectedPID int, id string) (askproto.Request, error) {
	if !askproto.ValidID(id) {
		return askproto.Request{}, askproto.ErrProtocol
	}
	r, e := Call(ctx, dir, expectedPID, askproto.Command{Action: askproto.ActionDetail, AskID: id}, nil)
	if e != nil {
		return askproto.Request{}, e
	}
	if r.Request == nil {
		return askproto.Request{}, askproto.ErrProtocol
	}
	return *r.Request, nil
}

// Answer answers one held request. With always, the answer also stands for the rest of the run, for the same
// operation, rule and exact target (ErrNotRememberable, ErrStandingFull or ErrStandingBusy leave the request
// pending, so the caller can answer it once instead).
func Answer(ctx context.Context, dir string, expectedPID int, id string, approve, always bool) (askproto.Decision, error) {
	if !askproto.ValidID(id) {
		return askproto.Decision{}, askproto.ErrProtocol
	}
	cmd := askproto.Command{Action: askproto.ActionAnswer, AskID: id, Approve: &approve}
	if always {
		cmd.Remember = &always
	}
	return answer(ctx, dir, expectedPID, cmd, nil)
}

// Alternate answers one held file open with an alternate (ADR 0057): file, which the caller opened when the person
// named it, by named, with no symbolic link on the way, is passed to the broker as a descriptor, and the supervisor
// reopens that descriptor, as the agent, in place of the target. The caller keeps file and closes it. With always
// the alternate also stands for every later request for the same operation, rule and exact target in this run.
// ErrNoAlternate, ErrBadAlternate and the "always" errors leave the request pending.
func Alternate(ctx context.Context, dir string, expectedPID int, id, named string, file Descriptor, always bool) (askproto.Decision, error) {
	if !askproto.ValidID(id) || file == nil || !askproto.ValidAlternate(named) {
		return askproto.Decision{}, askproto.ErrProtocol
	}
	no := false
	cmd := askproto.Command{Action: askproto.ActionAnswer, AskID: id, Approve: &no, Alternate: &named}
	if always {
		cmd.Remember = &always
	}
	return answer(ctx, dir, expectedPID, cmd, file)
}

func answer(ctx context.Context, dir string, expectedPID int, cmd askproto.Command, file Descriptor) (askproto.Decision, error) {
	r, e := Call(ctx, dir, expectedPID, cmd, file)
	if e != nil {
		return askproto.Decision{}, e
	}
	if r.Decision == nil {
		return askproto.Decision{}, askproto.ErrProtocol
	}
	return *r.Decision, nil
}
