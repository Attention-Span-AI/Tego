// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// ReceiveRights owns every descriptor an SCM_RIGHTS message in oob carried (the control bytes recvmsg
// filled, MSG_CMSG_CLOEXEC set by the caller). The kernel has installed each number in this process's table
// by the time recvmsg returns, so a number left unowned is a leak, and one wrapped twice closes twice (ADR 0023
// A4: unix.ParseUnixRights is forbidden outside this package). The messages are walked one at a time, so a
// malformed message later in the buffer cannot lose the numbers of the earlier ones: on any error every
// number already found is closed and the error returned. Numbers in a message whose own header is malformed
// cannot be located, and the kernel's MSG_CTRUNC is the caller's to check.
func ReceiveRights(oob []byte) ([]*FD, error) {
	var owned []*FD
	fail := func(err error) ([]*FD, error) {
		for _, f := range owned {
			_ = f.Close()
		}
		return nil, err
	}
	for rest := oob; len(rest) > 0; {
		hdr, data, remainder, err := unix.ParseOneSocketControlMessage(rest)
		if err != nil {
			return fail(fmt.Errorf("parse control message at byte %d of %d: %w", len(oob)-len(rest), len(oob), err))
		}
		rest = remainder
		if hdr.Level != unix.SOL_SOCKET || hdr.Type != unix.SCM_RIGHTS {
			continue
		}
		if len(data)%4 != 0 {
			// Own the whole numbers before refusing the message.
			data = data[:len(data)-len(data)%4]
			err = errors.New("SCM_RIGHTS payload is not a whole number of descriptors")
		}
		for i := 0; i+4 <= len(data); i += 4 {
			n := int(int32(binary.NativeEndian.Uint32(data[i:])))
			seal()
			f, ferr := newFD(n, 0, false)
			if ferr != nil {
				return fail(fmt.Errorf("SCM_RIGHTS: %w", ferr))
			}
			owned = append(owned, f)
		}
		if err != nil {
			return fail(err)
		}
	}
	return owned, nil
}
