// SPDX-License-Identifier: Apache-2.0

package ask

import "net"

// IdentifyFunc is how ask.sock reads who is on a connection: the peer, its start time, or an error.
type IdentifyFunc = func(*net.UnixConn) (Peer, uint64, error)

// SwapIdentify makes ask.sock read its peers through wrap(the real reading) and returns the call that puts the real
// one back. Swap before the broker under test is made and restore after it is closed: the socket's handlers read
// the variable, and only the broker's start and close order them against the test.
func SwapIdentify(wrap func(real IdentifyFunc) IdentifyFunc) (restore func()) {
	was := identify
	identify = wrap(was)
	return func() { identify = was }
}
