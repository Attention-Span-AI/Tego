// SPDX-License-Identifier: Apache-2.0

package edgelint

// The packages that dial, listen or open a socket inside their own calls, which the edge's depguard rule denies
// whole: the standard library's and golang.org/x/net's (a direct dependency, so an edge package can import any of
// them).
import (
	_ "log/syslog"        // want edge-holds-no-authority
	_ "net/http/httptest" // want edge-holds-no-authority
	_ "net/rpc"           // want edge-holds-no-authority
	_ "net/rpc/jsonrpc"   // want edge-holds-no-authority
	_ "net/smtp"          // want edge-holds-no-authority

	_ "golang.org/x/net/context/ctxhttp" // want edge-holds-no-authority
	_ "golang.org/x/net/dict"            // want edge-holds-no-authority
	_ "golang.org/x/net/icmp"            // want edge-holds-no-authority
	_ "golang.org/x/net/nettest"         // want edge-holds-no-authority
	_ "golang.org/x/net/proxy"           // want edge-holds-no-authority
	_ "golang.org/x/net/websocket"       // want edge-holds-no-authority
)
