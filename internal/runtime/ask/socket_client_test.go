// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"context"
	"net"
	"os"

	"github.com/attention-span-ai/tego/internal/askclient"
)

// The client moved to internal/askclient; the names this package's tests reach it by stay.

// call sends cmd and reads the reply (askclient.Call); alternate, when set, is the descriptor the packet passes.
func call(ctx context.Context, dir string, expectedPID int, cmd command, alternate *AlternateFile) (response, error) {
	var rights askclient.Descriptor
	if alternate != nil {
		rights = alternate
	}
	return askclient.Call(ctx, dir, expectedPID, cmd, rights)
}

// readResponse reads one broker packet (askclient.ReadResponse).
func readResponse(c *net.UnixConn) (response, error) { return askclient.ReadResponse(c) }

// socketDir opens a run directory as the broker binds by it (askclient.OpenSocketDir).
func socketDir(path string) (*os.File, string, error) { return askclient.OpenSocketDir(path) }
