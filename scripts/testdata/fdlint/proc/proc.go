// SPDX-License-Identifier: Apache-2.0

// Package proc stands in for internal/platform/proc in scripts/check-fd_test.sh: the test points ADR 0021's
// process-start exclusion at this directory, and the exclusion, scoped to ADR 0021's text, must still leave
// ADR 0023's rule reporting here (A7).
package proc

import (
	"os"

	"golang.org/x/sys/unix"
)

func start(fd int) {
	_, _ = os.StartProcess("/bin/true", nil, &os.ProcAttr{}) // excluded: ADR 0021
	_ = unix.Close(fd)                                       // want ADR 0023
}
