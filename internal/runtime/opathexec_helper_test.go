// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// opathExecArg selects opathExecHelper: the test binary run as `<binary> opath-exec <image> <dir>` inside a run.
const opathExecArg = "opath-exec"

// opathExecHelper is the agent of TestIntegrationAnExecThroughADescriptorIsJudgedWhereItsImageLies, which a shell
// cannot be: it opens image O_PATH, a descriptor Landlock never checks and a deny_read does not stop, makes dir
// unsearchable so the supervisor cannot walk the kernel's spelling of the image back to it, and runs the image
// through /proc/self/fd/<n>. It exits 126 when that exec is refused EACCES, as a shell does, after making dir
// searchable again so the test can remove it; any other failure is 9. It returns at once when the binary was not
// started as the helper, and never returns when it was.
func opathExecHelper() {
	if len(os.Args) != 4 || os.Args[1] != opathExecArg {
		return
	}
	image, dir := os.Args[2], os.Args[3]
	fd, err := unix.Open(image, unix.O_PATH, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s O_PATH: %v\n", image, err)
		os.Exit(9)
	}
	if err := os.Chmod(dir, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "chmod %s: %v\n", dir, err)
		os.Exit(9)
	}
	err = unix.Exec("/proc/self/fd/"+strconv.Itoa(fd), []string{"tool", "-u"}, os.Environ())
	_ = os.Chmod(dir, 0o700)
	if errors.Is(err, unix.EACCES) {
		os.Exit(126)
	}
	fmt.Fprintf(os.Stderr, "exec: %v\n", err)
	os.Exit(9)
}
