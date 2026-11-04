// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"os"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

// ttyGrants admits the multiplexor and the inherited terminal, including its
// device ioctl right (G6). The child's independent layer withholds every other
// terminal even if the main domain grants /dev recursively.
func (bd *builder) ttyGrants() error {
	if bd.rt.Builtins == nil {
		return nil
	}
	access := bd.profile.mask(accessReadFile | accessWriteFile | accessIoctlDev)
	for _, p := range []string{"/dev/ptmx", "/dev/pts/ptmx", "/dev/tty"} {
		if _, err := os.Stat(p); err == nil {
			if _, err := bd.hold(p, kindWrite, access); err != nil {
				return err
			}
		}
	}
	dev, err := sys.ControllingTTYDevice()
	if err != nil {
		return err
	}
	if dev == 0 {
		return nil
	}
	for _, dir := range []string{"/dev/pts", "/dev"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if !agent.OtherTTY(p) {
				continue
			}
			var st unix.Stat_t
			if err := unix.Stat(p, &st); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT == unix.S_IFCHR && st.Rdev == dev {
				if _, err := bd.hold(p, kindWrite, access); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
