// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// addWSLWarnings reports reach, not a new tier gate. Configuration alone is no
// proof that a running instance applied it; inspect the mounted channels too.
func (r *Report) addWSLWarnings() {
	warnings := wslWarnings(r.Kernel)
	if len(warnings) == 0 {
		return
	}
	for i := range r.Results {
		if r.Results[i].ID == CheckKernel {
			r.Results[i].Detail += "; WARNING: WSL host reach: " + strings.Join(warnings, "; ")
			return
		}
	}
}

var wslWarnings = func(kernel string) []string {
	return wslHostReach(kernel, os.DirFS("/"), os.Getenv("PATH"), os.Getenv("WSL_INTEROP"))
}

func wslHostReach(kernel string, files fs.FS, path, interop string) []string {
	lower := strings.ToLower(kernel)
	_, socketErr := fs.Stat(files, "run/WSL")
	_, handlerErr := fs.Stat(files, "proc/sys/fs/binfmt_misc/WSLInterop")
	if !(strings.Contains(lower, "microsoft") && strings.Contains(lower, "wsl2")) && socketErr != nil && handlerErr != nil {
		return nil
	}
	// A distro cannot disable the shared network using wsl.conf. Neither the
	// current NAT gateway nor absence of a localhost listener proves isolation.
	warnings := []string{
		"Windows network services can remain reachable (NAT gateway or mirrored localhost; firewall and contract rules apply)",
		"VM socket transport (AF_VSOCK; DrvFs ports 50002/50003): isolation is not established by disabling automount or interop; a net section refuses new AF_VSOCK sockets",
	}
	if interop != "" {
		warnings = append(warnings, "Windows program execution is OPEN for this session (WSL_INTEROP is set)")
	}
	mounts, err := fs.ReadFile(files, "proc/self/mountinfo")
	if err != nil {
		warnings = append(warnings, "mounts unknown: cannot establish whether Windows drives, /mnt/wsl or /mnt/wslg are exposed")
	} else {
		for _, line := range strings.Split(string(mounts), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 7 {
				continue
			}
			at := strings.Index(line, " - ")
			if at < 0 {
				continue
			}
			tail := line[at+3:]
			if strings.HasPrefix(tail, "drvfs ") || strings.Contains(tail, "aname=drvfs") || strings.HasPrefix(tail, "virtiofs ") {
				warnings = append(warnings, "Windows filesystem mount at "+fields[4])
			}
		}
	}
	var gui []string
	for _, name := range []string{
		"mnt/wslg/.X11-unix/X0", "mnt/wslg/PulseServer", "mnt/wslg/runtime-dir/wayland-0",
		"tmp/.X11-unix/X0", fmt.Sprintf("run/user/%d/wayland-0", os.Getuid()),
	} {
		info, err := fs.Stat(files, name)
		if err == nil && info.Mode()&fs.ModeSocket != 0 {
			gui = append(gui, "/"+name)
		} else if err != nil && !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("%s: GUI/audio reach unknown (%v)", name, err))
		}
	}
	if len(gui) != 0 {
		warnings = append(warnings, "WSLg GUI/audio sockets present at "+strings.Join(gui, ", ")+" (access was not tested)")
	}
	if info, err := fs.Stat(files, "dev/dxg"); err == nil && info.Mode()&fs.ModeDevice != 0 {
		warnings = append(warnings, "Windows GPU device node /dev/dxg is present (access was not tested)")
	} else if err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, fmt.Sprintf("dev/dxg: reach unknown (%v)", err))
	}
	for _, channel := range []struct{ path, name string }{
		{"mnt/wsl", "cross-distribution shared files /mnt/wsl (other distributions may publish files and sockets)"},
		{"run/WSL", "interop sockets /run/WSL (presence does not prove Windows execution is enabled)"},
	} {
		if _, err := fs.Stat(files, channel.path); err == nil {
			warnings = append(warnings, channel.name)
		} else if !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("%s: reach unknown (%v)", channel.path, err))
		}
	}
	b, err := fs.ReadFile(files, "proc/sys/fs/binfmt_misc/WSLInterop")
	if err == nil && strings.HasPrefix(string(b), "enabled") {
		warnings = append(warnings, "Windows executable binfmt handler enabled (VM-wide; interop.enabled=false must also close the distro server)")
	} else if err != nil && !os.IsNotExist(err) {
		warnings = append(warnings, "Windows executable binfmt handler unreadable: reach unknown")
	}
	for _, entry := range strings.Split(path, ":") {
		if strings.HasPrefix(entry, "/mnt/") || strings.HasPrefix(entry, "/usr/lib/wsl/") {
			warnings = append(warnings, "Windows PATH entry "+entry)
		}
	}
	const maxWarnings = 8
	if len(warnings) > maxWarnings {
		omitted := len(warnings) - maxWarnings
		warnings = append(warnings[:maxWarnings], fmt.Sprintf("%d more host-reach observations omitted", omitted))
	}
	return warnings
}
