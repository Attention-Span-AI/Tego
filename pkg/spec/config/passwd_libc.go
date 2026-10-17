// SPDX-License-Identifier: Apache-2.0

//go:build (cgo || darwin) && !osusergo

package config

// libcPasswd: os/user looks the passwd database up through libc (getpwuid_r, NSS), whose user.Current reports an
// error for a uid it does not find instead of building one from $USER and $HOME.
const libcPasswd = true
