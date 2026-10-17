// SPDX-License-Identifier: Apache-2.0

//go:build (!cgo && !darwin) || osusergo

package config

// libcPasswd: os/user is its pure-Go implementation, whose user.Current (and so LookupId of the real uid) falls back
// to $USER and $HOME when /etc/passwd lacks the uid; LookupPasswd reads /etc/passwd itself.
const libcPasswd = false
