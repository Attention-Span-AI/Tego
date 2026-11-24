// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package config

import "strings"

// SetOwnerOnlyForTest gives m the root-only approval floor without a trusted system file: a test of another
// package can then take a launch path that begins with ApprovalAuthority().OwnerOnly() without root or /etc.
// The pinned source is a stand-in digest with no walk, so Check on it proves nothing and a launch that reaches a
// second read of the system layer is not what such a test asserts. Only a test build has it.
func SetOwnerOnlyForTest(m *Machine) {
	m.LocalRoles = Setting[string]{Value: LocalRolesOwnerOnly}
	m.localAuthority = LocalAuthority{digest: strings.Repeat("ab", 32)}
	m.localAuthorityUnknown = false
}
