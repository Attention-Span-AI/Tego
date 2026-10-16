// SPDX-License-Identifier: Apache-2.0

package landlock

// filterTestOmit is the filter's test seam: it reports whether a syscall, by its table name, is left out of the
// notify arm and the root-tier arm. A product build leaves it as it is here, which omits nothing; a build with -tags
// tegotesthooks sets it from the environment (filter_testhook.go), so a root test can let a syscall past the arms
// that stand in front of a decision plane hook and see what that hook alone answers. `bpf(2)` is refused in the
// filter at tiers 2 and 3 (ADR 0033) and add_key, request_key and keyctl are notified to the supervisor (SEMANTICS §1), so
// in a product run neither reaches security_bpf or security_key_permission, which are the plane's second layer
// (enforce-plane §2.20). It is read only where buildFilter walks those two arms.
var filterTestOmit = func(string) bool { return false }
