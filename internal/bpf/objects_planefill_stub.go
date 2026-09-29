// SPDX-License-Identifier: Apache-2.0

//go:build !tegobpf

package bpf

// planeFillGenerated is empty in an untagged build, like generated (objects_stub.go).
var planeFillGenerated map[Object]binding
