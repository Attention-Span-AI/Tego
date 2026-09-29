// SPDX-License-Identifier: Apache-2.0

//go:build !tegobpf

package bpf

// planeGenerated is empty in an untagged build, like generated (objects_stub.go).
var planeGenerated map[Object]binding
