// SPDX-License-Identifier: Apache-2.0

//go:build !tegobpf

package bpf

// generated is empty in an untagged build: the committed bpf2go output is embedded only under the tegobpf
// tag, so a plain `go build` compiles and tests everything in this package that needs no object and Load
// reports ErrNotGenerated. See doc.go.
var generated map[Object]binding

// readerGenerated is empty in an untagged build, like generated.
var readerGenerated map[Object]binding
