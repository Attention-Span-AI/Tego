// SPDX-License-Identifier: Apache-2.0

package cireceipt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	maxRecordBytes   = 128 << 20
	maxReceiptBytes  = 64 << 20
	maxContractBytes = 4 << 20
	maxCheckBytes    = 1 << 20
	maxBundleBytes   = 4 << 20
)

// frozen keeps only private copies. Neither the checker nor the bundle consumer
// reopens evidence after freeze, so mutable files cannot supply different bytes
// to the two comparisons.
type frozen struct {
	dir   string
	files map[string][]byte
}

func freeze(ctx context.Context, in Input) (*frozen, error) {
	if in.ScratchDir == "" {
		return nil, errors.New("a private scratch directory is required")
	}
	src, err := filepath.Abs(in.Directory)
	if err != nil {
		return nil, err
	}
	scratch, err := filepath.Abs(in.ScratchDir)
	if err != nil {
		return nil, err
	}
	if scratch == src || strings.HasPrefix(scratch, src+string(filepath.Separator)) {
		return nil, errors.New("scratch directory must be outside evidence")
	}
	resolvedSource, err := filepath.EvalSymlinks(src)
	if err != nil {
		return nil, err
	}
	resolvedScratch, err := filepath.EvalSymlinks(scratch)
	if err != nil {
		return nil, err
	}
	if resolvedScratch == resolvedSource || strings.HasPrefix(resolvedScratch, resolvedSource+string(filepath.Separator)) {
		return nil, errors.New("scratch directory must be outside evidence, including aliases")
	}
	st, err := os.Lstat(src)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence must be a regular directory, without a link")
	}
	root, err := os.OpenRoot(src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }() // all copies own their bytes before this descriptor closes
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("evidence directory changed while opening")
	}
	dir, err := os.MkdirTemp(scratch, "ci-receipt-")
	if err != nil {
		return nil, err
	}
	f := &frozen{dir: dir, files: map[string][]byte{}}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}() // private partial copies have no other owner
	if err := os.Mkdir(filepath.Join(dir, "run"), 0o700); err != nil {
		return nil, err
	}
	for _, entry := range []struct {
		name     string
		max      int
		optional bool
	}{
		{"manifest.json", MaxManifestBytes, false}, {"receipt.json", maxReceiptBytes, false}, {"run/events.jsonl", maxRecordBytes, false},
		{"anchor-line.txt", 1024, false}, {"contract.yaml", maxContractBytes, false}, {"run-status.json", 4096, false}, {"signer-check.json", maxCheckBytes, false},
		{"receipt.sigstore.json", maxBundleBytes, true}, {"manifest.sigstore.json", maxBundleBytes, true},
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := readRegular(ctx, root, entry.name, entry.max)
		if err != nil {
			if entry.optional && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("freeze %s: %w", entry.name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(entry.name)), data, 0o600); err != nil {
			return nil, err
		}
		f.files[entry.name] = data
	}
	ok = true
	return f, nil
}

// readRegular rejects links and special files before reading. Root confines
// traversal, O_NOFOLLOW refuses a leaf link even during replacement, O_NONBLOCK
// keeps a replacement FIFO from holding the verifier, and SameFile detects a
// changed intermediate directory. No path originates in the manifest.
func readRegular(ctx context.Context, root *os.Root, name string, max int) ([]byte, error) {
	parts := strings.Split(name, "/")
	current := root
	var children []*os.Root
	defer func() {
		for _, child := range children {
			_ = child.Close()
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		st, err := current.Lstat(part)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("intermediate path is not a directory without links")
		}
		child, err := current.OpenRoot(part)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		actual, err := child.Stat(".")
		if err != nil || !os.SameFile(st, actual) {
			return nil, errors.New("intermediate directory changed while opening")
		}
		current = child
	}
	leaf := parts[len(parts)-1]
	expected, err := current.Lstat(leaf)
	if err != nil {
		return nil, err
	}
	if !expected.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("leaf must be a regular file without links")
	}
	file, err := current.OpenFile(leaf, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	st, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(expected, st) {
		return nil, errors.New("leaf changed while opening")
	}
	if !st.Mode().IsRegular() || st.Size() > int64(max) {
		return nil, fmt.Errorf("require regular file of at most %d bytes", max)
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, errors.New("file must have exactly one link")
	}
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, r: file}, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return data, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
