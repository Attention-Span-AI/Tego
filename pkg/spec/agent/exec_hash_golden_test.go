// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// hashGolden is the contract_hash of every contract in the repository's examples and testdata, and of a set of exec:
// sections, recorded before ADR 0048 added exec.deny, exec.ask and command patterns.
const hashGolden = "testdata/contract-hashes.golden"

// execVariants are the exec: shapes ADR 0048 must leave byte for byte as they were.
var execVariants = map[string]string{
	"no-exec":            ``,
	"exec-empty":         "exec: {}\n",
	"allow-empty":        "exec: {allow: []}\n",
	"allow-one":          "exec: {allow: [ls]}\n",
	"allow-two":          "exec: {allow: [ls, /usr/bin/env]}\n",
	"anonymous":          "exec: {anonymous: true}\n",
	"allow-anonymous":    "exec: {allow: [], anonymous: true}\n",
	"allow-one-anon":     "exec: {allow: [sh], anonymous: true}\n",
	"anonymous-false":    "exec: {anonymous: false}\n",
	"allow-and-fs-write": "exec: {allow: [ls]}\nfs: {write: [/tmp/x]}\n",
}

// TestContractHashesUnchanged: every existing contract's canonical bytes, and so its contract_hash, are what they
// were before ADR 0048 (its (1): "every existing contract's canonical bytes and contract_hash are unchanged"). The
// golden was written at the commit before the exec section changed; -update rewrites it.
func TestContractHashesUnchanged(t *testing.T) {
	got := map[string]string{}
	root := filepath.Join("..", "..", "..")
	sources := []ProfileSource{dirSource{root: filepath.Join(root, "examples", "profiles")}, testProfiles()}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".github", "node_modules", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, src := range sources {
			c, _, err := LoadBytes(p, data, src)
			if err != nil {
				continue
			}
			sum, err := c.Hash()
			if err != nil {
				t.Fatal(err)
			}
			rel, _ := filepath.Rel(root, p)
			got[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
			break
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, exec := range execVariants {
		src := "version: 0\nname: v\ncommand: [true]\n" + exec
		c, ds, err := LoadBytes(name+".yaml", []byte(src), nil)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, render(ds))
		}
		sum, err := c.Hash()
		if err != nil {
			t.Fatal(err)
		}
		got["variant:"+name] = hex.EncodeToString(sum[:])
	}
	if len(got) < 30 {
		t.Fatalf("hashed %d contracts: the walk found too few to prove anything", len(got))
	}
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + " " + got[k] + "\n")
	}
	if *update {
		if err := os.WriteFile(hashGolden, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(hashGolden)
	if err != nil {
		t.Fatal(err)
	}
	wantMap := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(want)), "\n") {
		k, v, _ := strings.Cut(line, " ")
		wantMap[k] = v
	}
	for k, v := range wantMap {
		if got[k] != v {
			t.Errorf("%s: contract_hash %s, was %s", k, got[k], v)
		}
	}
}
