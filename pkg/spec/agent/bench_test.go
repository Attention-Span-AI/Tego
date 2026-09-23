// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bigContract writes a 5,000-entry contract into the fixture (E24, §9).
func bigContract(b *testing.B, f *fixture) *Contract {
	b.Helper()
	var sb strings.Builder
	sb.WriteString("version: 0\nname: big\ncommand: [python]\nfs:\n  write:\n")
	for i := 0; i < 2000; i++ {
		d := filepath.Join(f.project, "out", fmt.Sprintf("d%d", i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			b.Fatal(err)
		}
		fmt.Fprintf(&sb, "    - %s\n", d)
	}
	sb.WriteString("net:\n  allow:\n")
	for i := 0; i < 2000; i++ {
		h := fmt.Sprintf("h%d.internal", i)
		f.resolver.table[h] = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
		fmt.Fprintf(&sb, "    - %s:443\n", h)
	}
	sb.WriteString("exec:\n  allow:\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&sb, "    - python\n")
	}
	path := filepath.Join(f.project, "big.yaml")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	c, ds, err := Load(path, nil)
	if err != nil {
		b.Fatalf("%v\n%s", err, render(ds))
	}
	return c
}

func BenchmarkCompile(b *testing.B) {
	f := newFixture(b)
	c := bigContract(b, f)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Compile(c, f.machine, f.opts()...); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoad(b *testing.B) {
	f := newFixture(b)
	bigContract(b, f)
	path := filepath.Join(f.project, "big.yaml")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := Load(path, nil); err != nil {
			b.Fatal(err)
		}
	}
}
