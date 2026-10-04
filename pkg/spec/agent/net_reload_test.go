// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

func TestNetworkDenyAllListsSurviveCanonicalLedgerReload(t *testing.T) {
	const declaration = "version: 0\nname: net-reload\ncommand: [/bin/true]\nnet:\n  listen: []\n  ingress: []\n  dns: {mode: broker, allow: [], types: [], cache: 0}\n"
	c, ds, err := LoadBytes("original.yaml", []byte(declaration), nil)
	if err != nil {
		t.Fatalf("original: %v %v", err, ds)
	}
	canonical, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	d, ds, err := LoadBytes("ledger-contract.yaml", canonical, nil)
	if err != nil {
		t.Fatalf("reload: %v %v\n%s", err, ds, canonical)
	}
	if d.Net.Listen == nil || d.Net.Ingress == nil || d.Net.DNS.Allow == nil || d.Net.DNS.Types == nil || d.Net.DNS.Cache == nil || *d.Net.DNS.Cache != 0 {
		t.Fatalf("canonical reload lost explicit deny/cache-disable intent: %s", canonical)
	}
	next, err := d.Canonical()
	if err != nil || string(next) != string(canonical) {
		t.Fatalf("reload not byte-stable: %v", err)
	}
	if strings.Contains(string(canonical), "allow:\n    -") {
		t.Fatal("internal placeholder leaked into contract")
	}
}

func TestNetworkNullCannotDisableARequestedGuarantee(t *testing.T) {
	for _, value := range []string{"listen: null", "ingress: null", "dns: null", "limits: null", "proxy: null", "limits: {bytes: null}", "dns: {cache: null}"} {
		_, _, err := LoadBytes("null.yaml", []byte("version: 0\nname: null-net\ncommand: [/bin/true]\nnet: {"+value+"}\n"), nil)
		if err == nil {
			t.Fatalf("null policy silently accepted: %s", value)
		}
	}
}
