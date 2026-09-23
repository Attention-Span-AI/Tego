// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"strings"
	"testing"
)

// TestKeyringOptIn is the contract half of the keyring opt-in: `keyring: true` is a P0-consumed scalar that
// loads, merges like io_uring (contract wins if set, else the profile's), changes contract_hash only when
// set, and rejects anything but a boolean. The supervisor reads it off the merged contract (SEMANTICS §1).
func TestKeyringOptIn(t *testing.T) {
	base := "version: 0\nname: a\ncommand: [x]\n"
	c, ds, err := LoadBytes("a.yaml", []byte(base+"keyring: true\n"), nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if !c.Keyring {
		t.Error("keyring: true did not load")
	}
	off, _, err := LoadBytes("a.yaml", []byte(base), nil)
	if err != nil {
		t.Fatal(err)
	}
	if off.Keyring {
		t.Error("an absent keyring: loaded as true; the default refuses the keyring")
	}
	on, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := off.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(on) == string(plain) || !strings.Contains(string(on), "keyring: true") {
		t.Errorf("contract_hash must see the opt-in:\n%s", on)
	}

	// A profile's opt-in is inherited; a contract's explicit false wins over it.
	profiles := mapSource{"p": "keyring: true\n"}
	inherited, ds, err := LoadBytes("a.yaml", []byte(base+"extends: p\n"), profiles)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if !inherited.Keyring {
		t.Error("the profile's keyring: true was not inherited")
	}
	overridden, _, err := LoadBytes("a.yaml", []byte(base+"extends: p\nkeyring: false\n"), profiles)
	if err != nil {
		t.Fatal(err)
	}
	if overridden.Keyring {
		t.Error("the contract's keyring: false did not win over the profile's true")
	}

	if _, _, err := LoadBytes("a.yaml", []byte(base+"keyring: sometimes\n"), nil); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("keyring: sometimes loaded (%v); only true or false is a keyring value", err)
	}
}

// TestIPCOptIn is the contract half of the System V IPC opt-in: `ipc: true` loads, merges like keyring:, changes
// contract_hash only when set, and takes a boolean alone.
func TestIPCOptIn(t *testing.T) {
	base := "version: 0\nname: a\ncommand: [x]\n"
	c, ds, err := LoadBytes("a.yaml", []byte(base+"ipc: true\n"), nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	off, _, err := LoadBytes("a.yaml", []byte(base), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IPC || off.IPC {
		t.Fatalf("ipc: true loaded as %v, absent as %v", c.IPC, off.IPC)
	}
	on, _ := c.Canonical()
	plain, _ := off.Canonical()
	if string(on) == string(plain) || !strings.Contains(string(on), "ipc: true") {
		t.Errorf("contract_hash must see the opt-in:\n%s", on)
	}
	profiles := mapSource{"p": "ipc: true\n"}
	if inherited, ds, err := LoadBytes("a.yaml", []byte(base+"extends: p\n"), profiles); err != nil || !inherited.IPC {
		t.Errorf("the profile's ipc: true was not inherited (%v)\n%s", err, render(ds))
	}
	if overridden, _, err := LoadBytes("a.yaml", []byte(base+"extends: p\nipc: false\n"), profiles); err != nil || overridden.IPC {
		t.Errorf("the contract's ipc: false did not win over the profile's true (%v)", err)
	}
	if _, _, err := LoadBytes("a.yaml", []byte(base+"ipc: yes please\n"), nil); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("ipc: yes please loaded (%v)", err)
	}
}
