// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestAdoptionFinalOwnerConfiguration(t *testing.T) {
	for _, mutation := range []string{"passwd", "records", "home placement", "home writable"} {
		t.Run(mutation, func(t *testing.T) {
			f := newGuardConfigFixture(t)
			f.write(t, "")
			m, _, err := guardLoadMachine(config.TrustAbort)
			if err != nil {
				t.Fatal(err)
			}
			records, _ := ownRecordsDir(f.ownerHome)
			location, err := resolveAdoptionHome(f.ownerHome)
			if err != nil {
				t.Fatal(err)
			}
			a := &preparedAdoption{m: m, owner: 1000, home: f.ownerHome, records: records, boundary: true, homeLocation: location}
			switch mutation {
			case "passwd":
				f.ownerHome = filepath.Join(f.home, "different")
			case "records":
				if err := os.Rename(ownRecords(f.ownerHome), ownRecords(f.ownerHome)+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(ownRecords(f.ownerHome), 0o700); err != nil {
					t.Fatal(err)
				}
			case "home placement":
				if err := os.Rename(f.ownerHome, f.ownerHome+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.ownerHome+".old", f.ownerHome); err != nil {
					t.Fatal(err)
				}
			case "home writable":
				if err := os.Remove(ownRecords(f.ownerHome)); err != nil {
					t.Fatal(err)
				}
				a.homeNotOwners = true
				a.records = records
				// Owner identity is irrelevant: other-write alone changes the former
				// non-writable admission into one that could create first-run records.
				if err := os.Chmod(f.ownerHome, 0o702); err != nil {
					t.Fatal(err)
				}
			}
			_, err = a.recheckOwnerConfiguration(m)
			if err == nil || !strings.Contains(err.Error(), "before adoption") {
				t.Fatalf("changed %s accepted: %v", mutation, err)
			}
		})
	}
}

func TestAdoptionFinalMissingHomeAlias(t *testing.T) {
	f := newGuardConfigFixture(t)
	absent := filepath.Join(f.home, "not-created")
	alias := filepath.Join(f.home, "owner-alias")
	if err := os.Symlink(absent, alias); err != nil {
		t.Fatal(err)
	}
	f.ownerHome = alias
	location, err := resolveAdoptionHome(alias)
	if err != nil {
		t.Fatal(err)
	}
	a := &preparedAdoption{owner: 1000, home: alias, boundary: true, homeMissing: true, homeLocation: location}
	m := config.Builtin()
	if _, err := a.recheckOwnerConfiguration(m); err != nil {
		t.Fatalf("unchanged absent home link refused: %v", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(absent+"-other", alias); err != nil {
		t.Fatal(err)
	}
	if _, err := a.recheckOwnerConfiguration(m); err == nil {
		t.Fatal("redirected absent home admitted")
	}
}
