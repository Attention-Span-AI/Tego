// SPDX-License-Identifier: Apache-2.0

package winpeer

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// fakeRow is one MIB_TCP6ROW_OWNER_PID, laid out as Windows lays it out.
func fakeRow(local, remote netip.AddrPort, state, pid uint32) []byte {
	b := make([]byte, rowSize)
	l, r := local.Addr().As16(), remote.Addr().As16()
	copy(b[0:16], l[:])
	binary.BigEndian.PutUint16(b[20:22], local.Port())
	b[22], b[23] = 0xAA, 0xBB // the upper 16 bits of a port DWORD may hold anything
	copy(b[24:40], r[:])
	binary.BigEndian.PutUint16(b[44:46], remote.Port())
	binary.LittleEndian.PutUint32(b[48:52], state)
	binary.LittleEndian.PutUint32(b[52:56], pid)
	return b
}

func fakeTable(rows ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(rows)))
	for _, r := range rows {
		b = append(b, r...)
	}
	return b
}

var (
	server = netip.MustParseAddrPort("[::1]:8484")
	client = netip.MustParseAddrPort("[::1]:50123")
	other  = netip.MustParseAddrPort("[::1]:50124")
)

const (
	me  = "S-1-5-21-1-2-3-1001"
	you = "S-1-5-21-1-2-3-1002"
)

func TestParseTCP6(t *testing.T) {
	b := fakeTable(fakeRow(client, server, StateEstablished, 4242), fakeRow(server, client, StateEstablished, 77))
	rows, err := ParseTCP6(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{{Local: client, Remote: server, State: StateEstablished, PID: 4242}, {Local: server, Remote: client, State: StateEstablished, PID: 77}}
	if len(rows) != 2 || rows[0] != want[0] || rows[1] != want[1] {
		t.Fatalf("rows %+v, want %+v", rows, want)
	}
}

func TestParseTCP6Scope(t *testing.T) {
	r := fakeRow(client, server, StateEstablished, 9)
	binary.LittleEndian.PutUint32(r[16:20], 14)
	rows, err := ParseTCP6(fakeTable(r))
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Local.Addr().Zone() != "14" || rows[0].Local == client {
		t.Fatalf("a scoped row %v must not equal the unscoped client %v", rows[0].Local, client)
	}
}

func TestParseTCP6Malformed(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":       nil,
		"short count": {1, 0},
		"short rows":  fakeTable(fakeRow(client, server, 5, 1))[:40],
		"huge count":  binary.LittleEndian.AppendUint32(nil, 0xFFFFFFFF),
		"over limit":  make([]byte, MaxTable+1),
	} {
		if _, err := ParseTCP6(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// TestDecide is R2's decision table: only a single established client row whose process runs as the relay's own
// user is let in; every other case refuses with ErrRefused.
func TestDecide(t *testing.T) {
	sids := map[uint32]string{100: me, 200: you}
	sidOf := func(pid uint32) (string, error) {
		if s, ok := sids[pid]; ok {
			return s, nil
		}
		return "", errors.New("access is denied")
	}
	accepted := fakeRow(server, client, StateEstablished, 1) // the relay's own accepted socket
	cases := []struct {
		name  string
		table []byte
		self  string
		ok    bool
		why   string
	}{
		{"same user", fakeTable(accepted, fakeRow(client, server, StateEstablished, 100)), me, true, ""},
		{"another user", fakeTable(accepted, fakeRow(client, server, StateEstablished, 200)), me, false, "runs as " + you},
		{"owner not openable", fakeTable(accepted, fakeRow(client, server, StateEstablished, 300)), me, false, "access is denied"},
		{"no client row", fakeTable(accepted), me, false, "no established socket"},
		{"only a closing row", fakeTable(accepted, fakeRow(client, server, 8, 100)), me, false, "no established socket"},
		{"another client port", fakeTable(accepted, fakeRow(other, server, StateEstablished, 100)), me, false, "no established socket"},
		{"swapped ends only", fakeTable(fakeRow(server, client, StateEstablished, 100)), me, false, "no established socket"},
		{"two rows", fakeTable(fakeRow(client, server, StateEstablished, 100), fakeRow(client, server, StateEstablished, 100)), me, false, "2 sockets"},
		{"system pid", fakeTable(fakeRow(client, server, StateEstablished, 4)), me, false, "system pid 4"},
		{"idle pid", fakeTable(fakeRow(client, server, StateEstablished, 0)), me, false, "system pid 0"},
		{"unreadable table", []byte{1}, me, false, "shorter than its row count"},
		{"own user unknown", fakeTable(fakeRow(client, server, StateEstablished, 100)), "", false, "own user is unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decide(c.table, client, server, c.self, sidOf)
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if !strings.Contains(err.Error(), c.why) {
				t.Fatalf("refusal %q does not say %q", err, c.why)
			}
		})
	}
}

func FuzzParseTCP6(f *testing.F) {
	f.Add(fakeTable(fakeRow(client, server, StateEstablished, 4242)))
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{2, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		rows, err := ParseTCP6(b)
		if err != nil {
			return
		}
		if 4+len(rows)*rowSize > len(b) {
			t.Fatalf("%d rows from %d bytes", len(rows), len(b))
		}
		for _, r := range rows {
			_, _ = ClientPID([]Row{r}, r.Local, r.Remote)
		}
	})
}
