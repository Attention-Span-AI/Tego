// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRefusedKeyDoesNotRescanTheTable: with every tracked connection mid-exchange, each chunk of a refused
// key scanned the whole table for a victim under the assembler's mutex (about 1000x a tracked chunk at 4096
// connections), so an agent holding MaxConns half-sent requests stalled every other connection's drain. The
// scan runs again only once a connection may have become retirable.
func TestRefusedKeyDoesNotRescanTheTable(t *testing.T) {
	a := NewAssembler(Options{MaxConns: 8})
	keys := make([]ConnKey, 8)
	for i := range keys {
		keys[i] = ConnKey{Src: record.SourceSSL, SSLPtr: uint64(i + 1)}
		if _, err := a.Feed(keys[i], DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
			t.Fatal(err)
		}
	}
	refused := ConnKey{Src: record.SourceSSL, SSLPtr: 99}
	for range 200 {
		if _, err := a.Feed(refused, DirRequest, Chunk{Data: []byte("x")}); !errors.Is(err, ErrSizeCap) {
			t.Fatalf("Feed on a full table = %v, want ErrSizeCap", err)
		}
	}
	if a.scans > 1 {
		t.Fatalf("%d full-table scans for 200 chunks of one refused key, want 1", a.scans)
	}
	// A response ends one exchange; the next new key must find that connection and retire it.
	if _, err := a.Feed(keys[3], DirResponse, Chunk{Data: httpResponse("200 OK", nil, []byte(respBody))}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Feed(refused, DirRequest, Chunk{Data: []byte(postRequest(reqBody))}); err != nil {
		t.Fatalf("Feed after a connection became retirable = %v, want it tracked in its place", err)
	}
	if _, ok := a.conns[keys[3]]; ok {
		t.Error("the finished connection was not the one retired")
	}
}
