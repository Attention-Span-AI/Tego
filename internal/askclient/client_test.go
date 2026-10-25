// SPDX-License-Identifier: Apache-2.0

package askclient_test

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/askclient"
)

type corpusCase struct {
	In    string `json:"in"`
	Err   string `json:"err,omitempty"`
	Value string `json:"value,omitempty"`
}

// TestReadResponseCorpusAsBefore: every response of the corpus recorded from readResponse before
// the client moved here, reads now as it read then, packet by packet over a SOCK_SEQPACKET pair: the same error
// text and the same decoded value.
func TestReadResponseCorpusAsBefore(t *testing.T) {
	b, err := os.ReadFile("../../pkg/spec/askproto/testdata/corpus-e47e1ba4.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Responses []corpusCase `json:"responses"`
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Responses) < 40 {
		t.Fatalf("the corpus holds %d responses", len(corpus.Responses))
	}
	for _, want := range corpus.Responses {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fa, fb := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
		ca, err := net.FileConn(fa)
		if err != nil {
			t.Fatal(err)
		}
		cb, err := net.FileConn(fb)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fa.Close(), fb.Close()
		if _, err := ca.Write([]byte(want.In)); err != nil {
			t.Fatal(err)
		}
		r, rerr := askclient.ReadResponse(cb.(*net.UnixConn))
		_, _ = ca.Close(), cb.Close()
		got := corpusCase{In: want.In}
		if rerr != nil {
			got.Err = rerr.Error()
		}
		v, _ := json.Marshal(r)
		got.Value = string(v)
		if got != want {
			t.Errorf("%q: read %q / %s, before the move %q / %s", want.In, got.Err, got.Value, want.Err, want.Value)
		}
	}
}

// TestReadResponseCloseIsEOF: a broker that closes with no reply (askproto's doc: a peer that has exited, a
// failed nonce draw) reads as io.EOF, as it did before the move, never as a hello or an empty success.
func TestReadResponseCloseIsEOF(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fa, fb := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
	cb, err := net.FileConn(fb)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fa.Close(), fb.Close()
	defer func() { _ = cb.Close() }()
	if r, err := askclient.ReadResponse(cb.(*net.UnixConn)); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadResponse after a close = %+v, %v; want io.EOF", r, err)
	}
}

// TestLedgerTargetAsBefore: LedgerTarget gives every target of the corpus the form internal/runtime's
// askLedgerTarget gave it at e47e1ba4, before it moved here.
func TestLedgerTargetAsBefore(t *testing.T) {
	b, err := os.ReadFile("testdata/ledgertarget-e47e1ba4.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Op, Target, Out string }
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 15 {
		t.Fatalf("the corpus holds %d targets", len(cases))
	}
	for _, c := range cases {
		if got := askclient.LedgerTarget(c.Op, c.Target); got != c.Out {
			t.Errorf("LedgerTarget(%q, %q) = %q, before the move %q", c.Op, c.Target, got, c.Out)
		}
	}
}

func TestLauncherOfARunWithNoLiveLock(t *testing.T) {
	if _, err := askclient.Launcher(t.TempDir()); err != askclient.ErrNoBroker {
		t.Fatalf("a run directory with no lock: %v, want ErrNoBroker", err)
	}
}
