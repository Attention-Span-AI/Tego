// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The stdio ledger record says what the agent's streams were wired to, so each kind must read as itself:
// a file read as a pipe would hide where output went.
func TestDescribeFDKinds(t *testing.T) {
	dir := t.TempDir()
	reg, err := os.Create(filepath.Join(dir, "out.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	dirF, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dirF.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sock, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	sockFile, err := sock.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer sockFile.Close()

	cases := []struct {
		name       string
		fd         int
		kind       string
		path       string
		rd, wr     bool
		checkPerms bool
	}{
		{"regular file", int(reg.Fd()), record.StdioFile, reg.Name(), true, true, true},
		{"/dev/null", int(null.Fd()), record.StdioNull, "", true, true, true},
		{"pipe read end", int(pr.Fd()), record.StdioPipe, "", true, false, true},
		{"pipe write end", int(pw.Fd()), record.StdioPipe, "", false, true, true},
		{"directory", int(dirF.Fd()), record.StdioDir, "", true, false, true},
		{"socket", int(sockFile.Fd()), record.StdioSocket, "", true, true, true},
	}
	for _, c := range cases {
		var st StdioStream
		describeFD(c.fd, &st)
		if st.Kind != c.kind || st.Path != c.path {
			t.Errorf("%s: kind %q path %q, want %q %q", c.name, st.Kind, st.Path, c.kind, c.path)
		}
		if c.checkPerms && (st.Readable != c.rd || st.Writable != c.wr) {
			t.Errorf("%s: readable=%v writable=%v, want %v %v", c.name, st.Readable, st.Writable, c.rd, c.wr)
		}
	}

	var bad StdioStream
	describeFD(1<<20, &bad)
	if bad.Kind != record.StdioUnknown {
		t.Errorf("an invalid descriptor is %q, want %q", bad.Kind, record.StdioUnknown)
	}
}

func TestGapEventCarriesTheGap(t *testing.T) {
	ev := gapEvent(source.Gap{What: "capture", Why: "uprobe attach failed", Binary: "/usr/bin/node", Count: 3})
	if ev == nil || ev.Kind != record.KindGap || ev.Source != record.SourceSupervisor {
		t.Fatalf("event = %+v", ev)
	}
	var p record.GapPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p != (record.GapPayload{What: "capture", Why: "uprobe attach failed", Binary: "/usr/bin/node", Count: 3}) {
		t.Fatalf("payload = %+v", p)
	}
}

func TestHostIDFallsBackAndIsStable(t *testing.T) {
	a, b := hostID([]byte("machine-a\n")), hostID([]byte("machine-b\n"))
	if a == b {
		t.Fatal("two machines must not share a host component")
	}
	if hostID([]byte("machine-a\n")) != a {
		t.Fatal("the same machine id must hash the same")
	}
	if hostID(nil) == ([32]byte{}) {
		t.Fatal("an unset id falls back to /etc/machine-id or the hostname, never to nothing")
	}
}
