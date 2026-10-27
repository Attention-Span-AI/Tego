// SPDX-License-Identifier: Apache-2.0

package procconn

import (
	"testing"
)

// procEvent builds a proc_event body (the bytes after the cn_msg header) in native order for a given what
// and union payload, so the decoder is tested against the layout the kernel writes.
func procEvent(what Kind, union []byte) []byte {
	b := make([]byte, procEventPrefix+len(union))
	native.PutUint32(b[0:4], uint32(what))
	native.PutUint32(b[4:8], 7) // cpu, arbitrary
	native.PutUint64(b[8:16], 0x1122334455667788)
	copy(b[procEventPrefix:], union)
	return b
}

func u32(vals ...uint32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		native.PutUint32(b[i*4:], v)
	}
	return b
}

func TestDecodeExec(t *testing.T) {
	ev, err := decodeProcEvent(procEvent(Exec, u32(4242, 4200)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Kind != Exec || ev.PID != 4242 || ev.TGID != 4200 {
		t.Fatalf("got %+v, want exec pid 4242 tgid 4200", ev)
	}
	if ev.CPU != 7 || ev.TimestampNS != 0x1122334455667788 {
		t.Fatalf("prefix not decoded: %+v", ev)
	}
}

func TestDecodeFork(t *testing.T) {
	// parent_pid, parent_tgid, child_pid, child_tgid
	ev, err := decodeProcEvent(procEvent(Fork, u32(100, 100, 555, 550)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Kind != Fork || ev.PID != 555 || ev.TGID != 550 || ev.ParentTGID != 100 {
		t.Fatalf("got %+v, want fork child 555/550 parent-tgid 100", ev)
	}
}

func TestDecodeExit(t *testing.T) {
	// process_pid, process_tgid, exit_code, exit_signal
	ev, err := decodeProcEvent(procEvent(Exit, u32(4242, 4200, 1, 0)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Kind != Exit || ev.TGID != 4200 || ev.ExitCode != 1 {
		t.Fatalf("got %+v, want exit tgid 4200 code 1", ev)
	}
}

func TestDecodeUnknownKindHasNoPIDs(t *testing.T) {
	// A UID event (0x4) is not one the watcher uses: it decodes with its number and zero pids.
	ev, err := decodeProcEvent(procEvent(Kind(0x4), u32(1, 2, 3, 4)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Kind != 0x4 || ev.PID != 0 || ev.TGID != 0 {
		t.Fatalf("got %+v, want kind 0x4 with zero pids", ev)
	}
}

func TestDecodeShort(t *testing.T) {
	if _, err := decodeProcEvent(make([]byte, procEventPrefix-1)); err != ErrShort {
		t.Fatalf("short prefix: got %v, want ErrShort", err)
	}
	if _, err := decodeProcEvent(procEvent(Exec, u32(1))); err != ErrShort {
		t.Fatalf("exec union too short: got %v, want ErrShort", err)
	}
}

func TestDecodeCnMsg(t *testing.T) {
	// A cn_msg header (idx/val = proc group) in front of an exec event decodes.
	hdr := make([]byte, cnMsgHeaderLen)
	native.PutUint32(hdr[0:4], cnIdxProc)
	native.PutUint32(hdr[4:8], cnValProc)
	data := append(hdr, procEvent(Exec, u32(9, 9))...)
	ev, ok, err := DecodeCnMsg(data)
	if err != nil || !ok {
		t.Fatalf("DecodeCnMsg: ok=%v err=%v", ok, err)
	}
	if ev.Kind != Exec || ev.TGID != 9 {
		t.Fatalf("got %+v", ev)
	}

	// A cn_msg for another connector id is skipped, not an error.
	native.PutUint32(hdr[0:4], 0x9) // some other idx
	data = append(hdr, procEvent(Exec, u32(9, 9))...)
	if _, ok, err := DecodeCnMsg(data); ok || err != nil {
		t.Fatalf("other id: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestKindString(t *testing.T) {
	if Exec.String() != "exec" || Fork.String() != "fork" || Exit.String() != "exit" {
		t.Fatalf("names: %s %s %s", Exec, Fork, Exit)
	}
	if Kind(0x4).String() != "kind(0x4)" {
		t.Fatalf("unknown name: %s", Kind(0x4))
	}
}
