// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ipcProbe attaches the segment whose id it is given, makes a segment and a message queue of its own, and
// opens a POSIX message queue, writing "ok" or the errno's name for each as JSON. It calls libc through
// ctypes, so no module outside the standard library is needed; mq_open is libc's since glibc 2.34.
const ipcProbe = `import ctypes, errno, json, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.shmat.restype = ctypes.c_void_p
res = {}
def attempt(name, f, bad):
    r = f()
    res[name] = errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno())) if r == bad else "ok"
attempt("shmat", lambda: libc.shmat(int(sys.argv[2]), None, 0), ctypes.c_void_p(-1).value)
attempt("shmget", lambda: libc.shmget(0, 4096, 0o1600), -1)
attempt("msgget", lambda: libc.msgget(0, 0o1600), -1)
rt = libc if hasattr(libc, "mq_open") else ctypes.CDLL("librt.so.1", use_errno=True)
attempt("mq_open", lambda: rt.mq_open(b"/tego-ipc-probe", os.O_CREAT | os.O_RDWR, 0o600, None), -1)
json.dump(res, open(sys.argv[1], "w"))
`

// TestSysVIPCIsRefusedAtTierOne: on the real kernel, a segment made outside the run was attached read-write inside
// it, and neither that nor a queue of the run's own left a line in the ledger. Now each System V IPC call is refused
// with EPERM and recorded, unless the contract declares ipc: true. A POSIX message queue also stays unopenable inside
// the run, whatever ipc: says, because its filesystem is outside every rule of the Landlock domain.
func TestSysVIPCIsRefusedAtTierOne(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, 4096, unix.IPC_CREAT|0o666)
	if err != nil {
		t.Skipf("no System V shared memory here: %v", err)
	}
	t.Cleanup(func() { _, _ = unix.SysvShmCtl(id, unix.IPC_RMID, nil) })
	for _, tc := range []struct {
		name, ipc string
		want      map[string]string
	}{
		{"default", "", map[string]string{"shmat": "EPERM", "shmget": "EPERM", "msgget": "EPERM"}},
		{"ipc: true", "ipc: true\n", map[string]string{"shmat": "ok", "shmget": "ok", "msgget": "ok"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("sysvipc", []string{python}, []string{python, resolved})+tc.ipc)
			script := filepath.Join(f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(ipcProbe), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			out := filepath.Join(f.out, "result.json")
			if _, err := Run(context.Background(), f.rt, []string{python, script, out, strconv.Itoa(id)}, f.deps(t, nil)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("the probe wrote nothing: %v", err)
			}
			got := map[string]string{}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s = %s, want %s (all: %v)", k, got[k], v, got)
				}
			}
			if got["mq_open"] == "ok" {
				t.Errorf("mq_open succeeded inside the run (all: %v)", got)
			}
			var refused, gaps []string
			for _, e := range events(t, runDirs(t, f.root)[0]) {
				switch e.Kind {
				case record.KindRefused:
					var p record.RefusedPayload
					if err := e.DecodePayload(&p); err == nil && p.Rule == "sysv-ipc" {
						refused = append(refused, p.Op)
					}
				case record.KindGap:
					var p record.GapPayload
					if err := e.DecodePayload(&p); err == nil && strings.HasPrefix(p.Why, "sysv-ipc-") {
						gaps = append(gaps, p.Why)
					}
				}
			}
			if tc.ipc == "" {
				for _, op := range []string{"shmat", "shmget", "msgget"} {
					if !strings.Contains(strings.Join(refused, " "), op) {
						t.Errorf("no refused rule=sysv-ipc line for %s; refused: %v", op, refused)
					}
				}
				return
			}
			if len(refused) != 0 || len(gaps) < 3 {
				t.Errorf("ipc: true: refused %v, gaps %v; want no refusal and a gap line per syscall", refused, gaps)
			}
		})
	}
}
