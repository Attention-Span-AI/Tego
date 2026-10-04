// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	bindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

const btrfsPlaneContract = `version: 0
name: plane-btrfs-subvolumes
command: ["python3", "./agent.py"]
fs:
  write: ["./out/", "./tree/", "./tree/allowed/"]
  deny_read: ["./tree/denied/"]
exec:
  allow: [python3]
net:
  allow: []
env:
  pass: ["PATH", "HOME"]
record: full
`

const btrfsPlaneAgent = `import errno, pathlib, time
for name in ("allowed", "denied"):
    try:
        text = pathlib.Path("tree", name, "payload").read_text()
        print("RESULT", name, "ok" if text == name + "\n" else "wrong-content", flush=True)
    except OSError as e:
        print("RESULT", name, "refused" if e.errno == errno.EACCES else "errno=%d" % e.errno, flush=True)
pathlib.Path("out/ready").touch()
while not pathlib.Path("out/go").exists():
    time.sleep(.02)
`

const btrfsPlaneTable = `version: 0
tests:
  - name: allowed subvolume
    action: fs.read
    path: ./tree/allowed/payload
    expect: allow
    rule: fs.write[./tree/allowed/]
  - name: denied subvolume
    action: fs.read
    path: ./tree/denied/payload
    expect: refused
    rule: fs.deny_read[./tree/denied/]
`

// btrfsImage is an empty 16 MiB btrfs, gzipped, so the fixture needs no btrfs-progs: only root, mount's loop
// option and the kernel's btrfs, which root-suites.sh's guests load by default (VM_MODULES) and a runner's mount
// loads on demand. Amended 2026-10-05: the test used to skip without mkfs.btrfs and btrfs on PATH, which no
// root gate provided, and root-skips.txt allowed that skip, so it never ran (gates-1). Made with btrfs-progs 6.16:
//
//	truncate -s 16M btrfs.img
//	mkfs.btrfs -q -f --mixed -n 4096 -s 4096 -U 0e7a1000-b7f5-4000-8000-000000000001 btrfs.img
//	gzip -9n <btrfs.img >testdata/btrfs-mixed-16m.img.gz
//
//go:embed testdata/btrfs-mixed-16m.img.gz
var btrfsImage []byte

const (
	btrfsImageSize = 16 << 20
	btrfsImageFSID = "0e7a1000b7f540008000000000000001"
	// _IOW(BTRFS_IOCTL_MAGIC, n, struct btrfs_ioctl_vol_args), whose size is 4096 (linux/btrfs.h).
	btrfsIocForgetDev    = 0x50009405
	btrfsIocSubvolCreate = 0x5000940e
)

// btrfsVolArgs is struct btrfs_ioctl_vol_args.
type btrfsVolArgs struct {
	FD   int64
	Name [4088]byte
}

// TestBtrfsFixtureImageIsAnEmptyFilesystem checks the embedded image without privilege: whole, a 16 MiB
// btrfs whose primary superblock carries the fsid the fixture's comment names.
func TestBtrfsFixtureImageIsAnEmptyFilesystem(t *testing.T) {
	raw, err := btrfsImageBytes()
	if err != nil {
		t.Fatal(err)
	}
	const super = 0x10000 // the primary superblock's offset
	if len(raw) != btrfsImageSize || string(raw[super+0x40:super+0x48]) != "_BHRfS_M" ||
		hex.EncodeToString(raw[super+0x20:super+0x30]) != btrfsImageFSID {
		t.Fatalf("embedded image: %d bytes, magic %q, fsid %x", len(raw), raw[super+0x40:super+0x48], raw[super+0x20:super+0x30])
	}
}

func btrfsImageBytes() ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(btrfsImage))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(zr, btrfsImageSize+1))
}

// Two btrfs subvolumes on one mount repeat their inode numbers under one superblock. The fill must retain two
// different inode-pointer keys, even though its kernel values have equal i_ino and s_dev. Userspace st_dev is a
// subvolume's own anonymous device number; comparing that with the kernel superblock's s_dev would also make
// Prepare fail. The compile columns, independent model, actual maps, kernel results and ledger must all agree.
// The loop device and mount belong only to this fixture, normally in the disposable root-suite KVM guest.
// root-skips.txt allows its skip in the plain build only, so every root run of the tegobpf suite runs it.
func TestPlaneRunBtrfsSubvolumeInodeIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the btrfs plane fixture needs a privileged disposable VM")
	}
	bin, uid, gid, modes := planePreconditions(t)
	for _, mode := range modes {
		tiers := []string{"cgroup"}
		if mode == "lsm" {
			tiers = append(tiers, "bpflsm")
		}
		for _, tier := range tiers {
			t.Run(tier+"@"+mode, func(t *testing.T) {
				btrfsPlaneRunCell(t, bin, uid, gid, mode, tier)
			})
		}
	}
}

func btrfsPlaneRunCell(t *testing.T, bin string, uid, gid int, mode, tier string) {
	t.Helper()
	p := newPlaneProject(t, uid, gid, map[string]string{
		"agent.py": btrfsPlaneAgent, "agent.yaml": btrfsPlaneContract, "table.yaml": btrfsPlaneTable,
	}, []string{"out", "tree"}, nil)
	btrfsPlaneFixture(t, p, uid, gid)
	indices := btrfsPlaneModel(t, p, uid)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var compileOut, compileErr bytes.Buffer
	compile := p.runAt(ctx, bin, tier, "agent.yaml", mode, &compileOut)
	compile.Args = []string{bin, "compile", "agent.yaml", "--test", "table.yaml", "--tier", "cgroup,bpflsm", "--json"}
	compile.Stderr = &compileErr
	if err := compile.Run(); err != nil {
		t.Fatalf("compile --test: %v\n%s\n%s", err, compileOut.String(), compileErr.String())
	}
	var report struct {
		Passed, Failed int
		Rows           []struct {
			Pass    bool
			Columns []struct {
				Pass bool
			}
		}
	}
	if err := json.Unmarshal(compileOut.Bytes(), &report); err != nil || report.Passed != 2 || report.Failed != 0 || len(report.Rows) != 2 {
		t.Fatalf("compile --test did not pass both rows: %v\n%s", err, compileOut.String())
	}
	for _, row := range report.Rows {
		if !row.Pass || len(row.Columns) != 2 || !row.Columns[0].Pass || !row.Columns[1].Pass {
			t.Fatalf("compile --test did not certify both model columns: %s", compileOut.String())
		}
	}

	var out lockedBuffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", mode, &out)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = os.WriteFile(filepath.Join(p.project, "out/go"), nil, 0o644)
			cancel()
			_ = cmd.Wait()
		}
	}()
	waitFile(t, filepath.Join(p.project, "out/ready"), time.Minute, cmd, nil)
	btrfsPlaneKernelRows(t, mode, indices)
	if err := os.WriteFile(filepath.Join(p.project, "out/go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("tego run --tier %s (%s): %v\n%s", tier, mode, err, out.String())
	}
	results := agentResults(t, out.String())
	if results["allowed"] != "ok" || results["denied"] != "refused" {
		t.Errorf("kernel reads = %v, want allowed=ok and denied=refused\n%s", results, out.String())
	}
	events := runEvents(t, p.ledger)
	for _, name := range []string{"allowed", "denied"} {
		path := filepath.Join(p.project, "tree", name, "payload")
		var lines []map[string]any
		for _, e := range events {
			if e["kind"] == "fs" && e["op"] == "open" && e["path"] == path {
				lines = append(lines, e)
			}
		}
		if len(lines) != 1 {
			t.Errorf("%s has %d open lines, want one: %v", name, len(lines), lines)
			continue
		}
		line := lines[0]
		if name == "allowed" {
			if line["verdict"] != "allow" || line["rule"] != "fs.write[./tree/allowed/]" {
				t.Errorf("allowed subvolume: %v, want allow by its own write entry", line)
			}
		} else if line["verdict"] != "refused" || line["rule"] != "fs.deny_read[./tree/denied/]" ||
			line["reason"] != "read-denied" || line["source"] != "kernel" || line["mechanism"] != "plane" || line["decision_plane"] != mode {
			t.Errorf("denied subvolume: %v, want the plane's single read-denied line", line)
		}
	}
	if t.Failed() {
		t.Log(ledgerDump(p.ledger))
	}
}

func btrfsPlaneFixture(t *testing.T, p *planeProject, uid, gid int) {
	t.Helper()
	image := filepath.Join(p.base, "btrfs.img")
	raw, err := btrfsImageBytes()
	if err != nil || len(raw) != btrfsImageSize {
		t.Fatalf("embedded btrfs image: %d bytes, %v", len(raw), err)
	}
	if err := os.WriteFile(image, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Every cell mounts a copy of one image, so one fsid. A kernel that keeps an unmounted single-device btrfs
	// registered refuses the next copy on another loop device when the last one's generation is higher ("already
	// registered with a higher generation"); forgetting the unmounted devices first leaves only this copy. With no
	// btrfs-control device nothing is registered (the module is not loaded yet).
	if fd, err := unix.Open("/dev/btrfs-control", unix.O_RDWR|unix.O_CLOEXEC, 0); err == nil {
		var args btrfsVolArgs // an empty name forgets every unmounted device
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), btrfsIocForgetDev, uintptr(unsafe.Pointer(&args)))
		_ = unix.Close(fd)
		if errno != 0 {
			t.Fatalf("forget unmounted btrfs devices: %v", errno)
		}
	} else if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENXIO) {
		t.Fatalf("open /dev/btrfs-control: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	mount := filepath.Join(p.project, "tree")
	if out, err := exec.CommandContext(ctx, "mount", "-t", "btrfs", "-o", "loop,nosuid,nodev", image, mount).CombinedOutput(); err != nil {
		if fs, _ := os.ReadFile("/proc/filesystems"); !bytes.Contains(fs, []byte("\tbtrfs\n")) {
			t.Skipf("the kernel has no btrfs (root-suites.sh's guests load it, VM_MODULES): mount: %v\n%s", err, out)
		}
		t.Fatalf("mount the private btrfs fixture: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(mount, 0); err != nil {
			if detach := unix.Unmount(mount, unix.MNT_DETACH); detach != nil {
				t.Errorf("unmount private btrfs fixture: %v (detach: %v)", err, detach)
			}
		}
	})
	var fs unix.Statfs_t
	if err := unix.Statfs(mount, &fs); err != nil || uint64(fs.Type) != unix.BTRFS_SUPER_MAGIC {
		t.Fatalf("fixture is not btrfs: type=%x, err=%v", fs.Type, err)
	}
	parent, err := unix.Open(mount, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)
	for _, name := range []string{"allowed", "denied"} {
		// `btrfs subvolume create`'s own ioctl, on the mount's root directory.
		var args btrfsVolArgs
		copy(args.Name[:], name)
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(parent), btrfsIocSubvolCreate, uintptr(unsafe.Pointer(&args))); errno != 0 {
			t.Fatalf("create subvolume %s: %v", name, errno)
		}
		if err := os.WriteFile(filepath.Join(mount, name, "payload"), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := filepath.Walk(mount, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "payload"} {
		var dev, ino, mnt [2]uint64
		for i, name := range []string{"allowed", "denied"} {
			fd, err := unix.Open(filepath.Join(mount, name, suffix), unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			dev[i], ino[i], mnt[i], err = (hostIdentity{}).fd(fd)
			_ = unix.Close(fd)
			if err != nil {
				t.Fatal(err)
			}
		}
		if ino[0] != ino[1] || mnt[0] != mnt[1] || dev[0] == dev[1] {
			t.Fatalf("subvolume %q identities do not exercise the collision: dev=%v ino=%v mount=%v", suffix, dev, ino, mnt)
		}
		t.Logf("btrfs subvolume %q: same inode %d and mount %d, distinct userspace devices %x/%x", suffix, ino[0], mnt[0], dev[0], dev[1])
	}
}

func btrfsPlaneModel(t *testing.T, p *planeProject, uid int) [2]uint16 {
	t.Helper()
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		t.Fatal(err)
	}
	sources, _, _ := config.Resolve(uid, false)
	sources.EnvFile = p.cfg
	m, _, err := config.LoadSources(sources, u.HomeDir, uid, config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.Load(filepath.Join(p.project, "agent.yaml"), nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, ds, err := agent.Compile(c, m, agent.WithCwd(p.project), agent.WithHome(u.HomeDir), agent.WithPATH(os.Getenv("PATH")),
		agent.WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM), agent.WithChainAnchor(filepath.Join(p.base, "chain.log")))
	if err != nil {
		t.Fatalf("compile btrfs contract: %v: %v", err, ds)
	}
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	var indices [2]uint16
	for i, name := range []string{"allowed", "denied"} {
		dir := filepath.Join(p.project, "tree", name)
		found := false
		for j, row := range rows.FS {
			if row.Path == dir {
				indices[i], found = uint16(j), true
			}
		}
		if !found {
			t.Fatalf("row compiler has no %s subvolume row", name)
		}
		a := agent.Action{Kind: agent.ActionFSRead, Path: filepath.Join(dir, "payload")}
		model := decide.EvaluateIn(rt, a, backend.TierCgroup, decide.Env{})
		plane := decide.NewPlaneEvaluator(rt).Evaluate(a, decide.Env{})
		want := agent.EvalResult{Verdict: agent.VerdictAllow, Rule: "fs.write[./tree/allowed/]"}
		if name == "denied" {
			want.Verdict, want.Rule, want.Reason = agent.VerdictRefused, "fs.deny_read[./tree/denied/]", "read-denied"
		}
		if model != want || plane != want {
			t.Fatalf("%s model=%+v plane=%+v, want %+v", name, model, plane, want)
		}
	}
	return indices
}

func btrfsPlaneKernelRows(t *testing.T, mode string, indices [2]uint16) {
	t.Helper()
	hash, err := bindings.Hash()
	if err != nil {
		t.Fatal(err)
	}
	outer, err := ebpf.LoadPinnedMap(filepath.Join(DefaultBPFFS, pinRoot, hash+"-"+mode, pinMaps, bindings.MapPlaneRows), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	var slot, id uint32
	it := outer.Iterate()
	for it.Next(&slot, &id) {
		inner, err := ebpf.NewMapFromID(ebpf.MapID(id))
		if err != nil {
			t.Fatal(err)
		}
		var keys [2]uint64
		var values [2]bindings.PlaneRow
		var key uint64
		var row bindings.PlaneRow
		rows := inner.Iterate()
		for rows.Next(&key, &row) {
			for i, idx := range indices {
				if row.RuleIdx == idx && row.Ino == 256 {
					keys[i], values[i] = key, row
				}
			}
		}
		err = rows.Err()
		_ = inner.Close()
		if err != nil {
			t.Fatal(err)
		}
		if keys[0] == 0 || keys[1] == 0 {
			continue
		}
		if keys[0] == keys[1] || values[0].Ino != values[1].Ino || values[0].Dev != values[1].Dev ||
			values[0].Gen != values[1].Gen || values[0].Kind&bindings.PlaneRowReadDeny != 0 || values[1].Kind&bindings.PlaneRowReadDeny == 0 {
			t.Fatalf("slot %d did not preserve two distinct subvolume policies under one superblock: keys-equal=%v rows=%+v", slot, keys[0] == keys[1], values)
		}
		t.Logf("slot %d holds distinct inode-pointer keys for two subvolume roots with i_ino=%d and kernel s_dev=%x", slot, values[0].Ino, values[0].Dev)
		return
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("no live slot contains both subvolume root rows %v", indices)
}
