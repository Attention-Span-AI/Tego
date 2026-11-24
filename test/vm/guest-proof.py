#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Boot one pinned cloud image, install tego as an ordinary user, and run one guest proof from guest-proof/.

Run one guest at a time. The image is checked against its SHA-256 first. No tego
binary runs on the host: the pairs of tego and tego-control (--pair-a, --pair-b) are built by the caller and only
copied into the guest. The proofs are guest-proof/dashboard-reuse.sh and guest-proof/uninstall-dropin.sh; each ends
with `FAILS=<n>` and exits with n.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROOFS = ("dashboard-reuse", "uninstall-dropin")
ADMIN_GROUP = {"fedora": "wheel", "debian": "sudo", "ubuntu": "sudo"}


def run(*args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, text=True, **kw)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--proof", choices=PROOFS, required=True)
    ap.add_argument("--family", choices=sorted(ADMIN_GROUP), required=True, help="the image's distribution")
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--image-sha256", required=True)
    ap.add_argument("--pair-a", type=Path, required=True, help="a folder with tego and tego-control")
    ap.add_argument("--pair-b", type=Path, required=True, help="the same with another tego-control (other bytes)")
    ap.add_argument("--out", type=Path, required=True, help="a new evidence folder")
    ap.add_argument("--memory", default="3G", choices=("1G", "2G", "3G"))
    ap.add_argument("--qemu", default=os.environ.get("TEGO_VM_QEMU", "qemu-system-x86_64"))
    ap.add_argument("--qemu-img", default="qemu-img")
    ap.add_argument("--genisoimage", default="genisoimage")
    ap.add_argument("--firmware-dir", action="append", type=Path, default=[], help="qemu -L (repeatable)")
    args = ap.parse_args()

    with args.image.open("rb") as f:
        if hashlib.file_digest(f, "sha256").hexdigest() != args.image_sha256:
            sys.exit("image SHA-256 does not match its pin")
    out = args.out.resolve()
    out.mkdir()
    seed, payload = out / "seed", out / "payload"
    seed.mkdir()
    (payload / "bin").mkdir(parents=True)
    for name, src in (("A", args.pair_a), ("B", args.pair_b)):
        (payload / "bin" / name).mkdir()
        for prog in ("tego", "tego-control"):
            shutil.copy2(src / prog, payload / "bin" / name / prog)
    shutil.copytree(HERE / "guest-proof", payload / "guest-proof")
    shutil.copyfile(ROOT / "examples/systemd/tego-agent@.service", payload / "tego-agent@.service")
    run("ssh-keygen", "-q", "-t", "ed25519", "-C", "tego-guest-proof", "-N", "", "-f", str(out / "key"))
    key = (out / "key.pub").read_text().strip()
    (seed / "user-data").write_text(f"""#cloud-config
users:
  - name: tego-admin
    groups: [{ADMIN_GROUP[args.family]}]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - {key}
  - name: tego
    shell: /bin/bash
    sudo: null
    lock_passwd: true
    ssh_authorized_keys:
      - {key}
ssh_pwauth: false
disable_root: true
""")
    (seed / "meta-data").write_text("instance-id: tego-guest-proof\nlocal-hostname: tego-guest-proof\n")
    run(args.genisoimage, "-quiet", "-output", str(out / "seed.iso"), "-volid", "cidata", "-joliet", "-rock",
        str(seed / "user-data"), str(seed / "meta-data"))
    run(args.genisoimage, "-quiet", "-output", str(out / "payload.iso"), "-volid", "TEGOP2", "-joliet", "-rock",
        str(payload))
    run(args.qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(args.image.resolve()),
        str(out / "disk.qcow2"), "12G", stdout=subprocess.DEVNULL)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ssh = ["ssh", "-i", str(out / "key"), "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=3", "-o", "LogLevel=ERROR"]
    admin, user = ssh + ["tego-admin@127.0.0.1"], ssh + ["tego@127.0.0.1"]
    cmd = [args.qemu, "-enable-kvm", "-cpu", "host", "-smp", "2", "-m", args.memory, "-nographic", "-no-reboot",
           "-drive", f"file={out}/disk.qcow2,if=virtio,format=qcow2",
           "-drive", f"file={out}/seed.iso,media=cdrom,readonly=on",
           "-drive", f"file={out}/payload.iso,media=cdrom,readonly=on",
           "-netdev", f"user,id=n1,hostfwd=tcp:127.0.0.1:{port}-:22", "-device", "virtio-net-pci,netdev=n1"]
    for d in args.firmware_dir:
        cmd += ["-L", str(d)]
    console = (out / "console.log").open("wb")
    proc = subprocess.Popen(cmd, stdout=console, stderr=subprocess.STDOUT)
    report = {"proof": args.proof, "family": args.family, "image_sha256": args.image_sha256, "verdict": "FAIL"}
    code = 1
    try:
        deadline = time.monotonic() + 420
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"qemu exited with status {proc.returncode} before SSH came up; see console.log")
            if time.monotonic() > deadline:
                raise TimeoutError("SSH did not come up in 420 s")
            if subprocess.run([*admin, "true"], capture_output=True).returncode == 0:
                break
            time.sleep(2)

        def guest(argv, name, who=user, timeout=900, stdin=None):
            r = subprocess.run([*who, shlex.join(argv)], capture_output=True, text=True, timeout=timeout, input=stdin)
            (out / f"{name}.log").write_text(r.stdout + r.stderr + f"\n[exit {r.returncode}]\n")
            return r

        guest(["sudo", "cloud-init", "status", "--wait"], "cloud-init", admin, 300)
        guest(["sudo", "sh", "-c", "mkdir -p /mnt/p2 && mount -o ro LABEL=TEGOP2 /mnt/p2"], "mount", admin).check_returncode()
        prereq = {
            "fedora": "command -v python3 && command -v curl",
            "debian": "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 curl dbus-user-session",
            "ubuntu": "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 curl dbus-user-session",
        }[args.family]
        guest(["sudo", "sh", "-c", prereq + " && loginctl enable-linger tego"], "prerequisites", admin, 600).check_returncode()
        uid = guest(["id", "-u", "tego"], "uid", admin).stdout.strip()
        for _ in range(60):  # the account's user manager starts at linger
            if guest(["sudo", "test", "-S", f"/run/user/{uid}/systemd/private"], "bus-wait", admin).returncode == 0:
                break
            time.sleep(1)
        time.sleep(3)
        # The proof runs in a user scope, as the guide's step 3 opens one: where the user's own services run.
        script = f"/mnt/p2/guest-proof/{args.proof}.sh"
        r = guest(["XDG_RUNTIME_DIR=/run/user/" + uid, "systemd-run", "--user", "--scope", "--quiet", "bash", script],
                  args.proof, user, 1500)
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        report["exit"] = r.returncode
        report["checks_pass"] = r.stdout.count("CHECK PASS:")
        report["checks_fail"] = r.stdout.count("CHECK FAIL:")
        # The proof's own captured outputs and the dashboard's log.
        r2 = subprocess.run([*user, "tar -C /home/tego -czf - proof-out .tego/dashboard.log"],
                            capture_output=True)
        (out / "guest-files.tgz").write_bytes(r2.stdout)
        report["verdict"] = "PASS" if r.returncode == 0 and report["checks_fail"] == 0 and report["checks_pass"] > 0 else "FAIL"
        code = 0 if report["verdict"] == "PASS" else 1
    except Exception as e:  # noqa: BLE001 - the report names it
        report["error"] = repr(e)
        print("guest-proof:", repr(e), file=sys.stderr)
    finally:
        # Quit the guest by its own pid, never by name.
        if proc.poll() is None:
            subprocess.run([*admin, "sudo", "systemctl", "poweroff"], capture_output=True, timeout=30)
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        console.close()
        report["qemu_exit_status"] = proc.returncode
        for name in ("disk.qcow2", "seed.iso", "payload.iso") if report["verdict"] == "PASS" else ("seed.iso", "payload.iso"):
            (out / name).unlink(missing_ok=True)
        shutil.rmtree(payload, ignore_errors=True)
        shutil.rmtree(seed, ignore_errors=True)
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
