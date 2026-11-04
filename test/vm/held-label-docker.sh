#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Disposable Ubuntu KVM guest only. Stage Docker and its libraries, /vm/tego,
# /vm/runtime.test, /vm/supervisor.test and the sibling test scripts first.
# No image pull: import the static BusyBox and test binaries already in the guest.
set -euo pipefail
[ -f /.vm/nonce ] || { echo 'requires the disposable KVM initramfs' >&2; exit 2; }
export DOCKER_HOST=unix:///run/docker-label.sock DOCKER_RAMDISK=1
for bin in docker dockerd containerd runc; do "$bin" --version; done
[ "$(cat /sys/kernel/security/apparmor/.ns_level)" = 0 ]
dockerd --storage-driver=vfs --feature containerd-snapshotter=false --bridge=none --iptables=false \
 --ip6tables=false --ip-forward=false --ip-masq=false --data-root=/docker-label-data \
 --exec-root=/docker-label-run --pidfile=/run/docker-label.pid --host="$DOCKER_HOST" >/vm/dockerd.log 2>&1 &
daemon=$!
trap 'rc=$?; kill "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true; if [ "$rc" -ne 0 ]; then tail -60 /vm/dockerd.log; fi; exit "$rc"' EXIT
for _ in $(seq 1 100); do docker info >/dev/null 2>&1 && break; sleep .1; done
docker info
mkdir -p /image/{bin,proc,sys,dev,tmp,etc,work/out}
cp /usr/lib/tego-vm/busybox /image/bin/busybox
for app in sh cat grep mkdir id sleep chmod chown find; do ln -s busybox "/image/bin/$app"; done
printf 'root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1000::/work:/bin/sh\n' >/image/etc/passwd
printf 'root:x:0:\nagent:x:1000:\n' >/image/etc/group
chmod 1777 /image/tmp
cp /vm/supervisor.test /image/bin/supervisor.test
cp /vm/tego /image/bin/tego
cp /vm/runtime.test /image/bin/actor
cp /vm/held-label-docker-engine.sh /image/bin/check-engine
chmod +x /image/bin/check-engine
if [ -f /vm/supervisor-reviewed.test ]; then cp /vm/supervisor-reviewed.test /image/bin/supervisor-reviewed.test; fi
/usr/lib/tego-vm/busybox tar -C /image -cf /image.tar .
docker import /image.tar tego-label-test:local
# AppArmor stays docker-default. The outer seccomp filter must permit the APIs
# under test. A securityfs bind proves actual profile denial, not just absence.
common=(--rm --network none --security-opt seccomp=unconfined -v /sys/kernel/security:/sys/kernel/security:ro)
if [ -f /vm/supervisor-reviewed.test ]; then
 rc=0
 docker run "${common[@]}" -e TEGO_TEST_DOCKER_LABELS=1 tego-label-test:local /bin/supervisor-reviewed.test \
  -test.v -test.run '^TestOpenLabelDockerAppArmor$' >/vm/reviewed.log 2>&1 || rc=$?
 cat /vm/reviewed.log
 [ "$rc" = 1 ] && grep -q -- '^--- FAIL: TestOpenLabelDockerAppArmor ' /vm/reviewed.log
fi
docker run "${common[@]}" -e TEGO_TEST_DOCKER_LABELS=1 tego-label-test:local /bin/supervisor.test \
 -test.v -test.run '^TestOpenLabelDockerAppArmor$' | tee /vm/docker-test.log
/vm/held-label-required.sh /vm/docker-test.log TestOpenLabelDockerAppArmor
for mode in direct refuse assume; do
 # Root launch needs CAP_SYS_ADMIN before no_new_privs and CAP_SYS_PTRACE for
 # cross-uid task access, plus a writable cgroup view. These are test prerequisites.
 docker run "${common[@]}" --cap-add SYS_PTRACE --cap-add SYS_ADMIN --cgroupns host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw -e SUDO_UID=1000 -e SUDO_GID=1000 -e SUDO_USER=agent \
  tego-label-test:local /bin/check-engine "$mode"
done
