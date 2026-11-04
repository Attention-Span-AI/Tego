#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Load a disposable policy ONLY inside kvm-run.sh's private initramfs. The
# supervisor regression recognizes only this disposable policy's process context.
set -eu
[ -f /.vm/nonce ] || { echo 'held-label-policy: requires a disposable kvm-run guest' >&2; exit 2; }
case "${1:-}" in
selinux)
 mkdir -p /sys/fs/selinux
 mount -t selinuxfs none /sys/fs/selinux
 cat "$2" > /sys/fs/selinux/load || { dmesg | tail -60; exit 1; }
 printf 1 > /sys/fs/selinux/enforce
 ;;
smack)
 mkdir -p /sys/fs/smackfs
 mount -t smackfs none /sys/fs/smackfs
 ;;
*) echo 'usage: held-label-policy.sh selinux POLICY | smack' >&2; exit 2 ;;
esac
