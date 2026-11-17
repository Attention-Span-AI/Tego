#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Only the dedicated disposable boot may invoke this kernel policy loader.
set -eu
[ -f /.vm/nonce ] || exit 2
printf 'PROFILE_VERSION=20150505\n0-CONFIG={ mode=disabled }\n' > /sys/kernel/security/tomoyo/profile
