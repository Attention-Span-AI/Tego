#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Only the dedicated disposable boot may invoke this kernel policy loader.
set -eu
[ -f /.vm/nonce ] || exit 2
printf 'PROFILE_VERSION=20150505\n0-CONFIG={ mode=disabled }\n' > /sys/kernel/security/tomoyo/profile
# The enforcing_profile boot also defines profile 7, which no domain uses, in mode enforcing (SEC08b).
[ ! -f /vm/tomoyo-enforcing ] || printf '7-CONFIG={ mode=enforcing }\n' > /sys/kernel/security/tomoyo/profile
# The flip-race and differential boots register the test binary as a TOMOYO manager: after activation only a registered
# manager may write policy, and the loader is the one place anything may.
[ ! -f /vm/tomoyo-manager ] || printf '/vm/runtime.test\n' > /sys/kernel/security/tomoyo/manager
