#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Owed in a guest. AlmaLinux 9.8 does not put systemd on PATH.
set -eu
systemd_version=$(/usr/lib/systemd/systemd --version)
printf '%s\n' "$systemd_version" | sed -n '1p'
