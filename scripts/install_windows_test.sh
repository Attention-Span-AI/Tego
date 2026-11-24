#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Linux stand-ins only; the real Windows workflow is a separate proof.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
pwsh=${TEGO_PWSH:-pwsh}
if ! command -v "$pwsh" >/dev/null 2>&1; then
    echo 'skip install_windows_test: PowerShell is not present (CI supplies it)'
    exit 0
fi
export POWERSHELL_TELEMETRY_OPTOUT=1
"$pwsh" -NoLogo -NoProfile -File "$here/install_windows_checks.ps1"
python3 "$here/windows_entry_test.py"
python3 "$here/windows_hosted_guest_test.py"
