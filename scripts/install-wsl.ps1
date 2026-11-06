# SPDX-License-Identifier: Apache-2.0
#
# Installs Tego on Windows, inside WSL2. Tego enforces its rules with Linux kernel features, and WSL2 runs a real
# Linux kernel, so Tego runs in an Ubuntu 24.04 distribution there.
#
# UNTESTED: this script has not been run on Windows. It was written and reviewed on Linux, where it cannot run.
# Each step is one command you can also type yourself (docs/INSTALL.md, "Windows").
#
# Usage, in PowerShell opened as administrator (step 1, `wsl --install`, needs it):
#
#   powershell -ExecutionPolicy Bypass -File install-wsl.ps1
#
# What it does:
#   1. If WSL has no Ubuntu-24.04 distribution, it runs `wsl --install -d Ubuntu-24.04` and stops. Windows may ask
#      you to restart; Ubuntu asks you to create a user the first time it starts. Then run this script again.
#   2. It runs the Linux one-line install inside Ubuntu-24.04, as your Ubuntu user.

$ErrorActionPreference = 'Stop'

$Distro = 'Ubuntu-24.04'
$Install = 'curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh'

# Step 1. `wsl -d <name> --exec true` fails when the distribution, or WSL itself, is not installed.
wsl.exe -d $Distro --exec true 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing $Distro in WSL."
    Write-Host "When it is done, create your Ubuntu user, close Ubuntu, and run this script again."
    wsl.exe --install -d $Distro
    exit $LASTEXITCODE
}

# Step 2.
Write-Host "Installing Tego in $Distro."
wsl.exe -d $Distro --exec sh -c $Install
if ($LASTEXITCODE -ne 0) {
    Write-Host "The install failed (exit $LASTEXITCODE). Its message is above."
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Done. To use Tego, open Ubuntu (wsl -d $Distro) and run:"
Write-Host "  tego doctor    # which tier WSL2 gives here; each check that fails prints its fix"
