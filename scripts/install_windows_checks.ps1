# SPDX-License-Identifier: Apache-2.0
$ErrorActionPreference = 'Stop'
Import-Module Pester -MinimumVersion 5.7.1 -ErrorAction Stop
Import-Module PSScriptAnalyzer -MinimumVersion 1.25.0 -ErrorAction Stop
$settings = @{
    IncludeRules = @('PSUseCompatibleSyntax','PSUseCompatibleCommands')
    Rules = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') }
        PSUseCompatibleCommands = @{
            Enable = $true
            TargetProfiles = @('win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework.json')
        }
    }
}
foreach ($name in @('install.ps1')) {
    $issues = @(Invoke-ScriptAnalyzer -Path (Join-Path $PSScriptRoot $name) -Settings $settings)
    $issues | Format-Table -AutoSize
    if ($issues.Count -ne 0) { throw "$name is not compatible with Windows PowerShell 5.1" }
}
$result = Invoke-Pester -Path (Join-Path $PSScriptRoot 'install_windows.Tests.ps1') -PassThru -Output Detailed
if ($result.FailedCount -ne 0 -or $result.PassedCount -eq 0) { exit 1 }
