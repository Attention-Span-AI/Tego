# SPDX-License-Identifier: Apache-2.0
# Requires Windows PowerShell 5.1 or PowerShell 7. No module installation.
& {
param([switch]$Yes, [switch]$Uninstall, [switch]$DisableWslg, [switch]$LoadOnly, [int]$LauncherPid = 0)
$ErrorActionPreference = 'Stop'
$TegoRepository = 'Attention-Span-AI/Tego'

function Stop-TegoInstall([int]$Code, [string]$Message) {
    Write-Host "  X $Message"
    $exception = New-Object System.Exception($Message)
    $exception.Data['TegoExitCode'] = $Code
    throw $exception
}
function Confirm-TegoStep([string]$Question, [string]$Command, [bool]$DefaultNo = $false, [bool]$Explicit = $false) {
    if ($TegoYes -and !$Explicit) {
        if ($DefaultNo) { Write-Host '  Skipped (optional). Nothing was changed.'; return $false }
        Write-Host "    $Question yes"
        return $true
    }
    if ([Console]::IsInputRedirected -or ![Environment]::UserInteractive) {
        if ($DefaultNo) { Write-Host '  Skipped. Nothing was changed.' }
        else { Write-Host "  To finish, $Command" }
        return $false
    }
    $hint = '[Y/n]'
    if ($DefaultNo) { $hint = '[y/N]' }
    $answer = Read-Host "    $Question $hint"
    return (!$DefaultNo -and $answer -eq '') -or $answer -match '^[yY](es)?$'
}

function Get-TegoPlatform {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Stop-TegoInstall 3 'This installer needs Windows. Next: use install.sh on Linux.' }
    $system = Get-CimInstance Win32_ComputerSystem
    $cpu = @(Get-CimInstance Win32_Processor)[0]
    $arch = 'unsupported'
    if ($cpu.Architecture -eq 12) { $arch = 'ARM64' }
    elseif ($cpu.Architecture -eq 9) { $arch = 'AMD64' }
    return @{ Build = [int](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber; Arch = $arch; Virtualization = ($system.HypervisorPresent -or $cpu.VirtualizationFirmwareEnabled) }
}
function Invoke-TegoWsl([string[]]$Arguments, [string]$InputText) {
    # All native argv are fixed words or base64, never caller shell text.
    $old = $OutputEncoding
    $oldErrorAction = $ErrorActionPreference
    $oldConsoleEncoding = [Console]::OutputEncoding
    $hadWslUtf8 = Test-Path Env:WSL_UTF8
    $oldWslUtf8 = $env:WSL_UTF8
    try {
        $ErrorActionPreference = 'Continue'
        $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        [Console]::OutputEncoding = $OutputEncoding
        $env:WSL_UTF8 = '1'
        $wsl = Join-Path $env:SystemRoot 'System32/wsl.exe'
        if (!$PSBoundParameters.ContainsKey('InputText')) { $InputText = '' }
        $output = $InputText | & $wsl @Arguments 2>&1
        $nativeCode = $LASTEXITCODE
        $plain = $output | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
        }
        return @{ Code = $nativeCode; Text = (($plain | Out-String) -replace "`0", '') }
    } finally {
        $OutputEncoding = $old
        [Console]::OutputEncoding = $oldConsoleEncoding
        if ($hadWslUtf8) { $env:WSL_UTF8 = $oldWslUtf8 } else { Remove-Item Env:WSL_UTF8 -ErrorAction SilentlyContinue }
        $ErrorActionPreference = $oldErrorAction
    }
}
function Get-TegoWslVersion {
    if (!(Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32/wsl.exe'))) { return $null }
    $result = Invoke-TegoWsl @('--version')
    if ($result.Code -eq 0 -and $result.Text -match '(\d+\.\d+\.\d+)') { return [version]$Matches[1] }
    return $null
}
function Update-TegoWsl([bool]$Installed) {
    $arguments = @('--install', '--no-distribution')
    if ($Installed) { $arguments = @('--update') }
    $line = 'wsl.exe ' + ($arguments -join ' ')
    Write-Host '  Tego needs WSL, the Windows feature that runs Linux. It is missing or needs an update.'
    Write-Host '  Next Windows will ask for administrator permission. Choose Yes to enable this feature.'
    Write-Host '  A separate window will show the work and then close. Your other Linux installations are kept.'
    if (!(Confirm-TegoStep 'Install or update it now?' "right-click Start, choose Terminal (Admin), and run: $line")) {
        Write-Host '  Nothing was changed. Run the installer again when you are ready.'
        return $false
    }
    $folder = Join-Path ([IO.Path]::GetTempPath()) ('tego-wsl-' + [Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $folder)
    try {
        $resultFile = Join-Path $folder 'result.json'
        $helper = Join-Path $folder 'enable.ps1'
        # A real elevated console is necessary for the in-box WSL bootstrap.
        # Read the result back: its success exit alone does not report a restart.
        $body = @'
$ErrorActionPreference = 'Stop'
try {
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/wsl.exe') -ArgumentList @ARGUMENTS@ -Wait -PassThru
    $feature = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or $feature.State -eq 'EnablePending' -or $p.ExitCode -in @(3010,1641)
    @{ Code = $p.ExitCode; Restart = $pending; FeatureState = [string]$feature.State } | ConvertTo-Json | Set-Content -LiteralPath '@RESULT@' -Encoding UTF8
} catch {
    @{ Code = 1; Error = [string]$_ } | ConvertTo-Json | Set-Content -LiteralPath '@RESULT@' -Encoding UTF8
}
'@
        $quoted = '@(' + (($arguments | ForEach-Object { "'$_'" }) -join ',') + ')'
        $body = $body.Replace('@ARGUMENTS@', $quoted).Replace('@RESULT@', $resultFile.Replace("'", "''"))
        [IO.File]::WriteAllText($helper, $body, (New-Object Text.UTF8Encoding($false)))
        $hostPS = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("& '" + $helper.Replace("'", "''") + "'"))
        [void](Start-Process -FilePath $hostPS -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -Verb RunAs -Wait -PassThru)
        if (!(Test-Path -LiteralPath $resultFile)) { Stop-TegoInstall 2 "Windows did not return an update result. Next: right-click Start, choose Terminal (Admin), and run: $line" }
        $result = Get-Content -Raw -LiteralPath $resultFile | ConvertFrom-Json
        if ($result.Code -notin @(0,3010,1641)) { Stop-TegoInstall 2 "WSL could not be enabled: $($result.Error). Next: right-click Start, choose Terminal (Admin), and run: $line" }
        if ($result.Restart) {
            Write-Host '  Windows must restart now. Save your work and restart.'
            Write-Host '  After restarting, open PowerShell from Start and paste this line again:'
            $again = "irm https://github.com/$TegoRepository/releases/latest/download/install.ps1 | iex"
            # A chosen version does not survive the restart (an environment variable set in this window is gone), so the line
            # carries it and fetches that version's own installer. Get-TegoRelease has not run yet: a value it would refuse
            # is not built into a URL here, and the person gets the plain line and that refusal after the restart.
            if ($env:TEGO_VERSION -match '^v?[0-9][0-9A-Za-z.+-]*$') {
                $settings = @()
                foreach ($name in @('TEGO_BASE_URL','TEGO_VERSION','TEGO_TEST_HTTP','TEGO_CHECKSUMS_SHA256','TEGO_YES')) {
                    $value = [Environment]::GetEnvironmentVariable($name)
                    if ($value) { $settings += ('$env:' + $name + "='" + $value.Replace("'", "''") + "'") }
                }
                $base = "https://github.com/$TegoRepository/releases/download"
                if ($env:TEGO_BASE_URL) { $base = $env:TEGO_BASE_URL.TrimEnd('/') }
                $tag = $env:TEGO_VERSION
                if (!$tag.StartsWith('v')) { $tag = 'v' + $tag }
                $url = $base + '/' + $tag + '/install.ps1'
                $again = ($settings -join '; ') + "; irm '" + $url.Replace("'", "''") + "' | iex"
            }
            Write-Host ('    ' + $again)
            return $false
        }
        return $true
    } catch {
        if ($_.Exception.Data.Contains('TegoExitCode')) { throw }
        Stop-TegoInstall 2 "Windows could not enable WSL: $_. Next: right-click Start, choose Terminal (Admin), and run: $line"
    } finally { Remove-Item -LiteralPath $folder -Recurse -Force }
}

function Receive-TegoFile([string]$Url, [string]$Destination, [int]$MissingCode = 5) {
    $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination -TimeoutSec 300 }
    catch {
        $code = 6
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -in @(404,410)) { $code = $MissingCode }
        Stop-TegoInstall $code "Download failed: $Url. Next: check your internet connection and run the installer again. Details: $_"
    }
}
function Get-TegoHash([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function Assert-TegoAsset([string]$Path, [string]$Name, [string]$Checksums) {
    $entries = [regex]::Matches($Checksums, ('(?m)^([0-9a-f]{64})  ' + [regex]::Escape($Name) + '\r?$'))
    if ($entries.Count -ne 1 -or (Get-TegoHash $Path) -ne $entries[0].Groups[1].Value) { Stop-TegoInstall 7 "Checksum mismatch or missing entry for $Name. No unchecked file was used. Next: retry the installer; if it repeats, report it at https://github.com/$TegoRepository/issues." }
}
function Get-TegoRelease([string]$Work, [string]$Arch = 'AMD64') {
    $tag = $env:TEGO_VERSION
    $base = $env:TEGO_BASE_URL
    if (!$base) { $base = "https://github.com/$TegoRepository/releases/download" }
    if ($base -notmatch '^https://[^\s''"`]+$' -and !($env:TEGO_TEST_HTTP -eq '1' -and $base -match '^http://[^\s''"`]+$')) { Stop-TegoInstall 2 'TEGO_BASE_URL requires HTTPS. Next: use an HTTPS release URL (HTTP needs the explicit TEGO_TEST_HTTP=1 test switch).' }
    if (!$tag) {
        $api = $env:TEGO_API_URL
        if (!$api) { $api = "https://api.github.com/repos/$TegoRepository/releases/latest" }
        Receive-TegoFile $api (Join-Path $Work 'latest.json')
        $tag = (Get-Content -Raw -LiteralPath (Join-Path $Work 'latest.json') | ConvertFrom-Json).tag_name
    }
    if (!$tag -or $tag -notmatch '^v?[0-9][0-9A-Za-z.+-]*$') { Stop-TegoInstall 5 'No valid release tag. Next: set TEGO_VERSION=vX.Y.Z to a published release.' }
    if (!$tag.StartsWith('v')) { $tag = 'v' + $tag }
    $sumName = 'tego_' + $tag.Substring(1) + '_checksums.txt'
    $sumPath = Join-Path $Work $sumName
    Receive-TegoFile "$base/$tag/$sumName" $sumPath
    $digest = Get-TegoHash $sumPath
    if ($env:TEGO_CHECKSUMS_SHA256 -and $digest -ne $env:TEGO_CHECKSUMS_SHA256) { Stop-TegoInstall 7 'Pinned checksums digest differs. Next: obtain the intended release again.' }
    $verify = $env:TEGO_VERIFY
    if (!$verify) { $verify = 'auto' }
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
    if ($verify -eq 'cosign' -or ($verify -eq 'auto' -and $cosign)) {
        if (!$cosign) { Stop-TegoInstall 2 'TEGO_VERIFY=cosign needs cosign on PATH. Next: install cosign and retry.' }
        Receive-TegoFile "$base/$tag/$sumName.sigstore.json" "$sumPath.sigstore.json" 9
        $identity = "https://github.com/$TegoRepository/.github/workflows/release.yml@refs/tags/$tag"
        & cosign verify-blob --bundle "$sumPath.sigstore.json" --certificate-identity $identity --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' $sumPath
        if ($LASTEXITCODE -ne 0) { Stop-TegoInstall 9 'Release signature did not verify. Next: obtain an authentic release; installation stopped.' }
    } elseif ($verify -in @('auto','sha256')) {
        if ($base.StartsWith('https://')) { Write-Host '  Download checksums came over HTTPS. Who published them was not checked (advanced: install cosign).' }
        else { Write-Host '  TEST ONLY: HTTP mirror; publisher identity and transport were not verified.' }
    } else { Stop-TegoInstall 2 'TEGO_VERIFY must be auto, sha256 or cosign. Next: choose one and rerun.' }
    $checksums = Get-Content -Raw -LiteralPath $sumPath
    $binaryArch = 'amd64'
    if ($Arch -eq 'ARM64') { $binaryArch = 'arm64' }
    $launcher = 'tego_' + $tag.Substring(1) + '_windows_' + $binaryArch + '.exe'
    foreach ($asset in @('install.sh','install.ps1','windows-provision.sh','windows-entry.py',$launcher)) {
        $path = Join-Path $Work $asset
        Receive-TegoFile "$base/$tag/$asset" $path
        Assert-TegoAsset $path $asset $checksums
    }
    return @{ Tag = $tag; Base = $base; Digest = $digest; InstallerHash = (Get-TegoHash (Join-Path $Work 'install.sh')); Launcher = $launcher }
}
function Get-TegoWslConfigPath { return Join-Path $env:USERPROFILE '.wslconfig' }
function Set-TegoWslg([string]$Root, [bool]$OptIn = $false) {
    if (!$OptIn) { Write-Host '  Kept Linux windows and sound settings. Optional: -DisableWslg turns them off for ALL your Linux installations.'; return }
    try {
    $path = Get-TegoWslConfigPath
    $text = ''
    if (Test-Path -LiteralPath $path) { $text = [IO.File]::ReadAllText($path) }
    $lines = @($text -split '\r?\n')
    $section = ''
    $sectionIndex = -1
    $keyIndex = -1
    for ($i=0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*\[([^]]+)\]\s*(?:[#;].*)?$') {
            $section = $Matches[1].ToLowerInvariant()
            if ($section -eq 'wsl2') {
                if ($sectionIndex -ge 0) { Stop-TegoInstall 8 'Duplicate [wsl2] sections. Next: resolve them in .wslconfig; it was not changed.' }
                $sectionIndex = $i
            }
        } elseif ($section -eq 'wsl2' -and $lines[$i] -match '^\s*guiApplications\s*=\s*(.*?)\s*(?:[#;].*)?$') {
            if ($keyIndex -ge 0) { Stop-TegoInstall 8 'Duplicate guiApplications keys. Next: resolve them in .wslconfig; it was not changed.' }
            $keyIndex = $i
        }
    }
    if ($keyIndex -ge 0 -and $lines[$keyIndex] -match '=\s*false\s*(?:[#;].*)?$') {
        Write-Host '  OK Linux windows and sound are already set to off. The setting applies after all your Linux installations restart.'
        return
    }
    Write-Host '  -DisableWslg: turns off Linux windows and sound for ALL Linux on this PC, including your own installations.'
    [void](New-Item -ItemType Directory -Force -Path $Root)
    $backup = Join-Path $Root 'wslconfig-before'
    if ((Test-Path -LiteralPath $path) -and !(Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $path -Destination $backup }
    if ($keyIndex -ge 0) { $lines[$keyIndex] = 'guiApplications=false' }
    elseif ($sectionIndex -ge 0) {
        $lines[$sectionIndex] += "`r`nguiApplications=false"
    } else { $lines += @('[wsl2]','guiApplications=false') }
    $current = ''
    if (Test-Path -LiteralPath $path) { $current = [IO.File]::ReadAllText($path) }
    if ($current -cne $text) { Stop-TegoInstall 8 'Global settings changed while asking. Next: review .wslconfig and retry; it was not overwritten.' }
    $pending = $path + '.tego-' + [Guid]::NewGuid().ToString('N')
    $previous = $pending + '.previous'
    try {
        [IO.File]::WriteAllText($pending, ($lines -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $path) { [IO.File]::Replace($pending, $path, $previous) }
        else { [IO.File]::Move($pending, $path) }
    } finally {
        if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending -Force }
        if (Test-Path -LiteralPath $previous) { Remove-Item -LiteralPath $previous -Force }
    }
    Copy-Item -LiteralPath $path -Destination (Join-Path $Root 'wslconfig-written') -Force
    Write-Host "  OK WSLg global setting saved; the previous file, if any, is at $backup."
    Write-Host '  It applies only after ALL your WSL distributions stop. Save their work and restart them yourself; this installer will not stop them.'
    } catch { Write-Host "  Optional Linux windows/sound setting was skipped: $_. Nothing else in the install was stopped." }
}
function Get-TegoInstallRoot { return Join-Path $env:LOCALAPPDATA 'Tego' }
function Set-TegoUserPath([string]$Bin, [bool]$Remove) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $value = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($key.GetValueNames() -contains 'Path') { $kind = $key.GetValueKind('Path') }
        $state = Join-Path (Split-Path $Bin -Parent) 'path-before.json'
        if (!$Remove -and !(Test-Path -LiteralPath $state)) {
            @{ Existed = ($key.GetValueNames() -contains 'Path'); Value = $value; Kind = [string]$kind } | ConvertTo-Json | Set-Content -LiteralPath $state -Encoding UTF8
        }
        $parts = @($value -split ';' | Where-Object { $_ -ne $Bin })
        if (!$Remove -and $parts -notcontains $Bin) { $parts += $Bin }
        $updated = $parts -join ';'
        $delete = $false
        if ($Remove -and $updated -eq '' -and (Test-Path -LiteralPath $state)) {
            $before = Get-Content -Raw -LiteralPath $state | ConvertFrom-Json
            $delete = !$before.Existed
        }
        if ($delete) { $key.DeleteValue('Path', $false) }
        else { $key.SetValue('Path', $updated, $kind) }
    } finally { $key.Dispose() }
    $launcher = Join-Path $Bin 'tego.exe'
    if (Test-Path -LiteralPath $launcher) { & $launcher __path-changed }
    if (!$Remove) { $env:PATH = $Bin + ';' + $env:PATH }
    else { $env:PATH = (($env:PATH -split ';' | Where-Object { $_ -ne $Bin }) -join ';') }
}

# The dashboard relay (tego.exe __relay, docs/adr/0123) runs the installed tego.exe, which Windows keeps open while
# it runs. Stop it before that file is replaced or removed: only the process relay.json names, still running that
# file with the recorded start time. Never fatal: removal also ends it when its Linux side is unregistered.
function Stop-TegoRelay([string]$Root) {
    $record = Join-Path $Root 'relay.json'
    if (!(Test-Path -LiteralPath $record)) { return }
    try {
        $relay = Get-Content -Raw -LiteralPath $record | ConvertFrom-Json
        $p = Get-Process -Id ([int]$relay.pid) -ErrorAction Stop
        if ($p.Path -eq (Join-Path $Root 'bin\tego.exe') -and [string]$p.StartTime.ToFileTimeUtc() -eq [string]$relay.start) {
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            [void]$p.WaitForExit(10000)
            Write-Host '  Stopped the dashboard relay.'
        }
    } catch {
        Write-Host '  The dashboard relay was not running.'
    }
    Remove-Item -LiteralPath $record -Force -ErrorAction SilentlyContinue
}

function Add-TegoCommand([string]$Work, [string]$Root, [string]$Launcher) {
    if (!(Confirm-TegoStep 'Add the tego command so you can type tego in PowerShell?' 'run the installer again and accept the command step.')) {
        Write-Host '  Skipped the command. Nothing was added to your Windows command path.'
        return $false
    }
    $bin = Join-Path $Root 'bin'
    [void](New-Item -ItemType Directory -Force -Path $bin)
    Copy-Item -LiteralPath (Join-Path $Work 'install.ps1') -Destination (Join-Path $Root 'install.ps1') -Force
    $installed = Join-Path $bin 'tego.exe'
    $staged = Join-Path $Work $Launcher
    if (!(Test-Path -LiteralPath $installed) -or (Get-TegoHash $installed) -ne (Get-TegoHash $staged)) {
        Stop-TegoRelay $Root
        Copy-Item -LiteralPath $staged -Destination $installed -Force
    }
    foreach ($name in @('tego.ps1','tego.cmd','tego-windows.ps1')) {
        $legacy = Join-Path $bin $name
        if (Test-Path -LiteralPath $legacy) { Remove-Item -LiteralPath $legacy -Force }
    }
    Set-TegoUserPath $bin $false
    Write-Host '  OK tego command added. New PowerShell windows will see the updated command path.'
    return $true
}

# Test-TegoFromCmd says whether the window this installer was started from is cmd.exe: its parent process is
# cmd.exe (powershell -Command "irm ... | iex" typed at a cmd prompt). Unknown is not cmd.
function Test-TegoFromCmd {
    try {
        $self = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId=" + $PID)
        $parent = Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId=" + $self.ParentProcessId)
        return ([string]$parent.Name -ieq 'cmd.exe')
    } catch { return $false }
}

# Get-TegoNextSteps is what the installer's closing lines say to type, for the window the person is in. PowerShell
# takes & before a quoted path and cmd does not know it (& was unexpected at this time), so each shell gets its own
# line, the one for the window the installer came from first. The command path is already updated for new windows.
function Get-TegoNextSteps([string]$Exe, [bool]$FromCmd) {
    $ps = '  PowerShell: & "' + $Exe + '" start'
    $cmd = '  cmd:        "' + $Exe + '" start'
    $here = @($ps, $cmd)
    if ($FromCmd) { $here = @($cmd, $ps) }
    return @('  Open a new terminal window and type: tego start',
        '  Or, in this window, type the line for your shell:') + $here
}

function Convert-TegoRegistrationPath([string]$Path) {
    if ($Path.StartsWith('\\?\')) { $Path = $Path.Substring(4) }
    return [IO.Path]::GetFullPath($Path).TrimEnd('\')
}
function Test-TegoDistroPathInUse([string]$Path) {
    $expected = Convert-TegoRegistrationPath $Path
    foreach ($key in @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue)) {
        $distro = Get-ItemProperty -LiteralPath $key.PSPath
        if ((Convert-TegoRegistrationPath $distro.BasePath) -eq $expected) { return $true }
    }
    return $false
}
function Test-TegoRegistration([string]$Root) {
    $lxss = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    $expected = Convert-TegoRegistrationPath (Join-Path $Root 'distro')
    foreach ($key in @(Get-ChildItem -LiteralPath $lxss -ErrorAction SilentlyContinue)) {
        $distro = Get-ItemProperty -LiteralPath $key.PSPath
        if ($distro.DistributionName -eq 'tego') {
            return (Convert-TegoRegistrationPath $distro.BasePath) -eq $expected
        }
    }
    return $false
}
function Restore-TegoWslg([string]$Root) {
    $backup = Join-Path $Root 'wslconfig-before'
    $ours = Join-Path $Root 'wslconfig-written'
    if (!(Test-Path -LiteralPath $ours)) { return }
    $path = Get-TegoWslConfigPath
    if ((Test-Path -LiteralPath $path) -and (Get-TegoHash $path) -eq (Get-TegoHash $ours)) {
        if (Test-Path -LiteralPath $backup) { Copy-Item -LiteralPath $backup -Destination $path -Force }
        else { Remove-Item -LiteralPath $path -Force }
        Write-Host '  Restored the Linux windows and sound settings from before the install.'
    } else {
        Write-Host "  Kept your later edits to $path; review its guiApplications setting to restore Linux windows and sound."
    }
}
function Remove-TegoWindows([string]$Root) {
    if (!$TegoRemovalYes -and !(Confirm-TegoStep 'Delete Tego and EVERYTHING in it (your projects and every run record)? This cannot be undone. Recommended: no.' 'run tego uninstall -Yes only when you intend to delete it.' $true $true)) {
        Write-Host '  Nothing was changed.'
        return
    }
    $marker = Join-Path $Root 'installer-owned'
    if (!(Test-Path -LiteralPath $marker) -and !(Test-TegoRegistration $Root)) { Stop-TegoInstall 8 'Cannot establish ownership. Nothing was removed. Next: inspect wsl --list --verbose; wsl --unregister tego deletes that installation and ALL its files if you choose to remove it.' }
    if ($LauncherPid -gt 0) {
        $launcher = Get-Process -Id $LauncherPid -ErrorAction Stop
        if ($launcher.Path -ne (Join-Path $Root 'bin/tego.exe')) { Stop-TegoInstall 8 'The removal caller is not the installed command. Next: run the saved install.ps1 -Uninstall -Yes from PowerShell.' }
        $start = $launcher.StartTime.ToFileTimeUtc()
    }
    $listed = Invoke-TegoWsl @('--list','--quiet')
    if ($listed.Code -ne 0) { Stop-TegoInstall 8 'Cannot check removal ownership. Nothing was removed. Next: run wsl --status and retry.' }
    if (@($listed.Text -split '\r?\n' | ForEach-Object { $_.Trim() }) -contains 'tego') {
        if (!(Test-TegoRegistration $Root)) { Stop-TegoInstall 8 'The registered tego is outside the installer folder. Nothing was removed. Next: inspect wsl --list --verbose before choosing which installation to remove.' }
    }
    Stop-TegoRelay $Root
    $result = Invoke-TegoWsl @('--unregister','tego')
    if ($result.Code -ne 0 -and $result.Text -notmatch 'WSL_E_DISTRO_NOT_FOUND') { Stop-TegoInstall 8 "Unregister failed: $($result.Text). Next: run wsl --status and retry removal." }
    Restore-TegoWslg $Root
    Set-TegoUserPath (Join-Path $Root 'bin') $true
    if ($LauncherPid -gt 0) {
        $quotedRoot = $Root.Replace("'", "''")
        # Windows keeps a running image open. A system PowerShell waits for this
        # exact launcher to exit, then removes the folder; no batch file or
        # on-disk cleanup program is left behind.
        $cleanup = @'
$ErrorActionPreference='Stop'
$p=Get-Process -Id @PID@ -ErrorAction SilentlyContinue
if ($p -and $p.StartTime.ToFileTimeUtc() -eq @START@) { $p.WaitForExit() }
for ($i=0; $i -lt 50; $i++) {
    try { Remove-Item -LiteralPath '@ROOT@' -Recurse -Force; break }
    catch { Start-Sleep -Milliseconds 100 }
}
if (Test-Path -LiteralPath '@ROOT@') { [Console]::Error.WriteLine('Tego removal could not delete @ROOT@. Close programs using it, then remove that folder.') }
'@
        $cleanup = $cleanup.Replace('@PID@',[string]$LauncherPid).Replace('@START@',[string]$start).Replace('@ROOT@',$quotedRoot)
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanup))
        [void](Start-Process -FilePath (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -ArgumentList @('-NoLogo','-NoProfile','-EncodedCommand',$encoded) -WindowStyle Hidden -PassThru)
    } else { Remove-Item -LiteralPath $Root -Recurse -Force }
    Write-Host '  OK Removed Tego, its projects, records and Windows command. WSL and your other Linux installations remain.'
}

function Invoke-TegoInstall([bool]$AcceptAll = $false, [bool]$Remove = $false, [bool]$GlobalWslg = $false) {
    $TegoYes = $AcceptAll -or (!$Remove -and $env:TEGO_YES -eq '1')
    $TegoRemovalYes = $Remove -and $AcceptAll
    $work = $null
    try {
        $platform = Get-TegoPlatform
        $root = Get-TegoInstallRoot
        if ($Remove) {
            if ($AcceptAll) { $TegoYes = $false; $TegoRemovalYes = $true }
            Remove-TegoWindows $root; return 0
        }
        Write-Host "  Tego keeps AI agents inside rules. It needs Linux; this installer sets up Tego's Linux, inside Windows."
        Write-Host '  First setup downloads about 500 MB and needs at least 5 GB free. Allow about 5 to 10 minutes.'
        if ($platform.Build -lt 19044) { Stop-TegoInstall 3 'Your Windows is too old. Next: open Settings > Windows Update, install updates, restart, and run this again.' }
        Write-Host '  OK Windows is recent enough'
        if ($platform.Arch -notin @('AMD64','ARM64')) { Stop-TegoInstall 4 'Tego supports x64 and arm64. Next: use a supported Windows machine.' }
        Write-Host '  OK 64-bit PC'
        if (!$platform.Virtualization) { Stop-TegoInstall 3 'Your PC cannot run Linux yet. Next: enable Intel VT-x or AMD-V (SVM) in BIOS/UEFI setup, then restart and run this again; your PC maker has instructions.' }
        Write-Host '  OK Virtualization is on'
        $version = Get-TegoWslVersion
        # Source-audited floor, not a claim that old flags first appeared here.
        if (!$version -or $version -lt [version]'2.6.3') {
            if (!(Update-TegoWsl ([bool]$version))) { return 2 }
            $version = Get-TegoWslVersion
            if (!$version -or $version -lt [version]'2.6.3') { Stop-TegoInstall 2 'WSL is still unavailable or too old. Next: open Terminal (Admin) from Start and run wsl --update, then rerun this installer.' }
        }
        Write-Host "  OK WSL (the Windows Linux feature) $version"
        $listed = Invoke-TegoWsl @('--list','--quiet')
        if ($listed.Code -ne 0) { Stop-TegoInstall 8 "Cannot list distributions: $($listed.Text). Next: run wsl --status." }
        $exists = @($listed.Text -split '\r?\n' | ForEach-Object { $_.Trim() }) -contains 'tego'
        $marker = Join-Path $root 'installer-owned'
        if ($exists -and !(Test-TegoRegistration $root)) { Stop-TegoInstall 8 'The name tego belongs to another installation. Nothing was changed. Next: inspect wsl --list --verbose; wsl --unregister tego deletes it and ALL its files if you choose to remove it.' }
        if (!(Confirm-TegoStep 'Set up or repair Tego now? Your other Linux installations are kept.' 'run the installer again in PowerShell when you are ready.')) { Write-Host '  Nothing was changed.'; return 0 }
        if ($exists -and !(Test-Path -LiteralPath $marker)) { [IO.File]::WriteAllText($marker, 'tego-windows-installer-v1') }
        $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($root))
        if ($drive.AvailableFreeSpace -lt 5GB) { Stop-TegoInstall 3 'Tego needs at least 5 GB free. Next: free space on your Windows drive, then rerun this installer.' }
        $work = Join-Path ([IO.Path]::GetTempPath()) ('tego-install-' + [Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $work)
        $release = Get-TegoRelease $work $platform.Arch
        if (!$exists) {
            $imageArch = 'amd64'
            $imageHash = 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e'
            if ($platform.Arch -eq 'ARM64') { $imageArch = 'arm64'; $imageHash = '74478b5024d9047397ba79d17c27f73caf85ada4988f88cffc2892d65e6a806b' }
            $image = Join-Path $work 'ubuntu.wsl'
            $imageUrl = "https://releases.ubuntu.com/24.04.5/ubuntu-24.04.5-wsl-amd64.wsl"
            if ($imageArch -eq 'arm64') { $imageUrl = 'https://cdimages.ubuntu.com/releases/24.04.5/release/ubuntu-24.04.5-wsl-arm64.wsl' }
            Write-Host '  Downloading Linux (about 500 MB)...'
            try { Receive-TegoFile $imageUrl $image }
            catch { Stop-TegoInstall 5 'The pinned Ubuntu Linux image could not be fetched. Next: check your connection and retry the latest Tego installer; if it repeats, report the missing Ubuntu image on the Tego issues page.' }
            if ((Get-TegoHash $image) -ne $imageHash) { Stop-TegoInstall 7 'Ubuntu image SHA-256 differs from the release pin. Next: retry; no distribution was imported.' }
            [void](New-Item -ItemType Directory -Force -Path $root)
            $distroPath = Join-Path $root 'distro'
            if (Test-Path -LiteralPath $distroPath) {
                if (!(Test-Path -LiteralPath $marker) -or (Test-TegoDistroPathInUse $distroPath)) { Stop-TegoInstall 8 'The import folder is already in use. Nothing was moved. Next: inspect wsl --list --verbose before retrying.' }
                $saved = Join-Path $root ('distro-interrupted-' + [Guid]::NewGuid().ToString('N'))
                Move-Item -LiteralPath $distroPath -Destination $saved
                Write-Host "  Kept files from an interrupted import at $saved. Retrying the import."
            }
            [IO.File]::WriteAllText($marker, 'tego-windows-installer-v1', [Text.Encoding]::ASCII)
            $result = Invoke-TegoWsl @('--import','tego',(Join-Path $root 'distro'),$image,'--version','2')
            if ($result.Code -ne 0) { Stop-TegoInstall 8 "Import failed: $($result.Text). Next: run wsl --status, restart if requested, then rerun." }
        }
        Write-Host "  OK Tego's own Linux is ready (your other Linux installations were kept)"
        $provision = Get-Content -Raw -LiteralPath (Join-Path $work 'windows-provision.sh')
        $entry = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $work 'windows-entry.py')))
        $needsRestart = $true
        if ($exists) {
            $running = Invoke-TegoWsl @('--list','--running','--quiet')
            if ($running.Code -ne 0) { Stop-TegoInstall 8 'Cannot check running installations. Next: run wsl --status, then retry.' }
            $wasRunning = @($running.Text -split '\r?\n' | ForEach-Object { $_.Trim() }) -contains 'tego'
            $check = Invoke-TegoWsl @('--distribution','tego','--user','root','--exec','bash','-s','--',$entry,'check') $provision
            if ($check.Code -notin @(0,10)) { Stop-TegoInstall 8 "Cannot check repair settings: $($check.Text). Next: run wsl --status and retry." }
            $needsRestart = $check.Code -eq 10
            if ($needsRestart -and $wasRunning -and !(Confirm-TegoStep 'This repair changes Linux startup settings and must stop all work running in Tego. Stop it now? Recommended: no.' 'save your work in Tego and rerun this installer.' $true $true)) {
                Write-Host '  Nothing in Tego was changed.'; return 0
            }
        }
        Write-Host '  Setting up Linux (a few minutes on the first run)...'
        $result = Invoke-TegoWsl @('--distribution','tego','--user','root','--exec','bash','-s','--',$entry) $provision
        if ($result.Code -ne 0) { Stop-TegoInstall 8 "Provision failed: $($result.Text). Next: rerun to repair tego." }
        if ($needsRestart) {
            Write-Host "  Restarting Tego's Linux to apply its startup settings."
            $result = Invoke-TegoWsl @('--terminate','tego')
            if ($result.Code -ne 0) { Stop-TegoInstall 8 "Could not restart Tego: $($result.Text). Next: run wsl --terminate tego, then rerun the installer." }
        }
        $fields = @($release.Tag,$release.Base,$release.Digest,$release.InstallerHash,([string]($env:TEGO_TEST_HTTP -eq '1')))
        $encoded = @($fields | ForEach-Object { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) })
        $result = Invoke-TegoWsl (@('--distribution','tego','--user','tego','--exec','/usr/local/lib/tego/windows-entry','--install') + $encoded)
        Write-Host $result.Text
        $added = $false
        if ($result.Code -in @(0,211,212)) {
            # Leave a verified, reachable diagnostics/removal command even when
            # Linux installed but a later capability or guide check refused.
            $added = Add-TegoCommand $work $root $release.Launcher
            if ($added) { Set-TegoWslg $root $GlobalWslg }
        }
        $diagnostic = 'doctor'
        if ($result.Code -eq 212) { $diagnostic = 'setup --json' }
        $next = 'wsl -d tego -u tego --exec /usr/local/lib/tego/windows-entry WyJkb2N0b3IiXQ=='
        if ($result.Code -eq 212) { $next = 'wsl -d tego -u tego --exec /usr/local/lib/tego/windows-entry WyJzZXR1cCIsIi0tanNvbiJd' }
        if ($added) { $next = '& "' + (Join-Path $root 'bin/tego.exe') + '" ' + $diagnostic }
        if ($result.Code -eq 211) { Stop-TegoInstall 8 ("The protection check found no usable level. Next: " + $next) }
        if ($result.Code -eq 212) { Stop-TegoInstall 8 ("The guide is not ready on this WSL setup. Next: " + $next) }
        if ($result.Code -ne 0) { Stop-TegoInstall 8 'Linux installation did not finish. Next: check the download or system error above and rerun this installer in PowerShell.' }
        Write-Host '  OK Linux install, protection and guide checks completed'
        if ($added) {
            Write-Host '  Next steps: choose your agent and a safe test project.'
            foreach ($line in (Get-TegoNextSteps (Join-Path $root 'bin/tego.exe') (Test-TegoFromCmd))) { Write-Host $line }
        } else { Write-Host '  Next: wsl -d tego -u tego --exec /usr/local/lib/tego/windows-entry W10=' }
        return 0
    } catch {
        if ($_.Exception.Data.Contains('TegoExitCode')) { return [int]$_.Exception.Data['TegoExitCode'] }
        Write-Host "  X Install failed: $_"
        Write-Host '  Next: check the message above and rerun this installer in PowerShell; if it repeats, send that message to the Tego issues page.'
        return 8
    } finally {
        if ($work -and (Test-Path -LiteralPath $work)) { Remove-Item -Recurse -Force -LiteralPath $work }
    }
}
if (!$LoadOnly) {
    $code = Invoke-TegoInstall -AcceptAll ([bool]$Yes) -Remove ([bool]$Uninstall) -GlobalWslg ([bool]$DisableWslg)
    if ($MyInvocation.MyCommand.ScriptBlock.File) { exit $code }
    $global:LASTEXITCODE = $code
}
} @args
