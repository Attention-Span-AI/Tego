# SPDX-License-Identifier: Apache-2.0
BeforeAll {
    $source = Get-Content -Raw (Join-Path $PSScriptRoot 'install.ps1')
    $body = $source.Substring($source.IndexOf('& {') + 3)
    $body = $body.Substring(0, $body.LastIndexOf('} @args'))
    . ([scriptblock]::Create($body)) -LoadOnly
}
Describe 'dedicated Windows install state machine (Linux stand-ins)' {
    BeforeEach {
        $script:Calls = New-Object 'System.Collections.Generic.List[string]'
        $script:Root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $script:Version = [version]'2.6.3'
        $script:Existing = $false
        $script:Failure = ''
        $script:Platform = @{Build=26100;Arch='AMD64';Virtualization=$true}
        $env:TEGO_YES = ''
        $env:TEGO_VERIFY = 'sha256'
        Mock Get-TegoPlatform { return $script:Platform }
        Mock Get-TegoWslVersion { return $script:Version }
        Mock Get-TegoInstallRoot { return $script:Root }
        Mock Set-TegoWslg {}
        Mock Test-TegoRegistration { return Test-Path (Join-Path $script:Root 'installer-owned') }
        Mock Restore-TegoWslg {}
        Mock Set-TegoUserPath { $script:Calls.Add('path:'+$Remove) }
        Mock Confirm-TegoStep { return $true }
        Mock Start-Process {
            $folders = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'tego-wsl-*')
            foreach ($folder in $folders) { [IO.File]::WriteAllText((Join-Path $folder.FullName 'result.json'),'{"Code":0,"Restart":true}') }
            return @{ExitCode=0}
        }
        Mock Get-TegoRelease {
            foreach ($asset in @('install.ps1','windows-provision.sh','windows-entry.py')) {
                Copy-Item (Join-Path $PSScriptRoot $asset) (Join-Path $Work $asset)
            }
            [IO.File]::WriteAllText((Join-Path $Work 'tego_0.2.0_windows_amd64.exe'),'native fixture')
            return @{Launcher='tego_0.2.0_windows_amd64.exe';Tag='v0.2.0';Base='https://mirror.invalid';Digest=('a'*64);InstallerHash=('b'*64)}
        }
        Mock Receive-TegoFile { [IO.File]::WriteAllText($Destination,'image fixture') }
        Mock Get-TegoHash { return 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e' }
        Mock Invoke-TegoWsl {
            $line = $Arguments -join ' '
            $script:Calls.Add($line)
            if ($script:Failure -and $line.Contains($script:Failure)) { return @{Code=1;Text='fixture failure'} }
            if ($line -eq '--list --quiet') {
                $names = "Ubuntu-24.04`nDebian"
                if ($script:Existing) { $names += "`ntego" }
                return @{Code=0;Text=$names}
            }
            return @{Code=0;Text='Tego protection: landlock'}
        }
    }
    It 'creates only tego, closes host channels, installs a command, and carries the release digest' {
        Invoke-TegoInstall $true | Should -Be 0
        ($script:Calls -join "`n") | Should -Match '--import tego'
        ($script:Calls -join "`n") | Should -Match '--terminate tego'
        ($script:Calls -join "`n") | Should -Not -Match '--shutdown|--set-default|--distribution Ubuntu'
        Test-Path (Join-Path $script:Root 'bin/tego.exe') | Should -BeTrue
        Test-Path (Join-Path $script:Root 'bin/tego-windows.ps1') | Should -BeFalse
        Test-Path (Join-Path $script:Root 'bin/tego.ps1') | Should -BeFalse
        (Get-Content -Raw (Join-Path $script:Root 'bin/tego.exe')) | Should -Be 'native fixture'
        (Get-Content -Raw (Join-Path $PSScriptRoot 'install.ps1')) | Should -Not -Match 'Set-ExecutionPolicy'
        $call = @($script:Calls | Where-Object { $_ -match 'windows-entry --install' })[0]
        $call | Should -Match ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('a'*64)))
        $provision = Get-Content -Raw (Join-Path $PSScriptRoot 'windows-provision.sh')
        $provision | Should -Match 'enabled=false'
        $provision | Should -Match 'mountFsTab=false'
        $provision | Should -Match 'appendWindowsPath=false'
        $provision | Should -Not -Match 'NOPASSWD|usermod.*sudo'
    }
    It 'repairs an existing owned distribution and a missing command without importing or touching Ubuntu' {
        $script:Existing=$true
        [void](New-Item -ItemType Directory -Force $script:Root)
        Set-Content (Join-Path $script:Root 'installer-owned') 'tego-windows-installer-v1'
        Invoke-TegoInstall $true | Should -Be 0
        Invoke-TegoInstall $true | Should -Be 0
        ($script:Calls -join "`n") | Should -Not -Match '--import|Ubuntu-24.04.*--exec'
        Test-Path (Join-Path $script:Root 'bin/tego.exe') | Should -BeTrue
    }
    It 'accepts TEGO_YES as well as the file switch' {
        $env:TEGO_YES='1'
        Mock Confirm-TegoStep { return [bool]$TegoYes }
        Invoke-TegoInstall | Should -Be 0
        Test-Path (Join-Path $script:Root 'bin/tego.exe') | Should -BeTrue
    }
    It 'refuses a pre-existing distribution without an ownership marker' {
        $script:Existing=$true
        Invoke-TegoInstall $true | Should -Be 8
        $script:Calls.Count | Should -Be 1
    }
    It 'stops after WSL installation or updating and gives reboot instructions' {
        $script:Version=$null
        $env:SystemRoot=$TestDrive
        Invoke-TegoInstall $true | Should -Be 2
        Should -Invoke Start-Process -Times 1 -ParameterFilter { $Verb -eq 'RunAs' -and $FilePath -match 'powershell.exe$' }
        $script:Calls.Count | Should -Be 0
        $script:Version=[version]'0.67.6'
        Invoke-TegoInstall $true | Should -Be 2
        Should -Invoke Start-Process -Times 2 -ParameterFilter { $Verb -eq 'RunAs' }
    }
    It 'explains the administrator prompt before elevation and prints the restart action' {
        $script:Version=$null
        $env:SystemRoot=$TestDrive
        $script:Messages=New-Object 'System.Collections.Generic.List[string]'
        Mock Write-Host { $script:Messages.Add([string]$Object) }
        Mock Start-Process {
            ($script:Messages -join "`n") | Should -Match 'administrator permission'
            $folders=@(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'tego-wsl-*')
            foreach ($folder in $folders) { [IO.File]::WriteAllText((Join-Path $folder.FullName 'result.json'),'{"Code":0,"Restart":true}') }
            return @{ExitCode=0}
        }
        Invoke-TegoInstall $true | Should -Be 2
        ($script:Messages -join "`n") | Should -Match 'Windows must restart now'
        $script:Messages[-1] | Should -Match 'irm .*install.ps1.*iex'
        Should -Invoke Invoke-TegoWsl -Times 0
    }
    It 'does not elevate or import when the WSL question is declined' {
        $script:Version=$null
        Mock Confirm-TegoStep { return $false }
        Invoke-TegoInstall | Should -Be 2
        Should -Invoke Start-Process -Times 0
        $script:Calls.Count | Should -Be 0
    }
    It 'does not create anything when distribution creation is declined' {
        Mock Confirm-TegoStep { return $false }
        Invoke-TegoInstall | Should -Be 0
        Should -Invoke Get-TegoRelease -Times 0
        Test-Path $script:Root | Should -BeFalse
    }
    It 'can decline adding a Windows command after provisioning' {
        Mock Confirm-TegoStep { return $Question -notmatch 'so you can type tego' }
        Invoke-TegoInstall | Should -Be 0
        Test-Path (Join-Path $script:Root 'bin/tego.exe') | Should -BeFalse
    }
    It 'closes with a line that works in the shell the person is in (PowerShell takes &, cmd does not)' -ForEach @(
        @{FromCmd=$false;First='PowerShell:';Second='cmd:'}, @{FromCmd=$true;First='cmd:';Second='PowerShell:'}
    ) {
        $script:Messages=New-Object 'System.Collections.Generic.List[string]'
        Mock Write-Host { $script:Messages.Add([string]$Object) }
        $script:FromCmd=$FromCmd
        Mock Test-TegoFromCmd { return $script:FromCmd }
        Invoke-TegoInstall $true | Should -Be 0
        $exe=Join-Path $script:Root 'bin/tego.exe'
        $text=$script:Messages -join "`n"
        $text | Should -Match 'Open a new terminal window and type: tego start'
        $shellLines=@($script:Messages | Where-Object { $_ -match '^\s+(PowerShell|cmd):' })
        $shellLines.Count | Should -Be 2
        $shellLines[0] | Should -Match ('^\s+'+[regex]::Escape($First))
        $shellLines[1] | Should -Match ('^\s+'+[regex]::Escape($Second))
        $cmdLine=@($shellLines | Where-Object { $_ -match '^\s+cmd:' })[0]
        $cmdLine | Should -Be ('  cmd:        "'+$exe+'" start')
        $cmdLine | Should -Not -Match '&'
        @($shellLines | Where-Object { $_ -match '^\s+PowerShell:' })[0] | Should -Be ('  PowerShell: & "'+$exe+'" start')
    }
    It 'names no shell to type in when the command was not added' {
        $script:Messages=New-Object 'System.Collections.Generic.List[string]'
        Mock Write-Host { $script:Messages.Add([string]$Object) }
        Mock Confirm-TegoStep { return $Question -notmatch 'so you can type tego' }
        Invoke-TegoInstall | Should -Be 0
        ($script:Messages -join "`n") | Should -Not -Match 'PowerShell:|cmd:|Open a new terminal'
    }
    It 'places a diagnostic command without claiming ready when Linux checks refuse' -ForEach @(
        @{Readiness=211;Diagnostic='doctor'}, @{Readiness=212;Diagnostic='setup --json'}
    ) {
        $script:ReadinessCode=$Readiness
        $script:Messages=New-Object 'System.Collections.Generic.List[string]'
        Mock Write-Host { $script:Messages.Add([string]$Object) }
        Mock Invoke-TegoWsl {
            $line=$Arguments -join ' '
            $script:Calls.Add($line)
            if($line -eq '--list --quiet'){return @{Code=0;Text='Ubuntu-24.04'}}
            if($line -match 'windows-entry --install '){return @{Code=$script:ReadinessCode;Text='Linux check refused'}}
            return @{Code=0;Text='fixture'}
        }
        Invoke-TegoInstall $true | Should -Be 8
        Test-Path (Join-Path $script:Root 'bin/tego.exe') | Should -BeTrue
        ($script:Messages -join "`n") | Should -Not -Match 'Type this.*start|OK Linux install'
        $script:Messages[-1] | Should -Match ('Next:.*'+[regex]::Escape($Diagnostic))
    }
    It 'reports unsupported build, architecture and virtualization with the matching Linux exit scheme' {
        $script:Platform.Build=18362
        Invoke-TegoInstall $true | Should -Be 3
        $script:Platform.Build=26100
        $script:Platform.Arch='x86'
        Invoke-TegoInstall $true | Should -Be 4
        $script:Platform.Arch='AMD64'
        $script:Platform.Virtualization=$false
        Invoke-TegoInstall $true | Should -Be 3
        $script:Calls.Count | Should -Be 0
    }
    It 'stops on each native failure and permits rerunning the installer' -ForEach @(
        @{Fail='--list';Expected=8}, @{Fail='--import';Expected=8},
        @{Fail='bash -s';Expected=8}, @{Fail='--terminate';Expected=8}, @{Fail='--install ';Expected=8}
    ) {
        $script:Failure=$Fail
        Invoke-TegoInstall $true | Should -Be $Expected
        $script:Calls[-1] | Should -Match ([regex]::Escape($Fail))
        Test-Path (Join-Path $script:Root 'bin/tego.exe') | Should -BeFalse
    }
    It 'rejects a mismatched image before import (with the valid image case above as control)' {
        Mock Get-TegoHash { return '0'*64 }
        Invoke-TegoInstall $true | Should -Be 7
        @($script:Calls | Where-Object { $_ -match '--import|--install ' }).Count | Should -Be 0
    }
    It 'requires fresh explicit removal consent even with TEGO_YES left by installation' {
        [void](New-Item -ItemType Directory -Force $script:Root)
        Set-Content (Join-Path $script:Root 'installer-owned') 'tego-windows-installer-v1'
        $env:TEGO_YES='1'
        Mock Confirm-TegoStep { return $false }
        Invoke-TegoInstall $false $true | Should -Be 0
        Should -Invoke Confirm-TegoStep -Times 1 -ParameterFilter { $DefaultNo -and $Explicit }
        @($script:Calls | Where-Object { $_ -match '--unregister' }).Count | Should -Be 0
        Test-Path $script:Root | Should -BeTrue
    }
    It 'does not inherit removal consent from a caller variable' {
        [void](New-Item -ItemType Directory -Force $script:Root)
        Set-Content (Join-Path $script:Root 'installer-owned') 'tego-windows-installer-v1'
        $script:TegoRemovalYes=$true
        try {
            Mock Confirm-TegoStep { return $false }
            Invoke-TegoInstall $false $true | Should -Be 0
            @($script:Calls | Where-Object { $_ -match '--unregister' }).Count | Should -Be 0
            Test-Path $script:Root | Should -BeTrue
        } finally { Remove-Variable TegoRemovalYes -Scope Script }
    }
    It 'keeps a running installation alive when startup settings already match' {
        $script:Existing=$true
        [void](New-Item -ItemType Directory -Force $script:Root)
        Set-Content (Join-Path $script:Root 'installer-owned') 'tego-windows-installer-v1'
        Invoke-TegoInstall $true | Should -Be 0
        @($script:Calls | Where-Object { $_ -match '--terminate' }).Count | Should -Be 0
        @($script:Calls | Where-Object { $_ -match 'bash -s' }).Count | Should -Be 2
        @($script:Calls | Where-Object { $_ -match 'windows-entry --install ' }).Count | Should -Be 1
    }
    It 'does not overwrite the same native image during a rerun' {
        Invoke-TegoInstall $true | Should -Be 0
        Mock Copy-Item {} -ParameterFilter { $Destination -eq (Join-Path $script:Root 'bin/tego.exe') }
        Invoke-TegoInstall $true | Should -Be 0
        Should -Invoke Copy-Item -Times 0 -ParameterFilter { $Destination -eq (Join-Path $script:Root 'bin/tego.exe') }
    }
    It 'preserves an interrupted imports files before importing again' {
        [void](New-Item -ItemType Directory -Force (Join-Path $script:Root 'distro'))
        Set-Content (Join-Path $script:Root 'installer-owned') 'tego-windows-installer-v1'
        Set-Content (Join-Path $script:Root 'distro/interrupted.vhdx') 'keep'
        Invoke-TegoInstall $true | Should -Be 0
        $saved=@(Get-ChildItem -LiteralPath $script:Root -Directory -Filter 'distro-interrupted-*')
        $saved.Count | Should -Be 1
        Get-Content (Join-Path $saved[0].FullName 'interrupted.vhdx') | Should -Be 'keep'
        @($script:Calls | Where-Object { $_ -match '--import tego' }).Count | Should -Be 1
    }
    It 'keeps files when an interrupted import folder belongs to a registered distribution' {
        [void](New-Item -ItemType Directory -Force (Join-Path $script:Root 'distro'))
        Set-Content (Join-Path $script:Root 'installer-owned') 'tego-windows-installer-v1'
        Set-Content (Join-Path $script:Root 'distro/keep.vhdx') 'keep'
        Mock Test-TegoDistroPathInUse { return $true }
        Invoke-TegoInstall $true | Should -Be 8
        Get-Content (Join-Path $script:Root 'distro/keep.vhdx') | Should -Be 'keep'
        @($script:Calls | Where-Object { $_ -match '--import' }).Count | Should -Be 0
    }
    It 'requires fresh consent to changed startup settings while Tego is running' -ForEach @(
        @{Consent=$false;Restarts=0}, @{Consent=$true;Restarts=1}
    ) {
        $script:Existing=$true
        [void](New-Item -ItemType Directory -Force $script:Root)
        Set-Content (Join-Path $script:Root 'installer-owned') 'tego-windows-installer-v1'
        Mock Invoke-TegoWsl {
            $line=$Arguments -join ' '
            $script:Calls.Add($line)
            if ($line -eq '--list --quiet' -or $line -eq '--list --running --quiet') { return @{Code=0;Text='tego'} }
            if ($line -match 'bash -s .* check$') { return @{Code=10;Text='settings differ'} }
            return @{Code=0;Text='fixture'}
        }
        $script:RestartConsent=$Consent
        Mock Confirm-TegoStep { if ($Explicit) { return $script:RestartConsent }; return $true }
        Invoke-TegoInstall $true | Should -Be 0
        Should -Invoke Confirm-TegoStep -Times 1 -ParameterFilter { $Explicit -and $DefaultNo -and $Question -match 'stop all work' }
        @($script:Calls | Where-Object { $_ -match '--terminate' }).Count | Should -Be $Restarts
        @($script:Calls | Where-Object { $_ -match 'bash -s' }).Count | Should -Be (1+[int]$Consent)
    }
    It 'unregisters only tego and removes only the two commands' {
        Invoke-TegoInstall $true | Should -Be 0
        Set-Content (Join-Path $script:Root 'bin/keep.txt') 'keep'
        $script:Calls.Clear()
        Invoke-TegoInstall $true $true | Should -Be 0
        @($script:Calls | Where-Object { $_ -match '--unregister' }) | Should -Be @('--unregister tego')
        Test-Path (Join-Path $script:Root 'bin/tego.exe') | Should -BeFalse
        Test-Path $script:Root | Should -BeFalse
    }
}
Describe 'real confirmation and digest functions' {
    It 'accepts installation yes and declines default-no independently of terminal presence' {
        $script:TegoYes=$true
        Confirm-TegoStep 'change?' 'manual command' | Should -BeTrue
        $script:TegoYes=$false
        Confirm-TegoStep 'change?' 'manual command' $true | Should -BeFalse
    }
    It 'keeps default-no even under an install-time blanket yes' {
        $script:TegoYes=$true
        Confirm-TegoStep 'optional global change?' 'manual command' $true | Should -BeFalse
    }
    It 'checks actual bytes and rejects duplicate or missing checksums' {
        $file=Join-Path $TestDrive 'asset'
        [IO.File]::WriteAllText($file, 'checked bytes')
        $hash=Get-TegoHash $file
        Assert-TegoAsset $file 'asset' "$hash  asset`n"
        { Assert-TegoAsset $file 'asset' '' } | Should -Throw '*Checksum*'
        { Assert-TegoAsset $file 'asset' "$hash  asset`n$hash  asset`n" } | Should -Throw '*Checksum*'
        Set-Content $file 'changed'
        { Assert-TegoAsset $file 'asset' "$hash  asset`n" } | Should -Throw '*Checksum*'
    }
}

Describe 'dashboard relay stop before tego.exe is replaced or removed' {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Force $script:Root)
        $script:Stopped = @()
        $script:Started = [datetime]::FromFileTimeUtc(133000000000000000)
        Mock Stop-Process { $script:Stopped += $Id }
    }
    It 'stops only the recorded relay still running the installed tego.exe with its recorded start' {
        $exe = Join-Path $script:Root 'bin\tego.exe'
        Mock Get-Process { $p = [pscustomobject]@{Id=$Id;Path=$exe;StartTime=$script:Started}; $p | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($t) $true }; return $p }
        [IO.File]::WriteAllText((Join-Path $script:Root 'relay.json'), '{"pid":4242,"start":133000000000000000,"port":8484,"exe":"x"}')
        Stop-TegoRelay $script:Root
        $script:Stopped | Should -Be @(4242)
        Test-Path (Join-Path $script:Root 'relay.json') | Should -BeFalse
    }
    It 'leaves a reused pid or another program alone, and drops the stale record' {
        foreach ($case in @(@{Path=(Join-Path $script:Root 'bin\tego.exe');Start='133000000000000001'}, @{Path='C:\Windows\notepad.exe';Start='133000000000000000'})) {
            $script:Case = $case
            Mock Get-Process { $p = [pscustomobject]@{Id=$Id;Path=$script:Case.Path;StartTime=$script:Started}; return $p }
            [IO.File]::WriteAllText((Join-Path $script:Root 'relay.json'), '{"pid":4242,"start":'+$case.Start+',"port":8484,"exe":"x"}')
            Stop-TegoRelay $script:Root
            Test-Path (Join-Path $script:Root 'relay.json') | Should -BeFalse
        }
        $script:Stopped.Count | Should -Be 0
    }
    It 'never fails the install when the relay is gone or its record is unreadable' {
        Mock Get-Process { throw 'Cannot find a process with the process identifier 4242.' }
        [IO.File]::WriteAllText((Join-Path $script:Root 'relay.json'), '{"pid":4242,"start":1,"port":8484,"exe":"x"}')
        { Stop-TegoRelay $script:Root } | Should -Not -Throw
        [IO.File]::WriteAllText((Join-Path $script:Root 'relay.json'), 'not json')
        { Stop-TegoRelay $script:Root } | Should -Not -Throw
        { Stop-TegoRelay (Join-Path $TestDrive 'absent') } | Should -Not -Throw
        $script:Stopped.Count | Should -Be 0
    }
}

Describe 'release selection and authenticated asset boundary' {
    BeforeAll {
        function cosign { $global:LASTEXITCODE = $script:CosignCode }
    }
    BeforeEach {
        $script:ReleaseWork = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $script:Origin = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory $script:ReleaseWork)
        [void](New-Item -ItemType Directory $script:Origin)
        $env:TEGO_VERSION='0.2.0'
        $env:TEGO_BASE_URL='https://release.invalid'
        $env:TEGO_CHECKSUMS_SHA256=''
        $env:TEGO_VERIFY='sha256'
        $script:CosignCode=0
        $script:Tamper=$false
        $sums=''
        foreach ($asset in @('install.sh','install.ps1','windows-provision.sh','windows-entry.py','tego_0.2.0_windows_amd64.exe')) {
            $path=Join-Path $script:Origin $asset
            [IO.File]::WriteAllText($path,'checked '+$asset)
            $sums += (Get-TegoHash $path)+'  '+$asset+"`n"
        }
        [IO.File]::WriteAllText((Join-Path $script:Origin 'tego_0.2.0_checksums.txt'),$sums)
        Mock Receive-TegoFile {
            $name=($Url -split '/')[-1]
            if ($name -eq 'latest') { [IO.File]::WriteAllText($Destination,'{"tag_name":"v0.2.0"}'); return }
            if ($name.EndsWith('.sigstore.json')) { [IO.File]::WriteAllText($Destination,'bundle'); return }
            Copy-Item -LiteralPath (Join-Path $script:Origin $name) -Destination $Destination
            if ($script:Tamper -and $name -eq 'windows-entry.py') { Add-Content -LiteralPath $Destination 'changed' }
        }
    }
    It 'normalizes the selected release and carries the checksums digest' {
        $release=Get-TegoRelease $script:ReleaseWork
        $release.Tag | Should -Be 'v0.2.0'
        $release.Digest | Should -Be (Get-TegoHash (Join-Path $script:Origin 'tego_0.2.0_checksums.txt'))
        Should -Invoke Receive-TegoFile -Times 0 -ParameterFilter { $Url.EndsWith('/latest') }
    }
    It 'resolves latest once before using only that selected release' {
        $env:TEGO_VERSION=''
        (Get-TegoRelease $script:ReleaseWork).Tag | Should -Be 'v0.2.0'
        Should -Invoke Receive-TegoFile -Times 1 -ParameterFilter { $Url.EndsWith('/latest') }
    }
    It 'rejects changed guest code before it can be executed' {
        $script:Tamper=$true
        { Get-TegoRelease $script:ReleaseWork } | Should -Throw '*Checksum*'
    }
    It 'rejects a changed pinned checksums file before interpreting assets' {
        $env:TEGO_CHECKSUMS_SHA256='0'*64
        { Get-TegoRelease $script:ReleaseWork } | Should -Throw '*Pinned checksums*'
        Should -Invoke Receive-TegoFile -Times 1
    }
    It 'rejects a bad signer result and never falls back to SHA256' {
        $env:TEGO_VERIFY='cosign'
        $script:CosignCode=1
        { Get-TegoRelease $script:ReleaseWork } | Should -Throw '*signature did not verify*'
        Should -Invoke Receive-TegoFile -Times 0 -ParameterFilter { $Url.EndsWith('/windows-entry.py') }
    }
    It 'refuses HTTP without an explicit test transport switch before any download' {
        $env:TEGO_BASE_URL='http://release.invalid'
        $env:TEGO_TEST_HTTP=''
        { Get-TegoRelease $script:ReleaseWork } | Should -Throw '*HTTPS*'
        Should -Invoke Receive-TegoFile -Times 0
    }
    It 'rejects unsafe version, mirror and verification modes with a next step' {
        $env:TEGO_VERSION='v1;bad'
        { Get-TegoRelease $script:ReleaseWork } | Should -Throw '*No valid release tag*'
        $env:TEGO_VERSION='v0.2.0'
        $env:TEGO_BASE_URL='https://host/space here'
        { Get-TegoRelease $script:ReleaseWork } | Should -Throw '*TEGO_BASE_URL*'
        $env:TEGO_BASE_URL='https://release.invalid'
        $env:TEGO_VERIFY='bad'
        { Get-TegoRelease $script:ReleaseWork } | Should -Throw '*TEGO_VERIFY must*'
    }
}

Describe 'explicit optional global WSLg change' {
    BeforeEach {
        $script:ConfigRoot = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory $script:ConfigRoot)
        $script:ConfigFile = Join-Path $script:ConfigRoot '.wslconfig'
        Mock Get-TegoWslConfigPath { return $script:ConfigFile }
    }
    It 'leaves the file absent on default-no and explains remaining channels' {
        Set-TegoWslg $script:ConfigRoot
        Test-Path $script:ConfigFile | Should -BeFalse
    }
    It 'preserves unrelated settings and creates a backup after explicit yes' {
        [IO.File]::WriteAllText($script:ConfigFile,"[wsl2]`nmemory=4GB`n[experimental]`nsparseVhd=true`n")
        Mock Confirm-TegoStep { return $true }
        Set-TegoWslg $script:ConfigRoot $true
        $text=[IO.File]::ReadAllText($script:ConfigFile)
        $text | Should -Match 'memory=4GB'
        $text | Should -Match 'sparseVhd=true'
        $text | Should -Match 'guiApplications=false'
        Test-Path (Join-Path $script:ConfigRoot 'wslconfig-before') | Should -BeTrue
        Set-TegoWslg $script:ConfigRoot $true
        ([regex]::Matches([IO.File]::ReadAllText($script:ConfigFile),'guiApplications=')).Count | Should -Be 1
    }
    It 'refuses ambiguous repeated sections instead of rewriting them' {
        [IO.File]::WriteAllText($script:ConfigFile,"[wsl2]`n[wsl2]`n")
        Mock Confirm-TegoStep { return $true }
        { Set-TegoWslg $script:ConfigRoot $true } | Should -Not -Throw
        [IO.File]::ReadAllText($script:ConfigFile) | Should -Be "[wsl2]`n[wsl2]`n"
    }
}

Describe 'installer entry and caller scope (real PowerShell subprocesses)' {
    It 'irm-style execution leaves preferences, helpers and installer variables out of the caller' {
        $env:TEGO_TEST_INSTALLER = Join-Path $PSScriptRoot 'install.ps1'
        $probe = @'
$ErrorActionPreference='Continue'
$before=@(Get-Variable | Select-Object -ExpandProperty Name)
Get-Content -Raw $env:TEGO_TEST_INSTALLER | Invoke-Expression
if ($ErrorActionPreference -ne 'Continue') { throw 'caller preference changed' }
if (Get-Command Stop-TegoInstall -ErrorAction SilentlyContinue) { throw 'installer function escaped' }
if (Get-Variable TegoRepository,Yes,Uninstall,LoadOnly -ErrorAction SilentlyContinue) { throw 'installer variable escaped' }
'SCOPE_OK'
'@
        $output = & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -Command $probe
        $LASTEXITCODE | Should -Be 0
        $output | Should -Contain 'SCOPE_OK'
    }
    It 'observes every file switch before any platform action' {
        $source=Get-Content -Raw (Join-Path $PSScriptRoot 'install.ps1')
        $probe='@{Yes=[bool]$Yes;Uninstall=[bool]$Uninstall;DisableWslg=[bool]$DisableWslg;LoadOnly=[bool]$LoadOnly;LauncherPid=$LauncherPid} | ConvertTo-Json -Compress; return; '
        $source=$source.Replace('if (!$LoadOnly) {',$probe+'if (!$LoadOnly) {')
        $file=Join-Path $TestDrive 'observed-install.ps1'
        [IO.File]::WriteAllText($file,$source)
        $output=& (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $file -Yes -Uninstall -DisableWslg -LoadOnly -LauncherPid 321
        $LASTEXITCODE | Should -Be 0
        $values=($output -join "`n") | ConvertFrom-Json
        $values.Yes | Should -BeTrue
        $values.Uninstall | Should -BeTrue
        $values.DisableWslg | Should -BeTrue
        $values.LoadOnly | Should -BeTrue
        $values.LauncherPid | Should -Be 321
    }
    It 'irm-style entry does not inherit a containing scripts removal arguments' {
        $source=Get-Content -Raw (Join-Path $PSScriptRoot 'install.ps1')
        $probe='@{Yes=[bool]$Yes;Uninstall=[bool]$Uninstall;DisableWslg=[bool]$DisableWslg;LauncherPid=$LauncherPid} | ConvertTo-Json -Compress; return; '
        $source=$source.Replace('if (!$LoadOnly) {',$probe+'if (!$LoadOnly) {')
        $file=Join-Path $TestDrive 'observed-iex.ps1'
        [IO.File]::WriteAllText($file,$source)
        $env:TEGO_TEST_OBSERVED_INSTALLER=$file
        $driver=Join-Path $TestDrive 'containing-script.ps1'
        [IO.File]::WriteAllText($driver,'Get-Content -Raw $env:TEGO_TEST_OBSERVED_INSTALLER | Invoke-Expression')
        $output=& (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File $driver -Uninstall -Yes -DisableWslg -LauncherPid 321
        $LASTEXITCODE | Should -Be 0
        $values=($output -join "`n") | ConvertFrom-Json
        $values.Yes | Should -BeFalse
        $values.Uninstall | Should -BeFalse
        $values.DisableWslg | Should -BeFalse
        $values.LauncherPid | Should -Be 0
    }
    It 'file switch binding returns the Linux rejection exit rather than falling through' {
        & (Join-Path $PSHOME 'pwsh') -NoLogo -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'install.ps1') -Yes
        $LASTEXITCODE | Should -Be 3
    }
}
