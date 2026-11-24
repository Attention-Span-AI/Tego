# SPDX-License-Identifier: Apache-2.0
# Only GitHub's Windows runner executes this. Linux stand-ins never run it.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$wsl = Join-Path $env:SystemRoot 'System32/wsl.exe'
function Get-RegisteredDistributions {
    $lxss='HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss'
    if (Test-Path $lxss) { Get-ChildItem $lxss | ForEach-Object { (Get-ItemProperty $_.PSPath).DistributionName } }
}
$before = @(Get-RegisteredDistributions)
$exeBytes = [IO.File]::ReadAllBytes((Join-Path $env:SystemRoot 'System32/cmd.exe'))
$exe = [Convert]::ToBase64String($exeBytes)
$exeHash = (Get-FileHash (Join-Path $env:SystemRoot 'System32/cmd.exe')).Hash.ToLowerInvariant()
$executionProbe = @'
import base64,hashlib,json,os,subprocess
from pathlib import Path
p=Path.home()/'windows-probe.exe'
p.write_bytes(base64.b64decode('@PAYLOAD@'));p.chmod(0o755)
assert hashlib.sha256(p.read_bytes()).hexdigest()=='@HASH@'
for argv in ([str(p),'/c','echo','TEGO_HOST_CONTROL'],['/init',str(p),str(p),'/c','echo','TEGO_HOST_CONTROL']):
    try:
        r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
        row={'argv':argv,'exit':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')}
    except OSError as e: row={'argv':argv,'exit':None,'errno':e.errno,'stdout':''}
    print(json.dumps(row))
    if '@KIND@'=='open': assert row['exit']==0 and 'TEGO_HOST_CONTROL' in row['stdout'],row
    else: assert row['exit']!=0 and 'TEGO_HOST_CONTROL' not in row['stdout'],row
'@
$executionProbe=$executionProbe.Replace('@PAYLOAD@',$exe).Replace('@HASH@',$exeHash)
$preflight = 'tego-ci-preflight-' + [Guid]::NewGuid().ToString('N')
$folder = Join-Path $env:RUNNER_TEMP $preflight
[void](New-Item -ItemType Directory $folder)
$image = Join-Path $folder 'ubuntu.wsl'
$imported = $false
try {
    & $wsl --version
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'CHECK: this runner has no WSL; installing its Windows feature before testing nested Linux'
        $bootstrap=Start-Process -FilePath $wsl -ArgumentList @('--install','--no-distribution','--web-download') -PassThru -Wait
        if($bootstrap.ExitCode -ne 0){throw "Runner WSL bootstrap failed or requires restart: $($bootstrap.ExitCode); never skipped."}
        & $wsl --version
        if($LASTEXITCODE -ne 0){throw 'Runner WSL bootstrap did not establish a working WSL client; a restart may be required.'}
    }
    Write-Host 'CHECK: downloading and verifying the pinned WSL2 preflight image'
    Invoke-WebRequest -UseBasicParsing 'https://releases.ubuntu.com/24.04.5/ubuntu-24.04.5-wsl-amd64.wsl' -OutFile $image
    if ((Get-FileHash -Algorithm SHA256 $image).Hash.ToLowerInvariant() -ne 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e') { throw 'Preflight image hash differs' }
    & $wsl --version
    & $wsl --status
    & $wsl --import $preflight (Join-Path $folder 'distro') $image --version 2
    if ($LASTEXITCODE -ne 0) { throw 'WSL2 cannot start on this hosted runner (import failed; nested virtualization or a Windows feature restart may be required).' }
    $imported = $true
    $kernel = & $wsl -d $preflight -u root --exec uname -r
    if ($LASTEXITCODE -ne 0 -or $kernel -notmatch 'WSL2') { throw 'WSL2 cannot start on this hosted runner (nested virtualization unavailable or WSL startup failed).' }
    Write-Host "CHECK: WSL2 actually started: $kernel"
    $route = & $wsl -d $preflight -u root --exec ip -4 route show default
    if ($route -notmatch 'via ([0-9.]+)') { throw 'No NAT host gateway established; mirrored-runner mirror addressing needs an explicit implementation.' }
    $gateway = $Matches[1]
    Write-Host 'CHECK: the same cmd.exe bytes execute through both interop paths in the ordinary preflight distribution'
    $controlSetup=@'
import pwd,subprocess
try: print(pwd.getpwuid(1000).pw_name)
except KeyError:
    subprocess.run(['/usr/sbin/useradd','--uid','1000','--create-home','tego-ci-control'],check=True)
    print('tego-ci-control')
'@
    $controlUser=($controlSetup | & $wsl -d $preflight -u root --exec python3 - | Out-String).Trim()
    if($LASTEXITCODE -or !$controlUser){throw 'Ordinary-user positive control setup failed'}
    $executionProbe.Replace('@KIND@','open') | & $wsl -d $preflight -u $controlUser --exec python3 -
    if ($LASTEXITCODE) { throw 'Windows execution positive control failed' }
} finally {
    if ($imported) { & $wsl --unregister $preflight }
}
$release = Join-Path $env:RUNNER_TEMP 'windows-release'
$server = Start-Process -FilePath 'python' -ArgumentList @('-m','http.server','8765','--bind','0.0.0.0','--directory',$release) -PassThru -RedirectStandardOutput (Join-Path $folder 'http.log') -RedirectStandardError (Join-Path $folder 'http.err')
$firewall = 'Tego CI mirror ' + $preflight
try {
    New-NetFirewallRule -DisplayName $firewall -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 | Out-Null
    $env:TEGO_BASE_URL = "http://${gateway}:8765"
    $env:TEGO_TEST_HTTP = '1'
    $env:TEGO_VERSION = 'v0.2.0'
    $env:TEGO_VERIFY = 'sha256'
    $installer = Join-Path $release 'v0.2.0/install.ps1'
    Write-Host 'CHECK: installing this commit under the current PowerShell edition'
    & $installer -Yes
    if ($LASTEXITCODE -ne 0) { throw "Installer failed: $LASTEXITCODE (a required Windows restart is a failure, never a skip)." }
    $shim = Join-Path $env:LOCALAPPDATA 'Tego/bin/tego.exe'
    Write-Host 'CHECK: only the dedicated tego distribution was added'
    $after = @(Get-RegisteredDistributions)
    if ((($before | Sort-Object) -join "`n") -cne (($after | Where-Object { $_.Trim() -ne 'tego' } | Sort-Object) -join "`n")) { throw 'An unrelated distribution list changed' }
    Write-Host 'CHECK: the identical cmd.exe bytes are refused for the dedicated user'
    $executionProbe.Replace('@KIND@','closed') | & $wsl -d tego -u tego --exec python3 -
    if ($LASTEXITCODE) { throw 'Windows execution negative control failed' }
    Write-Host 'CHECK: unprivileged host channels and a real systemd scope'
    $check = @'
set -eu
[ "$(id -u)" != 0 ]
if grep -E ' - drvfs | - 9p .*aname=drvfs' /proc/self/mountinfo; then echo 'Windows drive mount leaked'; exit 1; fi
case "$PATH" in *'/mnt/'*) echo 'Windows PATH leaked'; exit 1;; esac
export XDG_RUNTIME_DIR=/run/user/$(id -u)
systemd-run --user --scope --quiet sh -c 'cat /proc/self/cgroup; grep -q "/user@$(id -u).service/" /proc/self/cgroup'
'@
    (($check -replace "`r", '') + "`nexit`n") | & $wsl -d tego -u tego --exec bash -s
    if ($LASTEXITCODE -ne 0) { throw 'Closed host-channel or cgroup check failed' }
    Write-Host 'CHECK: literal hostile arguments through the installed native command'
    $probe = @'
from pathlib import Path
h=Path.home()
(h/'argv-echo.py').write_text("import json,sys\nprint(json.dumps(sys.argv[1:],ensure_ascii=True))\n")
(h/'argv-forward').write_text('exec python3 /home/tego/argv-echo.py "$@"\n')
'@
    $probe | & $wsl -d tego -u tego --exec python3 -
    if ($LASTEXITCODE) { throw 'Argument probe fixture failed' }
    $hostile=@('&','|','<','>','^','%VAR%','!','say "hi"','','two words','--','-c:v','-x:','-',([string][char]0x96ea+' caf'+[char]0xe9),('a'*20000))
    $expected=$hostile
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        $expected=@('&','|','<','>','^','%VAR%','!','say hi','two words','--','-c:v','-x:','-',([string][char]0x96ea+' caf'+[char]0xe9),('a'*20000))
    }
    $response=@(& $shim shell /home/tego/argv-forward @hostile)
    if ($LASTEXITCODE -or $response.Count -ne 1) { throw 'Native argument probe failed or added output' }
    [string[]]$actual=ConvertFrom-Json -InputObject $response[0]
    if ($actual.Count -ne $expected.Count) { throw 'Native argument count changed' }
    for($i=0;$i -lt $expected.Count;$i++){if($actual[$i] -cne $expected[$i]){throw "Argument $i changed"}}
    Write-Host 'CHECK: PowerShell literal argv matched, including the 20,000-character argument'
    $batch=@'
@echo off
chcp 65001 >nul
set VAR=EXPANDED
"@BIN@" shell /home/tego/argv-forward "&" "|" "<" ">" "^" "%VAR%" "!" "say \"hi\"" "" "two words" "--" "-c:v" "-x:" "-" "@UNICODE@"
'@
    $batchPath=Join-Path $folder 'argv.cmd'
    [IO.File]::WriteAllText($batchPath,$batch.Replace('@BIN@',$shim).Replace('@UNICODE@',([string][char]0x96ea+' caf'+[char]0xe9)).Replace("`r`n","`n").Replace("`n","`r`n"),(New-Object Text.UTF8Encoding($false)))
    $cmd=Join-Path $env:SystemRoot 'System32/cmd.exe'
    $response=@(& $cmd /d /v:off /c $batchPath)
    if($LASTEXITCODE -or $response.Count -ne 1){throw 'cmd argument probe failed or added output'}
    [string[]]$actual=ConvertFrom-Json -InputObject $response[0]
    $expected=@('&','|','<','>','^','EXPANDED','!','say "hi"','','two words','--','-c:v','-x:','-',([string][char]0x96ea+' caf'+[char]0xe9))
    if($actual.Count -ne $expected.Count){throw 'cmd argument count changed'}
    for($i=0;$i -lt $expected.Count;$i++){if($actual[$i] -cne $expected[$i]){throw "cmd argument $i changed"}}
    [IO.File]::WriteAllText($batchPath,"@echo off`r`n"+'"'+$shim+'" shell /home/tego/argv-forward "'+('a'*20000)+'"'+"`r`n",(New-Object Text.UTF8Encoding($false)))
    $response=@(& $cmd /d /v:off /c $batchPath)
    if($LASTEXITCODE -or $response.Count -ne 1){throw 'cmd long argument probe failed or added output'}
    [string[]]$actual=ConvertFrom-Json -InputObject $response[0]
    if($actual.Count -ne 1 -or $actual[0] -cne ('a'*20000)){throw 'cmd long argument changed'}
    Write-Host 'CHECK: cmd literal argv matched, including the 20,000-character argument'
    Write-Host 'CHECK: driving a real pseudo-terminal through all guide steps and the sample run'
    Get-Content -Raw (Join-Path $PSScriptRoot 'windows-hosted-guest.py') | & $wsl -d tego -u tego --exec python3 -
    if ($LASTEXITCODE -ne 0) { throw 'Guest guide/sample acceptance failed' }
    & $shim doctor
    if ($LASTEXITCODE -ne 0) { throw 'Doctor did not establish protection' }
    Write-Host 'CHECK: the dashboard opens through the relay on [::1], prints no link, and the WSL-forwarded address stays refused'
    foreach($arguments in @(@('dashboard'),@('serve','--open'))){
        $response=(& $shim @arguments 2>&1 | Out-String)
        if($LASTEXITCODE -ne 0 -or $response -notmatch 'Opened the dashboard in your browser' -or $response -match 'https?://|127\.0\.0\.1'){throw 'Windows dashboard did not open through the relay'}
    }
    $relay=Get-Content -Raw (Join-Path $env:LOCALAPPDATA 'Tego/relay.json') | ConvertFrom-Json
    $curl=Join-Path $env:SystemRoot 'System32/curl.exe'
    $viaRelay=& $curl -g -s -o NUL -w '%{http_code}' --noproxy '*' --max-time 15 ('http://[::1]:'+$relay.port+'/')
    if($viaRelay -ne '401'){throw ('The relay answered '+$viaRelay+', not the sign-in page: the dashboard did not admit its connection')}
    $viaWsl=& $curl -s -o NUL -w '%{http_code}' --noproxy '*' --max-time 15 ('http://127.0.0.1:'+$relay.port+'/')
    if($viaWsl -ne '403'){throw ('The WSL-forwarded address answered '+$viaWsl+', not the peer refusal')}
    & $shim dashboard --stop
    if($LASTEXITCODE -ne 0 -or (Test-Path (Join-Path $env:LOCALAPPDATA 'Tego/relay.json'))){throw 'tego dashboard --stop left the relay'}
} catch {
    Write-Host 'DIAGNOSTICS: collecting before removal'
    & $wsl --version
    & $wsl --status
    & $wsl --list --verbose
    & $wsl -d tego -u root --exec journalctl -b --no-pager -n 200
    & $wsl -d tego -u root --exec cat /etc/wsl.conf
    & $wsl -d tego -u root --exec cat /proc/self/mountinfo
    & $wsl -d tego -u tego --exec cat /home/tego/.tego/dashboard.log
    throw
} finally {
    Write-Host 'CHECK: removal leaves unrelated distributions and files alone'
    $installer = Join-Path $release 'v0.2.0/install.ps1'
    $root=Join-Path $env:LOCALAPPDATA 'Tego'
    $native=Join-Path $root 'bin/tego.exe'
    if (Test-Path $native) { & $native uninstall -Yes; if($LASTEXITCODE){throw 'Native uninstall failed'} }
    elseif (Test-Path (Join-Path $root 'installer-owned')) { & $installer -Uninstall -Yes }
    $deadline=(Get-Date).AddSeconds(20)
    while((Test-Path $root) -and (Get-Date) -lt $deadline){Start-Sleep -Milliseconds 100}
    $left = @(Get-RegisteredDistributions | Where-Object { $_ -eq 'tego' })
    if ($left.Count -or (Test-Path $root)) { Write-Error 'Removal left tego or its command' }
    Remove-NetFirewallRule -DisplayName $firewall -ErrorAction Continue
    Stop-Process -Id $server.Id -ErrorAction Continue
    Get-Content (Join-Path $folder 'http.err') -ErrorAction Continue
}
