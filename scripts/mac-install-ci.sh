#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Hosted Mac only. Every invocation is bounded by the workflow as well as the
# per-operation deadlines below. Never invoke this on the Linux build host.
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_OS:-}" != macOS ]; then
  echo 'mac-install-ci: only run by the hosted macOS workflow' >&2
  exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
helper="$here/mac-install-ci.py"
export MAC_CI_LOGS="${MAC_CI_LOGS:-$RUNNER_TEMP/mac-ci-raw}"
export MAC_CI_TMP="${MAC_CI_TMP:-$RUNNER_TEMP/mac-ci-tmp}"
export MAC_CI_ASSETS="${MAC_CI_ASSETS:-$RUNNER_TEMP/mac-release}"
mkdir -p "$MAC_CI_LOGS" "$MAC_CI_TMP"
export TMPDIR="$MAC_CI_TMP"
bound() { python3 "$helper" bound "$@"; }
terminal() { python3 "$helper" terminal "$@"; }
collect() { python3 "$helper" collect "$RUNNER_TEMP/mac-ci-scrubbed"; }
reject() { if grep -qE "$2" "$1"; then echo "CHECK FAILED: $1 contains $2"; exit 1; fi; }
need() { grep -qE "$2" "$1" || { echo "CHECK FAILED: $1 lacks $2"; exit 1; }; }
case "$1" in
probe)
  echo 'CHECK Intel host hypervisor support and Homebrew Lima version'
  sw_vers | tee "$MAC_CI_LOGS/host-facts.txt"
  uname -m | tee -a "$MAC_CI_LOGS/host-facts.txt"
  { sysctl kern.hv_support || true; } 2>&1 | tee -a "$MAC_CI_LOGS/host-facts.txt"
  brew install lima 2>&1 | tee "$MAC_CI_LOGS/brew-lima.log"
  limactl --version | tee -a "$MAC_CI_LOGS/host-facts.txt"
  limactl info >"$MAC_CI_LOGS/lima-info.json"
  cat "$MAC_CI_LOGS/lima-info.json"
  limactl start --help >"$MAC_CI_LOGS/start-help.txt"
  # Query the installed version, never assume the website's list is its list.
  python3 - "$MAC_CI_LOGS/lima-info.json" >"$MAC_CI_LOGS/drivers.txt" <<'PY'
import json, re, sys
info = json.load(open(sys.argv[1]))
drivers = info['vmTypes']
assert drivers and all(isinstance(x, str) and re.fullmatch('[a-z0-9_-]+', x) for x in drivers), drivers
# VZ is the template's documented default on macOS >=13.5; try it first.
print('\n'.join(sorted(drivers, key=lambda x: (x != 'vz', x))))
PY
  if grep -qx qemu "$MAC_CI_LOGS/drivers.txt"; then
    echo 'CHECK install QEMU dependency so its driver receives a real boot attempt'
    brew install qemu 2>&1 | tee "$MAC_CI_LOGS/brew-qemu.log"
  fi
  : >"$MAC_CI_LOGS/driver-results.txt"
  selected=''
  while IFS= read -r driver; do
    name="mac-ci-$driver"
    echo "CHECK smallest default instance: driver=$driver cpus=1 memory=1GiB disk=5GiB plain=true deadline=300s"
    rc=0
    bound 330 "$MAC_CI_LOGS/probe-$driver.log" limactl start --tty=false --name="$name" \
      --vm-type="$driver" --cpus=1 --memory=1 --disk=5 --plain --timeout=5m template:default || rc=$?
    if [ "$rc" = 0 ]; then
      bound 30 "$MAC_CI_LOGS/probe-$driver-guest.log" limactl shell "$name" uname -a || rc=$?
    fi
    printf '%s exit=%s\n' "$driver" "$rc" | tee -a "$MAC_CI_LOGS/driver-results.txt"
    if [ "$rc" = 0 ] && [ -z "$selected" ]; then selected=$driver; fi
    collect # preserve hostagent/serial evidence before deleting the probe
    if [ -d "$HOME/.lima/$name" ]; then
      bound 45 "$MAC_CI_LOGS/delete-$driver.log" limactl delete --force "$name"
    else
      echo "CHECK $name left no instance to delete"
    fi
  done <"$MAC_CI_LOGS/drivers.txt"
  printf '%s\n' "$selected" >"$MAC_CI_LOGS/selected-driver.txt"
  if [ -z "$selected" ]; then
    echo 'MAC_VM_CAPABILITY=none: no offered Lima driver booted a VM; real installer failure assertions will run.'
  else
    echo "MAC_VM_CAPABILITY=$selected: a default Linux VM booted and answered from the guest."
  fi
  ;;
install)
  echo 'CHECK artifact checksums, real installer, terminal restoration and Mac writes'
  export TEGO_YES=1 TEGO_VERSION=v0.2.0-macci TEGO_VERIFY=sha256
  # file:// is a supported installer mirror transport. No curl/verifier stand-in.
  export TEGO_BASE_URL="file://$MAC_CI_ASSETS"
  (cd "$MAC_CI_ASSETS/$TEGO_VERSION" && /usr/bin/shasum -a 256 -c "tego_${TEGO_VERSION#v}_checksums.txt")
  test ! -e "$HOME/.local/bin/tego"
  python3 - "$MAC_CI_LOGS/profiles-before.json" <<'PY'
import hashlib, json, pathlib, sys
home = pathlib.Path.home()
json.dump({f: hashlib.sha256((home/f).read_bytes()).hexdigest() if (home/f).exists() else None
           for f in ('.zshrc', '.profile', '.bash_profile', '.bash_login')}, open(sys.argv[1], 'w'))
PY
  driver=$(cat "$MAC_CI_LOGS/selected-driver.txt")
  if [ -n "$driver" ]; then
    export MAC_CI_LIMACTL
    MAC_CI_LIMACTL=$(command -v limactl)
    export MAC_CI_DRIVER=''
    if [ "$driver" != vz ]; then
      MAC_CI_DRIVER=$driver
      echo "CHECK hosted VM requires --vm-type=$driver (qemu also --mount-type=9p)."
      echo 'CHECK this is a nested hosted-machine workaround; a real Mac should use the unchanged default VZ.'
    fi
    export MAC_CI_HELPER="$helper"
    mkdir -p "$MAC_CI_TMP/bin"
    cat >"$MAC_CI_TMP/bin/limactl" <<'LAUNCHER'
#!/bin/sh
exec python3 "$MAC_CI_HELPER" dispatch "$@"
LAUNCHER
    chmod +x "$MAC_CI_TMP/bin/limactl"
    export PATH="$MAC_CI_TMP/bin:$PATH"
    echo 'CHECK CI-only read-only fixture mount; template bytes and checksum verification remain intact'
  fi
  rc=0
  terminal 900 "$MAC_CI_LOGS/installer.log" install /bin/sh "$here/install.sh" || rc=$?
  echo "CHECK real installer status=$rc"
  need "$MAC_CI_LOGS/installer.log" '✓ macOS '
  need "$MAC_CI_LOGS/installer.log" '✓ .*GB free'
  need "$MAC_CI_LOGS/installer.log" '✓ Lima '
  need "$MAC_CI_LOGS/installer.log" 'terminal restored=True'
  if [ -z "$driver" ]; then
    test "$rc" = 8
    need "$MAC_CI_LOGS/installer.log" 'The full log is in '
    if grep -q 'failed to download .*cloud-images[.]ubuntu[.]com/' "$MAC_CI_TMP"/tego-install.*/install.log; then
      need "$MAC_CI_LOGS/installer.log" 'First remove the incomplete VM: limactl delete tego'
      if grep -q 'failed to download .*cloud-images[.]ubuntu[.]com/.*unexpected HTTP status Not Found' "$MAC_CI_TMP"/tego-install.*/install.log; then
        need "$MAC_CI_LOGS/installer.log" 'The pinned VM image is no longer available'
      else
        need "$MAC_CI_LOGS/installer.log" 'The VM image download failed. Check the connection'
      fi
    else
      echo 'CHECK other VM failure: diagnostic log retained, no claim that the image is gone'
      reject "$MAC_CI_LOGS/installer.log" "image is no longer available"
    fi
    test ! -e "$HOME/.local/bin/tego"
    python3 - "$MAC_CI_LOGS/profiles-before.json" <<'PY'
import hashlib, json, pathlib, sys
home = pathlib.Path.home()
for name, digest in json.load(open(sys.argv[1])).items():
    p = home/name
    assert (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None) == digest, name
print('CHECK no partial Mac command or profile writes after VM failure')
PY
    # The installer deliberately retains its private work directory on failure
    # for diagnosis. Verified downloads there are not partially installed files.
    python3 - "$MAC_CI_TMP" <<'PY'
import pathlib, sys
for d in pathlib.Path(sys.argv[1]).glob('tego-install.*'):
    assert d.stat().st_mode & 0o077 == 0, d
    assert (d/'install.log').is_file(), d
assert not list((pathlib.Path.home()/'.local/bin').glob('.tego*'))
print('CHECK retained downloads/log are private; no partial installed executable')
PY
    echo 'MAC_INSTALL_EXPECTED_FAILURE=asserted: exit=8, terminal restored, no partial command or profile.'
  else
    test "$rc" = 0
    test -x "$HOME/.local/bin/tego"
    # -i is required because the zsh installer writes .zshrc, as a new Terminal does.
    # shellcheck disable=SC2016 # expanded by the new login shell
    bound 30 "$MAC_CI_LOGS/login-path.log" /bin/zsh -lic 'command -v tego; test "$(command -v tego)" = "$HOME/.local/bin/tego"'
  fi
  ;;
exercise)
  driver=$(cat "$MAC_CI_LOGS/selected-driver.txt")
  if [ -z "$driver" ]; then
    echo 'CHECK full VM path unavailable; expected real installer failure was asserted in the previous step'
    exit 0
  fi
  export PATH="$HOME/.local/bin:$PATH"
  echo 'CHECK Mac command answers version and commit from the VM'
  bound 60 "$MAC_CI_LOGS/version.log" tego version
  need "$MAC_CI_LOGS/version.log" '^tego=v0.2.0-macci'
  need "$MAC_CI_LOGS/version.log" "^commit=$(git rev-parse HEAD)"
  echo 'CHECK doctor names a protection level'
  # doctor writes its Ready line only for a person at a terminal, so it is run on one.
  terminal 90 "$MAC_CI_LOGS/doctor.log" install tego doctor
  need "$MAC_CI_LOGS/doctor.log" 'Ready: this shell can enforce at tier [123] [(](landlock|cgroup|bpflsm)[)]'
  echo 'CHECK all four guide steps with Another program (/bin/sh), no account, test project, Base development'
  # A stable prompt identifies the project shell after the guide, without guessing sleeps.
  # shellcheck disable=SC2016 # this code executes only inside the guest
  limactl shell tego sh -c 'printf "\nexport PS1=\047TEGO_CI_PROJECT_SHELL> \047\n" >> "$HOME/.bashrc"'
  mkdir -p "$MAC_CI_TMP/browser"
  cat >"$MAC_CI_TMP/browser/open" <<'BROWSER'
#!/bin/sh
printf '%s\n' "$1" >>"$MAC_CI_LOGS/browser-links.txt"
BROWSER
  chmod +x "$MAC_CI_TMP/browser/open"
  export PATH="$MAC_CI_TMP/browser:$PATH"
  terminal 300 "$MAC_CI_LOGS/guide.log" guide tego start
  for step in '1/4  Agent' '2/4  Login' '3/4  Project' '4/4  Rules' 'CHECK_PROJECT_FILES' 'tego-sample'; do
    need "$MAC_CI_LOGS/guide.log" "$step"
  done
  echo 'CHECK page answers on the Mac through the real SSH dashboard tunnel'
  # The link carries a one-time token: the dashboard answers it with a cookie and a redirect to the page.
  url=$(tail -n 1 "$MAC_CI_LOGS/browser-links.txt")
  case "$url" in http://127.0.0.1:8484/*) ;; *) echo 'CHECK FAILED unexpected dashboard URL'; exit 1 ;; esac
  bound 30 "$MAC_CI_LOGS/dashboard-fetch.log" /usr/bin/curl --fail --silent --show-error --max-time 20 --location --cookie-jar "$MAC_CI_LOGS/dashboard.cookies" --cookie "$MAC_CI_LOGS/dashboard.cookies" "$url" -o "$MAC_CI_LOGS/dashboard.html"
  need "$MAC_CI_LOGS/dashboard.html" '<!doctype|<!DOCTYPE|<html'
  echo 'CHECK tego dashboard opens the running dashboard again and reuses the tunnel'
  terminal 90 "$MAC_CI_LOGS/dashboard-again.log" dashboard tego dashboard
  need "$MAC_CI_LOGS/dashboard-again.log" 'The dashboard is already running'
  test "$(tail -n 1 "$MAC_CI_LOGS/browser-links.txt")" = "$url"
  echo 'CHECK tego shell enters the project; extra arguments give usage with status 2'
  terminal 90 "$MAC_CI_LOGS/shell.log" shell tego shell
  need "$MAC_CI_LOGS/shell.log" 'CHECK_PROJECT_FILES'
  rc=0
  bound 30 "$MAC_CI_LOGS/shell-usage.log" tego shell unexpected || rc=$?
  test "$rc" = 2
  need "$MAC_CI_LOGS/shell-usage.log" '^usage: tego shell [(]no arguments[)]'
  echo 'CHECK rerun refreshes Mac command before comparing the VM version'
  printf '\n# stale-ci-command\n' >>"$HOME/.local/bin/tego"
  export TEGO_YES=1 TEGO_VERSION=v0.2.0-macci TEGO_VERIFY=sha256 TEGO_BASE_URL="file://$MAC_CI_ASSETS"
  terminal 120 "$MAC_CI_LOGS/rerun.log" install /bin/sh "$here/install.sh"
  reject "$HOME/.local/bin/tego" stale-ci-command
  need "$MAC_CI_LOGS/rerun.log" 'tego command is up to date'
  need "$MAC_CI_LOGS/rerun.log" 'Tego v0.2.0-macci inside the VM is up to date'
  python3 - "$MAC_CI_LOGS/rerun.log" <<'PYORDER'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
assert text.index('tego command is up to date') < text.index('inside the VM is up to date')
print('CHECK Mac command refresh precedes guest-version judgment')
PYORDER
  echo 'CHECK supported release repairs a missing VM binary through the same verified mirror'
  # shellcheck disable=SC2016 # fixed guest code, no Mac expansion
  limactl shell tego sh -c 'mv "$HOME/.local/bin/tego" "$HOME/.local/bin/tego.before-repair"'
  terminal 180 "$MAC_CI_LOGS/repair.log" install /bin/sh "$here/install.sh"
  need "$MAC_CI_LOGS/repair.log" 'from missing or not working to v0.2.0-macci'
  need "$MAC_CI_LOGS/repair.log" 'Tego v0.2.0-macci inside the VM is ready'
  bound 60 "$MAC_CI_LOGS/repaired-version.log" tego version
  need "$MAC_CI_LOGS/repaired-version.log" '^tego=v0.2.0-macci'
  echo 'CHECK stopped VM restarts through tego dashboard and the Mac can fetch again'
  bound 60 "$MAC_CI_LOGS/stop.log" limactl stop tego
  terminal 360 "$MAC_CI_LOGS/restart-dashboard.log" dashboard tego dashboard
  need "$MAC_CI_LOGS/restart-dashboard.log" "Starting Tego's VM"
  url=$(tail -n 1 "$MAC_CI_LOGS/browser-links.txt")
  bound 30 "$MAC_CI_LOGS/dashboard-refetch.log" /usr/bin/curl --fail --silent --show-error --max-time 20 --location --cookie-jar "$MAC_CI_LOGS/dashboard-after.cookies" --cookie "$MAC_CI_LOGS/dashboard-after.cookies" "$url" -o "$MAC_CI_LOGS/dashboard-after.html"
  need "$MAC_CI_LOGS/dashboard-after.html" '<!doctype|<!DOCTYPE|<html'
  ;;
collect) collect ;;
cleanup)
  echo 'CHECK final VM removal (diagnostics were collected first)'
  # An earlier setup failure might have left no Lima executable or instance.
  if command -v limactl >/dev/null 2>&1; then
    limactl list --format '{{.Name}}' >"$MAC_CI_LOGS/final-instances.txt"
    while IFS= read -r name; do
      case "$name" in tego|mac-ci-*) ;; *) continue ;; esac
      bound 60 "$MAC_CI_LOGS/final-delete-$name.log" limactl delete --force "$name"
      if limactl list --format '{{.Name}}' | grep -qx "$name"; then
        echo "CHECK FAILED: instance $name survived deletion"; exit 1
      fi
    done <"$MAC_CI_LOGS/final-instances.txt"
  fi
  collect
  ;;
*) echo "unknown phase: $1" >&2; exit 2 ;;
esac
