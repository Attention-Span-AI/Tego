#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Hosted Mac only. Every invocation is bounded by the workflow as well as the
# per-operation deadlines below. Never invoke this on the Linux build host.
# GitHub documents these runner facts (no workflow override is needed):
# https://docs.github.com/en/actions/reference/workflows-and-actions/variables
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
  echo 'this script installs the real product and is only for GitHub-hosted machines' >&2
  exit 2
fi
set -euo pipefail
if [ "${RUNNER_OS:-}" != macOS ]; then
  echo 'mac-install-ci: only run by the hosted macOS workflow' >&2
  exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
helper="$here/mac-install-ci.py"
# The installer under test stays where a user gets it from: scripts/install.sh at the repository root.
installer="$(cd "$here/../../.." && pwd)/scripts/install.sh"
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
# The Mac uninstall check. The single-quoted bodies handed to guest() run in the VM's shell and expand there.
# shellcheck disable=SC2016
uninstall_phase() {
  driver=$(cat "$MAC_CI_LOGS/selected-driver.txt")
  if [ -z "$driver" ]; then
    echo 'CHECK no VM booted here, so the installer left no Mac command; the failed install was asserted in its own step'
    return 0
  fi
  export PATH="$HOME/.local/bin:$PATH"
  shim="$HOME/.local/bin/tego"
  vm_dir="$HOME/.lima/tego"
  path_line='export PATH="$HOME/.local/bin:$PATH" # added by the Tego installer'
  expect() { # DESCRIPTION COMMAND...: a plain check that names itself, pass or fail
    d=$1
    shift
    if "$@"; then echo "CHECK $d"; else echo "CHECK FAILED: $d"; exit 1; fi
  }
  gone() { ! "$@"; }
  vm_status() { limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | sed -n 's/^tego //p'; }
  vm_running() { [ "$(vm_status)" = Running ]; }
  guest() { limactl shell tego sh -c "$@"; }
  # PATH line: the installer removes it only while ~/.local/bin holds nothing but tego (the docs' words).
  others=0
  for entry in "$HOME/.local/bin"/* "$HOME/.local/bin"/.[!.]*; do
    { [ -e "$entry" ] || [ -L "$entry" ]; } || continue
    [ "${entry##*/}" = tego ] || others=$((others + 1))
  done
  echo "CHECK before: $others other file(s) in ~/.local/bin besides tego"
  expect 'before: the Mac command is installed' test -x "$shim"
  expect 'before: the installer wrote its PATH line to .zshrc' grep -qFx -- "$path_line" "$HOME/.zshrc"
  expect "before: the dashboard's tunnel is up (its control socket exists)" test -e "$vm_dir/tego-dashboard.sock"
  expect 'before: the VM runs' vm_running
  # Whether Lima keeps the installer's marker in the instance's lima.yaml decides whether tego uninstall may delete the VM.
  expect "before: the instance's lima.yaml carries the installer's marker" grep -qxF '# tego-mac-provisioning: 1' "$vm_dir/lima.yaml"
  expect 'before: Tego is installed inside the VM' guest 'test -x "$HOME/.local/bin/tego" && test -x "$HOME/.local/bin/tego-control"'
  # A record and a contract stand for what the person's runs left; the other files under ~/.tego are listed to compare.
  guest 'mkdir -p "$HOME/.tego" "$HOME/.config/tego" && echo records >"$HOME/.tego/uninstall-ci-records" && echo contract >"$HOME/.config/tego/uninstall-ci-contract"'
  guest 'cd "$HOME/.tego" && find . -type f ! -name "dashboard*" | sort' >"$MAC_CI_LOGS/records-before.txt"
  cat "$MAC_CI_LOGS/records-before.txt"
  cp "$HOME/.zshrc" "$MAC_CI_LOGS/zshrc-before-uninstall"
  cp "$shim" "$MAC_CI_TMP/tego-command-saved"
  url=$(tail -n 1 "$MAC_CI_LOGS/browser-links.txt")

  echo 'CHECK answering no to the first question changes nothing'
  rc=0
  terminal 120 "$MAC_CI_LOGS/uninstall-decline.log" uninstall-decline tego uninstall || rc=$?
  expect 'declined: exit status 0' test "$rc" = 0
  need "$MAC_CI_LOGS/uninstall-decline.log" 'Tego will remove'
  need "$MAC_CI_LOGS/uninstall-decline.log" 'the tego command '
  need "$MAC_CI_LOGS/uninstall-decline.log" 'Nothing was changed'
  expect 'declined: the Mac command is still there' test -x "$shim"
  expect 'declined: .zshrc is untouched' cmp -s "$HOME/.zshrc" "$MAC_CI_LOGS/zshrc-before-uninstall"
  expect 'declined: no backup was made' test ! -e "$HOME/.zshrc.tego-backup"
  expect "declined: the tunnel's control socket is still there" test -e "$vm_dir/tego-dashboard.sock"
  expect 'declined: the VM still runs' vm_running
  expect 'declined: Tego is still inside the VM' guest 'test -x "$HOME/.local/bin/tego"'

  echo 'CHECK Enter at the first question removes Tego; the default at the second keeps the VM and its records'
  rc=0
  terminal 360 "$MAC_CI_LOGS/uninstall-keep.log" uninstall-keep tego uninstall || rc=$?
  expect 'kept: exit status 0' test "$rc" = 0
  need "$MAC_CI_LOGS/uninstall-keep.log" 'the tego command '
  need "$MAC_CI_LOGS/uninstall-keep.log" 'Tego inside its VM'
  need "$MAC_CI_LOGS/uninstall-keep.log" 'delete the VM "tego" and everything in it'
  need "$MAC_CI_LOGS/uninstall-keep.log" 'Removed Tego inside the VM'
  need "$MAC_CI_LOGS/uninstall-keep.log" "Closed the dashboard's tunnel"
  need "$MAC_CI_LOGS/uninstall-keep.log" 'Removed the tego command'
  need "$MAC_CI_LOGS/uninstall-keep.log" 'Kept: the VM "tego"'
  need "$MAC_CI_LOGS/uninstall-keep.log" 'Tego is removed[.] The VM "tego" and your records stay'
  reject "$MAC_CI_LOGS/uninstall-keep.log" 'Deleted the VM'
  expect 'kept: the command is gone' test ! -e "$shim"
  expect "kept: the tunnel's control socket is gone" test ! -e "$vm_dir/tego-dashboard.sock"
  rc=0
  bound 30 "$MAC_CI_LOGS/dashboard-after-uninstall.log" curl --fail --silent --max-time 10 --location "$url" -o /dev/null || rc=$?
  expect 'kept: the dashboard no longer answers on the Mac' test "$rc" != 0
  if [ "$others" = 0 ]; then
    expect 'kept: the installer PATH line is gone from .zshrc' gone grep -qFx -- "$path_line" "$HOME/.zshrc"
    expect 'kept: a backup of the original .zshrc sits beside it' cmp -s "$HOME/.zshrc.tego-backup" "$MAC_CI_LOGS/zshrc-before-uninstall"
    grep -vFx -- "$path_line" "$MAC_CI_LOGS/zshrc-before-uninstall" >"$MAC_CI_LOGS/zshrc-expected" || :
    expect 'kept: .zshrc is the original minus that one line' cmp -s "$HOME/.zshrc" "$MAC_CI_LOGS/zshrc-expected"
  else
    expect 'kept: the PATH line stays while other files need it' grep -qFx -- "$path_line" "$HOME/.zshrc"
    need "$MAC_CI_LOGS/uninstall-keep.log" 'Left the PATH line'
  fi
  expect 'kept: the VM still exists and runs' vm_running
  expect 'kept: the record under ~/.tego is still in the VM' guest 'test "$(cat "$HOME/.tego/uninstall-ci-records")" = records'
  expect 'kept: the contract under ~/.config/tego is still in the VM' guest 'test "$(cat "$HOME/.config/tego/uninstall-ci-contract")" = contract'
  guest 'cd "$HOME/.tego" && find . -type f ! -name "dashboard*" | sort' >"$MAC_CI_LOGS/records-after.txt"
  expect 'kept: every record file listed before is still there' test -z "$(comm -23 "$MAC_CI_LOGS/records-before.txt" "$MAC_CI_LOGS/records-after.txt")"
  expect 'kept: tego and tego-control are gone inside the VM' guest 'test ! -e "$HOME/.local/bin/tego" && test ! -e "$HOME/.local/bin/tego-control"'
  expect "kept: the dashboard's and the clean-up units are gone inside the VM" guest 'test ! -e "$HOME/.config/systemd/user/tego-dashboard.service" && test ! -e "$HOME/.config/systemd/user/tego-gc.timer" && test ! -e "$HOME/.config/systemd/user/tego-gc.service"'
  expect "kept: the line tego start added to the VM's .bashrc is gone" guest '! grep -qF "# added by tego start" "$HOME/.bashrc"'
  expect 'kept: Lima itself stays' command -v limactl

  echo 'CHECK the VM is kept; deleting it with its records takes --delete-records (the command saved before)'
  # The VM's own logs go with the VM: keep them first.
  collect
  cp "$MAC_CI_TMP/tego-command-saved" "$shim"
  chmod +x "$shim"
  rc=0
  bound 240 "$MAC_CI_LOGS/uninstall-delete.log" tego uninstall --yes --delete-records || rc=$?
  expect 'deleted: exit status 0' test "$rc" = 0
  need "$MAC_CI_LOGS/uninstall-delete.log" 'Deleted the VM "tego", with your records and contracts'
  need "$MAC_CI_LOGS/uninstall-delete.log" 'Tego is removed, with the VM and your records'
  expect 'deleted: no tego instance is listed' test -z "$(limactl list --format '{{.Name}}' | grep -x tego || :)"
  expect "deleted: the instance's folder is gone, records with it" test ! -e "$vm_dir"
  expect 'deleted: the command is gone' test ! -e "$shim"
  expect 'deleted: Lima itself stays' command -v limactl

  echo 'CHECK a second run finds nothing to do and changes nothing'
  cp "$MAC_CI_TMP/tego-command-saved" "$shim"
  chmod +x "$shim"
  cp "$HOME/.zshrc" "$MAC_CI_LOGS/zshrc-after-delete"
  rc=0
  bound 60 "$MAC_CI_LOGS/uninstall-again.log" tego uninstall --yes || rc=$?
  expect 'again: exit status 0' test "$rc" = 0
  need "$MAC_CI_LOGS/uninstall-again.log" 'Tego is removed[.]'
  expect 'again: the command is gone' test ! -e "$shim"
  expect 'again: .zshrc did not change' cmp -s "$HOME/.zshrc" "$MAC_CI_LOGS/zshrc-after-delete"
  expect 'again: no second backup was made' test ! -e "$HOME/.zshrc.tego-backup-1"
  echo 'MAC_UNINSTALL_PROVEN=decline kept nothing changed; Enter removed the command, PATH line, tunnel and Tego inside the VM and kept the VM with its records; --delete-records deleted the VM; a second run changed nothing.'
}
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
  terminal 900 "$MAC_CI_LOGS/installer.log" install /bin/sh "$installer" || rc=$?
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
  terminal 120 "$MAC_CI_LOGS/rerun.log" install /bin/sh "$installer"
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
  terminal 180 "$MAC_CI_LOGS/repair.log" install /bin/sh "$installer"
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
uninstall) uninstall_phase ;;
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
