#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# tego uninstall with the service guide's drop-in (10-delegate.conf) present. Run as an ordinary user inside a
# user scope, with /mnt/p2 mounted (guest-proof.py).
# shellcheck source=common.sh
. /mnt/p2/guest-proof/common.sh
OUT=$HOME/proof-out
mkdir -p "$OUT"
U=$HOME/.config/systemd/user
D=$U/tego-agent@.service.d
facts
# setup: what the guide's "enable" step leaves, without starting the service
setup() {
	inst A
	rm -rf "$D" "$U/tego-agent@.service"
	mkdir -p "$U"
	install -m 0644 "$P/tego-agent@.service" "$U/tego-agent@.service"
	mkdir -p "$D"
	printf '[Service]\nDelegate=yes\n' >"$D/10-delegate.conf"
	systemctl --user daemon-reload
	echo "drop-ins systemd sees: $(systemctl --user show tego-agent@probe.service -p DropInPaths --value)"
}

echo "== C0 uninstall --yes (no --stop-agents): the service answer is no, the drop-in stays"
setup
tego uninstall --yes >"$OUT/c0.out" 2>&1; rc=$?
cat "$OUT/c0.out"; echo "rc=$rc"
chk "C0 rc 0, tego removed" "[ $rc = 0 ] && [ ! -e $B/tego ]"
chk "C0 the drop-in and the template stay" "[ -f $D/10-delegate.conf ] && [ -f $U/tego-agent@.service ]"

echo "== C1 only the guide's file in the folder, --yes --stop-agents"
setup
tego uninstall --yes --stop-agents >"$OUT/c1.out" 2>&1; rc=$?
cat "$OUT/c1.out"; echo "rc=$rc"
ls -la "$U"
chk "C1 rc 0" "[ $rc = 0 ]"
chk "C1 the drop-in file and its folder are gone" "[ ! -e $D/10-delegate.conf ] && [ ! -e $D ]"
chk "C1 the copy of the template is gone" "[ ! -e $U/tego-agent@.service ]"
chk "C1 the output says it removed the drop-in folder" "grep -q 'tego-agent@.service.d' $OUT/c1.out"
echo "drop-ins systemd sees after: '$(systemctl --user show tego-agent@probe.service -p DropInPaths --value)'"
chk "C1 systemd no longer sees the drop-in (daemon-reload ran)" "[ -z \"\$(systemctl --user show tego-agent@probe.service -p DropInPaths --value)\" ]"

echo "== C2 another file in the folder is named and left"
setup
printf '[Service]\nMemoryMax=1G\n' >"$D/20-mine.conf"
MINE=$(sha256sum "$D/20-mine.conf" | cut -d' ' -f1)
tego uninstall --yes --stop-agents >"$OUT/c2.out" 2>&1; rc=$?
cat "$OUT/c2.out"; echo "rc=$rc"
ls -la "$D"
chk "C2 rc 0" "[ $rc = 0 ]"
chk "C2 10-delegate.conf is gone, the folder and 20-mine.conf stay unchanged" "[ ! -e $D/10-delegate.conf ] && [ \"\$(sha256sum $D/20-mine.conf | cut -d' ' -f1)\" = '$MINE' ]"
chk "C2 the output names 20-mine.conf as left" "grep -q 'Left ~/.config/systemd/user/tego-agent@.service.d/20-mine.conf' $OUT/c2.out"
chk "C2 the template copy is gone" "[ ! -e $U/tego-agent@.service ]"
rm -rf "$D"

echo "== C3 an edited 10-delegate.conf is named and left"
setup
printf '[Service]\nDelegate=yes\nMemoryMax=2G\n' >"$D/10-delegate.conf"
EDIT=$(sha256sum "$D/10-delegate.conf" | cut -d' ' -f1)
tego uninstall --yes --stop-agents >"$OUT/c3.out" 2>&1; rc=$?
cat "$OUT/c3.out"; echo "rc=$rc"
chk "C3 rc 0" "[ $rc = 0 ]"
chk "C3 the edited file stays unchanged" "[ \"\$(sha256sum $D/10-delegate.conf | cut -d' ' -f1)\" = '$EDIT' ]"
chk "C3 the output names it as left" "grep -q 'Left ~/.config/systemd/user/tego-agent@.service.d/10-delegate.conf' $OUT/c3.out"
rm -rf "$D" "$U/tego-agent@.service"
echo "FAILS=$FAILS"
exit "$FAILS"
