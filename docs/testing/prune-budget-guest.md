# Retention startup checks owed in a guest

These checks are **owed in a guest**. They were not run for this fix. Use a disposable full Ubuntu guest
with systemd, a non-root login user with sudo, and this branch's engine installed at
`/opt/tego-prunebudget/tego`. Run every block below in that user's Bash shell. Build and boot with at most 3 GiB guest RAM; follow [the VM guide](../../test/vm/README.md).
Keep the guest exit status and console. These commands modify only the disposable guest.

Install the guest tools and make a local ledger root. `findmnt` must report a local disk filesystem
(for example ext4 or xfs), not NFS or FUSE. The launching contract stays on that disk too.

```sh
export PATH="/opt/tego-prunebudget:$PATH"
command -v tego
sudo apt-get update
sudo apt-get install -y nfs-kernel-server nfs-common python3 time iptables
case_dir="$HOME/prune-budget-check"
mkdir -m 700 "$case_dir"
mkdir -m 700 "$case_dir/runs"
findmnt -T "$case_dir/runs" -o TARGET,FSTYPE
cat > "$case_dir/config.yaml" <<EOF
ledger_root: $case_dir/runs
retention: 0s
gc_interval: 1s
EOF
chmod 600 "$case_dir/config.yaml"
cat > "$case_dir/start.yaml" <<'EOF'
version: 0
name: prune-budget-check
command: [/usr/bin/true]
env:
  pass: []
EOF
chmod 600 "$case_dir/start.yaml"
sudo -v
/usr/bin/time -o "$case_dir/local.time" -f '%e' sudo env TEGO_CONFIG="$case_dir/config.yaml" \
  "$(command -v tego)" run "$case_dir/start.yaml"
printf 'local start exit=%s\n' "$?"
cat "$case_dir/local.time"
```

Expected actual startup result: exit 0, the true command completes, and a completed run appears in
`runs/`. Record this local elapsed time for comparison. This exercises the actual root command start,
not only the in-process retention function.

Set up a hard NFS mount on loopback with attribute and lookup caching disabled. Create a synthetic
two-line pruning fixture: one contract on NFS, one missing on the local disk, and one shared, valid blob.
These lines test pruning only; they are not claimed to be real rule-edit history.

```sh
sudo mkdir -p /srv/prune-budget-export /mnt/prune-budget-nfs
sudo chmod 755 /srv/prune-budget-export /mnt/prune-budget-nfs
printf 'version: 0\nname: remote\n' | sudo tee /srv/prune-budget-export/remote.yaml >/dev/null
printf '/srv/prune-budget-export 127.0.0.1(rw,sync,no_subtree_check)\n' | \
  sudo tee /etc/exports.d/prune-budget.exports >/dev/null
sudo systemctl start nfs-server
sudo exportfs -ra
sudo mount -t nfs -o vers=4,hard,actimeo=0,lookupcache=none \
  127.0.0.1:/srv/prune-budget-export /mnt/prune-budget-nfs
python3 - "$case_dir" <<'PY'
import hashlib, json, os, pathlib, time, sys
base = pathlib.Path(sys.argv[1])
journal = base / 'runs/.rule-changes'
for d in (journal, journal / 'blobs', journal / 'locks'):
    d.mkdir(mode=0o700, exist_ok=True)
text = b'version: 0\nname: remote\n'
digest = hashlib.sha256(text).hexdigest()
blob = journal / 'blobs' / (digest + '.yaml')
blob.write_bytes(text)
blob.chmod(0o600)
os.utime(blob, (time.time() - 86400, time.time() - 86400))
paths = ['/mnt/prune-budget-nfs/remote.yaml', str(base / 'missing.yaml')]
with (journal / 'journal.jsonl').open('w') as f:
    for i, path in enumerate(paths):
        f.write(json.dumps(dict(v=1, id='guest-prune-' + str(i), op='change',
            at='2000-01-01T00:00:00Z', uid=os.getuid(), pid=os.getpid(), contract=path,
            old_sha256=digest, new_sha256=digest)) + '\n')
(journal / 'journal.jsonl').chmod(0o600)
PY
touch -d '2 hours ago' "$case_dir/runs/.gc-stamp"
sudo systemctl stop nfs-server
sudo iptables -I OUTPUT -d 127.0.0.1 -p tcp --dport 2049 -j DROP
/usr/bin/time -o "$case_dir/dead-nfs.time" -f '%e' timeout 15s sudo env \
  TEGO_CONFIG="$case_dir/config.yaml" "$(command -v tego)" run "$case_dir/start.yaml"
printf 'dead-NFS start exit=%s\n' "$?"
cat "$case_dir/dead-nfs.time"
grep -F '/mnt/prune-budget-nfs/remote.yaml' "$HOME/.tego/tego.log"
wc -l "$case_dir/runs/.rule-changes/journal.jsonl"
```

Expected: exit 0 with about 1 s extra look delay relative to the local start on an otherwise idle guest,
not a hard whole-command deadline. The log names `remote.yaml` as not looked at. One journal line remains
for it; the missing local contract's line is pruned. A timeout, another error or different lines is a
failed check, not a successful budget proof. Restore the server even if the check failed:

```sh
sudo iptables -D OUTPUT -d 127.0.0.1 -p tcp --dport 2049 -j DROP
sudo systemctl start nfs-server
sudo exportfs -ra
sudo rm /srv/prune-budget-export/remote.yaml
sudo env \
  TEGO_CONFIG="$case_dir/config.yaml" "$(command -v tego)" gc --keep 0s
wc -l "$case_dir/runs/.rule-changes/journal.jsonl"
stat -c '%u:%g %n' "$case_dir/runs/.rule-changes/journal.jsonl"
```

Expected: gc exit 0, the remaining journal line pruned, zero lines left, and the rewritten journal owned
by the invoking login user's uid and primary group. This also checks that the next pass can continue.

For the cross-owner check, give that same journal directory to a second user, add a torn line that would
otherwise be removed, and force another start pass. Keep the ledger root owned by the invoking user.

```sh
sudo useradd --no-create-home prune-other
printf 'torn fixture\n' >> "$case_dir/runs/.rule-changes/journal.jsonl"
sha256sum "$case_dir/runs/.rule-changes/journal.jsonl" > "$case_dir/cross-owner.before"
sudo chown -R prune-other:prune-other "$case_dir/runs/.rule-changes"
touch -d '2 hours ago' "$case_dir/runs/.gc-stamp"
timeout 15s sudo env TEGO_CONFIG="$case_dir/config.yaml" \
  "$(command -v tego)" run "$case_dir/start.yaml"
printf 'cross-owner start exit=%s\n' "$?"
sudo sha256sum "$case_dir/runs/.rule-changes/journal.jsonl" > "$case_dir/cross-owner.after"
diff -u "$case_dir/cross-owner.before" "$case_dir/cross-owner.after"
grep -F 'it is left to its owner' "$HOME/.tego/tego.log"
sudo umount /mnt/prune-budget-nfs
sudo rm /etc/exports.d/prune-budget.exports
sudo exportfs -ra
```

Expected: the starting command exits 0; both checksums match and diff exits 0. The log says the journal is
another user's and `it is left to its owner` (the operator wording "left to them"). Keep the output and
guest exit status with the report, then shut down the guest.
