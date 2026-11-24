# Measured cron distribution inputs

The Ubuntu 25.10 contents were copied without editing from the permitted
machine `/etc/crontab` and direct `/etc/cron.d` distribution files on 2026-11-12.
No home, spool contents or real user's crontab was read. These are cron/anacron,
e2fsprogs and sysstat package configuration examples, retained here to check
ordinary layouts. Their package copyright remains with their upstream authors;
this fixture directory makes no new licence claim over those files.

| Input | Bytes | Lines | Longest line | Parser outcome |
|---|---:|---:|---:|---|
| `/etc/crontab` | 1,136 | 23 | 94 | unresolved shell body; no rows retained |
| `/etc/cron.d/.placeholder` | 102 | 2 | 77 | read; comments only |
| `/etc/cron.d/anacron` | 224 | 5 | 144 | unresolved shell body; no rows retained |
| `/etc/cron.d/e2scrub_all` | 188 | 2 | 101 | unresolved shell body; no rows retained |
| `/etc/cron.d/sysstat` | 400 | 9 | 72 | unresolved shell body; no rows retained |

The direct directory has four entries. The largest content has 24 whitespace
words on a line; the largest file has four jobs. Each limit is shared with unit
parsing: 8,192 bytes per line, 4,096 combined physical lines and command words,
128 jobs per file and 256 command arguments. The 1 MiB per-file limit and the
shared content budget charge failed reads too. Directory enumeration charges
raw names and overflow lookahead against 4,096 entries. The source and item
collector arrays stop at 1,800/400 KiB and 512/450 KiB respectively, with a
reserved unknown-remainder source. These are work and retained-input bounds,
not a hard filesystem deadline or an RSS claim.

Synthetic fixtures cover the ordinary root-owned spool modes 0700, 0710, 0755
and root:crontab sticky 01730 without reading a real spool. Non-sticky 0730 and
other-writable 01733 are refused as mode. Files remain regular, single-link,
root-or-account owned and not group/other writable. Synthetic account, schedule,
native and Node entry point, shell, substitution, redirection, unknown account,
missing final newline, size, inode type and link cases are in `cron_test.go`.
A shell-containing file remains a disclosed unresolved source. It cannot change
the process-only `--check` answer or establish absence.
