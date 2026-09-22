# License texts

The repository is Apache-2.0, and the kernel programs under `bpf/` are
`GPL-2.0-only OR BSD-2-Clause` (ADR 0012).
The root [LICENSE](../LICENSE) contains the Apache text. The corresponding
GPL and BSD texts are here. The vendored libbpf headers retain their separate
`LGPL-2.1 OR BSD-2-Clause` declaration; their alternative LGPL text is included too.
`Lucide.txt` is the licence of the dashboard's icons.

Sources: [Apache](https://www.apache.org/licenses/LICENSE-2.0.txt),
[SPDX GPL-2.0-only](https://github.com/spdx/license-list-data/blob/main/text/GPL-2.0-only.txt),
[SPDX BSD-2-Clause](https://github.com/spdx/license-list-data/blob/main/text/BSD-2-Clause.txt),
[SPDX LGPL-2.1-only](https://github.com/spdx/license-list-data/blob/main/text/LGPL-2.1-only.txt).
The GPL and LGPL texts are complete license templates, and their bracketed example
copyright fields name no one. Source files and third-party notices remain
authoritative for attribution.

[THIRD_PARTY_NOTICES.txt](../THIRD_PARTY_NOTICES.txt) copies notices from the
versions linked into the release binaries, and holds the notices of what they
embed. Update it when a shipped dependency, an embedded asset or the toolchain
changes. The release includes these files in a checksummed license archive
alongside the raw binaries, and in each maze archive.
