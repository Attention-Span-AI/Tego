// SPDX-License-Identifier: Apache-2.0

// Package config holds the machine config of Tego (spec/config/v0/README.md):
// the Machine model with per-field provenance, the four-layer
// discovery and merge (built-in defaults, /etc/tego/config.yaml, <pw_dir>/.tego/config.yaml,
// $TEGO_CONFIG), the ceiling-versus-setting rule (a ceiling may only be lowered by a later layer,
// a setting is last-layer-wins), the per-layer trust check (open then fstat: regular file, owned by
// root or the invoking uid, no group/other write bit, and the same for its directory), the SUDO_UID
// and AT_SECURE rules, whether a person of another user reads what this process prints (StartedByAnother, from
// /proc, never the environment), the YAML units (IEC byte sizes, durations with a d suffix), the
// effective-value report that prints every value with the file and line it came from, and the
// invoking user's runtime directory bases (RuntimeDirBases), the one list the
// launcher, the CLI's compiles and the dashboard's rule service all name.
//
// Load is read-only end to end: it opens exactly the layer files, closes them before returning,
// reads no $HOME, never opens the file privileged_binary names, and returns a *Machine that is
// immutable for the process's lifetime. The trust check has one implementation shared by the
// callers. ReadRulesFile is the one function every rules file (a contract, a profile, a registry
// entry, a general policy layer) is read through: it refuses a file on a file system whose owner and
// permission bits cannot be relied on (WSL's Windows drive, 9p and virtiofs shares, FAT, exFAT, NTFS,
// SMB), asked of the descriptor it reads. Decision loads abort; observation and stop loads retain a degraded snapshot with an
// UNKNOWN baseline and its cause (ADR 0144). The system placement walk requires root ownership
// and no non-root write authority. OpenSystemFileAt shares its resolver and
// additionally pins file and ancestor descriptors for discovery account evidence.
// Configuration retains metadata-only ancestor inspection. Baseline is an
// immutable four-list union with every source. Baseline.Resolve accepts
// an explicit agent-owner home; the agent compiler applies its detached result once. LayerSources distinguishes
// exact-byte present digests, absence, unselected inputs and unknown failed layers.
//
// Local approval authority is an explicit live-check exception to ordinary immutable
// settings (ADR 0154): only system owner_only is pinned and rechecked; no ordinary
// setting is reloaded. Missing or replaced authority refuses without legacy fallback.
//
// Imports: standard library, x/sys/unix, gopkg.in/yaml.v3.
// Must not import: any other pkg/spec/* package (tier and capture names are kept as strings and
// parsed by pkg/spec/backend downstream), anything under internal/.
package config
