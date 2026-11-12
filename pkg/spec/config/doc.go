// SPDX-License-Identifier: Apache-2.0

// Package config holds the machine config of Tego (spec/config/v0/README.md,
// docs/p0/identity-config.md §2.4, §5): the Machine model with per-field provenance, the four-layer
// discovery and merge (built-in defaults, /etc/tego/config.yaml, <pw_dir>/.tego/config.yaml,
// $TEGO_CONFIG), the ceiling-versus-setting rule (a ceiling may only be lowered by a later layer,
// a setting is last-layer-wins), the per-layer trust check (open then fstat: regular file, owned by
// root or the invoking uid, no group/other write bit, and the same for its directory), the SUDO_UID
// and AT_SECURE rules, whether a person of another user reads what this process prints (StartedByAnother, from
// /proc, never the environment), the YAML units (IEC byte sizes, durations with a d suffix), the
// effective-value report that prints every value with the file and line it came from, and the
// invoking user's runtime directory bases (RuntimeDirBases, agent-contract.md R10a), the one list the
// launcher, the CLI's compiles and the dashboard's rule service all name.
//
// Load is read-only end to end: it opens exactly the layer files, closes them before returning,
// reads no $HOME, never opens the file privileged_binary names, and returns a *Machine that is
// immutable for the process's lifetime. The trust check has one implementation shared by the
// abort (tego run, tego gc) and warn-and-skip (compile, doctor) call sites through TrustMode.
//
// Imports: standard library, gopkg.in/yaml.v3.
// Must not import: any other pkg/spec/* package (tier and capture names are kept as strings and
// parsed by pkg/spec/backend downstream), anything under internal/.
package config
