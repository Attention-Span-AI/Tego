// SPDX-License-Identifier: Apache-2.0

// Package container holds the container image's files (Dockerfile, compose.yaml, the entrypoint, the machine config,
// the hello agent and its smoke script; docs/user/container.md) and the tests that hold them to each other and to
// the engine without a container runtime: the entrypoint's cgroup delegation over a stand-in cgroup tree, the
// compose file's settings against what the entrypoint and tego need, the Dockerfile's pins and paths, and the hello
// contract's verdicts through `tego compile --test`, and the release workflow's signing authority, artifacts and
// changelog body checks. Building and running the image is CI's container workflow. This package has no code of
// its own: the binary never imports it.
//
// Imports (tests only): the standard library, gopkg.in/yaml.v3, internal/cli, pkg/spec/config, pkg/spec/identity.
// Must not import: anything outside its tests.
package container
