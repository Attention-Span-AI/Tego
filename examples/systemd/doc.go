// SPDX-License-Identifier: Apache-2.0

// Package systemd holds the systemd user units for agents that run all the time: the template that runs one agent
// (tego-agent@.service), its planned daily restart (tego-agent-restart@.timer, tego-agent-restart@.service) and the
// daily retention pass (tego-gc.timer, tego-gc.service), with the tests that hold their keys to tego run's exit codes
// and to each other. example-restart-myapp.socket and example-restart-myapp@.service are an example to adapt, not units
// Tego needs: a one-verb helper that lets a governed agent restart one service without the user manager's socket
// (docs/user/built-in-refusals.md). It has no code of its own: the binary never imports it.
package systemd
