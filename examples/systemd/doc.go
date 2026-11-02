// SPDX-License-Identifier: Apache-2.0

// Package systemd holds the systemd user units for agents that run all the time: the template that runs one agent
// (tego-agent@.service), its planned daily restart (tego-agent-restart@.timer, tego-agent-restart@.service) and the
// daily retention pass (tego-gc.timer, tego-gc.service), with the tests that hold their keys to tego run's exit codes
// and to each other. It has no code of its own: the binary never imports it.
package systemd
