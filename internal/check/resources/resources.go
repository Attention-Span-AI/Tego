// SPDX-License-Identifier: Apache-2.0

// Package resources renders run_end.resources, what the run's cgroup said the run used, for the two views
// that show it: `tego measure` as rows of its table and `tego status` as one line under its table
// (docs/p0/limits-check-doctor-cli.md R-res). The peaks are what an operator sizes limits.memory and
// limits.pids from (docs/p0/record-ledger.md §2.2), and they are in the record only to be read.
//
// A key run_end did not carry is rendered Unknown, never 0: the runtime writes a key exactly when its file
// and key existed on the run's kernel and controllers, so its absence says the kernel did not tell, and a 0
// would claim it told a zero (docs/VERSIONING.md §2). A 0 that is present is the kernel's zero and renders
// as one.
//
// Imports: pkg/spec/record only. Must not import internal/runtime (docs/REPO-LAYOUT.md: the read side never
// imports the engine).
package resources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Unknown is what a field reads when run_end did not carry its key.
const Unknown = "unknown"

// Pending is what a view shows for the resources of a run whose run_end is not on disk yet: they are read
// once, at shutdown (runtime-launch.md §4.1 step 13), so a live run has none to show, and a bare Unknown would
// read as a kernel that told nothing.
const Pending = Unknown + " until the run ends"

// Recorded returns run_end's resources object as the ledger holds it, for a --json view. record.Resources
// holds the keys this binary knows, and decoding into it drops a key a newer binary adds (additive,
// docs/VERSIONING.md §2); the JSON view gives the object as recorded, as the capability map's does. nil when
// the payload carries no resources object: absent, null, or not an object.
func Recorded(runEnd *record.Event) json.RawMessage {
	var p struct {
		Resources json.RawMessage `json:"resources"`
	}
	if runEnd == nil || runEnd.DecodePayload(&p) != nil {
		return nil
	}
	if b := bytes.TrimSpace(p.Resources); len(b) > 0 && b[0] == '{' {
		return b
	}
	return nil
}

// Field is one rendered resource: the label a view prints and its value, Unknown when not recorded.
type Field struct {
	Label, Value string
}

// Fields renders r in a fixed order, one Field per group of run_end.resources keys: memory peak, pids peak,
// cpu, cpu throttled and memory events. A nil r, a run_end with no resources object (an older binary, a run
// that failed before its cgroup existed) or no run_end at all, renders every field Unknown, so the rows a
// view prints never depend on what one run happened to record.
func Fields(r *record.Resources) []Field {
	if r == nil {
		r = &record.Resources{}
	}
	return []Field{
		{"memory peak", bytesOf(r.MemoryPeak)},
		{"pids peak", countOf(r.PidsPeak)},
		{"cpu", cpu(r)},
		{"cpu throttled", throttled(r)},
		{"memory events", memoryEvents(r.MemoryEvents)},
	}
}

// Line is Fields joined into one line, "<label> <value>" per field, for a view that prints it under its
// table. A run whose run_end is not on disk yet reads Pending instead of "unknown" in every field.
func Line(r *record.Resources, ended bool) string {
	if !ended {
		return Pending
	}
	fs := Fields(r)
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = f.Label + " " + f.Value
	}
	return strings.Join(parts, ", ")
}

// bytesOf renders memory.peak in IEC units with the exact byte count beside it, since limits.memory is
// written in bytes or IEC units (spec/config/v0) and a rounded figure alone would not size it.
func bytesOf(v *uint64) string {
	if v == nil {
		return Unknown
	}
	n := *v
	if n < 1024 {
		return strconv.FormatUint(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	f := float64(n) / 1024
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s (%d B)", f, units[i], n)
}

func countOf(v *uint64) string {
	if v == nil {
		return Unknown
	}
	return strconv.FormatUint(*v, 10)
}

// usec renders a cpu.stat microsecond total as a duration rounded to the millisecond.
func usec(v *uint64) string {
	if v == nil {
		return Unknown
	}
	// Clamp before the multiplication: past MaxInt64/1000 microseconds (about 106 CPU-days, reachable by
	// a many-core agent) the product wraps to a negative duration.
	d := time.Duration(math.MaxInt64)
	if *v <= math.MaxInt64/uint64(time.Microsecond) {
		d = time.Duration(*v) * time.Microsecond
	}
	return d.Round(time.Millisecond).String()
}

// cpu is cpu.stat's usage_usec with its user and system halves. Each half is its own key, so each is
// unknown on its own.
func cpu(r *record.Resources) string {
	return fmt.Sprintf("%s (user %s, system %s)", usec(r.CPUUsageUsec), usec(r.CPUUserUsec), usec(r.CPUSystemUsec))
}

// throttled is how often and for how long cpu.max held the run back. Both keys need the cpu controller, so
// a run without it has neither, and saying "unknown" once reads better than twice.
func throttled(r *record.Resources) string {
	if r.CPUNrThrottled == nil && r.CPUThrottledUsec == nil {
		return Unknown
	}
	return fmt.Sprintf("%s times for %s", countOf(r.CPUNrThrottled), usec(r.CPUThrottledUsec))
}

// memoryEvents is memory.events' four counters in the file's own order; a file that was absent (no memory
// controller) is one Unknown, and a key the file lacked is Unknown beside the others.
func memoryEvents(m *record.MemoryEvents) string {
	if m == nil {
		return Unknown
	}
	return fmt.Sprintf("high %s, max %s, oom %s, oom_kill %s",
		countOf(m.High), countOf(m.Max), countOf(m.OOM), countOf(m.OOMKill))
}
