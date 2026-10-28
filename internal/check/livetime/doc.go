// SPDX-License-Identifier: Apache-2.0

// Package livetime reads and says the time limit of a live change (ADR 0125 decision 4): `tego block`, `tego
// unblock`, `tego lift` and `tego grant` take one as --for <duration> or --until <time>, and every surface says it the
// same way.
//
// Parse turns the two flags into one UTC instant: --for takes Go durations plus the units d (24 h) and w (7 d), so
// "45m", "72h", "3d", "1d12h" and "7w"; --until takes RFC 3339, "YYYY-MM-DD HH:MM", "<weekday> HH:MM" (the next such
// day and time), "HH:MM" (today if still ahead, else tomorrow) and "tomorrow HH:MM", read in the caller's location.
// The instant is held to liveblock.CheckUntil's bounds (1 minute to 400 days), the bounds every writer and the
// launcher keep. Describe says an instant as "until Fri 31 Oct 17:00 (in 3 days)".
//
// A duration is elapsed time: "3d" is 72 hours even across a daylight-saving change. A clock time is wall time in
// the location: "Sun 17:00" is 17:00 on that Sunday's clock, however many hours away that is.
//
// Nothing here does I/O, reads a clock or starts a goroutine: the caller passes now and the location.
//
// Imports: the standard library, internal/liveblock (CheckUntil and ErrInvalid only).
// Must not import: internal/runtime, internal/control, os, syscall.
package livetime
