// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"flag"
	"os"
	"strconv"
	"testing"
	"time"
)

// OffsetEnv names the offset ShuffleOffset returns when it is set, to rerun the subset a failed run took.
const OffsetEnv = "TEGO_TEST_SUBSET_OFFSET"

// ShuffleOffset is where, among every, a test that runs only every every-th of its cases (a reduced race run) starts:
// case i runs when i%every == ShuffleOffset(t, every). It is the remainder of the -shuffle seed where go test was given
// one (-shuffle=N: the same seed, the same subset), of the clock where it chose its own (-shuffle=on, which CI's race
// job uses and which the testing package does not hand to a test), and 0 where the tests run in order. So over a few
// shuffled runs every case is covered, where a fixed offset would leave three of four never raced. It logs the offset
// it chose, and OffsetEnv names one to rerun.
func ShuffleOffset(t testing.TB, every int) int {
	t.Helper()
	val := ""
	if f := flag.Lookup("test.shuffle"); f != nil {
		val = f.Value.String()
	}
	off := shuffleOffset(val, os.Getenv(OffsetEnv), every, time.Now())
	t.Logf("reduced run: every %dth case, from case %d (-shuffle=%q; %s=%d reruns it)", every, off, val, OffsetEnv, off)
	return off
}

// shuffleOffset is ShuffleOffset's decision from the -shuffle flag's value, the OffsetEnv override and the time.
func shuffleOffset(flagValue, override string, every int, now time.Time) int {
	if every < 1 {
		return 0
	}
	if n, err := strconv.Atoi(override); err == nil && n >= 0 {
		return n % every
	}
	switch flagValue {
	case "", "off":
		return 0
	case "on":
		return int(now.UnixNano() / 1000 % int64(every))
	}
	if seed, err := strconv.ParseInt(flagValue, 10, 64); err == nil {
		return int(((seed % int64(every)) + int64(every)) % int64(every))
	}
	return 0
}
