// SPDX-License-Identifier: Apache-2.0

//go:build race

package decide

// sweepStride is how far apart the generated tables are that a sampled sweep checks (sampled, tables_test.go): every
// eleventh under the race detector. The detector slows a sweep six to eleven times over
// (TestPlaneEvaluatorMatchesEvaluate from 11 s to 2 min) and can find nothing in it: the package starts no goroutine and
// takes no lock (doc.go), and the sweeps run one at a time, so a sweep is one goroutine's arithmetic. The build without
// the detector, which CI's unit steps and precommit run, checks every table. Eleven is prime, so the sample does not
// keep landing on one deny_write variant or one name dimension of each base table, which genPlaneTables and
// genNameTables visit in a fixed cycle.
const sweepStride = 11
