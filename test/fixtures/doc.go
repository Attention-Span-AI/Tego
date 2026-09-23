// SPDX-License-Identifier: Apache-2.0

// Package fixtures holds the recorded ledgers under test/fixtures/ledger and the test that replays them.
// It has no code of its own: the binary never imports it. P0-DESIGN §10 makes the frozen M0 fixture the
// contract for every view and has "every kill test add a recorded fixture", so a view that cannot read what
// a real run on a real kernel wrote fails here, next to the ledgers that show it, rather than on a user's
// run. The kill tests save their ledgers when KT_FIXTURE_DIR is set (test/e2e/lib.sh kt_save_fixture), and
// `test/vm/matrix.sh --save-fixtures <row>` copies one kernel-matrix row's into test/fixtures/ledger.
package fixtures
