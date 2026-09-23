// SPDX-License-Identifier: Apache-2.0
// A trivial module test/e2e/kt4-ordinary.sh's package.json depends on by file: path, so "npm
// install" (P0-DESIGN §12, docs/FEATURES.md R18 / kill test 4) has a real, local dependency to
// resolve and copy into node_modules without reaching a registry.
module.exports = function ok() {
  return "ok";
};
