// SPDX-License-Identifier: Apache-2.0
// Runs the server as a child and appends every byte the client writes to its stdin to argv[2].
const fs = require('fs'); const { spawn } = require('child_process');
const out = fs.openSync(process.argv[2], 'a');
const ch = spawn(process.execPath, process.argv.slice(3), { stdio: ['pipe', 'inherit', 'inherit'] });
process.stdin.on('data', (b) => { fs.writeSync(out, b); ch.stdin.write(b); });
process.stdin.on('end', () => ch.stdin.end());
ch.on('exit', (code) => process.exit(code ?? 0));
