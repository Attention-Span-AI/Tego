// SPDX-License-Identifier: Apache-2.0
const c = require('./common.cjs');
const { Client } = c.r('@modelcontextprotocol/sdk/client/index.js');
async function drive(transport) {
  const cl = new Client({ name: 'rec', version: '0.0.1' });
  await cl.connect(transport);
  await cl.listTools();
  await cl.callTool({ name: 'db_query', arguments: { sql: 'select count(*) from runs' } });
  await cl.callTool({ name: 'echo', arguments: { text: 'two\nlines "quoted"' } });
  await cl.close();
}
async function main() {
  const mode = process.argv[2];
  if (mode === 'stdio') {
    const { StdioClientTransport } = c.r('@modelcontextprotocol/sdk/client/stdio.js');
    await drive(new StdioClientTransport({ command: process.execPath, args: [__dirname + '/tee.cjs', process.argv[3], __dirname + '/server-stdio.cjs'] }));
  } else if (mode === 'http') {
    const { StreamableHTTPClientTransport } = c.r('@modelcontextprotocol/sdk/client/streamableHttp.js');
    await drive(new StreamableHTTPClientTransport(new URL(process.argv[3])));
  } else if (mode === 'sse') {
    const { SSEClientTransport } = c.r('@modelcontextprotocol/sdk/client/sse.js');
    await drive(new SSEClientTransport(new URL(process.argv[3])));
  }
}
main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
