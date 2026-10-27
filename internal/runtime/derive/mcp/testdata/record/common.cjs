// SPDX-License-Identifier: Apache-2.0
const { createRequire } = require('module');
// MCP_SDK_DIR holds: npm install @modelcontextprotocol/sdk@1.17.0 zod@3.23.8
const r = createRequire(process.env.MCP_SDK_DIR + '/package.json');
module.exports = {
  r,
  McpServer: r('@modelcontextprotocol/sdk/server/mcp.js').McpServer,
  z: r('zod').z,
};
module.exports.makeServer = function () {
  const s = new module.exports.McpServer({ name: 'postgres', version: '0.0.1' });
  const z = module.exports.z;
  s.tool('db_query', { sql: z.string() }, async ({ sql }) => ({ content: [{ type: 'text', text: 'rows for ' + sql }] }));
  s.tool('echo', { text: z.string() }, async ({ text }) => ({ content: [{ type: 'text', text }] }));
  return s;
};
