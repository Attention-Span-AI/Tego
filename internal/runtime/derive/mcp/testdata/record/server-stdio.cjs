// SPDX-License-Identifier: Apache-2.0
const c = require('./common.cjs');
const { StdioServerTransport } = c.r('@modelcontextprotocol/sdk/server/stdio.js');
c.makeServer().connect(new StdioServerTransport());
