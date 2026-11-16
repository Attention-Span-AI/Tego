// SPDX-License-Identifier: Apache-2.0

package cli

// groupedHelp is `tego --help`: the verbs a person starts with, grouped by what they act on, then every other command
// by what it is for. `tego help` keeps the flat list of every command (writeUsage), which scripts read.
// TestGroupedHelp holds it to the command table.
const groupedHelp = `Tego supervises AI agents: it blocks what your rules don't allow and records everything they do.

Get started
  start          Set up Tego and your first agent, step by step
  doctor         Check what this computer supports

Agents
  add agent      Add an agent for Tego to supervise
  apply -f FILE  Add or update an agent from a rules file
  get agents     List your agents
  describe agent Show an agent's rules in plain words
  edit agent     Edit an agent's rules file
  remove agent   Stop supervising an agent

Sessions
  run AGENT      Start a supervised session
  get sessions   List sessions
  describe session  What a session did and what Tego blocked
  logs SESSION   Show a session's events
  stop | pause | resume SESSION

Approvals
  get approvals  Actions waiting for your answer
  allow | deny APPROVAL

Presets
  get presets    List the presets
  describe preset  What a preset allows and blocks

Dashboard
  dashboard      Open the dashboard in your browser

More commands
  Check rules       compile  test     drift    measure
  Record            watch    adopt    agents   learn
  Live control      block    unblock  rule     lift     grant    alternate
  Approvals         ask      approve
  Network           dns
  Tools for agents  mcp      route
  Records           status   receipt  events   gc       restore  rules
  Setup             init     setup    serve    version  licenses

More: tego help advanced (compile, learn, drift, watch, adopt, mcp, route, gc, test)
Read more: https://github.com/Attention-Span-AI/Tego/blob/main/docs/user/README.md
`
