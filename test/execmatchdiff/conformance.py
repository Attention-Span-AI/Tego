#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run host conformance through cli.Main without executing a tego binary."""
import json
import pathlib
import sys

repo = pathlib.Path.cwd()
out = pathlib.Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
p = repo / 'test/conformance/harness_test.go'
s = p.read_text()
s = s.replace('import (', 'import (\n "github.com/attention-span-ai/tego/internal/cli"', 1)
a = s.index('func buildTego(')
b = s.index('\n}\n', a) + 3
s = s[:a] + '''func buildTego(_ string, _ ...string) (string, error) {
 return "in-process-cli-test", nil
}
''' + s[b:]
a = s.index('\tcmd := exec.Command(bin, "compile", "agent.yaml", "--test", tablePath, "--json", "--offline")')
b = s.index('\n\tout, err := answersOf', a)
s = s[:a] + ''' var stdout, stderr bytes.Buffer
 _ = compileInProcess(t, e, environ, &stdout, &stderr, "compile", "agent.yaml", "--test", tablePath, "--json", "--offline")
''' + s[b:]
a = s.index('\tcmd := exec.Command(bin, "compile", "agent.yaml", "--json", "--offline")')
b = s.index('\n\treturn stdout.Bytes()', a)
s = s[:a] + ''' var stdout, stderr bytes.Buffer
 if rc := compileInProcess(t, e, environ, &stdout, &stderr, "compile", "agent.yaml", "--json", "--offline"); rc != 0 {
  t.Fatalf("compile --json exit %d\\nstdout:\\n%s\\nstderr:\\n%s", rc, stdout.String(), stderr.String())
 }
''' + s[b:]
s += '''
// No product binary is started. The existing test machine hooks and private
// machineConfig environment are unchanged; untagged tests do not run in parallel.
func compileInProcess(t *testing.T, e *env, environ []string, stdout, stderr *bytes.Buffer, args ...string) int {
 t.Helper()
 cwd, err := os.Getwd()
 if err != nil { t.Fatal(err) }
 if err := os.Chdir(e.project); err != nil { t.Fatal(err) }
 defer func() { if err := os.Chdir(cwd); err != nil { t.Error(err) } }()
 type previous struct { value string; set bool }
 before := make(map[string]previous)
 defer func() {
  for k,v := range before {
   var err error
   if v.set { err = os.Setenv(k,v.value) } else { err = os.Unsetenv(k) }
   if err != nil { t.Error(err) }
  }
 }()
 for _,entry := range environ {
  k,v,ok := strings.Cut(entry,"=")
  if !ok || !strings.HasPrefix(k,"TEGO_") { continue }
  if _,seen := before[k]; !seen { old,set := os.LookupEnv(k); before[k] = previous{old,set} }
  if err := os.Setenv(k,v); err != nil { t.Fatal(err) }
 }
 return cli.Main(append([]string{"in-process-cli-test"},args...), stdout, stderr)
}
'''
(out / 'harness_test.go').write_text(s)
(out / 'overlay.json').write_text(json.dumps({'Replace': {str(p): str(out / 'harness_test.go')}}))
print(out / 'overlay.json')
