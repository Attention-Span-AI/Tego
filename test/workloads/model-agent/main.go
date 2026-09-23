// SPDX-License-Identifier: Apache-2.0

// Command model-agent is a capture workload: it calls the Anthropic Messages API through whatever
// ANTHROPIC_BASE_URL the run injected, which is the forwarder's loopback listener. Go's net/http over a
// plaintext loopback URL is exactly the shape R19 describes, so the run's record of the call comes from
// the forwarder rather than from an OpenSSL uprobe.
//
// $MODEL_CALLS calls are made (default 1), each with a distinct body so the retry recognition of R23 does
// not fold them into one attempt. With $MODEL_DIRECT set to a host:port it first tries to reach the
// upstream directly, which a contract with capture active refuses (R38).
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	base := os.Getenv("ANTHROPIC_BASE_URL")
	fmt.Println("model-agent: ANTHROPIC_BASE_URL=" + base)
	if base == "" {
		fmt.Fprintln(os.Stderr, "model-agent: the run injected no base URL")
		os.Exit(3)
	}
	if addr := os.Getenv("MODEL_DIRECT"); addr != "" {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Println("model-agent: direct connect refused:", err)
		} else {
			_ = conn.Close()
			fmt.Fprintln(os.Stderr, "model-agent: UNEXPECTED: the upstream was reachable directly")
		}
	}
	calls := 1
	if n, err := strconv.Atoi(os.Getenv("MODEL_CALLS")); err == nil && n > 0 {
		calls = n
	}
	for i := range calls {
		body := fmt.Sprintf(`{"model":"claude-test-1","max_tokens":16,`+
			`"messages":[{"role":"user","content":"ping %d"}]}`, i)
		req, err := http.NewRequest(http.MethodPost, base+"/v1/messages", bytes.NewReader([]byte(body)))
		if err != nil {
			fmt.Fprintln(os.Stderr, "model-agent: build request:", err)
			os.Exit(4)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", "sk-test-not-a-real-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "model-agent: call:", err)
			os.Exit(5)
		}
		answer, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		fmt.Printf("model-agent: call %d status %d %s\n", i+1, resp.StatusCode, bytes.TrimSpace(answer))
	}
}
