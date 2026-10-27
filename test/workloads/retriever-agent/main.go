// SPDX-License-Identifier: Apache-2.0

// Command retriever-agent is the retriever as a capture workload: it talks to the Anthropic Messages API
// through whatever ANTHROPIC_BASE_URL the run injected (the forwarder's loopback listener) and runs the tools each
// reply asks for, reporting their results in its next request as the API requires, until a reply asks for none.
// Its tools act in the agent's own process, so their actions are the ones attribution must tie to the reply that
// asked for them (capture-derive R42):
//
//	db_query         connects to $DB_ADDR, reads one line, and writes $OUT/summary.md
//	publish_summary  connects to $QUEUE_ADDR, then tries to write $NETRC, a path the contract does not let it write
//
// Before each tool it waits $TOOL_DELAY_MS (default 100) milliseconds, the time a real agent takes to read a reply
// before it acts on it. It prints one line per tool, "netrc refused" when the write was refused, and "done" after the
// reply that asked for nothing; any other end exits non-zero.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type block = map[string]any

func main() {
	base := os.Getenv("ANTHROPIC_BASE_URL")
	if base == "" {
		fmt.Fprintln(os.Stderr, "retriever-agent: the run injected no base URL")
		os.Exit(3)
	}
	delay := 100 * time.Millisecond
	if ms, err := strconv.Atoi(os.Getenv("TOOL_DELAY_MS")); err == nil {
		delay = time.Duration(ms) * time.Millisecond
	}
	messages := []any{block{"role": "user", "content": "Summarize last week's failed orders and publish the summary."}}
	for turn := 1; turn <= 5; turn++ {
		content, err := call(base, messages)
		if err != nil {
			fmt.Fprintf(os.Stderr, "retriever-agent: turn %d: %v\n", turn, err)
			os.Exit(1)
		}
		messages = append(messages, block{"role": "assistant", "content": content})
		var results []any
		for _, b := range content {
			if b["type"] != "tool_use" {
				continue
			}
			id, _ := b["id"].(string)
			name, _ := b["name"].(string)
			time.Sleep(delay)
			out, failed := runTool(name)
			fmt.Printf("tool %s %s: %s\n", name, id, out)
			results = append(results, block{"type": "tool_result", "tool_use_id": id, "content": out, "is_error": failed})
		}
		if len(results) == 0 {
			fmt.Println("done")
			return
		}
		messages = append(messages, block{"role": "user", "content": results})
	}
	fmt.Fprintln(os.Stderr, "retriever-agent: the model never stopped asking for tools")
	os.Exit(1)
}

// call makes one Messages API turn and returns the reply's content blocks.
func call(base string, messages []any) ([]block, error) {
	body, err := json.Marshal(block{"model": "claude-test-1", "max_tokens": 512, "messages": messages})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, base+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("x-api-key", "stub")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, raw)
	}
	var msg struct {
		Content []block `json:"content"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	return msg.Content, nil
}

// runTool runs one tool in this process and returns its result and whether it failed.
func runTool(name string) (string, bool) {
	switch name {
	case "db_query":
		line, err := exchange(os.Getenv("DB_ADDR"), "select * from orders where status = 'failed'\n")
		if err != nil {
			return err.Error(), true
		}
		if err := os.WriteFile(filepath.Join(os.Getenv("OUT"), "summary.md"), []byte("# Failed orders\n"+line), 0o644); err != nil {
			return err.Error(), true
		}
		return line, false
	case "publish_summary":
		if _, err := exchange(os.Getenv("QUEUE_ADDR"), "publish summary.md\n"); err != nil {
			return err.Error(), true
		}
		if err := os.WriteFile(os.Getenv("NETRC"), []byte("machine queue.internal login retriever\n"), 0o600); err != nil {
			fmt.Println("netrc refused")
			return err.Error(), true
		}
		return "published with credentials", false
	}
	return "unknown tool " + name, true
}

// exchange writes one line to addr and reads one back.
func exchange(addr, line string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, line); err != nil {
		return "", err
	}
	return bufio.NewReader(c).ReadString('\n')
}
