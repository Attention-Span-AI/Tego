// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func startedProtocolListener(t *testing.T, model agent.ModelEndpoint, raw *agent.ProxyPolicy, transport http.RoundTripper) (*Manager, *Listener, *fakeSink) {
	t.Helper()
	p := compiledProtocols(t, model, raw)
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Stop(); err != nil {
			t.Error(err)
		}
	})
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	run := testRun
	run.CgroupID, run.Contract = id, &agent.RuleTable{Record: agent.RecordSummary, Proxy: p}
	sink := &fakeSink{}
	if err := m.Start(context.Background(), run, sink); err != nil {
		t.Fatal(err)
	}
	return m, m.Listeners()[0], sink
}

func protocolConn(t *testing.T, listener *Listener, request string, prefetched []byte) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(listener.BaseURL(), "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(append([]byte(request), prefetched...)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, resp
}

func connectRequest(authority string) string {
	return "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
}

func TestConnectTunnelActualWirePrefetchHalfCloseAndAuthority(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := up.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		body, err := io.ReadAll(conn)
		if err == nil && string(body) != "prefetched" {
			err = fmt.Errorf("upstream body %q", body)
		}
		if err == nil {
			_, err = conn.Write([]byte("after-half-close"))
		}
		done <- err
	}()
	host, port := hostPort(t, up.Addr().String())
	m, l, sink := startedProtocolListener(t, agent.ModelEndpoint{Host: host, Port: port}, &agent.ProxyPolicy{Connect: []string{up.Addr().String()}}, nil)
	_, _, refused := protocolConn(t, l, connectRequest("unlisted.example:443"), nil)
	if refused.StatusCode != http.StatusForbidden {
		t.Fatalf("alternate authority: %d", refused.StatusCode)
	}
	conn, reader, response := protocolConn(t, l, connectRequest(up.Addr().String()), []byte("prefetched"))
	if response.StatusCode != 200 || response.Header.Get("Content-Length") != "" || response.Header.Get("Transfer-Encoding") != "" {
		t.Fatalf("CONNECT response: %#v", response)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "after-half-close" {
		t.Fatalf("half-close reply %q: %v", body, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.of(record.KindNet)); got != 2 {
		t.Fatalf("policy decisions=%d", got)
	}
}

func TestConnectTunnelActualByteLimitIdleAndStop(t *testing.T) {
	for _, mode := range []string{"bytes", "idle", "stop"} {
		t.Run(mode, func(t *testing.T) {
			up, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer up.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, err := up.Accept()
				if err == nil {
					accepted <- c
				}
			}()
			host, port := hostPort(t, up.Addr().String())
			raw := &agent.ProxyPolicy{Connect: []string{up.Addr().String()}}
			if mode == "bytes" {
				n := agent.ByteSize(3)
				raw.MaxTunnelBytes = &n
			}
			if mode == "idle" {
				d := agent.Duration(50 * time.Millisecond)
				raw.TunnelIdle = &d
			}
			m, l, _ := startedProtocolListener(t, agent.ModelEndpoint{Host: host, Port: port}, raw, nil)
			conn, reader, response := protocolConn(t, l, connectRequest(up.Addr().String()), nil)
			if response.StatusCode != 200 {
				t.Fatalf("CONNECT: %d", response.StatusCode)
			}
			upstream := <-accepted
			defer upstream.Close()
			_ = upstream.SetDeadline(time.Now().Add(time.Second))
			if mode == "bytes" {
				if _, err := conn.Write([]byte("over")); err != nil {
					t.Fatal(err)
				}
				var b [8]byte
				if n, _ := upstream.Read(b[:]); n != 0 {
					t.Fatalf("over-budget bytes reached upstream: %q", b[:n])
				}
			}
			if mode == "stop" {
				stopped := make(chan error, 1)
				go func() { stopped <- m.Stop() }()
				select {
				case err := <-stopped:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("Stop did not join active tunnel")
				}
			}
			if _, err := reader.ReadByte(); err == nil {
				t.Fatal("tunnel stayed open")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("closure waited for client deadline")
			}
		})
	}
}

func maskedFrame(op byte, payload []byte) []byte {
	frame := []byte{0x80 | op, 0x80 | byte(len(payload)), 1, 2, 3, 4}
	for i, b := range payload {
		frame = append(frame, b^byte(i%4+1))
	}
	return frame
}

func websocketRequest(path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: forged.example\r\nConnection: Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version, Sec-WebSocket-Protocol\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
}

func TestWebSocketActualTLSWireFramesAndCloseHandshake(t *testing.T) {
	done := make(chan error, 1)
	clientFrame := maskedFrame(1, []byte("hello"))
	serverFrame := []byte{0x81, 5, 'w', 'o', 'r', 'l', 'd'}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat" || r.Header.Get("Sec-WebSocket-Version") != "13" || r.Header.Get("Sec-WebSocket-Protocol") != "chat" || r.Header.Get("Sec-WebSocket-Key") == "" {
			done <- fmt.Errorf("upstream handshake fields missing: %v", r.Header)
			http.Error(w, "bad", 400)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, Sec-WebSocket-Accept\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: chat\r\n\r\n", websocketAccept(r.Header.Get("Sec-WebSocket-Key")))
		if err == nil {
			err = rw.Flush()
		}
		buf := make([]byte, len(clientFrame))
		if err == nil {
			_, err = io.ReadFull(rw, buf)
		}
		if err == nil && !bytes.Equal(buf, clientFrame) {
			err = fmt.Errorf("frame altered: %x", buf)
		}
		if err == nil {
			_, err = conn.Write(serverFrame)
		}
		close := maskedFrame(8, nil)
		buf = make([]byte, len(close))
		if err == nil {
			_, err = io.ReadFull(rw, buf)
		}
		if err == nil && !bytes.Equal(buf, close) {
			err = fmt.Errorf("close altered: %x", buf)
		}
		if err == nil {
			_, err = conn.Write([]byte{0x88, 0})
		}
		done <- err
	}))
	defer up.Close()
	host, port := hostPort(t, up.Listener.Addr().String())
	_, l, _ := startedProtocolListener(t, agent.ModelEndpoint{Host: host, Port: port}, &agent.ProxyPolicy{WebSocket: []agent.HTTPRule{{Host: host, Allow: []string{"/chat"}}}}, up.Client().Transport)
	_, _, denied := protocolConn(t, l, websocketRequest("/other"), nil)
	if denied.StatusCode != 403 {
		t.Fatalf("undeclared route=%d", denied.StatusCode)
	}
	conn, reader, response := protocolConn(t, l, websocketRequest("/chat"), clientFrame)
	if response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("handshake: %d %v", response.StatusCode, response.Header)
	}
	got := make([]byte, len(serverFrame))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, serverFrame) {
		t.Fatalf("server frame %x: %v", got, err)
	}
	if _, err := conn.Write(maskedFrame(8, nil)); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, 2)
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, []byte{0x88, 0}) {
		t.Fatalf("close acknowledgment %x: %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketFrameRefusalBeforeForwarding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frame  []byte
		masked bool
		max    int64
		want   error
	}{
		{"wrong-mask", []byte{0x81, 0}, true, 1024, errWebSocketFrame},
		{"reserved-bit", []byte{0xc1, 0}, false, 1024, errWebSocketFrame},
		{"unknown-op", []byte{0x83, 0}, false, 1024, errWebSocketFrame},
		{"continuation-without-start", []byte{0x80, 0}, false, 1024, errWebSocketFrame},
		{"fragmented-control", []byte{0x09, 0}, false, 1024, errWebSocketFrame},
		{"noncanonical-length", []byte{0x81, 126, 0, 1}, false, 1024, errWebSocketFrame},
		{"frame-ceiling", []byte{0x81, 3, 'a', 'b', 'c'}, false, 2, errTunnelLimit},
		{"one-byte-close", []byte{0x88, 1, 0}, false, 1024, errWebSocketFrame},
		{"reserved-close-code", []byte{0x88, 2, 3, 0xed}, false, 1024, errWebSocketFrame},
		{"invalid-close-utf8", []byte{0x88, 3, 3, 0xe8, 0xff}, false, 1024, errWebSocketFrame},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := websocketFrames(&out, bytes.NewReader(tc.frame), tc.masked, tc.max, &tunnelBudget{max: 1024})
			if !errors.Is(err, tc.want) || out.Len() != 0 {
				t.Fatalf("err=%v forwarded=%x", err, out.Bytes())
			}
		})
	}
	var out bytes.Buffer
	valid := []byte{1, 2, 'a', 'b', 0x89, 0, 0x80, 2, 'c', 'd'}
	err := websocketFrames(&out, bytes.NewReader(valid), false, 4, &tunnelBudget{max: 1024})
	if !errors.Is(err, io.EOF) || !bytes.Equal(out.Bytes(), valid) {
		t.Fatalf("fragment/control exchange: %x %v", out.Bytes(), err)
	}
	out.Reset()
	err = websocketFrames(&out, bytes.NewReader(valid), false, 3, &tunnelBudget{max: 1024})
	if !errors.Is(err, errTunnelLimit) || out.Len() != 6 {
		t.Fatalf("fragmented message ceiling: %x %v", out.Bytes(), err)
	}
}

func TestHTTP2ConnectActualDuplexStream(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	done := make(chan error, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = io.Copy(c, c)
		done <- err
	}()
	host, port := hostPort(t, up.Addr().String())
	_, l, _ := startedProtocolListener(t, agent.ModelEndpoint{Host: host, Port: port}, &agent.ProxyPolicy{HTTP2: true, Connect: []string{up.Addr().String()}}, nil)
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, _ := http.NewRequest(http.MethodConnect, l.BaseURL(), reader)
	req.Host = up.Addr().String()
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 || response.Header.Get("Content-Length") != "" {
		t.Fatalf("H2 CONNECT: %s %d %v", response.Proto, response.StatusCode, response.Header)
	}
	if _, err := writer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var got [4]byte
	if _, err := io.ReadFull(response.Body, got[:]); err != nil || string(got[:]) != "ping" {
		t.Fatalf("H2 duplex %q: %v", got, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectTunnelCapacityRefusesBeforeSecondDial(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	host, port := hostPort(t, up.Addr().String())
	m, l, _ := startedProtocolListener(t, agent.ModelEndpoint{Host: host, Port: port}, &agent.ProxyPolicy{HTTP2: true, MaxStreams: 1, Connect: []string{up.Addr().String()}}, nil)
	_, _, response := protocolConn(t, l, connectRequest(up.Addr().String()), nil)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	first, err := up.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_, _, second := protocolConn(t, l, connectRequest(up.Addr().String()), nil)
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("capacity=%d", second.StatusCode)
	}
	if err := up.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := up.Accept(); err == nil {
		unexpected.Close()
		t.Fatal("refused capacity opened an upstream connection")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestWebSocketHandshakeAmbiguityAndCaseSensitiveProtocol(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(websocketRequest("/chat"))))
	if err != nil || !validWebSocketRequest(req) {
		t.Fatalf("valid request: %v", err)
	}
	response := &http.Response{StatusCode: 101, Header: http.Header{}}
	response.Header.Set("Connection", "Upgrade")
	response.Header.Set("Upgrade", "websocket")
	response.Header.Set("Sec-WebSocket-Accept", websocketAccept(req.Header.Get("Sec-WebSocket-Key")))
	response.Header.Set("Sec-WebSocket-Protocol", "chat")
	if !validWebSocketResponse(req, response) {
		t.Fatal("valid handshake refused")
	}
	response.Header.Set("Sec-WebSocket-Protocol", "CHAT")
	if validWebSocketResponse(req, response) {
		t.Fatal("case-changed subprotocol admitted")
	}
	response.Header.Set("Sec-WebSocket-Protocol", "chat")
	response.Header.Add("Upgrade", "websocket")
	if validWebSocketResponse(req, response) {
		t.Fatal("ambiguous duplicate Upgrade admitted")
	}
	for _, tc := range []struct{ key, value string }{
		{"Sec-WebSocket-Key", "invalid"},
		{"Sec-WebSocket-Version", "12"},
		{"Sec-WebSocket-Protocol", "chat, invalid token"},
		{"Sec-WebSocket-Extensions", "permessage-deflate"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			clone := req.Clone(context.Background())
			clone.Header.Set(tc.key, tc.value)
			if validWebSocketRequest(clone) {
				t.Fatal("unsupported handshake admitted")
			}
		})
	}
}
