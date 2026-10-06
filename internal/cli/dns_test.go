// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"github.com/attention-span-ai/tego/pkg/policy/dnspolicy"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSCLIActualAuthenticatedBroker(t *testing.T) {
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw := make([]byte, dnsbroker.MaxPacket)
			n, from, e := up.ReadFromUDP(raw)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(raw[:n]) != nil {
				continue
			}
			m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 9}}}}}
			reply, _ := m.Pack()
			_, _ = up.WriteToUDP(reply, from)
		}
	}()
	t.Cleanup(func() { up.Close(); wg.Wait() })
	p, _ := dnspolicy.Compile([]string{"allowed.example"}, nil)
	dir := t.TempDir()
	b, err := dnsbroker.New(dir, dnsbroker.Options{UID: uint32(os.Geteuid()), Policy: p, Upstreams: []netip.AddrPort{up.LocalAddr().(*net.UDPAddr).AddrPort()}, Timeout: time.Second, Authorize: func(peer dnsbroker.Peer) error {
		if peer.PID != os.Getpid() {
			return dnsbroker.ErrUnauthorized
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, tc := range []struct {
		name string
		code int
	}{{"allowed.example", 0}, {"forbidden.example", 1}} {
		var out, errs bytes.Buffer
		code := mainWith(context.Background(), []string{"tego", "dns", tc.name, "--run-dir", dir, "--server-pid", strconv.Itoa(os.Getpid()), "--json"}, &out, &errs, []Command{cmdDNS()})
		if code != tc.code {
			t.Fatalf("actual CLI %s exit%d: %s", tc.name, code, errs.String())
		}
		var got struct {
			RCode   string            `json:"rcode"`
			Answers []json.RawMessage `json:"answers"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if tc.code == 0 && len(got.Answers) != 1 || tc.code != 0 && got.RCode != "RCodeRefused" {
			t.Fatalf("wrong CLI result %+v", got)
		}
	}
}

func TestDNSCLIRejectsMissingBrokerAndAmbiguousQuestion(t *testing.T) {
	t.Setenv("TEGO_DNS_BROKER_DIR", "")
	t.Setenv("TEGO_DNS_BROKER_PID", "")
	for _, args := range [][]string{{"dns"}, {"dns", "allowed.example"}, {"dns", "a..b", "--run-dir", "/absent", "--server-pid", "1"}, {"dns", "allowed.example", "--type", "INVALID", "--run-dir", "/absent", "--server-pid", "1"}} {
		var out, errs bytes.Buffer
		if code := mainWith(context.Background(), append([]string{"tego"}, args...), &out, &errs, []Command{cmdDNS()}); code != identity.ExitUsage {
			t.Fatalf("args%v exit%d: %s", args, code, errs.String())
		}
	}
}
