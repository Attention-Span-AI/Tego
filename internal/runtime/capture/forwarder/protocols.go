// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net/http"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Native HTTP/2 handles framing and flow control before each stream reaches the
// same authenticated handler and request policy as HTTP/1.1. Prior knowledge is
// explicit; HTTP/1.1 upgrade does not implicitly enable another protocol.
func configureDownstreamProtocols(s *http.Server, p *agent.CompiledProxyPolicy) {
	if !p.HTTP2Enabled() {
		return
	}
	s.Protocols = new(http.Protocols)
	s.Protocols.SetHTTP1(true)
	s.Protocols.SetUnencryptedHTTP2(true)
	s.HTTP2 = &http.HTTP2Config{
		MaxConcurrentStreams:          int(p.Bounds().MaxStreams),
		MaxDecoderHeaderTableSize:     4096,
		MaxEncoderHeaderTableSize:     4096,
		MaxReadFrameSize:              16 << 10,
		MaxReceiveBufferPerConnection: 256 << 10,
		MaxReceiveBufferPerStream:     64 << 10,
		SendPingTimeout:               30 * time.Second,
		PingTimeout:                   10 * time.Second,
		WriteByteTimeout:              5 * time.Second,
	}
}
