// SPDX-License-Identifier: Apache-2.0

package agent

// IngressRule admits a peer address to one declared inet listener. Reply traffic
// is handled separately by bounded kernel flow state.
type IngressRule struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// NetworkLimits bound run-owned network resources. Nil is unbounded; a pointer
// to zero explicitly permits none of that resource.
type NetworkLimits struct {
	Connections        *uint64   `yaml:"connections,omitempty"`
	PendingConnects    *uint64   `yaml:"pending_connects,omitempty"`
	Bytes              *ByteSize `yaml:"bytes,omitempty"`
	DatagramsPerSecond *uint64   `yaml:"datagrams_per_second,omitempty"`
}

// DNSPolicy chooses the agent's DNS transport. Host-side resolution of compiled
// grants remains governed by the machine configuration.
type DNSPolicy struct {
	Mode        string    `yaml:"mode,omitempty"`
	Allow       []string  `yaml:"allow,omitempty"`
	Types       []string  `yaml:"types,omitempty"`
	MaxStale    *Duration `yaml:"max_stale,omitempty"`
	MaxParallel int       `yaml:"max_parallel,omitempty"`
	Cache       *int      `yaml:"cache,omitempty"`
}

// ProxyPolicy explicitly enables additional protocols on declared model
// listeners. Tunnels remain destination controls; their bytes are opaque.
type ProxyPolicy struct {
	HTTP2          bool       `yaml:"http2,omitempty"`
	WebSocket      []HTTPRule `yaml:"websocket,omitempty"`
	Connect        []string   `yaml:"connect,omitempty"`
	MaxStreams     uint32     `yaml:"max_streams,omitempty"`
	MaxTunnelBytes *ByteSize  `yaml:"max_tunnel_bytes,omitempty"`
	MaxFrameBytes  *ByteSize  `yaml:"max_frame_bytes,omitempty"`
	TunnelIdle     *Duration  `yaml:"tunnel_idle,omitempty"`
	TunnelWall     *Duration  `yaml:"tunnel_wall,omitempty"`
}
