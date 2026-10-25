// SPDX-License-Identifier: Apache-2.0

// Package edgelint is scripts/check-edgelint_test.sh's golangci-lint fixture for the edge's socket ban (ADR 0100
// (1d), .golangci.yml's "the edge opens no socket"): every way to dial, listen, resolve a name or make a socket that
// the rule names, once each, on a line marked "want the edge opens no socket", and the ways the edge serves and uses
// what it is handed, unmarked. The types whose only use is to dial, listen or resolve are refused by name as well, so
// a value of one cannot be made, embedded or put behind an interface. It sits under internal/control/web so the
// rule's path scope reaches it, and under testdata so `./...` never builds, vets or lints it; no binary links it.
package edgelint

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"os"
	"syscall"

	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
)

// Dials, by function and by method.
func dials(ctx context.Context) {
	_, _ = net.Dial("tcp", "x:1")                                    // want the edge opens no socket
	_, _ = net.DialTimeout("tcp", "x:1", 0)                          // want the edge opens no socket
	_, _ = net.DialTCP("tcp", nil, nil)                              // want the edge opens no socket
	_, _ = net.DialUDP("udp", nil, nil)                              // want the edge opens no socket
	_, _ = net.DialUnix("unix", nil, nil)                            // want the edge opens no socket
	_, _ = net.DialIP("ip4:1", nil, nil)                             // want the edge opens no socket
	var d net.Dialer                                                 // want the edge opens no socket
	_, _ = d.Dial("tcp", "x:1")                                      // want the edge opens no socket
	_, _ = d.DialContext(ctx, "tcp", "x:1")                          // want the edge opens no socket
	_, _ = d.DialTCP(ctx, "tcp", netip.AddrPort{}, netip.AddrPort{}) // want the edge opens no socket
	_, _ = d.DialUDP(ctx, "udp", netip.AddrPort{}, netip.AddrPort{}) // want the edge opens no socket
	_, _ = d.DialIP(ctx, "ip4:1", netip.Addr{}, netip.Addr{})        // want the edge opens no socket
	_, _ = d.DialUnix(ctx, "unix", nil, nil)                         // want the edge opens no socket
	_, _ = tls.Dial("tcp", "x:1", nil)                               // want the edge opens no socket
	_, _ = tls.DialWithDialer(&d, "tcp", "x:1", nil)                 // want the edge opens no socket
	var td tls.Dialer                                                // want the edge opens no socket
	_, _ = td.Dial("tcp", "x:1")                                     // want the edge opens no socket
	_, _ = td.DialContext(ctx, "tcp", "x:1")                         // want the edge opens no socket
	dial := net.Dial                                                 // want the edge opens no socket
	_ = dial
	_, _ = textproto.Dial("tcp", "x:1") // want the edge opens no socket
}

// Listens.
func listens(ctx context.Context) {
	_, _ = net.Listen("tcp", ":0")                  // want the edge opens no socket
	_, _ = net.ListenTCP("tcp", nil)                // want the edge opens no socket
	_, _ = net.ListenUDP("udp", nil)                // want the edge opens no socket
	_, _ = net.ListenUnix("unix", nil)              // want the edge opens no socket
	_, _ = net.ListenUnixgram("unixgram", nil)      // want the edge opens no socket
	_, _ = net.ListenIP("ip4:1", nil)               // want the edge opens no socket
	_, _ = net.ListenPacket("udp", ":0")            // want the edge opens no socket
	_, _ = net.ListenMulticastUDP("udp", nil, nil)  // want the edge opens no socket
	var lc net.ListenConfig                         // want the edge opens no socket
	_, _ = lc.Listen(ctx, "tcp", ":0")              // want the edge opens no socket
	_, _ = lc.ListenPacket(ctx, "udp", ":0")        // want the edge opens no socket
	_, _ = tls.Listen("tcp", ":0", nil)             // want the edge opens no socket
	_ = http.ListenAndServe(":0", nil)              // want the edge opens no socket
	_ = http.ListenAndServeTLS(":0", "c", "k", nil) // want the edge opens no socket
	srv := &http.Server{}                           // a value
	_ = srv.ListenAndServe()                        // want the edge opens no socket
	_ = srv.ListenAndServeTLS("c", "k")             // want the edge opens no socket
}

// Name lookups, each of which can open a DNS socket.
func resolves(ctx context.Context) {
	_, _ = net.LookupHost("x")              // want the edge opens no socket
	_, _ = net.LookupIP("x")                // want the edge opens no socket
	_, _ = net.LookupAddr("192.0.2.1")      // want the edge opens no socket
	_, _ = net.LookupCNAME("x")             // want the edge opens no socket
	_, _, _ = net.LookupSRV("", "", "x")    // want the edge opens no socket
	_, _ = net.LookupMX("x")                // want the edge opens no socket
	_, _ = net.LookupNS("x")                // want the edge opens no socket
	_, _ = net.LookupTXT("x")               // want the edge opens no socket
	_, _ = net.LookupPort("tcp", "http")    // want the edge opens no socket
	_, _ = net.ResolveTCPAddr("tcp", "x:1") // want the edge opens no socket
	_, _ = net.ResolveUDPAddr("udp", "x:1") // want the edge opens no socket
	_, _ = net.ResolveIPAddr("ip", "x")     // want the edge opens no socket
	r := net.DefaultResolver                // want the edge opens no socket
	_ = r
	var res net.Resolver                   // want the edge opens no socket
	_, _ = res.LookupHost(ctx, "x")        // want the edge opens no socket
	_, _ = res.LookupIPAddr(ctx, "x")      // want the edge opens no socket
	_, _ = res.LookupNetIP(ctx, "ip", "x") // want the edge opens no socket
}

// HTTP clients: the package's helpers, a Client (which dials through DefaultTransport when it names none), and the
// Transports that dial.
func clients(req *http.Request) {
	_, _ = http.Get("http://x")                       // want the edge opens no socket
	_, _ = http.Head("http://x")                      // want the edge opens no socket
	_, _ = http.Post("http://x", "", nil)             // want the edge opens no socket
	_, _ = http.PostForm("http://x", nil)             // want the edge opens no socket
	_ = http.DefaultClient                            // want the edge opens no socket
	_ = http.DefaultTransport                         // want the edge opens no socket
	c := &http.Client{}                               // want the edge opens no socket
	_, _ = c.Do(req)                                  // want the edge opens no socket
	_, _ = c.Get("http://x")                          // want the edge opens no socket
	_, _ = c.Head("http://x")                         // want the edge opens no socket
	_, _ = c.Post("http://x", "", nil)                // want the edge opens no socket
	_, _ = c.PostForm("http://x", nil)                // want the edge opens no socket
	t := &http.Transport{}                            // want the edge opens no socket
	_, _ = t.RoundTrip(req)                           // want the edge opens no socket
	t2 := &http2.Transport{}                          // a value
	_, _ = t2.RoundTrip(req)                          // want the edge opens no socket
	_, _ = t2.RoundTripOpt(req, http2.RoundTripOpt{}) // want the edge opens no socket
}

// Promoted methods and calls through a named interface type: the rule reads the method's name whatever the receiver,
// so embedding a type the edge may hold (http.Server, http2.Transport) or naming an interface does not pass. A type
// the edge may not hold is refused where it is embedded.
type (
	embedServer struct{ http.Server }
	embedH2     struct{ http2.Transport }
	embedDialer struct{ net.Dialer }  // want the edge opens no socket
	embedClient struct{ http.Client } // want the edge opens no socket
	dialerIface interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
	listenIface interface{ ListenAndServe() error }
	lookupIface interface {
		LookupHost(ctx context.Context, host string) ([]string, error)
	}
)

func promoted(ctx context.Context, req *http.Request, di dialerIface, li listenIface, lk lookupIface) {
	var es embedServer
	_ = es.ListenAndServe()            // want the edge opens no socket
	_ = es.ListenAndServeTLS("c", "k") // want the edge opens no socket
	var eh embedH2
	_, _ = eh.RoundTripOpt(req, http2.RoundTripOpt{}) // want the edge opens no socket
	eh.DialTLSContext = nil                           // want the edge opens no socket
	var ed embedDialer
	_, _ = ed.DialContext(ctx, "tcp", "x:1") // want the edge opens no socket
	_, _ = di.DialContext(ctx, "tcp", "x:1") // want the edge opens no socket
	_ = li.ListenAndServe()                  // want the edge opens no socket
	_, _ = lk.LookupHost(ctx, "x")           // want the edge opens no socket
	var ec embedClient                       // its embedding is the refusal
	_ = ec
}

// Raw sockets, by wrapper and by syscall number, and the interface listings, each of which opens a netlink socket.
// io_uring, whose socket and connect operations need none of the socket syscalls, is refused in every package by
// ADR 0023's rule, so it is not repeated here.
func sockets(fd int) {
	_, _ = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)              // want the edge opens no socket
	_, _ = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)     // want the edge opens no socket
	_, _ = unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)          // want the edge opens no socket
	_, _ = syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0) // want the edge opens no socket
	_ = unix.Connect(fd, &unix.SockaddrInet4{})                        // want the edge opens no socket
	_ = syscall.Connect(fd, &syscall.SockaddrInet4{})                  // want the edge opens no socket
	_ = unix.Bind(fd, &unix.SockaddrInet4{})                           // want the edge opens no socket
	_ = syscall.Bind(fd, &syscall.SockaddrInet4{})                     // want the edge opens no socket
	_ = unix.Listen(fd, 1)                                             // want the edge opens no socket
	_ = syscall.Listen(fd, 1)                                          // want the edge opens no socket
	_, _, _ = unix.Syscall(unix.SYS_SOCKET, 0, 0, 0)                   // want the edge opens no socket
	_, _, _ = syscall.Syscall(syscall.SYS_SOCKET, 0, 0, 0)             // want the edge opens no socket
	_, _, _ = unix.RawSyscall6(unix.SYS_SOCKETPAIR, 0, 0, 0, 0, 0, 0)  // want the edge opens no socket
	_, _, _ = unix.Syscall(unix.SYS_CONNECT, 0, 0, 0)                  // want the edge opens no socket
	_, _, _ = unix.Syscall(unix.SYS_BIND, 0, 0, 0)                     // want the edge opens no socket
	_, _, _ = unix.Syscall(unix.SYS_LISTEN, 0, 0, 0)                   // want the edge opens no socket
	_, _ = net.Interfaces()                                            // want the edge opens no socket
	_, _ = net.InterfaceAddrs()                                        // want the edge opens no socket
	ifi, _ := net.InterfaceByIndex(1)                                  // want the edge opens no socket
	_, _ = net.InterfaceByName("lo")                                   // want the edge opens no socket
	_, _ = ifi.Addrs()                                                 // want the edge opens no socket
	_, _ = ifi.MulticastAddrs()                                        // want the edge opens no socket
	_, _ = syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)  // want the edge opens no socket
}

// What the edge does, which the rule leaves alone: it wraps the descriptors controld hands it, serves them over
// HTTP/1 and HTTP/2 and TLS, and sends its requests over the link's HTTP/2 connection.
func serves(f *os.File, l net.Listener, conn net.Conn, req *http.Request, fd int) {
	_, _ = net.FileListener(f)
	_, _ = net.FileConn(f)
	_, _ = net.FilePacketConn(f)
	srv := &http.Server{}
	_ = srv.Serve(l)
	_ = srv.ServeTLS(l, "c", "k")
	_ = http.Serve(l, nil)
	_ = http.ServeTLS(l, nil, "c", "k")
	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{})
	cc, _ := (&http2.Transport{}).NewClientConn(conn)
	_, _ = cc.RoundTrip(req)
	var rt http.RoundTripper = cc
	_, _ = rt.RoundTrip(req)
	_ = tls.Server(conn, &tls.Config{})
	_ = tls.NewListener(l, &tls.Config{})
	_, _ = net.ResolveUnixAddr("unix", "/x")
	_, _, _ = unix.Accept4(fd, unix.SOCK_CLOEXEC)
}
