//go:build linux && integration
// +build linux,integration

package diag

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/florianl/go-diag/internal/unix"
)

func TestDiagTCP(t *testing.T) {
	tests := map[string]struct {
		network string
		addr    netip.AddrPort
		netOpt  NetOption
	}{
		"tcp4:1234": {
			network: "tcp4",
			addr:    netip.MustParseAddrPort("127.0.0.2:1234"),
			netOpt: NetOption{
				Family:   unix.AF_INET,
				Protocol: unix.IPPROTO_TCP,
				State:    ^uint32(0),
			},
		},
		"tcp6:5432": {
			network: "tcp6",
			addr:    netip.MustParseAddrPort("[::1]:5432"),
			netOpt: NetOption{
				Family:   unix.AF_INET6,
				Protocol: unix.IPPROTO_TCP,
				State:    ^uint32(0),
			},
		},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen(test.network, test.addr.String())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				defer ln.Close()
				for {
					select {
					case <-ctx.Done():
						return
					default:
						_, err := ln.Accept()
						if err != nil {
							return
						}
					}
				}
			}()

			nl, err := Open(&Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer nl.Close()

			res, err := nl.NetDump(&test.netOpt)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range res {
				src, err := ToNetipAddrWithFamily(r.Family, r.ID.Src)
				if err != nil {
					t.Fatal(err)
				}
				srcPort := Ntohs(r.ID.SPort)
				if test.addr.Addr().Compare(src) == 0 && srcPort == test.addr.Port() {
					return
				}
			}
			t.Fatalf("Failed to identify socket information")
		})
	}
}

func TestDiagUDP(t *testing.T) {
	tests := map[string]struct {
		network string
		addr    netip.AddrPort
		netOpt  NetOption
	}{
		"udp4:1234": {
			network: "udp4",
			addr:    netip.MustParseAddrPort("127.0.0.2:1234"),
			netOpt: NetOption{
				Family:   unix.AF_INET,
				Protocol: unix.IPPROTO_UDP,
				State:    ^uint32(0),
			},
		},
		"udp6:5432": {
			network: "udp6",
			addr:    netip.MustParseAddrPort("[::1]:5432"),
			netOpt: NetOption{
				Family:   unix.AF_INET6,
				Protocol: unix.IPPROTO_UDP,
				State:    ^uint32(0),
			},
		},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			ln, err := net.ListenUDP(test.network, &net.UDPAddr{
				IP:   net.ParseIP(test.addr.Addr().String()),
				Port: int(test.addr.Port()),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			nl, err := Open(&Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer nl.Close()

			res, err := nl.NetDump(&test.netOpt)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range res {
				src, err := ToNetipAddrWithFamily(r.Family, r.ID.Src)
				if err != nil {
					t.Fatal(err)
				}
				srcPort := Ntohs(r.ID.SPort)
				if test.addr.Addr().Compare(src) == 0 && srcPort == test.addr.Port() {
					return
				}
			}
			t.Fatalf("Failed to identify socket information")
		})
	}
}
