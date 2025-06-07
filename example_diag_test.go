package diag_test

import (
	"fmt"
	"os"

	"github.com/florianl/go-diag"
)

func ExampleDiag() {
	// open a netlink socket
	nl, err := diag.Open(&diag.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open netlink socket: %v\n", err)
		return
	}
	defer nl.Close()

	// Dump all TCP sockets for inet and inet6
	tcpSockets, err := nl.TCPDump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not dump TCP data: %v\n", err)
		tcpSockets = []diag.NetObject{}
	}

	// Dump all UDP sockets for inet and inet6
	udpSockets, err := nl.UDPDump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not dump UDP data: %v\n", err)
		udpSockets = []diag.NetObject{}
	}

	// Loop over TCP and UDP information for inet and inet6 sockets and print out
	// source- and destination IP with the respective port information.
	for _, socket := range append(tcpSockets, udpSockets...) {
		src := diag.ToNetipAddr(socket.ID.Src)
		srcPort := diag.Ntohs(socket.ID.SPort)
		dst := diag.ToNetipAddr(socket.ID.Dst)
		dstPort := diag.Ntohs(socket.ID.DPort)
		fmt.Printf("%v:%d -> %v:%d\n", src, srcPort, dst, dstPort)
	}
}
