diag [![PkgGoDev](https://pkg.go.dev/badge/github.com/florianl/go-diag)](https://pkg.go.dev/github.com/florianl/go-diag) [![Go](https://github.com/florianl/go-diag/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/florianl/go-diag/actions/workflows/go.yml)
==
This is a work in progress version of `diag`.  It provides a [C](https://en.wikipedia.org/wiki/C_(programming_language))-binding free API to the [netlink](http://man7.org/linux/man-pages/man7/netlink.7.html) based [socket statistics system](https://man7.org/linux/man-pages/man8/ss.8.html).

## Example

```golang
package main

import (
	"fmt"
	"os"

	"github.com/florianl/go-diag"
)

func main() {
	// open a netlink socket
	nl, err := diag.Open(&diag.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open netlink socket: %v\n", err)
		return
	}
	defer nl.Close()

	// Dump all TCP sockets
	tcpSockets, err := nl.TCP().Dump()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not dump data: %v\n", err)
		return
	}

    // Loop over tcpSockets and print out source- and destination IP with
    // the respective port information.
	for _, socket := range tcpSockets {
		src := diag.ToNetipAddr(socket.ID.Src)
		srcPort := diag.Ntohs(socket.ID.SPort)
		dst := diag.ToNetipAddr(socket.ID.Dst)
		dstPort := diag.Ntohs(socket.ID.DPort)
		fmt.Printf("%v:%d -> %v:%d\n", src, srcPort, dst, dstPort)
	}
}
```

## Requirements

* A version of Go that is [supported by upstream](https://golang.org/doc/devel/release.html#policy)
