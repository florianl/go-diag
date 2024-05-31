package diag

import (
	"github.com/florianl/go-diag/internal/unix"
)

// NetOption defines a query to network sockets.
type NetOption struct {
	Family   uint8
	Protocol uint8
	State    uint32
}

// NetDump returns network socket information.
func (d *Diag) NetDump(opt *NetOption) ([]NetObject, error) {
	header := InetDiagReqV2{
		Family:   opt.Family,
		Protocol: opt.Protocol,
		States:   opt.State,
	}

	respMsgs, err := d.dumpQuery(header)
	if err != nil {
		return nil, err
	}
	return handleNetResponse(respMsgs)
}

// Dump returns all TCP connections.
// It is a wrapper around (*Diag).NetDump(..) for IPPROTO_TCP and
// the families AF_INET and AF_INET6 for all TCP states.
func (d *Diag) TCPDump() ([]NetObject, error) {
	var results []NetObject
	opt := &NetOption{
		Protocol: unix.IPPROTO_TCP,
		State:    0xFFFFFFFF,
	}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		opt.Family = family
		objs, err := d.NetDump(opt)
		if err != nil {
			return nil, err
		}
		results = append(results, objs...)
	}

	return results, nil
}

// Dump returns all TCP connections.
// It is a wrapper around (*Diag).NetDump(..) for IPPROTO_UDP and
// the families AF_INET and AF_INET6 for all UDP states.
func (d *Diag) UDPDump() ([]NetObject, error) {
	var results []NetObject
	opt := &NetOption{
		Protocol: unix.IPPROTO_UDP,
		State:    0xFFFFFFFF,
	}
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		opt.Family = family
		objs, err := d.NetDump(opt)
		if err != nil {
			return nil, err
		}
		results = append(results, objs...)
	}

	return results, nil
}
