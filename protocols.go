package diag

import (
	"github.com/florianl/go-diag/internal/unix"
)

// TcpInfo based on tcp_info in include/uapi/linux/tcp.h
type TcpInfo struct {
	State       uint8
	CaState     uint8
	Retransmits uint8
	Probes      uint8
	Backoff     uint8
	Options     uint8
	Wscale      uint8 // snd: 4, rcv : 4;
	ClientInfo  uint8 // DeliveryRateAppLimited:1, FastopenClientFail:2;

	Rto    uint32
	Ato    uint32
	SndMss uint32
	RcvMss uint32

	Unacked uint32
	Sacked  uint32
	Lost    uint32
	Retrans uint32
	Fackets uint32

	LastDataSent uint32
	LastAckSent  uint32
	LastDataRecv uint32
	LastAckRecv  uint32

	Pmtu        uint32
	RcvSsthresh uint32
	Rtt         uint32
	Rttvar      uint32
	SndSsthresh uint32
	SndCwnd     uint32
	Advmss      uint32
	Reordering  uint32

	RcvRtt   uint32
	RcvSpace uint32

	RotalRetrans uint32

	PacingRate    uint64
	MaxPacingRate uint64
	BytesAcked    uint64
	BytesReceived uint64
	SegsOut       uint32
	SegsIn        uint32

	NotsentBytes uint32
	MinRtt       uint32
	DataSegsIn   uint32
	DataSegsOut  uint32

	DeliveryRate uint64

	BusyTime      uint64
	RwndLimited   uint64
	SndbufLimited uint64

	Delivered   uint32
	DeliveredCe uint32

	BytesSent    uint64
	BytesRetrans uint64
	DsackDups    uint32
	ReordSeen    uint32

	RcvOoopack uint32

	SndWnd uint32
	RcvWnd uint32

	Rehash uint32

	TotalRto           uint16
	TotalRtoRecoveries uint16
	TotalRtoTime       uint32
}

// Based on __kernel_sockaddr_storage in include/uapi/linux/socket.h
type KernelSockaddrStorage struct {
	Family uint16
	Data   [126]byte
}

type SctpInfo struct {
	Tag                uint32
	State              uint32
	Rwnd               uint32
	Unackdata          uint16
	Penddata           uint16
	Instrms            uint16
	Outstrms           uint16
	FragmentationPoint uint32
	Inqueue            uint32
	Outqueue           uint32
	OverallError       uint32
	MaxBurst           uint32
	Maxseg             uint32
	PeerRwnd           uint32
	PeerTag            uint32
	PeerCapable        uint8
	PeerSack           uint8
	Reserved1          uint16

	Isacks       uint64
	Osacks       uint64
	Opackets     uint64
	Ipackets     uint64
	Rtxchunks    uint64
	Outofseqtsns uint64
	Idupchunks   uint64
	Gapcnt       uint64
	Ouodchunks   uint64
	Iuodchunks   uint64
	Oodchunks    uint64
	Iodchunks    uint64
	Octrlchunks  uint64
	Ictrlchunks  uint64

	SockaddrStorage      KernelSockaddrStorage
	PState               int32
	PCwnd                uint32
	PSrtt                uint32
	PRto                 uint32
	PHbinterval          uint32
	PPathmaxrxt          uint32
	PSackdelay           uint32
	PSackfreq            uint32
	PSsthresh            uint32
	PPartial_bytes_acked uint32
	PFlight_size         uint32
	PError               uint16
	Reserved2            uint16

	SAutoclose        uint32
	SAdaptation_ind   uint32
	SPdPoint          uint32
	SNodelay          uint8
	SDisableFragments uint8
	Sv4mapped         uint8
	SFragInterleave   uint8
	SType             uint32
	Reserved3         uint32
}

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
