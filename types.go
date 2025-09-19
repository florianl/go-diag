package diag

import (
	"bytes"
	"encoding/binary"

	"github.com/josharian/native"
)

// Config contains options for NETLINK_SOCK_DIAG
type Config struct {
	// NetNS defines the network namespace
	NetNS int

	// SkipOptional allows to skip decoding of
	// optional values likes NetAttribute and
	// UnixAttribute.
	SkipOptional bool
}

const (
	inetDiagNone = iota
	inetDiagMemInfo
	inetDiagInfo
	inetDiagVegasInfo
	inetDiagCong
	inetDiagTOS
	inetDiagTClass
	inetDiagSKMemInfo
	inetDiagShutdown
	inetDiagDCTCPInfo
	inetDiagProtocol
	inetDiagSKV6Only
	inetDiagLocals
	inetDiagPeers
	inetDiagPad
	inetDiagMark
	inetDiagBBRInfo
	inetDiagClassID
	inetDiagMD5Sig
	inetDiagULPInfo
	inetDiagSKBpfStorages
	inetDiagCGroupID
	inetDiagSockOpt
)

var nativeEndian = native.Endian

// Based on inet_diag_req_v2
type InetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       SockID
}

// Based on unix_diag_req
type UnixDiagReq struct {
	Family   uint8
	Protocol uint8
	Pad      uint16
	States   uint32
	Ino      uint32
	Show     uint32
	Cookie   [2]uint32
}

// Based on inet_diag_sockid
type SockID struct {
	SPort  uint16    // in network byte order, use Ntohs() for host byte order
	DPort  uint16    // in network byte order, use Ntohs() for host byte order
	Src    [4]uint32 // use ToNetipAddr() for netip.Addr representation
	Dst    [4]uint32 // use ToNetipAddr() for netip.Addr representation
	If     uint32
	Cookie [2]uint32
}

func marshalStruct(s interface{}) ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, nativeEndian, s)
	return buf.Bytes(), err
}

func unmarshalStruct(data []byte, s interface{}) error {
	b := bytes.NewReader(data)
	return binary.Read(b, nativeEndian, s)
}

// Based on inet_diag_msg
type DiagMsg struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	ID      SockID
	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	INode   uint32
}

// Based on unix_diag_msg
type UnixDiagMsg struct {
	Family uint8
	Type   uint8
	State  uint8
	Pad    uint8
	Ino    uint32
	Cookie [2]uint32
}

// Based on unix_diag_vfs
type UnixDiagVfs struct {
	Ino uint32
	Dev uint32
}

// Based on unix_diag_rqlen
type UnixDiagRqLen struct {
	RQueue uint32
	WQueue uint32
}

// NetObject represents a network response
type NetObject struct {
	DiagMsg
	NetAttribute
}

type UnixObject struct {
	UnixDiagMsg
	UnixAttribute
}

// NetAttribute contains various elements
type NetAttribute struct {
	MemInfo   *MemInfo
	VegasInfo *VegasInfo
	Cong      *string
	TOS       *uint8
	TClass    *uint8
	Shutdown  *uint8
	SkMemInfo *SkMemInfo
	DCTCPInfo *DCTCPInfo
	Protocol  *uint8
	SKV6Only  *uint8
	Mark      *uint32
	BBRInfo   *BBRInfo
	ClassID   *uint32
	CGroupID  *uint64
	SockOpt   *SockOpt
	TcpInfo   *TcpInfo
	SctpInfo  *SctpInfo
}

// UnixAttribute contains various elements
type UnixAttribute struct {
	Name     *string
	Vfs      *UnixDiagVfs
	RQLen    *UnixDiagRqLen
	MemInfo  *MemInfo
	Shutdown *uint8
	UID      *uint32
	Peer     *uint32
	Icons    []uint32
}

// Based on inet_diag_sockopt
// Bitfield1 and Bitfield2 are the Go representations for the
// following bit fields:
//
//	__u8  recverr:1,
//	      is_icsk:1,
//	      freebind:1,
//	      hdrincl:1,
//	      mc_loop:1,
//	      transparent:1,
//	      mc_all:1,
//	      nodefrag:1;
//	__u8  bind_address_no_port:1,
//	      recverr_rfc4884:1,
//	      defer_connect:1,
//	      unused:5;
type SockOpt struct {
	Bitfield1 uint8
	Bitfield2 uint8
}

// Based on inet_diag_meminfo
type MemInfo struct {
	RMem uint32
	WMem uint32
	FMem uint32
	TMem uint32
}

// Based on sock_diag(7)
type SkMemInfo struct {
	// The amount of data in receive queue.
	RMemAlloc uint32
	// The receive socket buffer as set by SO_RCVBUF.
	RcvBuff uint32
	// The amount of data in send queue.
	WMemAlloc uint32
	// The send socket buffer as set by SO_SNDBUF.
	SndBuff uint32
	// The amount of memory scheduled for future use (TCP only).
	FwdAlloc uint32
	// The amount of data queued by TCP, but not yet sent.
	WMemQueued uint32
	// The amount of memory allocated for the socket's service needs (e.g., socket filter).
	OptMem uint32
	// The amount of packets in the backlog (not yet processed).
	Backlog uint32
	// Check https://manpages.debian.org/stretch/manpages/sock_diag.7.en.html
	Drops uint32
}

// Based on tcp_bbr_info
type BBRInfo struct {
	BwLo       uint32
	BwHi       uint32
	MinRTT     uint32
	PacingGain uint32
	CwndGaing  uint32
}

// Based on tcpvegas_info
type VegasInfo struct {
	Enabled uint32
	RttCnt  uint32
	Rtt     uint32
	MinRtt  uint32
}

// Based on tcp_dctcp_info
type DCTCPInfo struct {
	Enabeld uint16
	CeState uint16
	Alpha   uint32
	AbECN   uint32
	AbTot   uint32
}
