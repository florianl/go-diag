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

// Based on inet_diag_sockid
type SockID struct {
	SPort  uint16 // network byte order
	DPort  uint16 // network byte order
	Src    [4]uint32
	Dst    [4]uint32
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
	Famiy   uint8
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

// Object represents a generic object
type Object struct {
	DiagMsg
	Attribute
}

// Attribute contains various elements
type Attribute struct {
	MemInfo   *MemInfo
	VegasInfo *VegasInfo
	Cong      *string
	TOS       *uint8
	TClass    *uint8
	Shutdown  *uint8
	DCTCPInfo *DCTCPInfo
	Protocol  *uint8
	SKV6Only  *uint8
	Mark      *uint32
	BBRInfo   *BBRInfo
	ClassID   *uint32
	CGroupID  *uint64
	SockOpt   *SockOpt
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
