package diag

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/florianl/go-diag/internal/unix"
	"github.com/mdlayher/netlink"
)

// diagConn defines a subset of netlink.Conn.
type diagConn interface {
	Close() error
	Execute(netlink.Message) ([]netlink.Message, error)
	JoinGroup(group uint32) error
	LeaveGroup(group uint32) error
	Receive() ([]netlink.Message, error)
	Send(m netlink.Message) (netlink.Message, error)
	SetOption(option netlink.ConnOption, enable bool) error
	SetReadDeadline(t time.Time) error
}

var _ diagConn = &netlink.Conn{}

// Diag represents a netlink wrapper
type Diag struct {
	con diagConn
}

// Open establishes a netlink socket for traffic control
func Open(config *Config) (*Diag, error) {
	var diag Diag

	if config == nil {
		config = &Config{}
	}

	con, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, &netlink.Config{NetNS: config.NetNS})
	if err != nil {
		return nil, err
	}
	diag.con = con

	return &diag, nil
}

// SetOption allows to enable or disable netlink socket options.
func (d *Diag) SetOption(o netlink.ConnOption, enable bool) error {
	return d.con.SetOption(o, enable)
}

// Close the connection
func (d *Diag) Close() error {
	return d.con.Close()
}

func (d *Diag) query(req netlink.Message) ([]netlink.Message, error) {
	verify, err := d.con.Send(req)
	if err != nil {
		return nil, err
	}

	if err := netlink.Validate(req, []netlink.Message{verify}); err != nil {
		return nil, err
	}

	return d.con.Receive()
}

func extractAttributes(data []byte, info *NetAttribute) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	var infoData []byte
	var multiError error
	for ad.Next() {
		switch adType := ad.Type(); adType {
		case inetDiagNone:
			// nothing to do here.
			continue
		case inetDiagMemInfo:
			mi := &MemInfo{}
			err := unmarshalStruct(ad.Bytes(), mi)
			multiError = errorsJoin(multiError, err)
			info.MemInfo = mi
		case inetDiagInfo:
			infoData = ad.Bytes()
		case inetDiagVegasInfo:
			vi := &VegasInfo{}
			err := unmarshalStruct(ad.Bytes(), vi)
			multiError = errorsJoin(multiError, err)
			info.VegasInfo = vi
		case inetDiagCong:
			info.Cong = stringPtr(ad.String())
		case inetDiagTOS:
			info.TOS = uint8Ptr(ad.Uint8())
		case inetDiagTClass:
			info.TClass = uint8Ptr(ad.Uint8())
		// case inetDiagSKMemInfo:
		case inetDiagShutdown:
			info.Shutdown = uint8Ptr(ad.Uint8())
		case inetDiagDCTCPInfo:
			di := &DCTCPInfo{}
			err := unmarshalStruct(ad.Bytes(), di)
			multiError = errorsJoin(multiError, err)
			info.DCTCPInfo = di
		case inetDiagProtocol:
			info.Protocol = uint8Ptr(ad.Uint8())
		case inetDiagSKV6Only:
			info.SKV6Only = uint8Ptr(ad.Uint8())
		// case inetDiagLocals:
		// case inetDiagPeers:
		case inetDiagPad:
			// nothing to do here.
			continue
		case inetDiagMark:
			info.Mark = uint32Ptr(ad.Uint32())
		case inetDiagBBRInfo:
			bbrInfo := &BBRInfo{}
			err := unmarshalStruct(ad.Bytes(), bbrInfo)
			multiError = errorsJoin(multiError, err)
			info.BBRInfo = bbrInfo
		case inetDiagClassID:
			info.ClassID = uint32Ptr(ad.Uint32())
		// case inetDiagMD5Sig:
		// case inetDiagULPInfo:
		// case inetDiagSKBpfStorages:
		case inetDiagCGroupID:
			info.CGroupID = uint64Ptr(ad.Uint64())
		case inetDiagSockOpt:
			so := &SockOpt{}
			err := unmarshalStruct(ad.Bytes(), so)
			multiError = errorsJoin(multiError, err)
			info.SockOpt = so
		default:
			multiError = errorsJoin(multiError, fmt.Errorf("net type %d not implemented", adType))
		}
	}
	if err := errorsJoin(multiError, ad.Err()); err != nil {
		return err
	}

	if len(infoData) != 0 {
		switch uint16(*info.Protocol) {
		case unix.IPPROTO_TCP:
			tcpInfo := &TcpInfo{}
			data := make([]byte, binary.Size(tcpInfo))
			copy(data, infoData)
			err := unmarshalStruct(data, tcpInfo)
			multiError = errorsJoin(multiError, err)
			info.TcpInfo = tcpInfo
		case unix.IPPROTO_SCTP:
			sctpInfo := &SctpInfo{}
			data := make([]byte, binary.Size(sctpInfo))
			copy(data, infoData)
			err := unmarshalStruct(data, sctpInfo)
			multiError = errorsJoin(multiError, err)
			info.SctpInfo = sctpInfo
		default:
			multiError = errorsJoin(multiError, fmt.Errorf("unhandled IPPROTO (%d) for INET_DIAG_INFO",
				*info.Protocol))
		}
	}

	return multiError
}

func (d *Diag) dumpQuery(header interface{}) ([]netlink.Message, error) {
	tcminfo, err := marshalStruct(header)
	if err != nil {
		return nil, err
	}

	data := []byte{}
	data = append(data, tcminfo...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.SOCK_DIAG_BY_FAMILY),
			Flags: netlink.Request | netlink.Dump,
			PID:   0,
		},
		Data: data,
	}

	return d.query(req)
}

func handleNetResponse(msgs []netlink.Message) ([]NetObject, error) {
	var results []NetObject
	sizeOfRecvMsg := binary.Size(DiagMsg{})

	for _, msg := range msgs {
		var result NetObject
		if err := unmarshalStruct(msg.Data[:sizeOfRecvMsg], &result.DiagMsg); err != nil {
			return nil, err
		}
		if err := extractAttributes(msg.Data[sizeOfRecvMsg:], &result.NetAttribute); err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func handleUnixResponse(msgs []netlink.Message) ([]UnixObject, error) {
	var results []UnixObject
	sizeOfRecvMsg := binary.Size(UnixDiagMsg{})

	for _, msg := range msgs {
		var result UnixObject
		if err := unmarshalStruct(msg.Data[:sizeOfRecvMsg], &result.UnixDiagMsg); err != nil {
			return nil, err
		}
		if err := extractUnixAttributes(msg.Data[sizeOfRecvMsg:], &result.UnixAttribute); err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}
