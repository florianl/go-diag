package diag

import (
	"encoding/binary"
	"errors"
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

func extractAttributes(data []byte, info *Attribute) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	var multiError error
	for ad.Next() {
		switch adType := ad.Type(); adType {
		case inetDiagNone:
			// nothing to do here.
			continue
		case inetDiagMemInfo:
			mi := &MemInfo{}
			err := unmarshalStruct(ad.Bytes(), mi)
			multiError = errors.Join(multiError, err)
			info.MemInfo = mi
		// case inetDiagInfo:
		case inetDiagVegasInfo:
			vi := &VegasInfo{}
			err := unmarshalStruct(ad.Bytes(), vi)
			multiError = errors.Join(multiError, err)
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
			multiError = errors.Join(multiError, err)
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
			multiError = errors.Join(multiError, err)
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
			multiError = errors.Join(multiError, err)
			info.SockOpt = so
		default:
			multiError = errors.Join(multiError, fmt.Errorf("type %d not implemented", adType))
		}
	}
	return multiError
}

func (d *Diag) dump(header InetDiagReqV2) ([]Object, error) {
	var results []Object

	tcminfo, err := marshalStruct(header)
	if err != nil {
		return results, err
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

	msgs, err := d.query(req)
	if err != nil {
		return results, err
	}

	for _, msg := range msgs {
		var result Object
		sizeOfDiagMsg := binary.Size(result.DiagMsg)
		if err := unmarshalStruct(msg.Data[:sizeOfDiagMsg], &result.DiagMsg); err != nil {
			return results, err
		}
		if err := extractAttributes(msg.Data[sizeOfDiagMsg:], &result.Attribute); err != nil {
			return results, err
		}
		results = append(results, result)
	}

	return results, nil
}
