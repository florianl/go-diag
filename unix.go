package diag

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/florianl/go-diag/internal/unix"
	"github.com/mdlayher/netlink"
)

const (
	unixDiagName = iota
	unixDiagVFS
	unixDiagPeer
	unixDiagIcons
	unixDiagRQLen
	unixDiagMemInfo
	unixDiagShutdown
	unixDiagUID
)

func extractUnixAttributes(data []byte, info *UnixAttribute) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}
	var multiError error
	for ad.Next() {
		switch adType := ad.Type(); adType {
		case unixDiagName:
			info.Name = stringPtr(ad.String())
		case unixDiagVFS:
			vfs := &UnixDiagVfs{}
			err := unmarshalStruct(ad.Bytes(), vfs)
			multiError = errors.Join(multiError, err)
			info.Vfs = vfs
		case unixDiagPeer:
			info.Peer = uint32Ptr(ad.Uint32())
		case unixDiagIcons:
			tmp := ad.Bytes()
			numIcons := len(tmp) / 4
			for i := 0; i < numIcons; i++ {
				fmt.Printf("icon: %d\t%d\n", i, binary.LittleEndian.Uint32(tmp[i*4:(i+1)*4]))
			}
		case unixDiagRQLen:
			rqlen := &UnixDiagRqLen{}
			err := unmarshalStruct(ad.Bytes(), rqlen)
			multiError = errors.Join(multiError, err)
			info.RQLen = rqlen
		case unixDiagMemInfo:
			mi := &MemInfo{}
			err := unmarshalStruct(ad.Bytes(), mi)
			multiError = errors.Join(multiError, err)
			info.MemInfo = mi
		case unixDiagShutdown:
			info.Shutdown = uint8Ptr(ad.Uint8())
		case unixDiagUID:
			info.UID = uint32Ptr(ad.Uint32())
		default:
			multiError = errors.Join(multiError, fmt.Errorf("unix type %d not implemented", adType))
		}
	}
	return errors.Join(multiError, ad.Err())
}

// UnixOption defines a query to Unix sockets.
type UnixOption struct {
	State uint32
	Show  uint32
}

// UnixDump returns Unix socket information.
func (d *Diag) UnixDump(opt *UnixOption) ([]UnixObject, error) {
	var results []UnixObject

	header := UnixDiagReq{
		Family:   unix.AF_UNIX,
		Protocol: 0,
		States:   opt.State,
		Show:     opt.Show,
	}
	respMsgs, err := d.dumpQuery(header)
	if err != nil {
		return nil, err
	}
	objs, err := handleUnixResponse(respMsgs)
	if err != nil {
		return nil, err
	}
	results = append(results, objs...)

	return results, nil
}
