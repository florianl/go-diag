package diag

import (
	"encoding/binary"
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
			multiError = errorsJoin(multiError, err)
			info.Vfs = vfs
		case unixDiagPeer:
			info.Peer = uint32Ptr(ad.Uint32())
		case unixDiagIcons:
			tmp := ad.Bytes()
			numIcons := len(tmp) / 4
			icons := make([]uint32, 0, numIcons)
			for i := 0; i < numIcons; i++ {
				icons = append(icons, binary.LittleEndian.Uint32(tmp[i*4:(i+1)*4]))
			}
			info.Icons = icons
		case unixDiagRQLen:
			rqlen := &UnixDiagRqLen{}
			err := unmarshalStruct(ad.Bytes(), rqlen)
			multiError = errorsJoin(multiError, err)
			info.RQLen = rqlen
		case unixDiagMemInfo:
			mi := &MemInfo{}
			err := unmarshalStruct(ad.Bytes(), mi)
			multiError = errorsJoin(multiError, err)
			info.MemInfo = mi
		case unixDiagShutdown:
			info.Shutdown = uint8Ptr(ad.Uint8())
		case unixDiagUID:
			info.UID = uint32Ptr(ad.Uint32())
		default:
			multiError = errorsJoin(multiError, fmt.Errorf("unix type %d not implemented", adType))
		}
	}
	return errorsJoin(multiError, ad.Err())
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
