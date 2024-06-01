package diag

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/florianl/go-diag/internal/unix"
)

func stringPtr(v string) *string {
	return &v
}

func uint8Ptr(v uint8) *uint8 {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

// ToNetipAddr converts an IP in [4]uint32 representation to netip.Addr.
//
// For the special case 0.0.0.0 or :: it can return an unspecified address.
// For details, see [netip.IsUnspecified].
func ToNetipAddr(in [4]uint32) netip.Addr {
	limiter := 16 // 4 * sizeof(uint32)
	s := unsafe.Slice((*byte)(unsafe.Pointer(&in[0])), limiter)
	ip, _ := netip.AddrFromSlice(s[:limiter])
	return ip
}

// ToNetipAddrWithFamily converts an IP in [4]uint32 representation to netip.Addr
// using family as hint to interpret the IP.
func ToNetipAddrWithFamily(family uint8, in [4]uint32) (netip.Addr, error) {
	var limiter int
	switch family {
	case unix.AF_INET:
		limiter = 4
	case unix.AF_INET6:
		limiter = 16
	default:
		return netip.Addr{},
			fmt.Errorf("expected AF_INET or AF_INET6 as family, but got %d", family)
	}
	s := unsafe.Slice((*byte)(unsafe.Pointer(&in[0])), limiter)
	ip, _ := netip.AddrFromSlice(s[:limiter])
	return ip, nil
}

// Ntohs converts in from network byte order to host byte order represenation.
func Ntohs(in uint16) uint16 {
	v := uint16((in & 0xFF) << 8)
	v |= uint16((in >> 8) & 0xFF)
	return v
}
