package diag

import (
	"net/netip"
	"unsafe"
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
func ToNetipAddr(in [4]uint32) netip.Addr {
	s := unsafe.Slice((*byte)(unsafe.Pointer(&in[0])), 16)
	limiter := 16
	if in[1] == 0 && in[2] == 0 && in[3] == 0 {
		limiter = 4
	}
	ip, _ := netip.AddrFromSlice(s[:limiter])
	return ip
}

// Ntohs converts in from network byte order to host byte order represenation.
func Ntohs(in uint16) uint16 {
	v := uint16((in & 0xFF) << 8)
	v |= uint16((in >> 8) & 0xFF)
	return v
}
