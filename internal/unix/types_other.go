//go:build !linux
// +build !linux

package unix

const (
	AF_UNIX  = 1
	AF_INET  = 2
	AF_INET6 = 10

	IPPROTO_TCP  = 6
	IPPROTO_UDP  = 17
	IPPROTO_SCTP = 132
	IPPROTO_RAW  = 255

	NETLINK_SOCK_DIAG   = 4
	SOCK_DIAG_BY_FAMILY = 20
)
