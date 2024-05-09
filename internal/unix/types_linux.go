//go:build linux
// +build linux

package unix

import linux "golang.org/x/sys/unix"

const (
	AF_INET  = linux.AF_INET
	AF_INET6 = linux.AF_INET6

	IPPROTO_TCP = linux.IPPROTO_TCP
	IPPROTO_UDP = linux.IPPROTO_UDP
	IPPROTO_RAW = linux.IPPROTO_RAW

	NETLINK_SOCK_DIAG = linux.NETLINK_SOCK_DIAG

	SOCK_DIAG_BY_FAMILY = linux.SOCK_DIAG_BY_FAMILY
)
