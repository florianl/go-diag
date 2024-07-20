module github.com/florianl/go-diag

go 1.18

require (
	github.com/josharian/native v1.1.0
	github.com/mdlayher/netlink v1.7.2
	golang.org/x/sys v0.20.1-0.20240506173926-6dfb94eaa3bd
)

require (
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
)

replace github.com/mdlayher/netlink => github.com/florianl/netlink v1.6.1-0.20240625172019-9b038ba321a8
