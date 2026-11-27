//go:build !linux

package poisoner

import (
	"net"

	"go-responder/internal/core"
)

// RunMITM6 is a stub on non-Linux platforms: DHCPv6 spoofing needs raw ICMPv6
// sockets, which are only implemented for Linux.
func RunMITM6(iface *net.Interface, ip6 net.IP) {
	core.LogError("mitm6: DHCPv6/RA spoofing is only supported on Linux")
}
