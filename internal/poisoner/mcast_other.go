//go:build !linux

package poisoner

import (
	"fmt"
	"net"
)

// listenMulticast is the portable fallback: net.ListenMulticastUDP joins the
// group on iface itself (it also sets SO_REUSEADDR).  Outgoing multicast TTL
// cannot be tuned portably, so ttl is ignored here.
func listenMulticast(iface *net.Interface, ifaddr net.IP, group [4]byte, port, ttl int) (net.PacketConn, error) {
	if ifaddr.To4() == nil {
		return nil, fmt.Errorf("no IPv4 address on %s", iface.Name)
	}
	return net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{IP: net.IP(group[:]), Port: port})
}
