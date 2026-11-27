//go:build linux

package poisoner

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// listenMulticast opens a UDP socket bound to port that receives traffic sent
// to the IPv4 multicast group on iface.  ttl > 0 sets the outgoing multicast
// TTL.
func listenMulticast(iface *net.Interface, ifaddr net.IP, group [4]byte, port, ttl int) (net.PacketConn, error) {
	ifaddr4 := ifaddr.To4()
	if ifaddr4 == nil {
		return nil, fmt.Errorf("no IPv4 address on %s", iface.Name)
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctlErr error
			c.Control(func(fd uintptr) {
				// SO_REUSEADDR is required to bind the port when another
				// resolver (systemd-resolved, avahi, ...) already holds it,
				// and lets several sockets share the multicast group.
				if ctlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); ctlErr != nil {
					return
				}
				mreq := &syscall.IPMreqn{Multiaddr: group, Ifindex: int32(iface.Index)}
				if ctlErr = syscall.SetsockoptIPMreqn(int(fd), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq); ctlErr != nil {
					return
				}
				if ctlErr = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF,
					[4]byte{ifaddr4[0], ifaddr4[1], ifaddr4[2], ifaddr4[3]}); ctlErr != nil {
					return
				}
				if ttl > 0 {
					ctlErr = syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, byte(ttl))
				}
			})
			return ctlErr
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port))
}
