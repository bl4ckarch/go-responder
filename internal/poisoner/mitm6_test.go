package poisoner

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// fakeIface returns a synthetic *net.Interface for testing.
func fakeIface() *net.Interface {
	return &net.Interface{
		Index:        1,
		Name:         "eth0",
		HardwareAddr: net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01},
	}
}

// ─── buildRA ─────────────────────────────────────────────────────────────────

func TestBuildRA_Type(t *testing.T) {
	pkt := buildRA(net.ParseIP("fe80::1"))
	if len(pkt) == 0 {
		t.Fatal("empty RA packet")
	}
	if pkt[0] != 134 {
		t.Fatalf("ICMPv6 type: want 134 (RA), got %d", pkt[0])
	}
	if pkt[1] != 0 {
		t.Fatalf("ICMPv6 code: want 0, got %d", pkt[1])
	}
}

func TestBuildRA_Flags(t *testing.T) {
	pkt := buildRA(net.ParseIP("fe80::1"))
	// Cur Hop Limit at offset 4, Flags at offset 5
	if pkt[4] != 64 {
		t.Fatalf("Cur Hop Limit: want 64, got %d", pkt[4])
	}
	if pkt[5] != 0xC0 {
		t.Fatalf("Flags: want 0xC0 (M=1,O=1), got 0x%02x", pkt[5])
	}
}

func TestBuildRA_RouterLifetime(t *testing.T) {
	pkt := buildRA(net.ParseIP("fe80::1"))
	lifetime := binary.BigEndian.Uint16(pkt[6:8])
	if lifetime != 1800 {
		t.Fatalf("Router Lifetime: want 1800, got %d", lifetime)
	}
}

func TestBuildRA_RDNSSOption(t *testing.T) {
	ip6 := net.ParseIP("fe80::dead:beef")
	pkt := buildRA(ip6)

	// RA base is 16 bytes, RDNSS starts at offset 16
	if len(pkt) < 16+24 {
		t.Fatalf("RA too short for RDNSS option: %d bytes", len(pkt))
	}
	rdnss := pkt[16:]
	if rdnss[0] != 25 {
		t.Fatalf("RDNSS type: want 25, got %d", rdnss[0])
	}
	if rdnss[1] != 3 {
		t.Fatalf("RDNSS length: want 3 (24 bytes), got %d", rdnss[1])
	}
	// Reserved at rdnss[2:4]
	lifetime := binary.BigEndian.Uint32(rdnss[4:8])
	if lifetime != 600 {
		t.Fatalf("RDNSS lifetime: want 600, got %d", lifetime)
	}
	addr := net.IP(rdnss[8:24])
	if !addr.Equal(ip6) {
		t.Fatalf("RDNSS address mismatch: want %s, got %s", ip6, addr)
	}
}

func TestBuildRA_InvalidIP(t *testing.T) {
	// nil IP should not panic
	pkt := buildRA(nil)
	if len(pkt) == 0 {
		t.Fatal("expected non-empty RA even with nil IP")
	}
}

// ─── dhcpv6Option ────────────────────────────────────────────────────────────

func TestDHCPv6Option_Encoding(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC}
	opt := dhcpv6Option(23, data)
	if len(opt) != 4+len(data) {
		t.Fatalf("want %d bytes, got %d", 4+len(data), len(opt))
	}
	if binary.BigEndian.Uint16(opt[0:2]) != 23 {
		t.Fatal("option code mismatch")
	}
	if binary.BigEndian.Uint16(opt[2:4]) != 3 {
		t.Fatal("option length mismatch")
	}
	if !bytes.Equal(opt[4:], data) {
		t.Fatal("option data mismatch")
	}
}

func TestDHCPv6Option_Empty(t *testing.T) {
	opt := dhcpv6Option(1, nil)
	if len(opt) != 4 {
		t.Fatalf("empty option: want 4 bytes, got %d", len(opt))
	}
	if binary.BigEndian.Uint16(opt[2:4]) != 0 {
		t.Fatal("empty option length should be 0")
	}
}

// ─── findDHCPv6Option ────────────────────────────────────────────────────────

func TestFindDHCPv6Option_Found(t *testing.T) {
	opts := dhcpv6Option(1, []byte{0x01, 0x02, 0x03})
	opts = append(opts, dhcpv6Option(23, []byte{0xFF, 0xFE})...)

	got := findDHCPv6Option(opts, 23)
	if !bytes.Equal(got, []byte{0xFF, 0xFE}) {
		t.Fatalf("want FF FE, got %v", got)
	}
}

func TestFindDHCPv6Option_NotFound(t *testing.T) {
	opts := dhcpv6Option(1, []byte{0x01})
	if findDHCPv6Option(opts, 99) != nil {
		t.Fatal("should return nil for missing option")
	}
}

func TestFindDHCPv6Option_Empty(t *testing.T) {
	if findDHCPv6Option(nil, 1) != nil {
		t.Fatal("nil opts should return nil")
	}
	if findDHCPv6Option([]byte{0x00}, 1) != nil {
		t.Fatal("truncated opts should return nil")
	}
}

func TestFindDHCPv6Option_TruncatedData(t *testing.T) {
	// Option claims length 10 but only 2 bytes of data follow
	opts := []byte{0x00, 0x01, 0x00, 0x0A, 0xAA, 0xBB}
	if findDHCPv6Option(opts, 1) != nil {
		t.Fatal("truncated data: should return nil")
	}
}

// ─── buildDUIDLL ─────────────────────────────────────────────────────────────

func TestBuildDUIDLL_WithMAC(t *testing.T) {
	iface := fakeIface()
	duid := buildDUIDLL(iface)
	// type=3 (2 bytes) + hw=1 (2 bytes) + MAC (6 bytes) = 10 bytes
	if len(duid) != 10 {
		t.Fatalf("DUID-LL: want 10 bytes, got %d", len(duid))
	}
	if duid[0] != 0x00 || duid[1] != 0x03 {
		t.Fatalf("DUID type: want 0x0003, got %02x%02x", duid[0], duid[1])
	}
	if duid[2] != 0x00 || duid[3] != 0x01 {
		t.Fatalf("hw type: want 0x0001 (Ethernet), got %02x%02x", duid[2], duid[3])
	}
	if !bytes.Equal(duid[4:], iface.HardwareAddr) {
		t.Fatalf("MAC mismatch: want %v, got %v", iface.HardwareAddr, duid[4:])
	}
}

func TestBuildDUIDLL_NoMAC(t *testing.T) {
	iface := &net.Interface{Index: 2, Name: "lo"}
	duid := buildDUIDLL(iface)
	if len(duid) != 10 {
		t.Fatalf("no-MAC DUID: want 10 bytes, got %d", len(duid))
	}
}

// ─── HandleDHCPv6Packet ──────────────────────────────────────────────────────

func buildDHCPv6Pkt(msgType byte, txID [3]byte, opts []byte) []byte {
	pkt := []byte{msgType, txID[0], txID[1], txID[2]}
	return append(pkt, opts...)
}

func TestHandleDHCPv6Packet_Solicit(t *testing.T) {
	iface := fakeIface()
	ip6 := net.ParseIP("fe80::1")
	clientDUID := []byte{0x00, 0x01, 0xAA, 0xBB}
	opts := dhcpv6Option(dhcp6OptClientID, clientDUID)

	pkt := buildDHCPv6Pkt(dhcp6Solicit, [3]byte{0x01, 0x02, 0x03}, opts)
	resp := HandleDHCPv6Packet(pkt, iface, ip6)

	if resp == nil {
		t.Fatal("expected Advertise response")
	}
	if resp[0] != dhcp6Advertise {
		t.Fatalf("want Advertise (%d), got %d", dhcp6Advertise, resp[0])
	}
	if resp[1] != 0x01 || resp[2] != 0x02 || resp[3] != 0x03 {
		t.Fatal("transaction ID not echoed")
	}
	// Must contain DNS servers option
	if findDHCPv6Option(resp[4:], dhcp6OptDNSServers) == nil {
		t.Fatal("response missing DNS servers option")
	}
	// DNS option data should be our ip6
	dnsData := findDHCPv6Option(resp[4:], dhcp6OptDNSServers)
	if !net.IP(dnsData).Equal(ip6) {
		t.Fatalf("DNS server mismatch: want %s, got %s", ip6, net.IP(dnsData))
	}
}

func TestHandleDHCPv6Packet_Request(t *testing.T) {
	iface := fakeIface()
	ip6 := net.ParseIP("2001:db8::1")
	pkt := buildDHCPv6Pkt(dhcp6Request, [3]byte{0xAA, 0xBB, 0xCC}, nil)
	resp := HandleDHCPv6Packet(pkt, iface, ip6)

	if resp == nil || resp[0] != dhcp6Reply {
		t.Fatalf("want Reply (%d), got %v", dhcp6Reply, resp)
	}
}

func TestHandleDHCPv6Packet_Confirm(t *testing.T) {
	resp := HandleDHCPv6Packet(
		buildDHCPv6Pkt(dhcp6Confirm, [3]byte{}, nil),
		fakeIface(), net.ParseIP("fe80::1"),
	)
	if resp == nil || resp[0] != dhcp6Reply {
		t.Fatal("Confirm should yield Reply")
	}
}

func TestHandleDHCPv6Packet_Renew(t *testing.T) {
	resp := HandleDHCPv6Packet(
		buildDHCPv6Pkt(dhcp6Renew, [3]byte{}, nil),
		fakeIface(), net.ParseIP("fe80::1"),
	)
	if resp == nil || resp[0] != dhcp6Reply {
		t.Fatal("Renew should yield Reply")
	}
}

func TestHandleDHCPv6Packet_Rebind(t *testing.T) {
	resp := HandleDHCPv6Packet(
		buildDHCPv6Pkt(dhcp6Rebind, [3]byte{}, nil),
		fakeIface(), net.ParseIP("fe80::1"),
	)
	if resp == nil || resp[0] != dhcp6Reply {
		t.Fatal("Rebind should yield Reply")
	}
}

func TestHandleDHCPv6Packet_InformRequest(t *testing.T) {
	resp := HandleDHCPv6Packet(
		buildDHCPv6Pkt(dhcp6InformRequest, [3]byte{0x01, 0x02, 0x03}, nil),
		fakeIface(), net.ParseIP("fe80::1"),
	)
	if resp == nil || resp[0] != dhcp6Reply {
		t.Fatal("Information-request should yield Reply")
	}
}

func TestHandleDHCPv6Packet_TooShort(t *testing.T) {
	if HandleDHCPv6Packet([]byte{0x01, 0x00}, fakeIface(), net.ParseIP("fe80::1")) != nil {
		t.Fatal("too-short packet should return nil")
	}
}

func TestHandleDHCPv6Packet_UnknownMsgType(t *testing.T) {
	pkt := buildDHCPv6Pkt(0xFF, [3]byte{}, nil)
	if HandleDHCPv6Packet(pkt, fakeIface(), net.ParseIP("fe80::1")) != nil {
		t.Fatal("unknown message type should return nil")
	}
}

func TestHandleDHCPv6Packet_WithClientID(t *testing.T) {
	clientDUID := []byte{0x00, 0x03, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	opts := dhcpv6Option(dhcp6OptClientID, clientDUID)
	pkt := buildDHCPv6Pkt(dhcp6Solicit, [3]byte{0x01, 0x02, 0x03}, opts)

	resp := HandleDHCPv6Packet(pkt, fakeIface(), net.ParseIP("fe80::1"))
	if resp == nil {
		t.Fatal("expected response")
	}
	// Client ID should be echoed in the response
	echoed := findDHCPv6Option(resp[4:], dhcp6OptClientID)
	if echoed == nil {
		t.Fatal("Client ID not echoed in response")
	}
	if !bytes.Equal(echoed, clientDUID) {
		t.Fatalf("Client ID echo mismatch: want %v, got %v", clientDUID, echoed)
	}
}

func TestHandleDHCPv6Packet_ServerIDPresent(t *testing.T) {
	pkt := buildDHCPv6Pkt(dhcp6Solicit, [3]byte{0x01, 0x02, 0x03}, nil)
	resp := HandleDHCPv6Packet(pkt, fakeIface(), net.ParseIP("fe80::1"))
	if resp == nil {
		t.Fatal("expected response")
	}
	if findDHCPv6Option(resp[4:], dhcp6OptServerID) == nil {
		t.Fatal("Server ID option missing from response")
	}
}
