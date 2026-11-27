package poisoner

import (
	"net"
	"testing"

	"go-responder/internal/core"
)

// buildDUIDLL(nil) used to panic; the exported HandleDHCPv6Packet takes the
// interface from the caller, so it must tolerate a missing one.
func TestHandleDHCPv6PacketNilIface(t *testing.T) {
	solicit := []byte{1, 0, 0, 1, 0, 1, 0, 4, 1, 2, 3, 4}
	resp := HandleDHCPv6Packet(solicit, nil, net.ParseIP("fe80::1"))
	if resp == nil {
		t.Fatal("expected an Advertise even without an interface")
	}
	if len(buildDUIDLL(nil)) != 10 {
		t.Fatalf("DUID-LL must be 10 bytes, got %d", len(buildDUIDLL(nil)))
	}
}

// The DNS poisoner must honour the same allow/deny filters as LLMNR/NBT-NS/mDNS.
func TestProcessDNSQueryAppliesFilters(t *testing.T) {
	query := buildLLMNRQuery(0x4242, "FILESERVER")
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5353}
	ip := net.ParseIP("192.0.2.1")

	if resp := processDNSQuery(query, src, ip); resp == nil {
		t.Fatal("expected an answer with no filters configured")
	}

	core.DontRespondIPs = []net.IP{net.ParseIP("192.0.2.10")}
	defer func() { core.DontRespondIPs = nil }()
	if resp := processDNSQuery(query, src, ip); resp != nil {
		t.Fatal("DontRespondTo host must not be answered")
	}

	core.DontRespondIPs = nil
	core.DontRespondNames = []string{"fileserver"}
	defer func() { core.DontRespondNames = nil }()
	if resp := processDNSQuery(query, src, ip); resp != nil {
		t.Fatal("DontRespondToName must not be answered")
	}
}
