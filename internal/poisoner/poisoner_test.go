package poisoner

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// ─── LLMNR ───────────────────────────────────────────────────────────────────

func buildLLMNRQuery(txID uint16, name string) []byte {
	var pkt []byte
	pkt = append(pkt, byte(txID>>8), byte(txID))
	pkt = append(pkt, 0x00, 0x00) // flags: query
	pkt = append(pkt, 0x00, 0x01) // QDCOUNT=1
	pkt = append(pkt, 0x00, 0x00)
	pkt = append(pkt, 0x00, 0x00)
	pkt = append(pkt, 0x00, 0x00)
	for _, part := range []string{name} {
		pkt = append(pkt, byte(len(part)))
		pkt = append(pkt, part...)
	}
	pkt = append(pkt, 0x00)
	pkt = append(pkt, 0x00, 0x01) // QTYPE A
	pkt = append(pkt, 0x00, 0x01) // QCLASS IN
	return pkt
}

func TestParseLLMNRQuery_Valid(t *testing.T) {
	pkt := buildLLMNRQuery(0x1234, "FILESERVER")
	name := ParseLLMNRQuery(pkt)
	if name != "FILESERVER" {
		t.Fatalf("want FILESERVER, got %q", name)
	}
}

func TestParseLLMNRQuery_MultiLabel(t *testing.T) {
	pkt := buildLLMNRQuery(0x0001, "HOST") // single label, as LLMNR typically sends
	if ParseLLMNRQuery(pkt) == "" {
		t.Fatal("should parse single-label name")
	}
}

func TestParseLLMNRQuery_TooShort(t *testing.T) {
	if ParseLLMNRQuery([]byte{0x00, 0x01, 0x00, 0x00}) != "" {
		t.Fatal("too-short packet should return empty")
	}
}

func TestParseLLMNRQuery_ResponseFlag(t *testing.T) {
	pkt := buildLLMNRQuery(0x0002, "HOST")
	pkt[2] = 0x80 // set QR=1 (response)
	if ParseLLMNRQuery(pkt) != "" {
		t.Fatal("response flag set - should return empty")
	}
}

func TestParseLLMNRQuery_ZeroQCount(t *testing.T) {
	pkt := buildLLMNRQuery(0x0003, "HOST")
	pkt[4] = 0x00
	pkt[5] = 0x00
	if ParseLLMNRQuery(pkt) != "" {
		t.Fatal("QDCOUNT=0 - should return empty")
	}
}

func TestDecodeDNSName_SingleLabel(t *testing.T) {
	pkt := []byte{0x04, 'T', 'E', 'S', 'T', 0x00}
	if got := DecodeDNSName(pkt, 0); got != "TEST" {
		t.Fatalf("want TEST, got %q", got)
	}
}

func TestDecodeDNSName_MultiLabel(t *testing.T) {
	pkt := []byte{0x02, 'a', 'b', 0x02, 'c', 'd', 0x00}
	if got := DecodeDNSName(pkt, 0); got != "ab.cd" {
		t.Fatalf("want ab.cd, got %q", got)
	}
}

func TestDecodeDNSName_Empty(t *testing.T) {
	if got := DecodeDNSName([]byte{0x00}, 0); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}

func TestBuildLLMNRResponse_Valid(t *testing.T) {
	query := buildLLMNRQuery(0xABCD, "WINHOST")
	ip := net.ParseIP("192.168.1.10").To4()
	resp := BuildLLMNRResponse(query, ip)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Fatalf("txID mismatch: got %02x%02x", resp[0], resp[1])
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("response QR bit should be set")
	}
	if !bytes.Equal(resp[len(resp)-4:], ip) {
		t.Fatalf("response IP mismatch: got %v", resp[len(resp)-4:])
	}
}

func TestBuildLLMNRResponse_TooShort(t *testing.T) {
	if BuildLLMNRResponse([]byte{0x01, 0x02}, net.ParseIP("1.2.3.4")) != nil {
		t.Fatal("too-short query should return nil")
	}
}

func TestBuildLLMNRResponse_NonAQuery(t *testing.T) {
	pkt := buildLLMNRQuery(0x0001, "HOST")
	// Replace QTYPE with AAAA (0x001C)
	binary.BigEndian.PutUint16(pkt[len(pkt)-4:], 0x001C)
	if BuildLLMNRResponse(pkt, net.ParseIP("1.2.3.4")) != nil {
		t.Fatal("non-A query type should return nil")
	}
}

// ─── NBT-NS ──────────────────────────────────────────────────────────────────

func buildNBTNSQuery(txID uint16, name string) []byte {
	encoded := EncodeNBTName(name, 0x00)
	var pkt []byte
	pkt = append(pkt, byte(txID>>8), byte(txID))
	pkt = append(pkt, 0x01, 0x10) // flags: query, NB
	pkt = append(pkt, 0x00, 0x01) // QDCOUNT=1
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	pkt = append(pkt, 0x20)
	pkt = append(pkt, encoded...)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, 0x00, 0x20) // QTYPE NB
	pkt = append(pkt, 0x00, 0x01) // QCLASS IN
	return pkt
}

func TestParseNBTNSQuery_Valid(t *testing.T) {
	pkt := buildNBTNSQuery(0x0001, "DC01")
	name := ParseNBTNSQuery(pkt)
	if name != "DC01" {
		t.Fatalf("want DC01, got %q", name)
	}
}

func TestParseNBTNSQuery_TooShort(t *testing.T) {
	if ParseNBTNSQuery([]byte{0x00, 0x01, 0x00}) != "" {
		t.Fatal("too-short packet should return empty")
	}
}

func TestParseNBTNSQuery_ResponseFlag(t *testing.T) {
	pkt := buildNBTNSQuery(0x0001, "HOST")
	pkt[2] = 0x80 // QR=1
	if ParseNBTNSQuery(pkt) != "" {
		t.Fatal("response flag - should return empty")
	}
}

func TestParseNBTNSQuery_ZeroQCount(t *testing.T) {
	pkt := buildNBTNSQuery(0x0001, "HOST")
	pkt[4] = 0x00
	pkt[5] = 0x00
	if ParseNBTNSQuery(pkt) != "" {
		t.Fatal("QDCOUNT=0 - should return empty")
	}
}

func TestDecodeNBTName_RoundTrip(t *testing.T) {
	for _, name := range []string{"SERVER", "DC01", "FILESERVER"} {
		encoded := EncodeNBTName(name, 0x00)
		decoded := DecodeNBTName(encoded)
		if decoded != name {
			t.Fatalf("round-trip failed for %q: got %q", name, decoded)
		}
	}
}

func TestDecodeNBTName_WrongLength(t *testing.T) {
	if DecodeNBTName([]byte("short")) != "" {
		t.Fatal("wrong-length input should return empty")
	}
}

func TestEncodeNBTName_Length(t *testing.T) {
	enc := EncodeNBTName("HOST", 0x00)
	if len(enc) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(enc))
	}
}

func TestBuildNBTNSResponse_Valid(t *testing.T) {
	pkt := buildNBTNSQuery(0x1234, "SERVER")
	ip := net.ParseIP("10.0.0.1").To4()
	resp := BuildNBTNSResponse(pkt, ip)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("txID mismatch: got %02x%02x", resp[0], resp[1])
	}
	if !bytes.Equal(resp[len(resp)-4:], ip) {
		t.Fatalf("IP mismatch in response: got %v", resp[len(resp)-4:])
	}
}

func TestBuildNBTNSResponse_TooShort(t *testing.T) {
	if BuildNBTNSResponse([]byte{0x00, 0x01}, net.ParseIP("1.2.3.4")) != nil {
		t.Fatal("too-short query should return nil")
	}
}

// ─── IfaceByIP ───────────────────────────────────────────────────────────────

func TestIfaceByIP_ValidIP(t *testing.T) {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				found, err := IfaceByIP(ipnet.IP.To4())
				if err != nil {
					t.Fatalf("IfaceByIP(%s): %v", ipnet.IP, err)
				}
				if found == nil {
					t.Fatal("expected non-nil interface")
				}
				return
			}
		}
	}
	t.Skip("no IPv4 interface available")
}

func TestIfaceByIP_InvalidIP(t *testing.T) {
	_, err := IfaceByIP(net.ParseIP("192.168.254.253"))
	if err == nil {
		t.Fatal("expected error for non-existent IP")
	}
}
