package poisoner

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"go-responder/internal/core"
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

// ─── DNS ─────────────────────────────────────────────────────────────────────

func TestBuildDNSResponse_DelegatesToLLMNR(t *testing.T) {
	query := buildLLMNRQuery(0x1234, "WPAD")
	ip := net.ParseIP("10.0.0.1").To4()
	resp := BuildDNSResponse(query, ip)
	if resp == nil {
		t.Fatal("expected non-nil DNS response")
	}
	// Same as LLMNR response — txID echoed
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("txID mismatch: %02x%02x", resp[0], resp[1])
	}
}

func TestBuildDNSResponse_NilForNonA(t *testing.T) {
	query := buildLLMNRQuery(0x0001, "HOST")
	// Set QTYPE to AAAA
	binary.BigEndian.PutUint16(query[len(query)-4:], 0x001C)
	if BuildDNSResponse(query, net.ParseIP("1.2.3.4")) != nil {
		t.Fatal("non-A query should return nil")
	}
}

func TestHandleDNSQuery_RespondsWithIP(t *testing.T) {
	// Use a real loopback UDP pair
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind UDP:", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind client UDP:", err)
	}
	defer clientConn.Close()

	query := buildLLMNRQuery(0xABCD, "FILESERVER")
	ip := net.ParseIP("10.10.10.1").To4()

	go HandleDNSQuery(serverConn, clientConn.LocalAddr(), query, ip)

	buf := make([]byte, 512)
	clientConn.SetDeadline(timeAfterMs(500))
	n, _, err := clientConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no response from HandleDNSQuery: %v", err)
	}
	if n < 4 {
		t.Fatal("response too short")
	}
	if buf[0] != 0xAB || buf[1] != 0xCD {
		t.Fatalf("txID mismatch: %02x%02x", buf[0], buf[1])
	}
}

func TestHandleDNSQuery_AnalyzeMode(t *testing.T) {
	import_core_analyze_mode_was := analyzeModeSaved
	defer func() { restoreAnalyzeMode(import_core_analyze_mode_was) }()
	setAnalyzeMode(true)

	query := buildLLMNRQuery(0x0001, "WPAD")
	serverConn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer serverConn.Close()
	src := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	// In analyze mode, HandleDNSQuery should log but not write
	done := make(chan struct{})
	go func() {
		HandleDNSQuery(serverConn, src, query, net.ParseIP("10.0.0.1"))
		close(done)
	}()
	<-done
}

func TestHandleDNSQuery_EmptyName(t *testing.T) {
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer conn.Close()
	// Packet with QDCOUNT=0 -> ParseLLMNRQuery returns "" -> HandleDNSQuery returns early
	pkt := buildLLMNRQuery(0x0001, "HOST")
	pkt[4] = 0x00
	pkt[5] = 0x00
	HandleDNSQuery(conn, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, pkt, net.ParseIP("10.0.0.1"))
}

func TestHandleDNSQuery_NilConn(t *testing.T) {
	query := buildLLMNRQuery(0x0001, "WPAD")
	// conn=nil, should not panic (resp!=nil && conn!=nil guard)
	HandleDNSQuery(nil, nil, query, net.ParseIP("10.0.0.1"))
}

// ─── readFull ────────────────────────────────────────────────────────────────

func TestReadFull_Complete(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, _ := ln.Accept()
		defer c.Close()
		c.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	}()

	client, _ := net.Dial("tcp4", ln.Addr().String())
	defer client.Close()
	<-done

	buf := make([]byte, 5)
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("readFull error: %v", err)
	}
	if n != 5 {
		t.Fatalf("want 5, got %d", n)
	}
}

func TestReadFull_EOF(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		c.Write([]byte{0x01, 0x02})
		c.Close() // close before writing all bytes
	}()

	client, _ := net.Dial("tcp4", ln.Addr().String())
	defer client.Close()

	buf := make([]byte, 10)
	n, err := readFull(client, buf)
	if err == nil {
		t.Fatal("expected error on EOF")
	}
	_ = n
}

// ─── helpers for analyze mode toggling ───────────────────────────────────────

var analyzeModeSaved = core.AnalyzeMode

func setAnalyzeMode(v bool)     { core.AnalyzeMode = v }
func restoreAnalyzeMode(v bool) { core.AnalyzeMode = v }

func timeAfterMs(ms int) time.Time {
	return time.Now().Add(time.Duration(ms) * time.Millisecond)
}
