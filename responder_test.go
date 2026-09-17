package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func init() {
	outFile = filepath.Join(os.TempDir(), "go-responder-test-hashes.txt")
	initSession("")
}

// buildType1 constructs a minimal NTLMSSP_NEGOTIATE (Type 1) message.
func buildType1(flags uint32, domain, workstation string) []byte {
	domBytes := []byte(domain)
	wsBytes := []byte(workstation)

	// domain at offset 32 (after 32-byte fixed header)
	domOff := uint32(32)
	wsOff := domOff + uint32(len(domBytes))

	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(1))       // msg type
	binary.Write(&b, binary.LittleEndian, flags)            // flags
	binary.Write(&b, binary.LittleEndian, uint16(len(domBytes))) // domain len
	binary.Write(&b, binary.LittleEndian, uint16(len(domBytes)))
	binary.Write(&b, binary.LittleEndian, domOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(wsBytes))) // workstation len
	binary.Write(&b, binary.LittleEndian, uint16(len(wsBytes)))
	binary.Write(&b, binary.LittleEndian, wsOff)
	b.Write(domBytes)
	b.Write(wsBytes)
	return b.Bytes()
}

// buildType3 constructs a minimal NTLMSSP_AUTHENTICATE (Type 3) message.
// ntResp length controls whether it looks like NTLMv1 (24) or NTLMv2 (>24).
func buildType3(domain, username string, lmResp, ntResp []byte) []byte {
	encDomain := encodeUTF16LE(domain)
	encUser := encodeUTF16LE(username)

	// Fixed header is 72 bytes (12 sig+type + 10 fields of 8 bytes = 80 actually)
	// Layout: sig(8) type(4) LmResp(8) NtResp(8) Domain(8) User(8) WS(8) Key(8) Flags(4) = 64
	hdrSize := 64
	lmOff := uint32(hdrSize)
	ntOff := lmOff + uint32(len(lmResp))
	domOff := ntOff + uint32(len(ntResp))
	userOff := domOff + uint32(len(encDomain))

	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(3))

	// LmChallengeResponse at offset 12
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, lmOff)

	// NtChallengeResponse at offset 20
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, ntOff)

	// DomainName at offset 28
	binary.Write(&b, binary.LittleEndian, uint16(len(encDomain)))
	binary.Write(&b, binary.LittleEndian, uint16(len(encDomain)))
	binary.Write(&b, binary.LittleEndian, domOff)

	// UserName at offset 36
	binary.Write(&b, binary.LittleEndian, uint16(len(encUser)))
	binary.Write(&b, binary.LittleEndian, uint16(len(encUser)))
	binary.Write(&b, binary.LittleEndian, userOff)

	// Workstation (empty) at offset 44
	wsOff := userOff + uint32(len(encUser))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, wsOff)

	// EncryptedRandomSessionKey (empty) at offset 52
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, wsOff)

	// NegotiateFlags at offset 60
	binary.Write(&b, binary.LittleEndian, uint32(0x00000001))

	// Payload
	b.Write(lmResp)
	b.Write(ntResp)
	b.Write(encDomain)
	b.Write(encUser)
	return b.Bytes()
}

// buildDNSQuery builds a minimal DNS A-query for name.
func buildDNSQuery(txID uint16, name string) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, txID) // ID
	b.Write([]byte{0x01, 0x00})              // FLAGS: RD
	binary.Write(&b, binary.BigEndian, uint16(1)) // QDCOUNT
	b.Write([]byte{0, 0, 0, 0, 0, 0})       // ANCOUNT NSCOUNT ARCOUNT

	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	binary.Write(&b, binary.BigEndian, uint16(1)) // QTYPE A
	binary.Write(&b, binary.BigEndian, uint16(1)) // QCLASS IN
	return b.Bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// config.go
// ─────────────────────────────────────────────────────────────────────────────

func TestInitSession_Random(t *testing.T) {
	initSession("")
	c := getChallenge()
	// Statistically impossible for 8 random bytes to all be zero
	allZero := true
	for _, b := range c {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("challenge is all zeros — RNG probably failed")
	}
}

func TestInitSession_Fixed(t *testing.T) {
	initSession("1122334455667788")
	c := getChallenge()
	want := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if c != want {
		t.Fatalf("want %x got %x", want, c)
	}
	if challengeHexStr() != "1122334455667788" {
		t.Fatalf("challengeHexStr mismatch: %s", challengeHexStr())
	}
}

func TestInitSession_InvalidHex(t *testing.T) {
	// Invalid hex → should fall back to random (no panic)
	initSession("ZZZZZZZZZZZZZZZZ")
	initSession("") // restore random
}

func TestGenMachineName(t *testing.T) {
	name := genMachineName()
	if !strings.HasPrefix(name, "WIN-") {
		t.Fatalf("expected WIN- prefix, got %s", name)
	}
	if len(name) != 13 { // "WIN-" + 9 chars
		t.Fatalf("expected len 13, got %d (%s)", len(name), name)
	}
}

func TestGenDomainName(t *testing.T) {
	d := genDomainName()
	if !strings.HasSuffix(d, ".LOCAL") {
		t.Fatalf("expected .LOCAL suffix, got %s", d)
	}
}

func TestGenPort(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := genPort()
		if p < 20000 || p >= 50000 {
			t.Fatalf("port %d out of expected range [20000, 50000)", p)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// filter.go
// ─────────────────────────────────────────────────────────────────────────────

func TestParseIPList(t *testing.T) {
	ips := parseIPList("192.168.1.1,10.0.0.1")
	if len(ips) != 2 {
		t.Fatalf("want 2 IPs, got %d", len(ips))
	}
	empty := parseIPList("")
	if len(empty) != 0 {
		t.Fatal("expected empty slice for empty input")
	}
	skipped := parseIPList("not-an-ip,10.0.0.1")
	if len(skipped) != 1 {
		t.Fatalf("want 1 valid IP, got %d", len(skipped))
	}
}

func TestParseNameList(t *testing.T) {
	names := parseNameList("host1,host2,  host3  ")
	if len(names) != 3 {
		t.Fatalf("want 3, got %d", len(names))
	}
	if parseNameList("")[0:0] != nil {
		// just confirm it doesn't panic
	}
	if len(parseNameList("")) != 0 {
		t.Fatal("expected empty")
	}
}

func TestAddrToIP(t *testing.T) {
	udp := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 137}
	if got := addrToIP(udp); !got.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("UDPAddr: got %s", got)
	}
	tcp := &net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 80}
	if got := addrToIP(tcp); !got.Equal(net.ParseIP("5.6.7.8")) {
		t.Fatalf("TCPAddr: got %s", got)
	}
	if got := addrToIP(nil); got != nil {
		t.Fatalf("nil addr: expected nil, got %s", got)
	}
}

func TestShouldRespond_NoFilters(t *testing.T) {
	respondToIPs = nil
	dontRespondIPs = nil
	respondToNames = nil
	dontRespondNames = nil

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if !shouldRespond(src, "ANYTHING") {
		t.Fatal("should respond with no filters set")
	}
}

func TestShouldRespond_DontRespondTo(t *testing.T) {
	dontRespondIPs = parseIPList("10.0.0.5")
	defer func() { dontRespondIPs = nil }()

	blocked := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 137}
	if shouldRespond(blocked, "HOST") {
		t.Fatal("should NOT respond to blocked IP")
	}
	allowed := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if !shouldRespond(allowed, "HOST") {
		t.Fatal("should respond to non-blocked IP")
	}
}

func TestShouldRespond_RespondTo(t *testing.T) {
	respondToIPs = parseIPList("10.0.0.2")
	defer func() { respondToIPs = nil }()

	allowed := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 137}
	if !shouldRespond(allowed, "HOST") {
		t.Fatal("should respond to allowlisted IP")
	}
	other := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 137}
	if shouldRespond(other, "HOST") {
		t.Fatal("should NOT respond to non-allowlisted IP")
	}
}

func TestShouldRespond_DontRespondToName(t *testing.T) {
	dontRespondNames = parseNameList("BADHOST")
	defer func() { dontRespondNames = nil }()

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if shouldRespond(src, "BADHOST") {
		t.Fatal("should NOT respond to blocked name")
	}
	if !shouldRespond(src, "GOODHOST") {
		t.Fatal("should respond to non-blocked name")
	}
}

func TestShouldRespond_RespondToName(t *testing.T) {
	respondToNames = parseNameList("TARGETHOST")
	defer func() { respondToNames = nil }()

	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if !shouldRespond(src, "TARGETHOST") {
		t.Fatal("should respond to allowlisted name")
	}
	if shouldRespond(src, "OTHERHOST") {
		t.Fatal("should NOT respond to non-allowlisted name")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ntlm.go
// ─────────────────────────────────────────────────────────────────────────────

func TestUTF16RoundTrip(t *testing.T) {
	for _, s := range []string{"WORKGROUP", "Administrator", "AD.TRILOCOR.LOCAL", ""} {
		got := decodeUTF16LE(encodeUTF16LE(s))
		if got != s {
			t.Fatalf("round-trip failed: want %q got %q", s, got)
		}
	}
}

func TestBuildNTLMChallenge_Structure(t *testing.T) {
	initSession("deadbeefcafebabe")
	c := getChallenge()
	pkt := BuildNTLMChallenge(c, "TESTDOM", "TESTPC")

	if !strings.HasPrefix(string(pkt), "NTLMSSP\x00") {
		t.Fatal("missing NTLMSSP signature")
	}
	if binary.LittleEndian.Uint32(pkt[8:12]) != 2 {
		t.Fatal("message type must be 2")
	}
	// Challenge bytes at offset 24
	var got [8]byte
	copy(got[:], pkt[24:32])
	if got != c {
		t.Fatalf("challenge mismatch: want %x got %x", c, got)
	}
}

func TestBuildNTLMChallenge_LMMode(t *testing.T) {
	lmMode = true
	defer func() { lmMode = false }()
	initSession("1122334455667788")
	c := getChallenge()
	pkt := BuildNTLMChallenge(c, "DOM", "PC")
	flags := binary.LittleEndian.Uint32(pkt[20:24])
	// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (0x00080000) must NOT be set
	if flags&0x00080000 != 0 {
		t.Fatal("LM mode: EXTENDED_SESSIONSECURITY should be absent")
	}
}

func TestFindNTLMSSP(t *testing.T) {
	sig := []byte("NTLMSSP\x00")
	// Signature at start
	data := append(sig, 0x01, 0x00, 0x00, 0x00)
	if !bytes.Equal(FindNTLMSSP(data), data) {
		t.Fatal("should find sig at offset 0")
	}
	// Signature with prefix junk
	junk := append([]byte("JUNK"), data...)
	if !bytes.Equal(FindNTLMSSP(junk), data) {
		t.Fatal("should find sig after junk")
	}
	// No signature
	if FindNTLMSSP([]byte("no sig here")) != nil {
		t.Fatal("should return nil when sig absent")
	}
}

func TestNtlmMsgType(t *testing.T) {
	sig := []byte("NTLMSSP\x00")
	for _, tc := range []struct{ typ uint32 }{
		{1}, {2}, {3},
	} {
		pkt := append(sig, 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(pkt[8:], tc.typ)
		if got := ntlmMsgType(pkt); got != tc.typ {
			t.Fatalf("type %d: got %d", tc.typ, got)
		}
	}
	if ntlmMsgType([]byte{1, 2, 3}) != 0 {
		t.Fatal("too-short data should return 0")
	}
}

func TestParseNTLMAuthenticate_NTLMv2(t *testing.T) {
	initSession("1122334455667788")
	challenge := getChallenge()

	lmResp := make([]byte, 24)
	// NTLMv2: NtResp = 16-byte NTProofStr + blob (must be > 24 total)
	ntProofStr := make([]byte, 16)
	blob := make([]byte, 28) // 44 total
	ntResp := append(ntProofStr, blob...)

	msg := buildType3("DOMAIN", "user", lmResp, ntResp)
	hash, user, domain, err := ParseNTLMAuthenticate(msg, challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" || domain != "DOMAIN" {
		t.Fatalf("got user=%s domain=%s", user, domain)
	}
	// Hash format: user::domain:challenge:NTProofStr:blob
	parts := strings.Split(hash, ":")
	if len(parts) < 5 {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if parts[0] != "user" || parts[1] != "" || parts[2] != "DOMAIN" {
		t.Fatalf("bad hash prefix: %s", hash)
	}
	if parts[3] != strings.ToLower(hex.EncodeToString(challenge[:])) {
		t.Fatalf("challenge mismatch in hash: %s", parts[3])
	}
}

func TestParseNTLMAuthenticate_NTLMv1(t *testing.T) {
	initSession("aabbccddeeff0011")
	challenge := getChallenge()

	lmResp := make([]byte, 24)
	ntResp := make([]byte, 24) // exactly 24 = NTLMv1

	msg := buildType3("CORP", "alice", lmResp, ntResp)
	hash, user, domain, err := ParseNTLMAuthenticate(msg, challenge)
	if err != nil {
		t.Fatalf("NTLMv1 parse error: %v", err)
	}
	if user != "alice" || domain != "CORP" {
		t.Fatalf("got user=%s domain=%s", user, domain)
	}
	// NTLMv1 format: user::domain:LMhex:NThex:challenge
	if !strings.HasPrefix(hash, "alice::CORP:") {
		t.Fatalf("bad NTLMv1 hash format: %s", hash)
	}
	if !strings.HasSuffix(hash, hex.EncodeToString(challenge[:])) {
		t.Fatalf("NTLMv1 hash missing challenge at end: %s", hash)
	}
}

func TestParseNTLMAuthenticate_Errors(t *testing.T) {
	challenge := getChallenge()

	// Not NTLMSSP
	_, _, _, err := ParseNTLMAuthenticate([]byte("GARBAGE"), challenge)
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	// Wrong message type (type 1 instead of 3)
	msg := buildType1(0x00000001, "", "")
	_, _, _, err = ParseNTLMAuthenticate(msg, challenge)
	if err == nil {
		t.Fatal("expected error for type 1 message")
	}
	// Too short
	_, _, _, err = ParseNTLMAuthenticate([]byte("NTLMSSP\x00\x03\x00\x00\x00"), challenge)
	if err == nil {
		t.Fatal("expected error for too-short type 3")
	}
	// NtResponse too short (between 0 and 16)
	lm := make([]byte, 4)
	nt := make([]byte, 8) // not 24, not >= 16 for v2 path
	msg2 := buildType3("D", "u", lm, nt)
	_, _, _, err = ParseNTLMAuthenticate(msg2, challenge)
	if err == nil {
		t.Fatal("expected error for too-short NtResponse")
	}
}

func TestParseNTLMNegotiate(t *testing.T) {
	flags := uint32(0x00000001 | 0x00001000 | 0x00002000 | 0x02000000)
	msg := buildType1(flags, "CORP", "WORKSTATION")
	ws, dom, osVer := ParseNTLMNegotiate(msg)
	if ws != "WORKSTATION" {
		t.Fatalf("workstation: want WORKSTATION got %q", ws)
	}
	if dom != "CORP" {
		t.Fatalf("domain: want CORP got %q", dom)
	}
	// Version field present (flag 0x02000000) — osVer may be empty if offset too short
	_ = osVer

	// No fields
	ws2, dom2, _ := ParseNTLMNegotiate(buildType1(0x00000001, "", ""))
	if ws2 != "" || dom2 != "" {
		t.Fatalf("expected empty ws/domain, got %q/%q", ws2, dom2)
	}

	// Too short / wrong type
	ws3, _, _ := ParseNTLMNegotiate([]byte("short"))
	if ws3 != "" {
		t.Fatal("expected empty for too-short data")
	}
	// Type 2 message — should return empty
	ws4, _, _ := ParseNTLMNegotiate(append([]byte("NTLMSSP\x00"), []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...))
	if ws4 != "" {
		t.Fatal("expected empty for type-2 message passed to ParseNTLMNegotiate")
	}
}

func TestBuildSPNEGO(t *testing.T) {
	token := BuildSPNEGONegotiateToken()
	if len(token) == 0 {
		t.Fatal("empty SPNEGO token")
	}
	// Outer tag = 0x60 (APPLICATION 0)
	if token[0] != 0x60 {
		t.Fatalf("expected APPLICATION tag 0x60, got 0x%02x", token[0])
	}
}

func TestWrapSPNEGOChallenge(t *testing.T) {
	challenge := BuildNTLMChallenge(getChallenge(), "DOM", "PC")
	wrapped := WrapSPNEGOChallenge(challenge)
	// Outer tag = 0xa1 (context [1])
	if len(wrapped) == 0 || wrapped[0] != 0xa1 {
		t.Fatalf("expected [1] context tag 0xa1, got 0x%02x", wrapped[0])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// llmnr.go / dns.go
// ─────────────────────────────────────────────────────────────────────────────

func TestDecodeDNSName(t *testing.T) {
	cases := []struct {
		name   string
		labels []string
	}{
		{"WORKSTATION", []string{"WORKSTATION"}},
		{"mail.corp.local", []string{"mail", "corp", "local"}},
	}
	for _, tc := range cases {
		var pkt []byte
		for _, l := range tc.labels {
			pkt = append(pkt, byte(len(l)))
			pkt = append(pkt, []byte(l)...)
		}
		pkt = append(pkt, 0)
		got := decodeDNSName(pkt, 0)
		if got != tc.name {
			t.Fatalf("want %q got %q", tc.name, got)
		}
	}
	// Truncated label
	if decodeDNSName([]byte{10, 'a'}, 0) == "" {
		// acceptable — short label cut off
	}
}

func TestParseLLMNRQuery(t *testing.T) {
	q := buildDNSQuery(0x1234, "FILESERVER")
	name := parseLLMNRQuery(q)
	if name != "FILESERVER" {
		t.Fatalf("want FILESERVER, got %q", name)
	}

	// Too short
	if parseLLMNRQuery([]byte{1, 2, 3}) != "" {
		t.Fatal("should return empty for too-short packet")
	}
	// Response bit set (QR=1)
	q[2] |= 0x80
	if parseLLMNRQuery(q) != "" {
		t.Fatal("should ignore response packets")
	}
	// No questions
	noQ := buildDNSQuery(0x0001, "X")
	binary.BigEndian.PutUint16(noQ[4:6], 0)
	if parseLLMNRQuery(noQ) != "" {
		t.Fatal("should return empty when QDCOUNT=0")
	}
}

func TestBuildLLMNRResponse(t *testing.T) {
	ip := net.ParseIP("192.168.1.99").To4()
	q := buildDNSQuery(0xBEEF, "TARGET")
	resp := buildLLMNRResponse(q, ip)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// TX ID preserved
	if binary.BigEndian.Uint16(resp[0:2]) != 0xBEEF {
		t.Fatalf("TX ID mismatch")
	}
	// IP at end
	if !bytes.Equal(resp[len(resp)-4:], ip) {
		t.Fatalf("IP not embedded correctly: %v", resp[len(resp)-4:])
	}

	// Too short
	if buildLLMNRResponse([]byte{1, 2}, ip) != nil {
		t.Fatal("expected nil for too-short query")
	}
	// QTYPE AAAA — should return nil
	q2 := buildDNSQuery(0x0001, "X")
	// Set QTYPE to 0x001C (AAAA)
	for i := len(q2) - 4; i < len(q2)-2; i++ {
		q2[i] = 0
	}
	q2[len(q2)-4] = 0x00
	q2[len(q2)-3] = 0x1c
	if buildLLMNRResponse(q2, ip) != nil {
		t.Fatal("expected nil for AAAA query")
	}
}

func TestBuildDNSResponse(t *testing.T) {
	ip := net.ParseIP("10.0.0.1").To4()
	q := buildDNSQuery(0x0001, "evil")
	resp := buildDNSResponse(q, ip)
	if resp == nil {
		t.Fatal("buildDNSResponse should not return nil for valid query")
	}
}

func TestIfaceByIP_NotFound(t *testing.T) {
	_, err := ifaceByIP(net.ParseIP("192.0.2.255"))
	if err == nil {
		t.Fatal("expected error for non-existent IP")
	}
}

func TestReadFull(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		server.Write([]byte{1, 2, 3, 4})
		server.Close()
	}()

	buf := make([]byte, 4)
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("readFull error: %v", err)
	}
	if n != 4 || !bytes.Equal(buf, []byte{1, 2, 3, 4}) {
		t.Fatalf("readFull: got %v (n=%d)", buf, n)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// nbtns.go
// ─────────────────────────────────────────────────────────────────────────────

func TestEncodeDecodeNBTName(t *testing.T) {
	for _, name := range []string{"WORKSTATION", "DC01", "SRV"} {
		encoded := encodeNBTName(name, 0x00)
		decoded := decodeNBTName(encoded)
		if decoded != name {
			t.Fatalf("NBT round-trip: want %q got %q", name, decoded)
		}
	}
	// Bad length
	if decodeNBTName([]byte{1, 2, 3}) != "" {
		t.Fatal("should return empty for wrong length")
	}
}

func buildNBTNSQuery(txID uint16, name string) []byte {
	encoded := encodeNBTName(name, 0x00)
	var pkt []byte
	// Transaction ID
	pkt = append(pkt, byte(txID>>8), byte(txID))
	// Flags: query, NB query
	pkt = append(pkt, 0x01, 0x10)
	// QDCOUNT=1 ANCOUNT=0 NSCOUNT=0 ARCOUNT=0
	pkt = append(pkt, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Name: length(32) + 32 encoded bytes + 0x00
	pkt = append(pkt, 0x20)
	pkt = append(pkt, encoded...)
	pkt = append(pkt, 0x00)
	// QTYPE NB=0x0020, QCLASS IN=0x0001
	pkt = append(pkt, 0x00, 0x20, 0x00, 0x01)
	return pkt
}

func TestParseNBTNSQuery(t *testing.T) {
	q := buildNBTNSQuery(0xABCD, "FILESERVER")
	name := parseNBTNSQuery(q)
	if name != "FILESERVER" {
		t.Fatalf("want FILESERVER, got %q", name)
	}
	// Too short
	if parseNBTNSQuery([]byte{1, 2, 3}) != "" {
		t.Fatal("should return empty for short packet")
	}
	// Response bit set
	q2 := buildNBTNSQuery(0x0001, "HOST")
	q2[2] |= 0x80
	if parseNBTNSQuery(q2) != "" {
		t.Fatal("should ignore responses")
	}
	// QDCOUNT=0
	q3 := buildNBTNSQuery(0x0001, "HOST")
	q3[4] = 0
	q3[5] = 0
	if parseNBTNSQuery(q3) != "" {
		t.Fatal("should return empty when QDCOUNT=0")
	}
	// Wrong label length (not 32)
	q4 := buildNBTNSQuery(0x0001, "HOST")
	q4[12] = 16
	if parseNBTNSQuery(q4) != "" {
		t.Fatal("should return empty for wrong label length")
	}
}

func TestBuildNBTNSResponse(t *testing.T) {
	ip := net.ParseIP("10.10.10.10").To4()
	q := buildNBTNSQuery(0x1234, "TARGET")
	resp := buildNBTNSResponse(q, ip)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// TX ID
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatal("TX ID not preserved")
	}
	// IP at the end
	if !bytes.Equal(resp[len(resp)-4:], ip) {
		t.Fatalf("IP not in response: %v", resp[len(resp)-4:])
	}

	// Too short packet
	if buildNBTNSResponse([]byte{1, 2, 3}, ip) != nil {
		t.Fatal("expected nil for too-short packet")
	}
	// Wrong label length
	q2 := buildNBTNSQuery(0x0001, "X")
	q2[12] = 10
	if buildNBTNSResponse(q2, ip) != nil {
		t.Fatal("expected nil for bad label length")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// lnkgen.go
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildLNK_Header(t *testing.T) {
	lnk := buildLNK(`\\192.168.1.1\share`)
	if len(lnk) < 76 {
		t.Fatal("LNK too short — header must be >= 76 bytes")
	}
	// HeaderSize = 0x4C
	if binary.LittleEndian.Uint32(lnk[0:4]) != 0x4C {
		t.Fatal("HeaderSize mismatch")
	}
	// ClassID first bytes
	if lnk[4] != 0x01 || lnk[5] != 0x14 {
		t.Fatal("ClassID first bytes wrong")
	}
	// HasLinkInfo flag
	linkFlags := binary.LittleEndian.Uint32(lnk[20:24])
	if linkFlags&0x00000001 == 0 {
		t.Fatal("HasLinkInfo flag not set")
	}
}

func TestGenerateTriggerFiles(t *testing.T) {
	dir := t.TempDir()
	ip := net.ParseIP("192.168.1.99")
	if err := GenerateTriggerFiles(ip, dir); err != nil {
		t.Fatalf("GenerateTriggerFiles: %v", err)
	}

	expected := []string{"@trigger.scf", "@trigger.url", "desktop.ini", "@trigger.lnk"}
	for _, name := range expected {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("missing file %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("file %s is empty", name)
		}
		if strings.Contains(name, ".scf") || strings.Contains(name, ".url") || name == "desktop.ini" {
			// Text files must reference the UNC path
			if !strings.Contains(string(data), "192.168.1.99") {
				t.Fatalf("%s does not reference our IP", name)
			}
		}
	}
	// LNK must start with 0x4C header
	lnkData, _ := os.ReadFile(filepath.Join(dir, "@trigger.lnk"))
	if binary.LittleEndian.Uint32(lnkData[0:4]) != 0x4C {
		t.Fatal("LNK file has wrong header")
	}
}

func TestGenerateTriggerFiles_BadDir(t *testing.T) {
	// Can only fail if the path is truly invalid — test that it creates subdirs
	dir := filepath.Join(t.TempDir(), "sub", "dir")
	ip := net.ParseIP("1.2.3.4")
	if err := GenerateTriggerFiles(ip, dir); err != nil {
		t.Fatalf("GenerateTriggerFiles should create subdirs: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// https_server.go
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := generateSelfSignedCert("192.168.1.1")
	if err != nil {
		t.Fatalf("generateSelfSignedCert error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate data")
	}
	// Hostname
	cert2, err := generateSelfSignedCert("myhost.local")
	if err != nil {
		t.Fatalf("hostname cert error: %v", err)
	}
	if len(cert2.Certificate) == 0 {
		t.Fatal("no certificate data for hostname")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// http_server.go — handleHTTPNTLM via httptest
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleHTTPNTLM_NoAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handleHTTPNTLM(rr, req)
	if rr.Code != 401 {
		t.Fatalf("want 401, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("WWW-Authenticate"), "NTLM") {
		t.Fatal("missing WWW-Authenticate: NTLM")
	}
}

func TestHandleHTTPNTLM_BasicAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("admin:password")))
	rr := httptest.NewRecorder()
	handleHTTPNTLM(rr, req)
	if rr.Code != 401 {
		t.Fatalf("want 401 for basic auth, got %d", rr.Code)
	}
}

func TestHandleHTTPNTLM_UnknownAuth(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rr := httptest.NewRecorder()
	handleHTTPNTLM(rr, req)
	if rr.Code != 401 {
		t.Fatalf("want 401 for unknown auth, got %d", rr.Code)
	}
}

func TestHandleHTTPNTLM_NTLM_FullExchange(t *testing.T) {
	initSession("1122334455667788")

	// Step 1: Type1 negotiate
	type1 := buildType1(0x00000001|0x00001000|0x00002000, "CORP", "WKSTN")
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(type1))
	req1.RemoteAddr = "10.0.0.1:54321"
	rr1 := httptest.NewRecorder()
	handleHTTPNTLM(rr1, req1)
	if rr1.Code != 401 {
		t.Fatalf("Type1: want 401, got %d", rr1.Code)
	}
	wwwAuth := rr1.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "NTLM ") {
		t.Fatalf("Type1: no NTLM challenge in response: %q", wwwAuth)
	}

	// Step 2: Type3 authenticate
	challenge := getChallenge()
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "bob", lmResp, ntResp)

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(type3))
	req3.RemoteAddr = "10.0.0.1:54321"
	rr3 := httptest.NewRecorder()
	handleHTTPNTLM(rr3, req3)
	if rr3.Code != 401 {
		t.Fatalf("Type3: want 401, got %d", rr3.Code)
	}
	_ = challenge

	// Step 3: Type3 without a prior challenge stored — should 401
	req3b := httptest.NewRequest("GET", "/", nil)
	req3b.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(type3))
	req3b.RemoteAddr = "10.0.0.2:99999"
	rr3b := httptest.NewRecorder()
	handleHTTPNTLM(rr3b, req3b)
	if rr3b.Code != 401 {
		t.Fatalf("Type3 no-state: want 401, got %d", rr3b.Code)
	}
}

func TestHandleHTTPNTLM_BadBase64(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "NTLM not-valid-base64!!!")
	rr := httptest.NewRecorder()
	handleHTTPNTLM(rr, req)
	if rr.Code != 400 {
		t.Fatalf("want 400 for bad base64, got %d", rr.Code)
	}
}

func TestHandleHTTPNTLM_ShortNTLM(t *testing.T) {
	// Valid base64 but payload too short to be NTLMSSP
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString([]byte("short")))
	rr := httptest.NewRecorder()
	handleHTTPNTLM(rr, req)
	if rr.Code != 400 {
		t.Fatalf("want 400 for short NTLM, got %d", rr.Code)
	}
}

func TestHandleHTTPNTLM_UnknownMsgType(t *testing.T) {
	// Valid NTLMSSP signature but message type 99
	sig := []byte("NTLMSSP\x00")
	pkt := append(sig, 99, 0, 0, 0) // type=99
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(pkt))
	rr := httptest.NewRecorder()
	handleHTTPNTLM(rr, req)
	if rr.Code != 400 {
		t.Fatalf("want 400 for unknown msg type, got %d", rr.Code)
	}
}

func TestHandleWPAD(t *testing.T) {
	wpadEnabled = true
	wpadProxyHost = "10.0.0.1:3128"
	defer func() { wpadEnabled = false; wpadProxyHost = "" }()

	req := httptest.NewRequest("GET", "/wpad.dat", nil)
	rr := httptest.NewRecorder()
	handleWPAD(rr, req)
	if rr.Code != 200 {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "FindProxyForURL") {
		t.Fatal("WPAD response missing FindProxyForURL")
	}
	if !strings.Contains(body, "10.0.0.1:3128") {
		t.Fatal("WPAD response missing proxy address")
	}
}

func TestHandleWPAD_DefaultProxy(t *testing.T) {
	wpadEnabled = true
	wpadProxyHost = ""
	defer func() { wpadEnabled = false }()

	req := httptest.NewRequest("GET", "/wpad.dat", nil)
	req.Host = "192.168.1.1"
	rr := httptest.NewRecorder()
	handleWPAD(rr, req)
	if rr.Code != 200 {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, ":3128") {
		t.Fatalf("WPAD should default to port 3128: %s", body)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// proxy_server.go — handleProxy via net.Pipe
// ─────────────────────────────────────────────────────────────────────────────

func proxyExchange(t *testing.T, msgs []string) string {
	t.Helper()
	server, client := net.Pipe()
	var out strings.Builder

	go func() {
		defer server.Close()
		handleProxy(server)
	}()

	client.SetDeadline(time.Now().Add(3 * time.Second))
	for _, msg := range msgs {
		client.Write([]byte(msg))
		buf := make([]byte, 4096)
		n, _ := client.Read(buf)
		out.Write(buf[:n])
	}
	client.Close()
	return out.String()
}

func TestHandleProxy_NoAuth(t *testing.T) {
	resp := proxyExchange(t, []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
	})
	if !strings.Contains(resp, "407") {
		t.Fatalf("expected 407, got: %s", resp)
	}
	if !strings.Contains(resp, "Proxy-Authenticate: NTLM") {
		t.Fatalf("missing Proxy-Authenticate header: %s", resp)
	}
}

func TestHandleProxy_BasicAuth(t *testing.T) {
	creds := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	resp := proxyExchange(t, []string{
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic " + creds + "\r\n\r\n",
	})
	if !strings.Contains(resp, "407") {
		t.Fatalf("expected 407 for basic auth: %s", resp)
	}
}

func TestHandleProxy_NTLMExchange(t *testing.T) {
	initSession("1122334455667788")

	type1 := buildType1(0x00000001, "", "")
	type1b64 := base64.StdEncoding.EncodeToString(type1)

	server, client := net.Pipe()
	results := make(chan string, 10)

	go func() {
		defer server.Close()
		handleProxy(server)
	}()

	client.SetDeadline(time.Now().Add(3 * time.Second))

	// Send Type1
	req1 := fmt.Sprintf("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: NTLM %s\r\n\r\n", type1b64)
	client.Write([]byte(req1))

	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	resp1 := string(buf[:n])
	results <- resp1

	if !strings.Contains(resp1, "407") {
		t.Fatalf("Type1: expected 407 with challenge, got: %s", resp1)
	}

	// Extract challenge from Proxy-Authenticate header and send Type3
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "eve", lmResp, ntResp)
	type3b64 := base64.StdEncoding.EncodeToString(type3)

	req3 := fmt.Sprintf("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: NTLM %s\r\n\r\n", type3b64)
	client.Write([]byte(req3))
	n2, _ := client.Read(buf)
	resp3 := string(buf[:n2])
	results <- resp3

	close(results)
	client.Close()

	// At minimum, no crash and some 407 response
	if !strings.Contains(resp1, "407") {
		t.Fatalf("proxy NTLM exchange: no 407 in Type1 response")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FTP handler via net.Pipe
// ─────────────────────────────────────────────────────────────────────────────

func ftpExchange(t *testing.T, send func(write func(string), read func() string)) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleFTP(server)
	}()

	client.SetDeadline(time.Now().Add(3 * time.Second))
	r := make([]byte, 4096)

	write := func(s string) { client.Write([]byte(s + "\r\n")) }
	readLine := func() string {
		n, _ := client.Read(r)
		return string(r[:n])
	}

	readLine() // banner "220 ..."
	send(write, readLine)
	client.Close()
	<-done
}

func TestFTP_UserPass(t *testing.T) {
	ftpExchange(t, func(write func(string), read func() string) {
		write("USER bob")
		resp := read()
		if !strings.Contains(resp, "331") {
			t.Fatalf("expected 331, got %s", resp)
		}
		write("PASS secret")
		resp2 := read()
		if !strings.Contains(resp2, "530") {
			t.Fatalf("expected 530, got %s", resp2)
		}
	})
}

func TestFTP_Quit(t *testing.T) {
	ftpExchange(t, func(write func(string), read func() string) {
		write("QUIT")
		resp := read()
		if !strings.Contains(resp, "221") {
			t.Fatalf("expected 221, got %s", resp)
		}
	})
}

func TestFTP_Unknown(t *testing.T) {
	ftpExchange(t, func(write func(string), read func() string) {
		write("HELP")
		resp := read()
		if !strings.Contains(resp, "530") {
			t.Fatalf("expected 530 for unknown cmd, got %s", resp)
		}
	})
}

func TestFTP_AuthNTLM(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	type1b64 := base64.StdEncoding.EncodeToString(type1)

	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "ftpuser", lmResp, ntResp)
	type3b64 := base64.StdEncoding.EncodeToString(type3)

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleFTP(server)
	}()

	client.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)

	readResp := func() string {
		n, _ := client.Read(buf)
		return string(buf[:n])
	}
	send := func(s string) { client.Write([]byte(s + "\r\n")) }

	readResp() // banner

	send("AUTH NTLM")
	readResp() // 334
	send(type1b64)
	readResp() // 334 challenge
	send(type3b64)
	resp := readResp() // 530
	if !strings.Contains(resp, "530") {
		t.Fatalf("expected 530 after type3, got: %s", resp)
	}
	client.Close()
	<-done
}

func TestFTP_AuthNTLM_InlineToken(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	type1b64 := base64.StdEncoding.EncodeToString(type1)

	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "ftpuser2", lmResp, ntResp)
	type3b64 := base64.StdEncoding.EncodeToString(type3)

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleFTP(server)
	}()

	client.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	readResp := func() string {
		n, _ := client.Read(buf)
		return string(buf[:n])
	}
	send := func(s string) { client.Write([]byte(s + "\r\n")) }

	readResp()
	// Inline token on AUTH line
	send("AUTH NTLM " + type1b64)
	readResp() // 334 challenge
	send(type3b64)
	resp := readResp()
	if !strings.Contains(resp, "530") {
		t.Fatalf("inline auth: want 530, got %s", resp)
	}
	client.Close()
	<-done
}

// ─────────────────────────────────────────────────────────────────────────────
// logger.go
// ─────────────────────────────────────────────────────────────────────────────

func TestSaveHash_DeduplicatesAndPersists(t *testing.T) {
	f := filepath.Join(t.TempDir(), "hashes.txt")
	outFile = f
	hashLog = nil

	saveHash("hash1")
	saveHash("hash1") // duplicate — should not write twice
	saveHash("hash2")

	if len(hashLog) != 2 {
		t.Fatalf("want 2 unique hashes, got %d", len(hashLog))
	}
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read hash file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines in file, got %d: %v", len(lines), lines)
	}
}

func TestSaveHash_BadFile(t *testing.T) {
	outFile = "/dev/null/impossible/path"
	hashLog = nil
	// Should not panic — just logs an error
	saveHash("orphaned-hash")
	outFile = filepath.Join(os.TempDir(), "go-responder-test-hashes.txt")
}

func TestLogFunctions(t *testing.T) {
	// Just confirm they don't panic
	verbose = true
	logInfo("info %d", 1)
	logSuccess("success %s", "ok")
	logError("error %v", fmt.Errorf("test"))
	logVerbose("verbose %q", "msg")
	verbose = false
	logVerbose("should not print")
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP server integration — serveHTTP startup check
// ─────────────────────────────────────────────────────────────────────────────

func TestServeHTTP_Mux(t *testing.T) {
	// Test that the HTTP mux correctly routes WPAD and falls through to NTLM handler
	wpadEnabled = true
	wpadProxyHost = "10.0.0.1:3128"
	defer func() { wpadEnabled = false; wpadProxyHost = "" }()

	mux := http.NewServeMux()
	mux.HandleFunc("/wpad.dat", handleWPAD)
	mux.HandleFunc("/wpad/wpad.dat", handleWPAD)
	mux.HandleFunc("/proxy.pac", handleWPAD)
	mux.HandleFunc("/", handleHTTPNTLM)

	// WPAD route
	req := httptest.NewRequest("GET", "/wpad.dat", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("WPAD route: want 200, got %d", rr.Code)
	}

	// NTLM route
	req2 := httptest.NewRequest("GET", "/anything", nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != 401 {
		t.Fatalf("NTLM route: want 401, got %d", rr2.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// kerberos.go — pure parsing logic
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleKerberosPacket_TooShort(t *testing.T) {
	// Should not panic
	handleKerberosPacket([]byte{1, 2, 3}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
}

func TestHandleKerberosPacket_WrongTag(t *testing.T) {
	// A SEQUENCE with unknown application tag
	pkt := []byte{0x30, 0x03, 0x02, 0x01, 0x05} // SEQUENCE { INTEGER 5 }
	handleKerberosPacket(pkt, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
}

func TestParsePrincipalName_Empty(t *testing.T) {
	// Empty data — should return ""
	if parsePrincipalName(nil) != "" {
		t.Fatal("expected empty string for nil data")
	}
	if parsePrincipalName([]byte{}) != "" {
		t.Fatal("expected empty string for empty data")
	}
	if parsePrincipalName([]byte{0xff, 0xff}) != "" {
		t.Fatal("expected empty string for invalid ASN.1")
	}
}

func TestParseReqBody_Empty(t *testing.T) {
	p, r := parseReqBody(nil)
	if p != "" || r != "" {
		t.Fatal("expected empty principal/realm for nil data")
	}
}

func TestParsePAData_Empty(t *testing.T) {
	entries := parsePAData(nil)
	if entries != nil {
		t.Fatal("expected nil for nil input")
	}
	entries2 := parsePAData([]byte{0x30, 0x00}) // empty SEQUENCE
	_ = entries2 // may be nil or empty — just no panic
}

func TestParseKDCReq_Empty(t *testing.T) {
	p, r, pa := parseKDCReq(nil)
	if p != "" || r != "" || len(pa) != 0 {
		t.Fatal("expected empty results for nil data")
	}
}
