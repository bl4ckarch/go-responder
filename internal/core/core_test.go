package core

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	OutFile = filepath.Join(os.TempDir(), "go-responder-core-test-hashes.txt")
	InitSession("")
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func buildType1(flags uint32, domain, workstation string) []byte {
	domBytes := []byte(domain)
	wsBytes := []byte(workstation)
	domOff := uint32(32)
	wsOff := domOff + uint32(len(domBytes))
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(1))
	binary.Write(&b, binary.LittleEndian, flags)
	binary.Write(&b, binary.LittleEndian, uint16(len(domBytes)))
	binary.Write(&b, binary.LittleEndian, uint16(len(domBytes)))
	binary.Write(&b, binary.LittleEndian, domOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(wsBytes)))
	binary.Write(&b, binary.LittleEndian, uint16(len(wsBytes)))
	binary.Write(&b, binary.LittleEndian, wsOff)
	b.Write(domBytes)
	b.Write(wsBytes)
	return b.Bytes()
}

func buildType3(domain, username string, lmResp, ntResp []byte) []byte {
	encDomain := EncodeUTF16LE(domain)
	encUser := EncodeUTF16LE(username)
	hdrSize := 64
	lmOff := uint32(hdrSize)
	ntOff := lmOff + uint32(len(lmResp))
	domOff := ntOff + uint32(len(ntResp))
	userOff := domOff + uint32(len(encDomain))
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(3))
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, lmOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, ntOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(encDomain)))
	binary.Write(&b, binary.LittleEndian, uint16(len(encDomain)))
	binary.Write(&b, binary.LittleEndian, domOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(encUser)))
	binary.Write(&b, binary.LittleEndian, uint16(len(encUser)))
	binary.Write(&b, binary.LittleEndian, userOff)
	wsOff := userOff + uint32(len(encUser))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, wsOff)
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, wsOff)
	binary.Write(&b, binary.LittleEndian, uint32(0x00000001))
	b.Write(lmResp)
	b.Write(ntResp)
	b.Write(encDomain)
	b.Write(encUser)
	return b.Bytes()
}

// ─── config.go ───────────────────────────────────────────────────────────────

func TestInitSession_Random(t *testing.T) {
	InitSession("")
	c := GetChallenge()
	allZero := true
	for _, b := range c {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("challenge is all zeros")
	}
}

func TestInitSession_Fixed(t *testing.T) {
	InitSession("1122334455667788")
	c := GetChallenge()
	want := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if c != want {
		t.Fatalf("want %x got %x", want, c)
	}
	if ChallengeHexStr() != "1122334455667788" {
		t.Fatalf("challengeHexStr mismatch: %s", ChallengeHexStr())
	}
}

func TestInitSession_InvalidHex(t *testing.T) {
	InitSession("ZZZZZZZZZZZZZZZZ")
	InitSession("")
}

func TestGenMachineName(t *testing.T) {
	name := GenMachineName()
	if !strings.HasPrefix(name, "WIN-") {
		t.Fatalf("expected WIN- prefix, got %s", name)
	}
	if len(name) != 13 {
		t.Fatalf("expected len 13, got %d (%s)", len(name), name)
	}
}

func TestGenDomainName(t *testing.T) {
	d := GenDomainName()
	if !strings.HasSuffix(d, ".LOCAL") {
		t.Fatalf("expected .LOCAL suffix, got %s", d)
	}
}

func TestGenPort(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := GenPort()
		if p < 20000 || p >= 50000 {
			t.Fatalf("port %d out of expected range [20000, 50000)", p)
		}
	}
}

func TestNewChallenge(t *testing.T) {
	InitSession("aabbccddeeff0011")
	c := NewChallenge()
	want := GetChallenge()
	if c != want {
		t.Fatalf("NewChallenge mismatch: %x vs %x", c, want)
	}
}

// ─── filter.go ───────────────────────────────────────────────────────────────

func TestParseIPList(t *testing.T) {
	ips := ParseIPList("192.168.1.1,10.0.0.1")
	if len(ips) != 2 {
		t.Fatalf("want 2 IPs, got %d", len(ips))
	}
	empty := ParseIPList("")
	if len(empty) != 0 {
		t.Fatal("expected empty slice for empty input")
	}
	skipped := ParseIPList("not-an-ip,10.0.0.1")
	if len(skipped) != 1 {
		t.Fatalf("want 1 valid IP, got %d", len(skipped))
	}
}

func TestParseNameList(t *testing.T) {
	names := ParseNameList("host1,host2,  host3  ")
	if len(names) != 3 {
		t.Fatalf("want 3, got %d", len(names))
	}
	if len(ParseNameList("")) != 0 {
		t.Fatal("expected empty")
	}
}

func TestAddrToIP(t *testing.T) {
	udp := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 137}
	if got := AddrToIP(udp); !got.Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("UDPAddr: got %s", got)
	}
	tcp := &net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 80}
	if got := AddrToIP(tcp); !got.Equal(net.ParseIP("5.6.7.8")) {
		t.Fatalf("TCPAddr: got %s", got)
	}
	if got := AddrToIP(nil); got != nil {
		t.Fatalf("nil addr: expected nil, got %s", got)
	}
}

func TestShouldRespond_NoFilters(t *testing.T) {
	RespondToIPs = nil
	DontRespondIPs = nil
	RespondToNames = nil
	DontRespondNames = nil
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if !ShouldRespond(src, "ANYTHING") {
		t.Fatal("should respond with no filters set")
	}
}

func TestShouldRespond_DontRespondTo(t *testing.T) {
	DontRespondIPs = ParseIPList("10.0.0.5")
	defer func() { DontRespondIPs = nil }()
	blocked := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 137}
	if ShouldRespond(blocked, "HOST") {
		t.Fatal("should NOT respond to blocked IP")
	}
	allowed := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if !ShouldRespond(allowed, "HOST") {
		t.Fatal("should respond to non-blocked IP")
	}
}

func TestShouldRespond_RespondTo(t *testing.T) {
	RespondToIPs = ParseIPList("10.0.0.2")
	defer func() { RespondToIPs = nil }()
	allowed := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 137}
	if !ShouldRespond(allowed, "HOST") {
		t.Fatal("should respond to allowlisted IP")
	}
	other := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 137}
	if ShouldRespond(other, "HOST") {
		t.Fatal("should NOT respond to non-allowlisted IP")
	}
}

func TestShouldRespond_DontRespondToName(t *testing.T) {
	DontRespondNames = ParseNameList("BADHOST")
	defer func() { DontRespondNames = nil }()
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if ShouldRespond(src, "BADHOST") {
		t.Fatal("should NOT respond to blocked name")
	}
	if !ShouldRespond(src, "GOODHOST") {
		t.Fatal("should respond to non-blocked name")
	}
}

func TestShouldRespond_RespondToName(t *testing.T) {
	RespondToNames = ParseNameList("TARGETHOST")
	defer func() { RespondToNames = nil }()
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 137}
	if !ShouldRespond(src, "TARGETHOST") {
		t.Fatal("should respond to allowlisted name")
	}
	if ShouldRespond(src, "OTHERHOST") {
		t.Fatal("should NOT respond to non-allowlisted name")
	}
}

// ─── ntlm.go ─────────────────────────────────────────────────────────────────

func TestUTF16RoundTrip(t *testing.T) {
	for _, s := range []string{"WORKGROUP", "Administrator", "AD.TRILOCOR.LOCAL", ""} {
		got := DecodeUTF16LE(EncodeUTF16LE(s))
		if got != s {
			t.Fatalf("round-trip failed: want %q got %q", s, got)
		}
	}
}

func TestBuildNTLMChallenge_Structure(t *testing.T) {
	InitSession("deadbeefcafebabe")
	c := GetChallenge()
	pkt := BuildNTLMChallenge(c, "TESTDOM", "TESTPC")
	if !strings.HasPrefix(string(pkt), "NTLMSSP\x00") {
		t.Fatal("missing NTLMSSP signature")
	}
	if binary.LittleEndian.Uint32(pkt[8:12]) != 2 {
		t.Fatal("message type must be 2")
	}
	var got [8]byte
	copy(got[:], pkt[24:32])
	if got != c {
		t.Fatalf("challenge mismatch: want %x got %x", c, got)
	}
}

func TestBuildNTLMChallenge_LMMode(t *testing.T) {
	LMMode = true
	defer func() { LMMode = false }()
	InitSession("1122334455667788")
	c := GetChallenge()
	pkt := BuildNTLMChallenge(c, "DOM", "PC")
	flags := binary.LittleEndian.Uint32(pkt[20:24])
	if flags&0x00080000 != 0 {
		t.Fatal("LM mode: EXTENDED_SESSIONSECURITY should be absent")
	}
}

func TestFindNTLMSSP(t *testing.T) {
	sig := []byte("NTLMSSP\x00")
	data := append(sig, 0x01, 0x00, 0x00, 0x00)
	if !bytes.Equal(FindNTLMSSP(data), data) {
		t.Fatal("should find sig at offset 0")
	}
	junk := append([]byte("JUNK"), data...)
	if !bytes.Equal(FindNTLMSSP(junk), data) {
		t.Fatal("should find sig after junk")
	}
	if FindNTLMSSP([]byte("no sig here")) != nil {
		t.Fatal("should return nil when sig absent")
	}
}

func TestNtlmMsgType(t *testing.T) {
	sig := []byte("NTLMSSP\x00")
	for _, tc := range []struct{ typ uint32 }{{1}, {2}, {3}} {
		pkt := append(sig, 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(pkt[8:], tc.typ)
		if got := NTLMMsgType(pkt); got != tc.typ {
			t.Fatalf("type %d: got %d", tc.typ, got)
		}
	}
	if NTLMMsgType([]byte{1, 2, 3}) != 0 {
		t.Fatal("too-short data should return 0")
	}
}

func TestParseNTLMAuthenticate_NTLMv2(t *testing.T) {
	InitSession("1122334455667788")
	challenge := GetChallenge()
	lmResp := make([]byte, 24)
	ntProofStr := make([]byte, 16)
	blob := make([]byte, 28)
	ntResp := append(ntProofStr, blob...)
	msg := buildType3("DOMAIN", "user", lmResp, ntResp)
	hash, user, domain, err := ParseNTLMAuthenticate(msg, challenge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" || domain != "DOMAIN" {
		t.Fatalf("got user=%s domain=%s", user, domain)
	}
	parts := strings.Split(hash, ":")
	if len(parts) < 5 {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if parts[3] != strings.ToLower(hex.EncodeToString(challenge[:])) {
		t.Fatalf("challenge mismatch in hash: %s", parts[3])
	}
}

func TestParseNTLMAuthenticate_NTLMv1(t *testing.T) {
	InitSession("aabbccddeeff0011")
	challenge := GetChallenge()
	lmResp := make([]byte, 24)
	ntResp := make([]byte, 24)
	msg := buildType3("CORP", "alice", lmResp, ntResp)
	hash, user, domain, err := ParseNTLMAuthenticate(msg, challenge)
	if err != nil {
		t.Fatalf("NTLMv1 parse error: %v", err)
	}
	if user != "alice" || domain != "CORP" {
		t.Fatalf("got user=%s domain=%s", user, domain)
	}
	if !strings.HasPrefix(hash, "alice::CORP:") {
		t.Fatalf("bad NTLMv1 hash format: %s", hash)
	}
	if !strings.HasSuffix(hash, hex.EncodeToString(challenge[:])) {
		t.Fatalf("NTLMv1 hash missing challenge at end: %s", hash)
	}
}

func TestParseNTLMAuthenticate_Errors(t *testing.T) {
	challenge := GetChallenge()
	_, _, _, err := ParseNTLMAuthenticate([]byte("GARBAGE"), challenge)
	if err == nil {
		t.Fatal("expected error for garbage input")
	}
	msg := buildType1(0x00000001, "", "")
	_, _, _, err = ParseNTLMAuthenticate(msg, challenge)
	if err == nil {
		t.Fatal("expected error for type 1 message")
	}
	_, _, _, err = ParseNTLMAuthenticate([]byte("NTLMSSP\x00\x03\x00\x00\x00"), challenge)
	if err == nil {
		t.Fatal("expected error for too-short type 3")
	}
	lm := make([]byte, 4)
	nt := make([]byte, 8)
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
	_ = osVer
	ws2, dom2, _ := ParseNTLMNegotiate(buildType1(0x00000001, "", ""))
	if ws2 != "" || dom2 != "" {
		t.Fatalf("expected empty ws/domain, got %q/%q", ws2, dom2)
	}
	ws3, _, _ := ParseNTLMNegotiate([]byte("short"))
	if ws3 != "" {
		t.Fatal("expected empty for too-short data")
	}
}

func TestBuildSPNEGO(t *testing.T) {
	token := BuildSPNEGONegotiateToken()
	if len(token) == 0 {
		t.Fatal("empty SPNEGO token")
	}
	if token[0] != 0x60 {
		t.Fatalf("expected APPLICATION tag 0x60, got 0x%02x", token[0])
	}
}

func TestWrapSPNEGOChallenge(t *testing.T) {
	challenge := BuildNTLMChallenge(GetChallenge(), "DOM", "PC")
	wrapped := WrapSPNEGOChallenge(challenge)
	if len(wrapped) == 0 || wrapped[0] != 0xa1 {
		t.Fatalf("expected [1] context tag 0xa1, got 0x%02x", wrapped[0])
	}
}

func TestDerLen_LargeValues(t *testing.T) {
	l1 := DerLen(0x7f)
	if len(l1) != 1 || l1[0] != 0x7f {
		t.Fatalf("DerLen(0x7f): got %v", l1)
	}
	l2 := DerLen(0xff)
	if len(l2) != 2 || l2[0] != 0x81 {
		t.Fatalf("DerLen(0xff): got %v", l2)
	}
	l3 := DerLen(0x100)
	if len(l3) != 3 || l3[0] != 0x82 {
		t.Fatalf("DerLen(0x100): got %v", l3)
	}
}

func TestEncodeUTF16LE_Surrogate(t *testing.T) {
	s := "\U0001F600"
	b := EncodeUTF16LE(s)
	if len(b) != 2 {
		t.Fatalf("surrogate path: expected 2 bytes, got %d", len(b))
	}
	val := binary.LittleEndian.Uint16(b)
	if val != 0xFFFD {
		t.Fatalf("surrogate: expected 0xFFFD, got 0x%04x", val)
	}
}

// ─── logger.go ───────────────────────────────────────────────────────────────

func TestSaveHash_DeduplicatesAndPersists(t *testing.T) {
	f := filepath.Join(t.TempDir(), "hashes.txt")
	OutFile = f
	ResetHashLog()

	SaveHash("hash1")
	SaveHash("hash1")
	SaveHash("hash2")

	if len(HashLog) != 2 {
		t.Fatalf("want 2 unique hashes, got %d", len(HashLog))
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
	OutFile = "/dev/null/impossible/path"
	ResetHashLog()
	SaveHash("orphaned-hash")
	OutFile = filepath.Join(os.TempDir(), "go-responder-core-test-hashes.txt")
}

func TestLogFunctions(t *testing.T) {
	Verbose = true
	LogInfo("info %d", 1)
	LogSuccess("success %s", "ok")
	LogError("error %v", "test")
	LogVerbose("verbose %q", "msg")
	Verbose = false
	LogVerbose("should not print")
}

// ─── config.go ─── GetIfaceIP ────────────────────────────────────────────────

func TestGetIfaceIP_ValidInterface(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no interfaces available")
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ip, err := GetIfaceIP(iface.Name)
					if err != nil {
						t.Fatalf("GetIfaceIP(%s): %v", iface.Name, err)
					}
					if ip.To4() == nil {
						t.Fatalf("GetIfaceIP returned non-IPv4: %v", ip)
					}
					return
				}
			}
		}
	}
	t.Skip("no interface with IPv4 address")
}

func TestGetIfaceIP_InvalidInterface(t *testing.T) {
	_, err := GetIfaceIP("nonexistent99999")
	if err == nil {
		t.Fatal("expected error for nonexistent interface")
	}
}

// ─── filter.go ─── AddrToIP string fallback ──────────────────────────────────

type testAddr struct{ s string }

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return a.s }

func TestAddrToIP_StringFallback(t *testing.T) {
	ip := AddrToIP(testAddr{"10.0.0.5:1234"})
	if ip == nil || !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("string addr: expected 10.0.0.5, got %v", ip)
	}
	ip2 := AddrToIP(testAddr{"10.0.0.6"})
	_ = ip2
}
