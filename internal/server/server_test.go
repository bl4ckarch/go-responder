package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-responder/internal/core"
)

func init() {
	core.OutFile = filepath.Join(os.TempDir(), "go-responder-server-test-hashes.txt")
	core.InitSession("1122334455667788")
}

// ─── dial helper ─────────────────────────────────────────────────────────────

func pipeConn() (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	server := <-ch
	return client, server
}

// ─── NTLM helpers ────────────────────────────────────────────────────────────

func buildType1Blob() []byte {
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(1))
	binary.Write(&b, binary.LittleEndian, uint32(0x00000001|0x00002000|0x00001000|0x02000000))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint32(32))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint32(32))
	return b.Bytes()
}

func buildType3Blob(challenge [8]byte) []byte {
	domain := core.EncodeUTF16LE("TESTDOM")
	username := core.EncodeUTF16LE("testuser")
	lmResp := make([]byte, 24)
	ntProofStr := make([]byte, 16)
	blob := make([]byte, 28)
	ntResp := append(ntProofStr, blob...)
	hdrSize := 64
	lmOff := uint32(hdrSize)
	ntOff := lmOff + uint32(len(lmResp))
	domOff := ntOff + uint32(len(ntResp))
	userOff := domOff + uint32(len(domain))

	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	binary.Write(&b, binary.LittleEndian, uint32(3))
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(lmResp)))
	binary.Write(&b, binary.LittleEndian, lmOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, uint16(len(ntResp)))
	binary.Write(&b, binary.LittleEndian, ntOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(domain)))
	binary.Write(&b, binary.LittleEndian, uint16(len(domain)))
	binary.Write(&b, binary.LittleEndian, domOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(username)))
	binary.Write(&b, binary.LittleEndian, uint16(len(username)))
	binary.Write(&b, binary.LittleEndian, userOff)
	wsOff := userOff + uint32(len(username))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, wsOff)
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, wsOff)
	binary.Write(&b, binary.LittleEndian, uint32(0x00000001))
	b.Write(lmResp)
	b.Write(ntResp)
	b.Write(domain)
	b.Write(username)
	return b.Bytes()
}

// ─── FTP tests ───────────────────────────────────────────────────────────────

func TestHandleFTP_AuthNTLM(t *testing.T) {
	core.ResetHashLog()
	client, server := pipeConn()
	defer client.Close()
	go HandleFTP(server)

	challenge := core.GetChallenge()
	r := bufio.NewReader(client)

	banner, _ := r.ReadString('\n')
	if !strings.HasPrefix(banner, "220") {
		t.Fatalf("want 220 banner, got: %q", banner)
	}

	type1 := buildType1Blob()
	fmt.Fprintf(client, "AUTH NTLM\r\n")
	resp334a, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp334a, "334") {
		t.Fatalf("want 334 for AUTH NTLM, got %q", resp334a)
	}

	fmt.Fprintf(client, "%s\r\n", base64.StdEncoding.EncodeToString(type1))
	resp334b, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp334b, "334") {
		t.Fatalf("want 334 challenge, got %q", resp334b)
	}

	type3 := buildType3Blob(challenge)
	fmt.Fprintf(client, "%s\r\n", base64.StdEncoding.EncodeToString(type3))
	resp530, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp530, "530") {
		t.Fatalf("want 530 after type3, got %q", resp530)
	}

	if len(core.HashLog) == 0 {
		t.Fatal("expected hash to be captured")
	}
}

func TestHandleFTP_PlaintextUser(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleFTP(server)

	r := bufio.NewReader(client)
	r.ReadString('\n') // banner

	fmt.Fprintf(client, "USER admin\r\n")
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "331") {
		t.Fatalf("want 331, got %q", resp)
	}

	fmt.Fprintf(client, "PASS password123\r\n")
	resp2, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp2, "530") {
		t.Fatalf("want 530, got %q", resp2)
	}
}

func TestHandleFTP_Quit(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleFTP(server)

	r := bufio.NewReader(client)
	r.ReadString('\n')
	fmt.Fprintf(client, "QUIT\r\n")
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "221") {
		t.Fatalf("want 221, got %q", resp)
	}
}

func TestHandleFTP_UnknownCmd(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleFTP(server)

	r := bufio.NewReader(client)
	r.ReadString('\n')
	fmt.Fprintf(client, "LIST\r\n")
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "530") {
		t.Fatalf("want 530, got %q", resp)
	}
}

// ─── SMTP tests ───────────────────────────────────────────────────────────────

func TestHandleSMTP_AuthNTLM(t *testing.T) {
	core.ResetHashLog()
	client, server := pipeConn()
	defer client.Close()
	go HandleSMTP(server)

	challenge := core.GetChallenge()
	r := bufio.NewReader(client)

	banner, _ := r.ReadString('\n')
	if !strings.HasPrefix(banner, "220") {
		t.Fatalf("want 220, got %q", banner)
	}

	fmt.Fprintf(client, "EHLO test\r\n")
	for {
		line, _ := r.ReadString('\n')
		if strings.HasPrefix(line, "250 ") || strings.HasPrefix(line, "250-") {
			if !strings.Contains(line, "-") {
				break
			}
		}
		if !strings.HasPrefix(line, "250") {
			break
		}
	}

	fmt.Fprintf(client, "AUTH NTLM\r\n")
	resp334, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp334, "334") {
		t.Fatalf("want 334, got %q", resp334)
	}

	type1 := buildType1Blob()
	fmt.Fprintf(client, "%s\r\n", base64.StdEncoding.EncodeToString(type1))
	resp334b, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp334b, "334") {
		t.Fatalf("want 334 challenge, got %q", resp334b)
	}

	type3 := buildType3Blob(challenge)
	fmt.Fprintf(client, "%s\r\n", base64.StdEncoding.EncodeToString(type3))
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "535") && !strings.HasPrefix(resp, "235") {
		t.Fatalf("want 535 or 235, got %q", resp)
	}
}

// ─── POP3 tests ───────────────────────────────────────────────────────────────

func TestHandlePOP3_AuthNTLM(t *testing.T) {
	core.ResetHashLog()
	client, server := pipeConn()
	defer client.Close()
	go HandlePOP3(server)

	challenge := core.GetChallenge()
	r := bufio.NewReader(client)

	banner, _ := r.ReadString('\n')
	if !strings.HasPrefix(banner, "+OK") {
		t.Fatalf("want +OK banner, got %q", banner)
	}

	type1 := buildType1Blob()
	fmt.Fprintf(client, "AUTH NTLM %s\r\n", base64.StdEncoding.EncodeToString(type1))
	resp334, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp334, "+") {
		t.Fatalf("want + challenge, got %q", resp334)
	}

	type3 := buildType3Blob(challenge)
	fmt.Fprintf(client, "%s\r\n", base64.StdEncoding.EncodeToString(type3))
	resp, _ := r.ReadString('\n')
	_ = resp
}

// ─── IMAP tests ───────────────────────────────────────────────────────────────

func TestHandleIMAP_AuthNTLM(t *testing.T) {
	core.ResetHashLog()
	client, server := pipeConn()
	defer client.Close()
	go HandleIMAP(server)

	challenge := core.GetChallenge()
	r := bufio.NewReader(client)

	banner, _ := r.ReadString('\n')
	if !strings.Contains(banner, "OK") {
		t.Fatalf("want OK banner, got %q", banner)
	}

	type1 := buildType1Blob()
	fmt.Fprintf(client, "a001 AUTHENTICATE NTLM %s\r\n", base64.StdEncoding.EncodeToString(type1))
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "+") && !strings.Contains(resp, "NO") {
		t.Fatalf("want + or NO, got %q", resp)
	}

	if strings.HasPrefix(resp, "+") {
		type3 := buildType3Blob(challenge)
		fmt.Fprintf(client, "%s\r\n", base64.StdEncoding.EncodeToString(type3))
		resp2, _ := r.ReadString('\n')
		_ = resp2
	}
}

// ─── LDAP tests ───────────────────────────────────────────────────────────────

func buildLDAPSimpleBind(msgID int, dn, password string) []byte {
	ver := []byte{0x02, 0x01, 0x03}
	dnBytes := []byte{0x04, byte(len(dn))}
	dnBytes = append(dnBytes, dn...)
	passBytes := []byte{0x80, byte(len(password))}
	passBytes = append(passBytes, password...)
	body := append(ver, dnBytes...)
	body = append(body, passBytes...)
	bind := append([]byte{0x60, byte(len(body))}, body...)

	msgIDBytes := []byte{0x02, 0x01, byte(msgID)}
	msg := append(msgIDBytes, bind...)
	return append([]byte{0x30, byte(len(msg))}, msg...)
}

func TestHandleLDAP_SimpleBind_Cleartext(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleLDAP(server)

	pkt := buildLDAPSimpleBind(1, "cn=admin,dc=test,dc=local", "secret123")
	client.Write(pkt)

	resp := make([]byte, 256)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(resp)
	if n == 0 {
		t.Fatal("expected LDAP response")
	}
	if resp[0] != 0x30 {
		t.Fatalf("expected SEQUENCE 0x30, got 0x%02x", resp[0])
	}
}

// ─── MSSQL tests ──────────────────────────────────────────────────────────────

func buildTDSPacket(ptype byte, payload []byte) []byte {
	hdr := make([]byte, 8)
	hdr[0] = ptype
	hdr[1] = 0x01
	binary.BigEndian.PutUint16(hdr[2:4], uint16(8+len(payload)))
	hdr[6] = 0x01
	return append(hdr, payload...)
}

func TestHandleMSSQL_Prelogin(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleMSSQL(server)

	prelogin := buildTDSPacket(0x12, []byte{
		0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	client.Write(prelogin)

	resp := make([]byte, 512)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(resp)
	if n < 8 {
		t.Fatalf("MSSQL prelogin: expected at least 8 bytes, got %d", n)
	}
	if resp[0] != 0x04 {
		t.Fatalf("expected TDS_TABULAR_RESULT (0x04), got 0x%02x", resp[0])
	}
}

// ─── SMB2 tests ───────────────────────────────────────────────────────────────

func buildSMB2NegotiateReq() []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 0x53, 0x4D, 0x42})
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[12:14], 0x0000)
	binary.LittleEndian.PutUint32(hdr[16:20], 0x00000001)

	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(36))
	binary.Write(&body, binary.LittleEndian, uint16(1))
	binary.Write(&body, binary.LittleEndian, uint16(0))
	binary.Write(&body, binary.LittleEndian, uint16(0))
	body.Write(make([]byte, 16))
	binary.Write(&body, binary.LittleEndian, uint32(0))
	binary.Write(&body, binary.LittleEndian, uint32(0))
	binary.Write(&body, binary.LittleEndian, uint16(0x0210))

	return append(hdr, body.Bytes()...)
}

func buildSMB2SessionSetupType1(challenge [8]byte) []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 0x53, 0x4D, 0x42})
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[12:14], 0x0001)

	ntlm := buildType1Blob()
	spnego := core.BuildSPNEGONegotiateToken()
	_ = spnego
	secBlob := ntlm

	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(25))
	binary.Write(&body, binary.LittleEndian, uint8(0))
	binary.Write(&body, binary.LittleEndian, uint8(0))
	binary.Write(&body, binary.LittleEndian, uint32(0))
	binary.Write(&body, binary.LittleEndian, uint64(0))
	binary.Write(&body, binary.LittleEndian, uint16(64+24))
	binary.Write(&body, binary.LittleEndian, uint16(len(secBlob)))
	body.Write(secBlob)

	return append(hdr, body.Bytes()...)
}

func sendNBFrame(conn net.Conn, data []byte) {
	hdr := []byte{0x00, byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}
	conn.Write(append(hdr, data...))
}

func readNBFrame(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	msgLen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if msgLen == 0 {
		return nil, nil
	}
	msg := make([]byte, msgLen)
	_, err := io.ReadFull(conn, msg)
	return msg, err
}

func TestHandleSMB_SMB2Negotiate(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleSMB(server)

	sendNBFrame(client, buildSMB2NegotiateReq())
	resp, err := readNBFrame(client)
	if err != nil {
		t.Fatalf("read SMB2 negotiate resp: %v", err)
	}
	if len(resp) < 4 {
		t.Fatal("SMB2 negotiate response too short")
	}
	if !bytes.HasPrefix(resp, []byte{0xFE, 0x53, 0x4D, 0x42}) {
		t.Fatalf("expected SMB2 magic, got %v", resp[:4])
	}
	cmd := binary.LittleEndian.Uint16(resp[12:14])
	if cmd != 0x0000 {
		t.Fatalf("expected NegotiateResp cmd 0x0000, got 0x%04x", cmd)
	}
}

func TestHandleSMB_SMB1Negotiate_SMB2Upgrade(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleSMB(server)

	// Build SMB1 header (32 bytes)
	var msg []byte
	msg = append(msg, 0xFF, 0x53, 0x4D, 0x42) // magic
	msg = append(msg, 0x72)                     // cmd: Negotiate
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)  // status
	msg = append(msg, 0x88)                     // flags
	msg = append(msg, 0x53, 0xC8)              // flags2
	msg = append(msg, make([]byte, 20)...)      // pad to 32 bytes total

	// Build body: WordCount(1) + ByteCount(2) + dialects
	dialects := []byte{0x02}
	dialects = append(dialects, []byte("SMB 2.???")...)
	dialects = append(dialects, 0x00)
	dialects = append(dialects, 0x02)
	dialects = append(dialects, []byte("NT LM 0.12")...)
	dialects = append(dialects, 0x00)

	msg = append(msg, 0x00) // wc=0
	msg = binary.LittleEndian.AppendUint16(msg, uint16(len(dialects)))
	msg = append(msg, dialects...)

	sendNBFrame(client, msg)

	resp, err := readNBFrame(client)
	if err != nil {
		t.Fatalf("read SMB1->SMB2 upgrade resp: %v", err)
	}
	if len(resp) < 4 {
		t.Fatal("SMB upgrade response too short")
	}
	if !bytes.HasPrefix(resp, []byte{0xFE, 0x53, 0x4D, 0x42}) {
		t.Fatalf("expected SMB2 magic in upgrade resp, got %02x", resp[:4])
	}
}

// ─── DCE-RPC tests ────────────────────────────────────────────────────────────

func buildDCERPCPkt(ptype byte, callID uint32, body []byte, authVerif []byte) []byte {
	var authLen uint16
	if authVerif != nil {
		authLen = uint16(len(authVerif) - 8)
	}
	fragLen := uint16(16 + len(body) + len(authVerif))
	hdr := buildDCERPCHeader(ptype, fragLen, authLen, callID)
	pkt := append(hdr, body...)
	if authVerif != nil {
		pkt = append(pkt, authVerif...)
	}
	return pkt
}

func buildDCERPCBindBody() []byte {
	var body []byte
	body = append(body, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00)
	body = append(body, 0x01, 0x00)
	body = append(body, 0x00, 0x00, 0x00, 0x00)
	body = append(body, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	body = append(body, 0x00, 0x00, 0x00, 0x00)
	body = append(body,
		0x6b, 0xfb, 0xd1, 0x5b, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	)
	return body
}

func buildDCERPCAuthVerifFull(authType byte, contextID uint32, ntlmBlob []byte) []byte {
	av := make([]byte, 8+len(ntlmBlob))
	av[0] = authType
	av[1] = 0x02
	binary.LittleEndian.PutUint32(av[4:8], contextID)
	copy(av[8:], ntlmBlob)
	return av
}

func TestHandleDCERPC_BindNoAuth(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleDCERPC(server)

	body := buildDCERPCBindBody()
	pkt := buildDCERPCPkt(rpcPTYPEBind, 1, body, nil)
	client.Write(pkt)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, _ := client.Read(resp)
	if n < 16 {
		t.Fatalf("BindAck too short: %d bytes", n)
	}
	if resp[2] != rpcPTYPEBindAck {
		t.Fatalf("expected BindAck (0x%02x), got 0x%02x", rpcPTYPEBindAck, resp[2])
	}
}

func TestHandleDCERPC_BindWithNTLMType1(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleDCERPC(server)

	type1 := buildType1Blob()
	av := buildDCERPCAuthVerifFull(rpcAuthNTLM, 0x01, type1)
	body := buildDCERPCBindBody()
	pkt := buildDCERPCPkt(rpcPTYPEBind, 2, body, av)
	client.Write(pkt)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 1024)
	n, _ := client.Read(resp)
	if n < 16 {
		t.Fatalf("BindAck with challenge too short: %d bytes", n)
	}
	if resp[2] != rpcPTYPEBindAck {
		t.Fatalf("expected BindAck, got 0x%02x", resp[2])
	}
}

func TestHandleDCERPC_Auth3Type3CapturesHash(t *testing.T) {
	core.ResetHashLog()
	client, server := pipeConn()
	defer client.Close()
	go HandleDCERPC(server)

	challenge := core.GetChallenge()

	type1 := buildType1Blob()
	av1 := buildDCERPCAuthVerifFull(rpcAuthNTLM, 0x01, type1)
	body := buildDCERPCBindBody()
	bindPkt := buildDCERPCPkt(rpcPTYPEBind, 1, body, av1)
	client.Write(bindPkt)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp1 := make([]byte, 1024)
	client.Read(resp1)

	type3 := buildType3Blob(challenge)
	auth3Body := make([]byte, 12)
	av3 := buildDCERPCAuthVerifFull(rpcAuthNTLM, 0x01, type3)
	auth3Pkt := buildDCERPCPkt(rpcPTYPEAuth3, 2, auth3Body, av3)
	client.Write(auth3Pkt)

	time.Sleep(200 * time.Millisecond)
	if len(core.HashLog) == 0 {
		t.Fatal("expected hash to be captured via DCE-RPC")
	}
}

func TestHandleDCERPC_Request_ReturnsFFault(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleDCERPC(server)

	body := make([]byte, 20)
	pkt := buildDCERPCPkt(rpcPTYPERequest, 5, body, nil)
	client.Write(pkt)

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 128)
	n, _ := client.Read(resp)
	if n < 16 {
		t.Fatalf("fault too short: %d", n)
	}
	if resp[2] != rpcPTYPEFault {
		t.Fatalf("expected FAULT (0x%02x), got 0x%02x", rpcPTYPEFault, resp[2])
	}
}

// ─── DCE-RPC helper unit tests ────────────────────────────────────────────────

func TestBuildDCERPCHeader_Fields(t *testing.T) {
	hdr := buildDCERPCHeader(rpcPTYPEBind, 0x0050, 0x0020, 0x00000003)
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		t.Fatal("RPC version mismatch")
	}
	if hdr[2] != rpcPTYPEBind {
		t.Fatalf("ptype mismatch: got 0x%02x", hdr[2])
	}
	if binary.LittleEndian.Uint16(hdr[8:10]) != 0x0050 {
		t.Fatal("fragLen mismatch")
	}
	if binary.LittleEndian.Uint16(hdr[10:12]) != 0x0020 {
		t.Fatal("authLen mismatch")
	}
	if binary.LittleEndian.Uint32(hdr[12:16]) != 3 {
		t.Fatal("callID mismatch")
	}
}

// ─── Proxy tests ──────────────────────────────────────────────────────────────

func TestHandleProxy_NoAuth(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleProxy(server)

	fmt.Fprintf(client, "CONNECT example.com:443 HTTP/1.1\r\n")
	fmt.Fprintf(client, "Host: example.com\r\n")
	fmt.Fprintf(client, "\r\n")

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(client)
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/1.1 407") {
		t.Fatalf("want 407, got %q", line)
	}
}

func TestHandleProxy_NTLMType1(t *testing.T) {
	client, server := pipeConn()
	defer client.Close()
	go HandleProxy(server)

	type1 := buildType1Blob()
	encoded := base64.StdEncoding.EncodeToString(type1)

	fmt.Fprintf(client, "CONNECT example.com:443 HTTP/1.1\r\n")
	fmt.Fprintf(client, "Host: example.com\r\n")
	fmt.Fprintf(client, "Proxy-Authorization: NTLM %s\r\n", encoded)
	fmt.Fprintf(client, "\r\n")

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(client)
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "HTTP/1.1 407") {
		t.Fatalf("want 407 with NTLM challenge, got %q", line)
	}
}

func TestHandleProxy_FullNTLMExchange(t *testing.T) {
	core.ResetHashLog()
	client, server := pipeConn()
	defer client.Close()
	go HandleProxy(server)

	challenge := core.GetChallenge()
	r := bufio.NewReader(client)

	drainHeaders := func() {
		for {
			l, _ := r.ReadString('\n')
			if l == "\r\n" || l == "" {
				break
			}
		}
	}

	type1 := buildType1Blob()
	encoded1 := base64.StdEncoding.EncodeToString(type1)
	fmt.Fprintf(client, "CONNECT example.com:443 HTTP/1.1\r\n")
	fmt.Fprintf(client, "Host: example.com\r\n")
	fmt.Fprintf(client, "Proxy-Authorization: NTLM %s\r\n", encoded1)
	fmt.Fprintf(client, "\r\n")

	firstLine, _ := r.ReadString('\n')
	if !strings.HasPrefix(firstLine, "HTTP/1.1 407") {
		t.Fatalf("type1 want 407, got %q", firstLine)
	}
	drainHeaders()

	type3 := buildType3Blob(challenge)
	encoded3 := base64.StdEncoding.EncodeToString(type3)
	fmt.Fprintf(client, "CONNECT example.com:443 HTTP/1.1\r\n")
	fmt.Fprintf(client, "Host: example.com\r\n")
	fmt.Fprintf(client, "Proxy-Authorization: NTLM %s\r\n", encoded3)
	fmt.Fprintf(client, "\r\n")

	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "HTTP/1.1 407") {
		t.Logf("type3 resp: %q (server closed after hash capture)", resp)
	}

	time.Sleep(200 * time.Millisecond)
	if len(core.HashLog) == 0 {
		t.Fatal("expected hash captured via proxy NTLM")
	}
}

// ─── LDAP BER helpers ────────────────────────────────────────────────────────

func TestBerTag_SmallData(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	result := berTag(0x30, data)
	if result[0] != 0x30 {
		t.Fatalf("want tag 0x30, got 0x%02x", result[0])
	}
	if result[1] != 0x03 {
		t.Fatalf("want length 3, got 0x%02x", result[1])
	}
	if !bytes.Equal(result[2:], data) {
		t.Fatal("data mismatch")
	}
}

func TestBerTag_LargeData(t *testing.T) {
	data := make([]byte, 200)
	result := berTag(0x04, data)
	if result[0] != 0x04 {
		t.Fatalf("tag mismatch")
	}
	if result[1] != 0x81 {
		t.Fatalf("expected 0x81 for long form, got 0x%02x", result[1])
	}
}

func TestBerReadLen_ShortForm(t *testing.T) {
	if l := berReadLen([]byte{0x05}); l != 5 {
		t.Fatalf("want 5, got %d", l)
	}
}

func TestBerReadLen_LongForm(t *testing.T) {
	if l := berReadLen([]byte{0x81, 0x80}); l != 128 {
		t.Fatalf("want 128, got %d", l)
	}
}

func TestBerLenBytes(t *testing.T) {
	if berLenBytes(0x7f) != 1 {
		t.Fatal("short form should be 1")
	}
	if berLenBytes(0x80) != 2 {
		t.Fatal("medium form should be 2")
	}
	if berLenBytes(0x100) != 3 {
		t.Fatal("long form should be 3")
	}
}
