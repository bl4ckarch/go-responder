package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

// pipeExchange opens a net.Pipe, runs fn(server) in a goroutine, returns
// a write/read helper pair, and the background done channel.
func pipeSession(t *testing.T, fn func(net.Conn)) (write func([]byte), readBytes func() []byte, done <-chan struct{}) {
	t.Helper()
	server, client := net.Pipe()
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		fn(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))

	w := func(b []byte) { client.Write(b) }
	r := func() []byte {
		buf := make([]byte, 65536)
		n, _ := client.Read(buf)
		return buf[:n]
	}
	// Close client after test
	t.Cleanup(func() { client.Close(); <-ch })
	return w, r, ch
}

// lineSession creates a loopback TCP connection (buffered by OS) so that
// multi-line protocol responses from the server don't deadlock the test.
func lineSession(t *testing.T, fn func(net.Conn)) (send func(string), recv func() string, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("lineSession listen: %v", err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		ln.Close()
		if err != nil {
			return
		}
		accepted <- c
		fn(c)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("lineSession dial: %v", err)
	}
	<-accepted // wait for server side to be accepted
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	br := bufio.NewReader(c)
	send = func(s string) { c.Write([]byte(s + "\r\n")) }
	recv = func() string {
		line, _ := br.ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	return send, recv, c
}

// ─────────────────────────────────────────────────────────────────────────────
// SMTP
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleSMTP_EHLO_Quit(t *testing.T) {
	send, recv, _ := lineSession(t, handleSMTP)
	recv() // banner
	send("EHLO client.local")
	recv() // 250-<hostname>
	recv() // 250-AUTH NTLM
	recv() // 250 AUTH NTLM
	send("QUIT")
	r := recv()
	if !strings.Contains(r, "221") {
		t.Fatalf("QUIT: want 221, got %s", r)
	}
}

func TestHandleSMTP_Unknown(t *testing.T) {
	send, recv, _ := lineSession(t, handleSMTP)
	recv()
	send("VRFY nobody")
	r := recv()
	if !strings.Contains(r, "502") {
		t.Fatalf("unknown cmd: want 502, got %s", r)
	}
}

func TestHandleSMTP_AuthNTLM(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "smtpuser", lmResp, ntResp)

	send, recv, _ := lineSession(t, handleSMTP)
	recv() // banner
	send("EHLO x")
	recv() // 250-<hostname>
	recv() // 250-AUTH NTLM
	recv() // 250 AUTH NTLM
	send("AUTH NTLM")
	recv() // 334
	send(base64.StdEncoding.EncodeToString(type1))
	recv() // 334 challenge
	send(base64.StdEncoding.EncodeToString(type3))
	r := recv()
	if !strings.Contains(r, "535") {
		t.Fatalf("AUTH NTLM: want 535, got %s", r)
	}
}

func TestHandleSMTP_AuthNTLM_InlineToken(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "smtpuser2", lmResp, ntResp)

	send, recv, _ := lineSession(t, handleSMTP)
	recv()
	send("EHLO x")
	recv() // 250-<hostname>
	recv() // 250-AUTH NTLM
	recv() // 250 AUTH NTLM
	// Inline token
	send("AUTH NTLM " + base64.StdEncoding.EncodeToString(type1))
	recv() // 334 challenge
	send(base64.StdEncoding.EncodeToString(type3))
	r := recv()
	if !strings.Contains(r, "535") {
		t.Fatalf("AUTH NTLM inline: want 535, got %s", r)
	}
}

func TestHandleSMTP_AuthNTLM_BadBase64(t *testing.T) {
	send, recv, _ := lineSession(t, handleSMTP)
	recv()
	send("AUTH NTLM !!!invalid!!!")
	r := recv()
	if !strings.Contains(r, "535") {
		t.Fatalf("bad base64: want 535, got %s", r)
	}
}

func TestHandleSMTP_AuthNTLM_WrongMsgType(t *testing.T) {
	// Send a type-2 (challenge) message instead of type-1 — should fail
	type2like := append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	send, recv, _ := lineSession(t, handleSMTP)
	recv()
	send("AUTH NTLM " + base64.StdEncoding.EncodeToString(type2like))
	r := recv()
	if !strings.Contains(r, "535") {
		t.Fatalf("wrong msg type: want 535, got %s", r)
	}
}

func TestHandleSMTP_HELO(t *testing.T) {
	send, recv, _ := lineSession(t, handleSMTP)
	recv()
	send("HELO client")
	r := recv()
	if !strings.Contains(r, "250") {
		t.Fatalf("HELO: want 250, got %s", r)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// POP3
// ─────────────────────────────────────────────────────────────────────────────

func TestHandlePOP3_CAPA_Quit(t *testing.T) {
	send, recv, _ := lineSession(t, handlePOP3)
	recv() // +OK banner
	send("CAPA")
	recv() // +OK Capability list follows
	recv() // AUTH NTLM
	recv() // USER
	recv() // .
	send("QUIT")
	r := recv()
	if !strings.Contains(r, "+OK") {
		t.Fatalf("QUIT: want +OK, got %s", r)
	}
}

func TestHandlePOP3_UserPass(t *testing.T) {
	send, recv, _ := lineSession(t, handlePOP3)
	recv()
	send("USER alice")
	r := recv()
	if !strings.Contains(r, "+OK") {
		t.Fatalf("USER: want +OK, got %s", r)
	}
	send("PASS s3cr3t")
	r2 := recv()
	if !strings.Contains(r2, "-ERR") {
		t.Fatalf("PASS: want -ERR, got %s", r2)
	}
}

func TestHandlePOP3_Unknown(t *testing.T) {
	send, recv, _ := lineSession(t, handlePOP3)
	recv()
	send("NOOP")
	r := recv()
	if !strings.Contains(r, "-ERR") {
		t.Fatalf("unknown: want -ERR, got %s", r)
	}
}

func TestHandlePOP3_AuthNTLM(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "pop3user", lmResp, ntResp)

	send, recv, _ := lineSession(t, handlePOP3)
	recv()
	send("AUTH NTLM")
	recv() // +
	send(base64.StdEncoding.EncodeToString(type1))
	recv() // + challenge
	send(base64.StdEncoding.EncodeToString(type3))
	r := recv()
	if !strings.Contains(r, "-ERR") {
		t.Fatalf("AUTH NTLM: want -ERR, got %s", r)
	}
}

func TestHandlePOP3_AuthNTLM_BadBase64(t *testing.T) {
	send, recv, _ := lineSession(t, handlePOP3)
	recv()
	send("AUTH NTLM")
	recv()
	send("!!!bad!!!")
	r := recv()
	if !strings.Contains(r, "-ERR") {
		t.Fatalf("bad base64: want -ERR, got %s", r)
	}
}

func TestHandlePOP3_AuthNTLM_WrongMsgType(t *testing.T) {
	type2like := append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	send, recv, _ := lineSession(t, handlePOP3)
	recv()
	send("AUTH NTLM")
	recv()
	send(base64.StdEncoding.EncodeToString(type2like))
	r := recv()
	if !strings.Contains(r, "-ERR") {
		t.Fatalf("wrong type: want -ERR, got %s", r)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IMAP
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleIMAP_Capability_Logout(t *testing.T) {
	send, recv, _ := lineSession(t, handleIMAP)
	recv() // * OK banner
	send("a1 CAPABILITY")
	recv() // * CAPABILITY IMAP4rev1 AUTH=NTLM
	recv() // a1 OK CAPABILITY completed
	send("a2 LOGOUT")
	recv() // * BYE ...
	r := recv()
	if !strings.Contains(r, "OK LOGOUT") {
		t.Fatalf("LOGOUT: want OK LOGOUT, got %s", r)
	}
}

func TestHandleIMAP_Login_Cleartext(t *testing.T) {
	send, recv, _ := lineSession(t, handleIMAP)
	recv()
	send("a1 LOGIN myuser mypass")
	r := recv()
	if !strings.Contains(r, "AUTHENTICATIONFAILED") {
		t.Fatalf("LOGIN: want AUTHENTICATIONFAILED, got %s", r)
	}
}

func TestHandleIMAP_Authenticate_NTLM(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "imapuser", lmResp, ntResp)

	send, recv, _ := lineSession(t, handleIMAP)
	recv()
	send("a1 AUTHENTICATE NTLM")
	recv() // +
	send(base64.StdEncoding.EncodeToString(type1))
	recv() // + challenge
	send(base64.StdEncoding.EncodeToString(type3))
	r := recv()
	if !strings.Contains(r, "AUTHENTICATIONFAILED") {
		t.Fatalf("AUTHENTICATE NTLM: want AUTHENTICATIONFAILED, got %s", r)
	}
}

func TestHandleIMAP_Authenticate_UnsupportedMech(t *testing.T) {
	send, recv, _ := lineSession(t, handleIMAP)
	recv()
	send("a1 AUTHENTICATE PLAIN")
	r := recv()
	if !strings.Contains(r, "NO") {
		t.Fatalf("unsupported mech: want NO, got %s", r)
	}
}

func TestHandleIMAP_Authenticate_BadBase64(t *testing.T) {
	send, recv, _ := lineSession(t, handleIMAP)
	recv()
	send("a1 AUTHENTICATE NTLM")
	recv()
	send("!!!bad!!!")
	r := recv()
	if !strings.Contains(r, "NO") {
		t.Fatalf("bad base64: want NO, got %s", r)
	}
}

func TestHandleIMAP_Authenticate_WrongMsgType(t *testing.T) {
	type2like := append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	send, recv, _ := lineSession(t, handleIMAP)
	recv()
	send("a1 AUTHENTICATE NTLM")
	recv()
	send(base64.StdEncoding.EncodeToString(type2like))
	r := recv()
	if !strings.Contains(r, "NO") {
		t.Fatalf("wrong type: want NO, got %s", r)
	}
}

func TestHandleIMAP_UnknownCmd(t *testing.T) {
	send, recv, _ := lineSession(t, handleIMAP)
	recv()
	send("a1 SELECT INBOX")
	r := recv()
	if !strings.Contains(r, "BAD") {
		t.Fatalf("unknown cmd: want BAD, got %s", r)
	}
}

func TestHandleIMAP_ShortLine(t *testing.T) {
	send, recv, _ := lineSession(t, handleIMAP)
	recv()
	// Line with fewer than 2 parts — should be ignored (continue loop)
	send("lonely")
	send("a1 LOGOUT")
	// LOGOUT sends two lines: "* BYE ..." then "a1 OK LOGOUT completed"
	r1 := recv()
	r2 := recv()
	combined := r1 + r2
	if !strings.Contains(combined, "BYE") {
		t.Fatalf("short line recovery: want BYE in response, got %q", combined)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// LDAP BER helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestBERHelpers(t *testing.T) {
	// berTag and berInner round-trip
	data := []byte{1, 2, 3, 4}
	tagged := berTag(0x04, data)
	if tagged[0] != 0x04 {
		t.Fatal("berTag: wrong tag byte")
	}
	inner, ok := berInner(tagged)
	if !ok {
		t.Fatal("berInner: ok=false")
	}
	if !bytes.Equal(inner, data) {
		t.Fatalf("berInner: got %v want %v", inner, data)
	}

	// berReadLen: short form
	if berReadLen([]byte{5}) != 5 {
		t.Fatal("berReadLen short form")
	}
	// berReadLen: long form 1-byte
	if berReadLen([]byte{0x81, 200}) != 200 {
		t.Fatal("berReadLen long form 1 byte")
	}
	// berReadLen: empty
	if berReadLen([]byte{}) != 0 {
		t.Fatal("berReadLen empty")
	}

	// berLenBytes
	if berLenBytes(0x7f) != 1 {
		t.Fatal("berLenBytes 0x7f")
	}
	if berLenBytes(0x80) != 2 {
		t.Fatal("berLenBytes 0x80")
	}
	if berLenBytes(0x100) != 3 {
		t.Fatal("berLenBytes 0x100")
	}

	// berInner: too short
	if _, ok := berInner([]byte{0x30}); ok {
		t.Fatal("berInner too short: should return false")
	}
	// berInner: length exceeds data
	if _, ok := berInner([]byte{0x30, 0x10, 0x01}); ok {
		t.Fatal("berInner length overflow: should return false")
	}

	// Large data (>= 0x80 bytes) tests berTag multi-byte length
	big := make([]byte, 200)
	bigTagged := berTag(0x04, big)
	if bigTagged[1] != 0x81 {
		t.Fatalf("berTag large: expected 0x81 length indicator, got 0x%02x", bigTagged[1])
	}
}

func TestLDAPBindResponse(t *testing.T) {
	resp := ldapBindResponse(1, 0, nil)
	if len(resp) == 0 || resp[0] != 0x30 {
		t.Fatal("ldapBindResponse: should be a SEQUENCE")
	}
	// With SASL creds
	resp2 := ldapBindResponse(2, 14, []byte{1, 2, 3})
	if len(resp2) == 0 {
		t.Fatal("ldapBindResponse with creds: empty")
	}
}

// buildLDAPBind constructs a minimal LDAP BindRequest BER packet.
// authTag: 0x80=simple, 0xa3=SASL
func buildLDAPBind(msgID int, dn string, authTag byte, authPayload []byte) []byte {
	var bindBody []byte
	// version INTEGER = 3
	bindBody = append(bindBody, berTag(0x02, []byte{3})...)
	// name OCTET STRING
	bindBody = append(bindBody, berTag(0x04, []byte(dn))...)
	// authentication
	bindBody = append(bindBody, berTag(authTag, authPayload)...)

	bindReq := berTag(0x60, bindBody)

	var msgIDBuf [4]byte
	binary.BigEndian.PutUint32(msgIDBuf[:], uint32(msgID))
	msgIDBytes := msgIDBuf[:]
	for len(msgIDBytes) > 1 && msgIDBytes[0] == 0 {
		msgIDBytes = msgIDBytes[1:]
	}
	msgIDField := berTag(0x02, msgIDBytes)
	msg := append(msgIDField, bindReq...)
	return berTag(0x30, msg)
}

// buildLDAPSASLBind builds a SASL BindRequest with mechanism + credentials.
func buildLDAPSASLBind(msgID int, mech string, creds []byte) []byte {
	var saslBody []byte
	saslBody = append(saslBody, berTag(0x04, []byte(mech))...)
	saslBody = append(saslBody, berTag(0x04, creds)...)
	return buildLDAPBind(msgID, "", 0xa3, saslBody)
}

func TestHandleLDAP_SimpleBind(t *testing.T) {
	w, r, _ := pipeSession(t, handleLDAP)
	pkt := buildLDAPBind(1, "cn=admin", 0x80, []byte("secretpassword"))
	w(pkt)
	resp := r()
	if len(resp) == 0 {
		t.Fatal("expected LDAP response for simple bind")
	}
	// Response should be a SEQUENCE (0x30)
	if resp[0] != 0x30 {
		t.Fatalf("LDAP response: expected 0x30, got 0x%02x", resp[0])
	}
}

func TestHandleLDAP_SimpleBind_EmptyPassword(t *testing.T) {
	w, r, _ := pipeSession(t, handleLDAP)
	pkt := buildLDAPBind(1, "cn=anon", 0x80, []byte(""))
	w(pkt)
	resp := r()
	if len(resp) == 0 {
		t.Fatal("expected LDAP response for anonymous bind")
	}
}

func TestHandleLDAP_SASL_NTLM_Type1(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	spnego := append([]byte("NTLMSSP\x00"), type1[8:]...)
	// Wrap as GSS-SPNEGO to get it accepted
	pkt := buildLDAPSASLBind(1, "GSS-SPNEGO", type1)
	w, r, _ := pipeSession(t, handleLDAP)
	w(pkt)
	resp := r()
	// Should get saslBindInProgress (result 14) or any valid response
	if len(resp) == 0 {
		t.Fatal("expected LDAP response for SASL NTLM type1")
	}
	_ = spnego
}

func TestHandleLDAP_SASL_NTLM_Type3(t *testing.T) {
	initSession("1122334455667788")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "ldapuser", lmResp, ntResp)

	pkt := buildLDAPSASLBind(2, "NTLM", type3)
	w, r, _ := pipeSession(t, handleLDAP)
	w(pkt)
	resp := r()
	if len(resp) == 0 {
		t.Fatal("expected LDAP response for SASL NTLM type3")
	}
}

func TestHandleLDAP_InvalidTag(t *testing.T) {
	w, _, _ := pipeSession(t, handleLDAP)
	// Not a BER SEQUENCE
	w([]byte{0x01, 0x01, 0x00})
	// No response expected, just no crash
}

func TestHandleLDAP_TruncatedPacket(t *testing.T) {
	w, _, _ := pipeSession(t, handleLDAP)
	w([]byte{0x30, 0x10, 0x02}) // SEQUENCE but truncated body
}

func TestHandleLDAP_SASL_UnknownMech(t *testing.T) {
	var saslBody []byte
	saslBody = append(saslBody, berTag(0x04, []byte("KERBEROS_V5"))...)
	saslBody = append(saslBody, berTag(0x04, []byte{1, 2, 3})...)
	pkt := buildLDAPBind(1, "", 0xa3, saslBody)
	w, _, _ := pipeSession(t, handleLDAP)
	w(pkt)
}

func TestHandleLDAP_NotBindRequest(t *testing.T) {
	// Send a SEQUENCE with a non-BindRequest op (0x62 = SearchRequest APPLICATION 2)
	var msgIDField = berTag(0x02, []byte{1})
	var searchBody = berTag(0x04, []byte("dc=corp,dc=local"))
	var searchReq = berTag(0x63, searchBody)
	msg := append(msgIDField, searchReq...)
	pkt := berTag(0x30, msg)
	w, _, _ := pipeSession(t, handleLDAP)
	w(pkt)
}

// ─────────────────────────────────────────────────────────────────────────────
// DCE-RPC
// ─────────────────────────────────────────────────────────────────────────────

func buildDCERPCPkt(ptype byte, callID uint32, body []byte, authVerif []byte) []byte {
	// authLen in PDU header = size of auth_value only (excludes the 8-byte sec_trailer header)
	var authLen uint16
	if len(authVerif) > 8 {
		authLen = uint16(len(authVerif) - 8)
	}
	fragLen := uint16(16 + len(body) + len(authVerif))
	hdr := buildDCERPCHeader(ptype, fragLen, authLen, callID)
	out := append(hdr, body...)
	return append(out, authVerif...)
}

func buildDCERPCBindPkt(callID uint32, withNTLM bool) []byte {
	var body []byte
	// max_xmit_frag, max_recv_frag, assoc_group
	body = append(body, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00)
	// p_context_elem: num_contexts=1
	body = append(body, 0x01, 0x00, 0x00, 0x00)
	// abstract syntax (random UUID)
	body = append(body, make([]byte, 20)...)
	// transfer syntax (NDR)
	body = append(body, make([]byte, 20)...)

	if !withNTLM {
		return buildDCERPCPkt(rpcPTYPE_BIND, callID, body, nil)
	}

	type1 := buildType1(0x00000001, "", "")
	// auth verifier: type(1) level(1) pad(1) rsrvd(1) contextID(4) + NTLM
	av := make([]byte, 8+len(type1))
	av[0] = rpcAuthNTLM
	av[1] = 0x02
	binary.LittleEndian.PutUint32(av[4:8], 1)
	copy(av[8:], type1)

	return buildDCERPCPkt(rpcPTYPE_BIND, callID, body, av)
}

func buildDCERPCAuth3Pkt(callID uint32, type3 []byte) []byte {
	// AUTH3 body: 4 bytes pad
	body := make([]byte, 4)
	av := make([]byte, 8+len(type3))
	av[0] = rpcAuthNTLM
	av[1] = 0x02
	binary.LittleEndian.PutUint32(av[4:8], 1)
	copy(av[8:], type3)

	// authLen = auth_value only (excludes 8-byte sec_trailer)
	authLen := uint16(len(av) - 8)
	fragLen := uint16(16 + len(body) + len(av))
	hdr := buildDCERPCHeader(rpcPTYPE_AUTH3, fragLen, authLen, callID)
	return append(append(hdr, body...), av...)
}

func TestDCERPCHeader(t *testing.T) {
	hdr := buildDCERPCHeader(rpcPTYPE_BIND, 100, 0, 42)
	if hdr[0] != 5 || hdr[2] != rpcPTYPE_BIND {
		t.Fatal("DCE-RPC header: wrong version or type")
	}
	if binary.LittleEndian.Uint16(hdr[8:10]) != 100 {
		t.Fatal("fragLen mismatch")
	}
	if binary.LittleEndian.Uint32(hdr[12:16]) != 42 {
		t.Fatal("callID mismatch")
	}
}

func TestDCERPCBindAck(t *testing.T) {
	ack := buildDCERPCBindAck(7, nil)
	if len(ack) < 16 {
		t.Fatal("BindAck too short")
	}
	if ack[2] != rpcPTYPE_BIND_ACK {
		t.Fatalf("expected BIND_ACK type, got 0x%02x", ack[2])
	}
}

func TestDCERPCFault(t *testing.T) {
	fault := buildDCERPCFault(99)
	if fault[2] != rpcPTYPE_FAULT {
		t.Fatalf("expected FAULT type, got 0x%02x", fault[2])
	}
}

func TestDCERPCAuthVerif(t *testing.T) {
	av := buildDCERPCAuthVerif(rpcAuthNTLM, 1, []byte{1, 2, 3})
	if av[0] != rpcAuthNTLM {
		t.Fatal("auth type mismatch")
	}
	if len(av) != 8+3 {
		t.Fatalf("wrong length: %d", len(av))
	}
}

func TestHandleDCERPC_BindNoAuth(t *testing.T) {
	w, r, _ := pipeSession(t, handleDCERPC)
	pkt := buildDCERPCBindPkt(1, false)
	w(pkt)
	resp := r()
	if len(resp) < 16 || resp[2] != rpcPTYPE_BIND_ACK {
		t.Fatalf("no-auth bind: expected BIND_ACK, got %v", resp[:min(16, len(resp))])
	}
}

func TestHandleDCERPC_BindWithNTLM(t *testing.T) {
	initSession("1122334455667788")
	w, r, _ := pipeSession(t, handleDCERPC)
	pkt := buildDCERPCBindPkt(2, true)
	w(pkt)
	resp := r()
	if len(resp) < 16 || resp[2] != rpcPTYPE_BIND_ACK {
		t.Fatalf("ntlm bind: expected BIND_ACK, got type 0x%02x", func() byte {
			if len(resp) >= 16 {
				return resp[2]
			}
			return 0
		}())
	}
}

func TestHandleDCERPC_Auth3_Type3(t *testing.T) {
	initSession("1122334455667788")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "rpcuser", lmResp, ntResp)

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDCERPC(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer client.Close()

	// First send BIND with NTLM
	bindPkt := buildDCERPCBindPkt(3, true)
	client.Write(bindPkt)
	buf := make([]byte, 65536)
	n, _ := client.Read(buf)
	if n < 16 || buf[2] != rpcPTYPE_BIND_ACK {
		t.Fatalf("auth3 test: BIND step failed (type=0x%02x)", func() byte {
			if n >= 16 {
				return buf[2]
			}
			return 0
		}())
	}

	// Send AUTH3
	auth3Pkt := buildDCERPCAuth3Pkt(3, type3)
	client.Write(auth3Pkt)
	// Server closes after capture — no response to read; just wait for done
	<-done
}

func TestHandleDCERPC_Request(t *testing.T) {
	// Send a REQUEST packet — should get a FAULT back
	body := make([]byte, 24)
	pkt := buildDCERPCPkt(rpcPTYPE_REQUEST, 5, body, nil)
	w, r, _ := pipeSession(t, handleDCERPC)
	w(pkt)
	resp := r()
	if len(resp) >= 16 && resp[2] != rpcPTYPE_FAULT {
		t.Fatalf("REQUEST: expected FAULT, got type 0x%02x", resp[2])
	}
}

func TestHandleDCERPC_TooShort(t *testing.T) {
	w, _, _ := pipeSession(t, handleDCERPC)
	// Only 5 bytes — can't fill 16-byte header
	w([]byte{1, 2, 3, 4, 5})
}

func TestHandleDCERPC_AuthLenTooLarge(t *testing.T) {
	// fragLen=20 (body=4) but authLen=100 — authLen > body
	hdr := buildDCERPCHeader(rpcPTYPE_BIND, 20, 100, 1)
	body := make([]byte, 4)
	w, _, _ := pipeSession(t, handleDCERPC)
	w(append(hdr, body...))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// MSSQL (TDS)
// ─────────────────────────────────────────────────────────────────────────────

func wrapTDSPkt(pktType byte, body []byte) []byte {
	pktLen := 8 + len(body)
	hdr := []byte{pktType, 0x01, byte(pktLen >> 8), byte(pktLen), 0, 0, 1, 0}
	return append(hdr, body...)
}

func TestHandleMSSQL_Prelogin(t *testing.T) {
	w, r, _ := pipeSession(t, handleMSSQL)
	w(wrapTDSPkt(tdsPrelogin, []byte{0x00}))
	resp := r()
	if len(resp) < 8 {
		t.Fatal("PRELOGIN: expected response")
	}
	// Response type = tdsTabularResp (0x04)
	if resp[0] != tdsTabularResp {
		t.Fatalf("PRELOGIN resp type: want 0x04, got 0x%02x", resp[0])
	}
}

func TestHandleMSSQL_Login7_WithNTLM(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	w, r, _ := pipeSession(t, handleMSSQL)
	w(wrapTDSPkt(tdsLogin7, type1))
	resp := r()
	if len(resp) < 8 {
		t.Fatal("LOGIN7 NTLM: expected response")
	}
	// Should be tdsSSPI (0x11) challenge
	if resp[0] != tdsSSPI {
		t.Fatalf("LOGIN7 NTLM resp: want tdsSSPI(0x11), got 0x%02x", resp[0])
	}
}

func TestHandleMSSQL_Login7_NoNTLM(t *testing.T) {
	w, r, _ := pipeSession(t, handleMSSQL)
	// Plain body with no NTLMSSP signature
	w(wrapTDSPkt(tdsLogin7, []byte("plain text login data")))
	resp := r()
	if len(resp) < 8 {
		t.Fatal("LOGIN7 no-NTLM: expected error response")
	}
	// Should be tdsTabularResp (error)
	if resp[0] != tdsTabularResp {
		t.Fatalf("LOGIN7 no-NTLM: want tdsTabularResp(0x04), got 0x%02x", resp[0])
	}
}

func TestHandleMSSQL_SSPI_Type1(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	w, r, _ := pipeSession(t, handleMSSQL)
	w(wrapTDSPkt(tdsSSPI, type1))
	resp := r()
	if resp[0] != tdsSSPI {
		t.Fatalf("SSPI type1: want tdsSSPI(0x11), got 0x%02x", resp[0])
	}
}

func TestHandleMSSQL_SSPI_Type3(t *testing.T) {
	initSession("1122334455667788")
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleMSSQL(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer client.Close()

	type1 := buildType1(0x00000001, "", "")
	client.Write(wrapTDSPkt(tdsSSPI, type1))
	buf := make([]byte, 4096)
	client.Read(buf)

	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "sqluser", lmResp, ntResp)
	client.Write(wrapTDSPkt(tdsSSPI, type3))
	n, _ := client.Read(buf)
	resp := buf[:n]
	if len(resp) > 0 && resp[0] != tdsTabularResp {
		t.Fatalf("SSPI type3: want tdsTabularResp error, got 0x%02x", resp[0])
	}
	<-done
}

func TestHandleMSSQL_SSPI_ShortNTLM(t *testing.T) {
	w, _, _ := pipeSession(t, handleMSSQL)
	// Send SSPI with body too short to be NTLMSSP
	w(wrapTDSPkt(tdsSSPI, []byte{1, 2, 3}))
}

func TestHandleMSSQL_InvalidLength(t *testing.T) {
	// pktLen < 8 — should terminate cleanly
	hdr := []byte{tdsPrelogin, 0x01, 0x00, 0x04, 0, 0, 1, 0} // pktLen=4 < 8
	w, _, _ := pipeSession(t, handleMSSQL)
	w(hdr)
}

func TestWrapTDS(t *testing.T) {
	body := []byte{1, 2, 3}
	pkt := wrapTDS(tdsTabularResp, body)
	if pkt[0] != tdsTabularResp {
		t.Fatal("wrapTDS: wrong type byte")
	}
	pktLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if pktLen != 8+len(body) {
		t.Fatalf("wrapTDS: wrong length %d", pktLen)
	}
}

func TestBuildTDSPreloginResp(t *testing.T) {
	resp := buildTDSPreloginResp()
	if len(resp) == 0 {
		t.Fatal("empty prelogin response")
	}
}

func TestBuildTDSError(t *testing.T) {
	pkt := buildTDSError("Login failed")
	if len(pkt) < 8 {
		t.Fatal("TDS error too short")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// SMB
// ─────────────────────────────────────────────────────────────────────────────

// buildSMB2NegotiateReq builds a minimal SMB2 NEGOTIATE request.
func buildSMB2NegotiateReq(msgID uint64) []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(hdr[4:6], 64) // StructureSize
	hdr[12] = 0x00                               // Command lo = NEGOTIATE
	hdr[13] = 0x00                               // Command hi
	binary.LittleEndian.PutUint64(hdr[24:32], msgID)
	// SMB2 NEGOTIATE body: StructureSize(2) DialectCount(2) SecurityMode(2) ...
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], 1) // 1 dialect
	body[32] = 0x00
	body[33] = 0x03 // SMB 3.0.0
	return append(hdr, body...)
}

// buildSMB2SessionSetup builds a minimal SMB2 SESSION_SETUP request with a security buffer.
func buildSMB2SessionSetup(msgID uint64, secBuf []byte) []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[12:14], smb2CmdSessionSetup)
	binary.LittleEndian.PutUint64(hdr[24:32], msgID)

	// SESSION_SETUP body: StructureSize(2) Flags(1) SecurityMode(1)
	// Capabilities(4) Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2) ...
	// SecurityBufferOffset is relative to start of SMB2 header (offset 64+4+2+2+4+4 = 76)
	secOff := uint16(76 + 8) // header(64) + fixed-body offset to where secbuf starts
	// Actually we need to be precise. secBuf offset from start of SMB2 header:
	// body starts at byte 64, body layout:
	// [0-1]=StructSize [2]=Flags [3]=SecMode [4-7]=Cap [8-11]=Channel
	// [12-13]=SecBufferOffset [14-15]=SecBufferLen [16-23]=PrevSessID
	// SecurityBuffer starts at body[24] = absolute position 64+24 = 88
	secOff = 88 // absolute offset from start of header
	body := make([]byte, 24+len(secBuf))
	binary.LittleEndian.PutUint16(body[0:2], 25)                     // StructureSize
	binary.LittleEndian.PutUint16(body[12:14], secOff)               // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(secBuf)))   // SecurityBufferLength
	copy(body[24:], secBuf)
	return append(hdr, body...)
}

func sendNBFrame(conn net.Conn, data []byte) {
	hdr := []byte{0x00, byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}
	conn.Write(append(hdr, data...))
}

func readNBFrame(conn net.Conn) []byte {
	nb := make([]byte, 4)
	conn.Read(nb)
	msgLen := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	if msgLen <= 0 || msgLen > 1<<20 {
		return nil
	}
	msg := make([]byte, msgLen)
	conn.Read(msg)
	return msg
}

func TestHandleSMB_SMB2_Negotiate(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	req := buildSMB2NegotiateReq(1)
	sendNBFrame(client, req)
	resp := readNBFrame(client)
	if len(resp) < 4 || !bytes.HasPrefix(resp, smb2Magic) {
		t.Fatalf("SMB2 NEGOTIATE: expected SMB2 response, got %v", resp[:min(8, len(resp))])
	}
}

func TestHandleSMB_SMB2_SessionSetup_Type1(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	// NEGOTIATE first
	sendNBFrame(client, buildSMB2NegotiateReq(1))
	readNBFrame(client)

	// SESSION_SETUP with Type1
	setupReq := buildSMB2SessionSetup(2, type1)
	sendNBFrame(client, setupReq)
	resp := readNBFrame(client)
	if len(resp) < 4 {
		t.Fatal("SESSION_SETUP type1: no response")
	}
}

func TestHandleSMB_SMB2_SessionSetup_Type3(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "smbuser", lmResp, ntResp)

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	sendNBFrame(client, buildSMB2NegotiateReq(1))
	readNBFrame(client)

	sendNBFrame(client, buildSMB2SessionSetup(2, type1))
	readNBFrame(client)

	sendNBFrame(client, buildSMB2SessionSetup(3, type3))
	resp := readNBFrame(client)
	// After type3 capture, server sends error and closes
	_ = resp
	<-done
}

func TestHandleSMB_UnknownProtocol(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	garbage := make([]byte, 64)
	garbage[0] = 0xAA
	sendNBFrame(client, garbage)
	<-done // server should close on unknown protocol
}

func TestHandleSMB_InvalidLength(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	// NetBIOS header reporting length=3 (< minimum 4)
	client.Write([]byte{0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03})
	<-done
}

// ─────────────────────────────────────────────────────────────────────────────
// SMB helpers directly
// ─────────────────────────────────────────────────────────────────────────────

func buildSMB1NegotiateReq(dialects []string) []byte {
	hdr := make([]byte, 32)
	copy(hdr[0:4], smb1Magic)
	hdr[4] = smb1CmdNegotiate

	var dialectBytes []byte
	for _, d := range dialects {
		dialectBytes = append(dialectBytes, 0x02)
		dialectBytes = append(dialectBytes, []byte(d)...)
		dialectBytes = append(dialectBytes, 0x00)
	}

	var body []byte
	body = append(body, 0x00) // WordCount=0
	byteCount := len(dialectBytes)
	body = append(body, byte(byteCount), byte(byteCount>>8))
	body = append(body, dialectBytes...)

	return append(hdr, body...)
}

func TestSMB1FindDialect_NTLM(t *testing.T) {
	req := buildSMB1NegotiateReq([]string{"PC NETWORK PROGRAM 1.0", "NT LM 0.12"})
	idx := smb1FindDialect(req)
	if idx != 1 {
		t.Fatalf("NT LM 0.12 dialect: expected index 1, got %d", idx)
	}
}

func TestSMB1FindDialect_SMB2Upgrade(t *testing.T) {
	req := buildSMB1NegotiateReq([]string{"NT LM 0.12", "SMB 2.???"})
	idx := smb1FindDialect(req)
	if idx != -2 {
		t.Fatalf("SMB2 upgrade: expected -2, got %d", idx)
	}
}

func TestSMB1FindDialect_NoMatch(t *testing.T) {
	req := buildSMB1NegotiateReq([]string{"PC NETWORK PROGRAM 1.0"})
	idx := smb1FindDialect(req)
	if idx != -1 {
		t.Fatalf("no match: expected -1, got %d", idx)
	}
}

func TestSMB1FindDialect_TooShort(t *testing.T) {
	req := buildSMB1NegotiateReq([]string{})
	req = req[:20] // truncate
	idx := smb1FindDialect(req)
	if idx != -1 {
		t.Fatalf("too short: expected -1, got %d", idx)
	}
}

func TestSMB1ExtractBlob_Valid(t *testing.T) {
	// Build a minimal SMB1 SESSION_SETUP_ANDX request with WordCount=12
	hdr := make([]byte, 32)
	copy(hdr[0:4], smb1Magic)
	hdr[4] = smb1CmdSessionSetup

	secBlob := []byte{1, 2, 3, 4, 5}

	body := make([]byte, 27+len(secBlob))
	body[0] = 12 // WordCount
	// SecurityBlobLength at body[15:17]
	binary.LittleEndian.PutUint16(body[15:17], uint16(len(secBlob)))
	// ByteCount at body[25:27]
	binary.LittleEndian.PutUint16(body[25:27], uint16(len(secBlob)))
	copy(body[27:], secBlob)

	msg := append(hdr, body...)
	got := smb1ExtractBlob(msg)
	if !bytes.Equal(got, secBlob) {
		t.Fatalf("smb1ExtractBlob: want %v got %v", secBlob, got)
	}
}

func TestSMB1ExtractBlob_WrongWC(t *testing.T) {
	hdr := make([]byte, 32)
	body := make([]byte, 30)
	body[0] = 10 // wrong WordCount (not 12)
	msg := append(hdr, body...)
	if smb1ExtractBlob(msg) != nil {
		t.Fatal("wrong WordCount: expected nil")
	}
}

func TestSMB1ExtractBlob_TooShort(t *testing.T) {
	if smb1ExtractBlob(make([]byte, 10)) != nil {
		t.Fatal("too short: expected nil")
	}
}

func TestHandleSMB_SMB1_Negotiate_NTLM(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	req := buildSMB1NegotiateReq([]string{"NT LM 0.12"})
	sendNBFrame(client, req)
	resp := readNBFrame(client)
	if len(resp) < 4 || !bytes.HasPrefix(resp, smb1Magic) {
		t.Fatalf("SMB1 NEGOTIATE: expected SMB1 response")
	}
}

func TestHandleSMB_SMB1_Negotiate_SMB2Upgrade(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	req := buildSMB1NegotiateReq([]string{"NT LM 0.12", "SMB 2.???"})
	sendNBFrame(client, req)
	resp := readNBFrame(client)
	if len(resp) < 4 || !bytes.HasPrefix(resp, smb2Magic) {
		t.Fatalf("SMB2 upgrade: expected SMB2 response, got %v", resp[:min(8, len(resp))])
	}
}

func TestHandleSMB_SMB1_Negotiate_NoDialect(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	req := buildSMB1NegotiateReq([]string{"UNKNOWN DIALECT"})
	sendNBFrame(client, req)
	<-done // server returns immediately when dialectIdx==-1
}

func TestHandleSMB_SMB1_SessionSetup_Type1(t *testing.T) {
	initSession("1122334455667788")

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSMB(server)
	}()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	defer func() { client.Close(); <-done }()

	// NEGOTIATE first
	sendNBFrame(client, buildSMB1NegotiateReq([]string{"NT LM 0.12"}))
	readNBFrame(client)

	// Build SMB1 SESSION_SETUP with NTLM Type1 blob
	type1 := buildType1(0x00000001, "", "")
	hdr := make([]byte, 32)
	copy(hdr[0:4], smb1Magic)
	hdr[4] = smb1CmdSessionSetup

	body := make([]byte, 27+len(type1))
	body[0] = 12
	binary.LittleEndian.PutUint16(body[15:17], uint16(len(type1)))
	binary.LittleEndian.PutUint16(body[25:27], uint16(len(type1)))
	copy(body[27:], type1)
	sendNBFrame(client, append(hdr, body...))
	resp := readNBFrame(client)
	if len(resp) < 4 {
		t.Fatal("SMB1 SESSION_SETUP type1: no response")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ntlm.go — derLen coverage (>= 0x100 path)
// ─────────────────────────────────────────────────────────────────────────────

func TestDerLen_LargeValues(t *testing.T) {
	// < 0x80
	l1 := derLen(0x7f)
	if len(l1) != 1 || l1[0] != 0x7f {
		t.Fatalf("derLen(0x7f): got %v", l1)
	}
	// 0x80-0xff
	l2 := derLen(0xff)
	if len(l2) != 2 || l2[0] != 0x81 {
		t.Fatalf("derLen(0xff): got %v", l2)
	}
	// >= 0x100
	l3 := derLen(0x100)
	if len(l3) != 3 || l3[0] != 0x82 {
		t.Fatalf("derLen(0x100): got %v", l3)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// encodeUTF16LE — multi-byte code point (0x10000+) path
// ─────────────────────────────────────────────────────────────────────────────

func TestEncodeUTF16LE_Surrogate(t *testing.T) {
	// U+1F600 EMOJI is > 0xFFFF — code replaces with 0xFFFD
	s := "\U0001F600"
	b := encodeUTF16LE(s)
	if len(b) != 2 {
		t.Fatalf("surrogate path: expected 2 bytes (replacement), got %d", len(b))
	}
	val := binary.LittleEndian.Uint16(b)
	if val != 0xFFFD {
		t.Fatalf("surrogate: expected 0xFFFD, got 0x%04x", val)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// addrToIP — string addr fallback
// ─────────────────────────────────────────────────────────────────────────────

type testAddr struct{ s string }

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return a.s }

func TestAddrToIP_StringFallback(t *testing.T) {
	// Valid host:port string
	ip := addrToIP(testAddr{"10.0.0.5:1234"})
	if ip == nil || !ip.Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("string addr: expected 10.0.0.5, got %v", ip)
	}
	// Plain IP string (no port)
	ip2 := addrToIP(testAddr{"10.0.0.6"})
	_ = ip2 // may or may not parse — just no panic
}

// ─────────────────────────────────────────────────────────────────────────────
// main.go helpers
// ─────────────────────────────────────────────────────────────────────────────

func TestGetIfaceIP_ValidInterface(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no interfaces available")
	}
	// Find an interface that has an IPv4 address
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ip, err := getIfaceIP(iface.Name)
					if err != nil {
						t.Fatalf("getIfaceIP(%s): %v", iface.Name, err)
					}
					if ip.To4() == nil {
						t.Fatalf("getIfaceIP returned non-IPv4: %v", ip)
					}
					return // success
				}
			}
		}
	}
	t.Skip("no interface with IPv4 address")
}

func TestGetIfaceIP_InvalidInterface(t *testing.T) {
	_, err := getIfaceIP("nonexistent99999")
	if err == nil {
		t.Fatal("expected error for nonexistent interface")
	}
}

func TestPrintStartup_NoFlags(t *testing.T) {
	// Just confirm it doesn't panic
	ip := net.ParseIP("192.168.1.1")
	printStartup(ip, false, false, false, false, false, false, false, false, false, false, false, false, false, false)
}

func TestPrintStartup_AllEnabled(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	respondToIPs = parseIPList("10.0.0.1")
	dontRespondIPs = parseIPList("10.0.0.2")
	respondToNames = parseNameList("host1")
	dontRespondNames = parseNameList("host2")
	wpadEnabled = true
	wpadProxyHost = "10.0.0.1:3128"
	defer func() {
		respondToIPs = nil
		dontRespondIPs = nil
		respondToNames = nil
		dontRespondNames = nil
		wpadEnabled = false
		wpadProxyHost = ""
	}()
	printStartup(ip, true, true, true, true, true, true, true, true, true, true, true, true, true, true)
}

// ─────────────────────────────────────────────────────────────────────────────
// NewChallenge
// ─────────────────────────────────────────────────────────────────────────────

func TestNewChallenge(t *testing.T) {
	initSession("aabbccddeeff0011")
	c := NewChallenge()
	want := getChallenge()
	if c != want {
		t.Fatalf("NewChallenge mismatch: %x vs %x", c, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sendProxyResponse coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestSendProxyResponse_200(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		sendProxyResponse(server, 200, "", nil)
		server.Close()
	}()
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("sendProxyResponse 200: got %s", resp)
	}
}

func TestSendProxyResponse_407WithBody(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		sendProxyResponse(server, 407, "NTLM", []byte("body"))
		server.Close()
	}()
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "407") {
		t.Fatalf("sendProxyResponse 407: got %s", resp)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS TCP handler integration
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleDNSQuery_Analyze(t *testing.T) {
	analyzeMode = true
	defer func() { analyzeMode = false }()

	server, client := net.Pipe()
	defer client.Close()

	q := buildDNSQuery(0x0001, "evilhost")
	go handleDNSQuery(nil, &net.UDPAddr{IP: net.ParseIP("1.2.3.4")}, q, net.ParseIP("10.0.0.1"))
	server.Close()
	// Just no panic
}

func TestHandleDNSQuery_Empty(t *testing.T) {
	// Empty query — parseLLMNRQuery returns "" → returns early, no crash
	go handleDNSQuery(nil, &net.UDPAddr{}, []byte{}, net.ParseIP("10.0.0.1"))
	time.Sleep(5 * time.Millisecond)
}

// ─────────────────────────────────────────────────────────────────────────────
// smb2 helpers invoked by handleSMB
// ─────────────────────────────────────────────────────────────────────────────

func TestSMB2NegotiateResp(t *testing.T) {
	resp := smb2NegotiateResp(1)
	if !bytes.HasPrefix(resp, smb2Magic) {
		t.Fatal("smb2NegotiateResp: missing SMB2 magic")
	}
}

func TestSMB2SessionSetupChallenge(t *testing.T) {
	initSession("1122334455667788")
	c := getChallenge()
	resp := smb2SessionSetupChallenge(2, c)
	if !bytes.HasPrefix(resp, smb2Magic) {
		t.Fatal("smb2SessionSetupChallenge: missing SMB2 magic")
	}
}

func TestSMB2Error(t *testing.T) {
	resp := smb2Error(smb2CmdSessionSetup, 3, statusLogonFailure)
	if !bytes.HasPrefix(resp, smb2Magic) {
		t.Fatal("smb2Error: missing SMB2 magic")
	}
}

func TestSMB1Header(t *testing.T) {
	hdr := smb1Header(smb1CmdNegotiate, statusSuccess, 0, 1)
	if !bytes.HasPrefix(hdr, smb1Magic) {
		t.Fatal("smb1Header: missing SMB1 magic")
	}
	if hdr[4] != smb1CmdNegotiate {
		t.Fatal("smb1Header: wrong command")
	}
}

func TestSendNB(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	go func() {
		sendNB(server, []byte{1, 2, 3})
		server.Close()
	}()
	buf := make([]byte, 64)
	n, _ := client.Read(buf)
	client.Close()
	// Should have 4-byte NB header + 3 bytes data
	if n != 7 {
		t.Fatalf("sendNB: expected 7 bytes, got %d", n)
	}
	if buf[0] != 0x00 || buf[3] != 0x03 {
		t.Fatalf("sendNB: wrong NB header: %v", buf[:4])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// FTP edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestFTP_AuthNTLM_BadBase64OnType1(t *testing.T) {
	send, recv, _ := lineSession(t, handleFTP)
	recv()
	send("AUTH NTLM")
	recv() // 334
	send("!!!bad base64!!!")
	r := recv()
	if !strings.Contains(r, "530") {
		t.Fatalf("FTP bad base64 type1: want 530, got %s", r)
	}
}

func TestFTP_AuthNTLM_WrongMsgType(t *testing.T) {
	type2like := append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	send, recv, _ := lineSession(t, handleFTP)
	recv()
	send("AUTH NTLM")
	recv()
	send(base64.StdEncoding.EncodeToString(type2like))
	r := recv()
	if !strings.Contains(r, "530") {
		t.Fatalf("FTP wrong msg type: want 530, got %s", r)
	}
}

func TestFTP_AuthNTLM_BadType3Base64(t *testing.T) {
	initSession("1122334455667788")
	type1 := buildType1(0x00000001, "", "")
	send, recv, _ := lineSession(t, handleFTP)
	recv()
	send("AUTH NTLM")
	recv()
	send(base64.StdEncoding.EncodeToString(type1))
	recv() // 334 challenge
	// Send bad type3
	send("!!!bad type3!!!")
	r := recv()
	if !strings.Contains(r, "530") {
		t.Fatalf("FTP bad type3: want 530, got %s", r)
	}
}

// Test inline AUTH NTLM with bad base64 (type1 directly on the same line)
func TestFTP_AuthNTLM_InlineBadToken(t *testing.T) {
	send, recv, _ := lineSession(t, handleFTP)
	recv()
	send("AUTH NTLM !!!bad!!!")
	r := recv()
	if !strings.Contains(r, "530") {
		t.Fatalf("inline bad token: want 530, got %s", r)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleProxy_Type3_NoPriorChallenge(t *testing.T) {
	initSession("1122334455667788")
	lmResp := make([]byte, 24)
	ntProof := make([]byte, 16)
	blob := make([]byte, 32)
	ntResp := append(ntProof, blob...)
	type3 := buildType3("CORP", "proxyuser", lmResp, ntResp)
	type3b64 := base64.StdEncoding.EncodeToString(type3)

	resp := proxyExchange(t, []string{
		fmt.Sprintf("CONNECT host:443 HTTP/1.1\r\nProxy-Authorization: NTLM %s\r\n\r\n", type3b64),
	})
	if !strings.Contains(resp, "407") {
		t.Fatalf("proxy type3 no challenge: want 407, got %s", resp)
	}
}

func TestHandleProxy_BadBase64(t *testing.T) {
	resp := proxyExchange(t, []string{
		"CONNECT host:443 HTTP/1.1\r\nProxy-Authorization: NTLM !!bad!!\r\n\r\n",
	})
	if !strings.Contains(resp, "407") {
		t.Fatalf("proxy bad base64: want 407, got %s", resp)
	}
}

func TestHandleProxy_ShortNTLM(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	resp := proxyExchange(t, []string{
		fmt.Sprintf("CONNECT host:443 HTTP/1.1\r\nProxy-Authorization: NTLM %s\r\n\r\n", short),
	})
	if !strings.Contains(resp, "407") {
		t.Fatalf("proxy short NTLM: want 407, got %s", resp)
	}
}
