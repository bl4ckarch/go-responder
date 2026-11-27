package server

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-responder/internal/core"
)

func readLDAPMsgID(t *testing.T, p []byte) int {
	t.Helper()
	// LDAPMessage ::= SEQUENCE { messageID INTEGER, ... }
	if len(p) < 6 || p[0] != 0x30 {
		t.Fatalf("not an LDAP message: % x", p)
	}
	off := 2
	if p[1]&0x80 != 0 {
		off = 2 + int(p[1]&0x7f)
	}
	if p[off] != 0x02 {
		t.Fatalf("expected INTEGER messageID: % x", p)
	}
	n := int(p[off+1])
	v := 0
	for i := 0; i < n; i++ {
		v = v<<8 | int(p[off+2+i])
	}
	return v
}

// messageID is per LDAPMessage: the second bind on a connection used to echo
// an accumulated value (e.g. 258 instead of 2).
func TestHandleLDAP_MsgIDIsPerMessage(t *testing.T) {
	client, srv := pipeConn()
	defer client.Close()
	go HandleLDAP(srv)

	type1 := buildType1Blob()
	client.Write(buildLDAPSASLBind(1, "GSS-SPNEGO", type1))
	buf := make([]byte, 1024)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil || n < 6 {
		t.Fatalf("no first response: %v", err)
	}
	if id := readLDAPMsgID(t, buf[:n]); id != 1 {
		t.Fatalf("first response messageID = %d, want 1", id)
	}

	client.Write(buildLDAPSASLBind(2, "GSS-SPNEGO", type1))
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = client.Read(buf)
	if err != nil || n < 6 {
		t.Fatalf("no second response: %v", err)
	}
	if id := readLDAPMsgID(t, buf[:n]); id != 2 {
		t.Fatalf("second response messageID = %d, want 2", id)
	}
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buildEncryptedData(t *testing.T, etype int, cipher []byte) []byte {
	t.Helper()
	etypeField := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, Bytes: mustMarshal(t, etype),
	})
	cipherField := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 2, Bytes: mustMarshal(t, cipher),
	})
	return mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(etypeField, cipherField...),
	})
}

func TestParseEncryptedDataExtractsCipher(t *testing.T) {
	cipher := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	blob := buildEncryptedData(t, 23, cipher)
	etype, got, ok := parseEncryptedData(blob)
	if !ok || etype != 23 || string(got) != string(cipher) {
		t.Fatalf("parseEncryptedData = (%d, % x, %v), want (23, % x, true)", etype, got, ok, cipher)
	}
}

// buildASReqWithPAData wraps a PA-ENC-TIMESTAMP value in an AS-REQ.
func buildASReqWithPAData(t *testing.T, padataValue []byte) []byte {
	t.Helper()
	paTypeField := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 1, Bytes: mustMarshal(t, 2),
	})
	paValueField := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 2, Bytes: mustMarshal(t, padataValue),
	})
	paItem := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(paTypeField, paValueField...),
	})
	paSeq := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: paItem,
	})
	paField := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: paSeq,
	})
	realmField := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 7, Bytes: mustMarshal(t, "CORP.LOCAL"),
	})
	principalField := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 8, IsCompound: true,
		Bytes: mustMarshal(t, asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
			Bytes: mustMarshal(t, asn1.RawValue{
				Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true,
				Bytes: mustMarshal(t, asn1.RawValue{
					Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
					Bytes: mustMarshal(t, "alice"),
				}),
			}),
		}),
	})
	bodySeq := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(realmField, principalField...),
	})
	reqBody := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: bodySeq,
	})
	kdcReq := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(paField, reqBody...),
	})
	appTag := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassApplication, Tag: asReqTag, IsCompound: true, Bytes: kdcReq,
	})
	return mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: appTag,
	})
}

// The emitted hash must be the RC4 ciphertext ("$krb5pa$23$user$realm$hex"),
// not the DER EncryptedData wrapper, otherwise hashcat can never crack it.
func TestKerberosHashUsesCiphertext(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "hashes.txt")
	oldOut := core.OutFile
	core.OutFile = outFile
	defer func() { core.OutFile = oldOut }()
	core.ResetHashLog()

	cipher := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	handleKerberosPacket(buildASReqWithPAData(t, buildEncryptedData(t, 23, cipher)), nil)

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("no hash written: %v", err)
	}
	line := strings.TrimSpace(string(data))
	want := "$krb5pa$23$alice$CORP.LOCAL$" + hex.EncodeToString(cipher)
	if line != want {
		t.Fatalf("hash = %q, want %q", line, want)
	}
}

// BindAck: p_result_list must be n_results(1)+reserved(1)+reserved2(2) then
// one 24-byte item, and auth_len must cover the auth_value only (not the
// 8-byte verifier header) — otherwise clients locate the NTLM challenge wrong.
func TestDCERPCBindAckLayout(t *testing.T) {
	ntlm := make([]byte, 40)
	pkt := buildDCERPCBindAck(9, buildDCERPCAuthVerif(rpcAuthNTLM, 3, ntlm))

	if fragLen := int(binary.LittleEndian.Uint16(pkt[8:10])); fragLen != len(pkt) {
		t.Fatalf("frag_len = %d, packet is %d bytes", fragLen, len(pkt))
	}
	if authLen := int(binary.LittleEndian.Uint16(pkt[10:12])); authLen != len(ntlm) {
		t.Fatalf("auth_len = %d, want %d (auth_value only)", authLen, len(ntlm))
	}

	// 16 header + 4 max frags + 4 assoc + 8 secondary address (2 len + 4 str + 2 pad)
	off := 16 + 4 + 4 + 8
	if pkt[off] != 0x01 {
		t.Fatalf("n_results = %d, want 1", pkt[off])
	}
	item := off + 4
	wantGUID := []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	if got := pkt[item+4 : item+20]; string(got) != string(wantGUID) {
		t.Fatalf("transfer syntax uuid = % x, want % x", got, wantGUID)
	}
	if ver := binary.LittleEndian.Uint32(pkt[item+20 : item+24]); ver != 2 {
		t.Fatalf("syntax version = %d, want 2", ver)
	}
	// ctx item ends where the secondary auth verifier begins
	verif := pkt[len(pkt)-8-len(ntlm):]
	if verif[0] != rpcAuthNTLM {
		t.Fatalf("auth verifier not at the end of the PDU: %02x", verif[0])
	}
	if item+24 != len(pkt)-8-len(ntlm) {
		t.Fatalf("p_result_list size mismatch: ends at %d, verifier at %d",
			item+24, len(pkt)-8-len(ntlm))
	}
}

// The SMB negotiate replies advertise a system time; it used to be the
// saturated time.Duration constant.
func TestSMBNegotiateTimestampIsCurrent(t *testing.T) {
	resp := smb2NegotiateResp(0)
	if len(resp) < 64+48 {
		t.Fatalf("negotiate response too short: %d", len(resp))
	}
	ft := binary.LittleEndian.Uint64(resp[64+40 : 64+48])
	got := time.Unix(0, int64(ft-116444736000000000)*100)
	if d := time.Since(got); d < -time.Minute || d > time.Minute {
		t.Fatalf("SMB2 negotiate timestamp is %v away from now (%v)", d, got)
	}
}

// The ERROR token length must match the bytes actually written, otherwise the
// client swallows the following DONE token.
func TestBuildTDSErrorTokenLength(t *testing.T) {
	pkt := buildTDSError("Login failed")
	if len(pkt) < 12 {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	body := pkt[8:]
	if body[0] != 0xAA {
		t.Fatalf("missing ERROR token: %02x", body[0])
	}
	tokLen := int(binary.LittleEndian.Uint16(body[1:3]))
	end := 3 + tokLen
	if end >= len(body) {
		t.Fatalf("token length %d overruns payload (%d bytes)", tokLen, len(body))
	}
	if body[end] != 0xFD {
		t.Fatalf("token ends at %d (0x%02x), expected DONE token 0xFD there", end, body[end])
	}
}
