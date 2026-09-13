package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const ntlmSSPSig = "NTLMSSP\x00"

const challengeFlags = uint32(
	0x00000001 | // UNICODE
		0x00000002 | // OEM
		0x00000004 | // REQUEST_TARGET
		0x00000200 | // NTLM
		0x00000800 | // ANONYMOUS
		0x00001000 | // DOMAIN_TYPE
		0x00020000 | // NTLM2
		0x00080000 | // EXTENDED_SESSIONSECURITY
		0x00800000 | // TARGET_INFO
		0x02000000 | // VERSION
		0x20000000 | // 128
		0x40000000 | // KEY_EXCH
		0x80000000) // 56

// ---------- UTF-16 helpers ----------

func encodeUTF16LE(s string) []byte {
	var b bytes.Buffer
	for _, r := range s {
		if r <= 0xFFFF {
			binary.Write(&b, binary.LittleEndian, uint16(r))
		} else {
			binary.Write(&b, binary.LittleEndian, uint16(0xFFFD))
		}
	}
	return b.Bytes()
}

func decodeUTF16LE(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n := len(b) / 2
	u16 := make([]uint16, n)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16))
}

// ---------- NTLM challenge building ----------

func buildTargetInfo(domain, computer string) []byte {
	var b bytes.Buffer
	avp := func(id uint16, val []byte) {
		binary.Write(&b, binary.LittleEndian, id)
		binary.Write(&b, binary.LittleEndian, uint16(len(val)))
		b.Write(val)
	}
	avp(0x0002, encodeUTF16LE(domain))
	avp(0x0001, encodeUTF16LE(computer))
	avp(0x0004, encodeUTF16LE(strings.ToLower(domain)))
	avp(0x0003, encodeUTF16LE(strings.ToLower(computer)+"."+strings.ToLower(domain)))
	// MsvAvTimestamp
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := uint64(time.Since(epoch).Nanoseconds() / 100)
	ftb := make([]byte, 8)
	binary.LittleEndian.PutUint64(ftb, ft)
	avp(0x0007, ftb)
	avp(0x0000, nil) // EOL
	return b.Bytes()
}

// NewChallenge returns the global session challenge (fixed per run, like real Responder).
func NewChallenge() [8]byte { return globalChallenge }

func BuildNTLMChallenge(challenge [8]byte, domain, computer string) []byte {
	targetName := encodeUTF16LE(domain)
	targetInfo := buildTargetInfo(domain, computer)

	const hdrSize = 56 // fixed header before payload
	tnOffset := uint32(hdrSize)
	tiOffset := tnOffset + uint32(len(targetName))

	var b bytes.Buffer
	b.WriteString(ntlmSSPSig)
	binary.Write(&b, binary.LittleEndian, uint32(2))
	binary.Write(&b, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&b, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&b, binary.LittleEndian, tnOffset)
	binary.Write(&b, binary.LittleEndian, challengeFlags)
	b.Write(challenge[:])
	binary.Write(&b, binary.LittleEndian, uint64(0)) // reserved
	binary.Write(&b, binary.LittleEndian, uint16(len(targetInfo)))
	binary.Write(&b, binary.LittleEndian, uint16(len(targetInfo)))
	binary.Write(&b, binary.LittleEndian, tiOffset)
	b.Write([]byte{0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F}) // version
	b.Write(targetName)
	b.Write(targetInfo)
	return b.Bytes()
}

// ---------- NTLM authenticate parsing ----------

func ParseNTLMAuthenticate(data []byte, challenge [8]byte) (hash, username, domain string, err error) {
	if len(data) < 12 || !strings.HasPrefix(string(data), ntlmSSPSig) {
		return "", "", "", fmt.Errorf("not NTLMSSP")
	}
	if binary.LittleEndian.Uint32(data[8:12]) != 3 {
		return "", "", "", fmt.Errorf("not type 3")
	}
	if len(data) < 52 {
		return "", "", "", fmt.Errorf("too short")
	}

	field := func(off int) []byte {
		if off+8 > len(data) {
			return nil
		}
		flen := binary.LittleEndian.Uint16(data[off:])
		foff := binary.LittleEndian.Uint32(data[off+4:])
		if flen == 0 || int(foff)+int(flen) > len(data) {
			return nil
		}
		return data[foff : foff+uint32(flen)]
	}

	ntData := field(20)
	if len(ntData) < 16 {
		return "", "", "", fmt.Errorf("NtChallengeResponse too short")
	}
	ntProofStr := ntData[:16]
	blob := ntData[16:]

	username = decodeUTF16LE(field(36))
	domain = decodeUTF16LE(field(28))

	hash = fmt.Sprintf("%s::%s:%s:%s:%s",
		username, domain,
		hex.EncodeToString(challenge[:]),
		hex.EncodeToString(ntProofStr),
		hex.EncodeToString(blob),
	)
	return hash, username, domain, nil
}

func FindNTLMSSP(buf []byte) []byte {
	idx := bytes.Index(buf, []byte(ntlmSSPSig))
	if idx < 0 {
		return nil
	}
	return buf[idx:]
}

// ---------- ASN.1 DER helpers ----------

var ntlmsspOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
var spnegoOID = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func derTag(tag byte, data []byte) []byte {
	out := []byte{tag}
	out = append(out, derLen(len(data))...)
	return append(out, data...)
}

// BuildSPNEGONegotiateToken builds the SPNEGO NegTokenInit for the SMB2 NEGOTIATE response.
// It declares we support NTLMSSP only.
func BuildSPNEGONegotiateToken() []byte {
	mechTypeList := derTag(0x30, ntlmsspOID) // SEQUENCE OF OID
	mechTypes := derTag(0xa0, mechTypeList)   // [0] mechTypes
	innerSeq := derTag(0x30, mechTypes)
	negTokenInit := derTag(0xa0, innerSeq)
	content := append(spnegoOID, negTokenInit...)
	return derTag(0x60, content) // APPLICATION 0
}

// WrapSPNEGOChallenge wraps NTLMSSP_CHALLENGE in a SPNEGO NegTokenResp (accept-incomplete).
func WrapSPNEGOChallenge(ntlmChallenge []byte) []byte {
	negState := derTag(0xa0, []byte{0x0a, 0x01, 0x01})     // accept-incomplete
	supportedMech := derTag(0xa1, ntlmsspOID)               // [1] supportedMech
	responseToken := derTag(0xa2, derTag(0x04, ntlmChallenge)) // [2] responseToken = OCTET STRING

	inner := append(negState, supportedMech...)
	inner = append(inner, responseToken...)
	return derTag(0xa1, derTag(0x30, inner))
}
