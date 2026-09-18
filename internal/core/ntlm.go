package core

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const NTLMSSPSig = "NTLMSSP\x00"

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

const challengeFlagsLM = uint32(
	0x00000001 | // UNICODE
		0x00000002 | // OEM
		0x00000004 | // REQUEST_TARGET
		0x00000080 | // LM_KEY
		0x00000200 | // NTLM
		0x00001000 | // DOMAIN_TYPE
		0x00020000 | // NTLM2
		0x00800000 | // TARGET_INFO
		0x20000000 | // 128
		0x40000000 | // KEY_EXCH
		0x80000000) // 56

// NTLMMsgType returns the NTLM message type (1, 2, or 3).
func NTLMMsgType(ntlm []byte) uint32 {
	if len(ntlm) < 12 {
		return 0
	}
	return uint32(ntlm[8]) | uint32(ntlm[9])<<8 | uint32(ntlm[10])<<16 | uint32(ntlm[11])<<24
}

func EncodeUTF16LE(s string) []byte {
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

func DecodeUTF16LE(b []byte) string {
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

func buildTargetInfo(domain, computer string) []byte {
	var b bytes.Buffer
	avp := func(id uint16, val []byte) {
		binary.Write(&b, binary.LittleEndian, id)
		binary.Write(&b, binary.LittleEndian, uint16(len(val)))
		b.Write(val)
	}
	avp(0x0002, EncodeUTF16LE(domain))
	avp(0x0001, EncodeUTF16LE(computer))
	avp(0x0004, EncodeUTF16LE(strings.ToLower(domain)))
	avp(0x0003, EncodeUTF16LE(strings.ToLower(computer)+"."+strings.ToLower(domain)))
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := uint64(time.Since(epoch).Nanoseconds() / 100)
	ftb := make([]byte, 8)
	binary.LittleEndian.PutUint64(ftb, ft)
	avp(0x0007, ftb)
	avp(0x0000, nil)
	return b.Bytes()
}

func BuildNTLMChallenge(challenge [8]byte, domain, computer string) []byte {
	flags := challengeFlags
	if LMMode {
		flags = challengeFlagsLM
	}
	targetName := EncodeUTF16LE(domain)
	targetInfo := buildTargetInfo(domain, computer)
	const hdrSize = 56
	tnOffset := uint32(hdrSize)
	tiOffset := tnOffset + uint32(len(targetName))

	var b bytes.Buffer
	b.WriteString(NTLMSSPSig)
	binary.Write(&b, binary.LittleEndian, uint32(2))
	binary.Write(&b, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&b, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&b, binary.LittleEndian, tnOffset)
	binary.Write(&b, binary.LittleEndian, flags)
	b.Write(challenge[:])
	binary.Write(&b, binary.LittleEndian, uint64(0))
	binary.Write(&b, binary.LittleEndian, uint16(len(targetInfo)))
	binary.Write(&b, binary.LittleEndian, uint16(len(targetInfo)))
	binary.Write(&b, binary.LittleEndian, tiOffset)
	b.Write([]byte{0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F})
	b.Write(targetName)
	b.Write(targetInfo)
	return b.Bytes()
}

// ParseNTLMAuthenticate parses a Type3 NTLM message and returns the hash string.
// NTLMv2 format: USER::DOMAIN:CHALLENGE:NTProofStr:blob  (hashcat -m 5600)
// NTLMv1/ESS format: USER::DOMAIN:LMResp:NTResp:CHALLENGE (hashcat -m 5500)
// version is "NTLMv1" when ntData is exactly 24 bytes, "NTLMv2" otherwise.
func ParseNTLMAuthenticate(data []byte, challenge [8]byte) (hash, username, domain, version string, err error) {
	if len(data) < 12 || !strings.HasPrefix(string(data), NTLMSSPSig) {
		return "", "", "", "", fmt.Errorf("not NTLMSSP")
	}
	if binary.LittleEndian.Uint32(data[8:12]) != 3 {
		return "", "", "", "", fmt.Errorf("not type 3")
	}
	if len(data) < 52 {
		return "", "", "", "", fmt.Errorf("too short")
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
	lmData := field(12)
	ntData := field(20)
	username = DecodeUTF16LE(field(36))
	domain = DecodeUTF16LE(field(28))

	if len(ntData) == 24 {
		version = "NTLMv1"
		hash = fmt.Sprintf("%s::%s:%s:%s:%s",
			username, domain,
			hex.EncodeToString(lmData),
			hex.EncodeToString(ntData),
			hex.EncodeToString(challenge[:]))
	} else {
		if len(ntData) < 16 {
			return "", "", "", "", fmt.Errorf("NtChallengeResponse too short")
		}
		version = "NTLMv2"
		hash = fmt.Sprintf("%s::%s:%s:%s:%s",
			username, domain,
			hex.EncodeToString(challenge[:]),
			hex.EncodeToString(ntData[:16]),
			hex.EncodeToString(ntData[16:]))
	}
	return hash, username, domain, version, nil
}

// ParseNTLMNegotiate extracts workstation, domain, and OS version from a Type1 message.
func ParseNTLMNegotiate(data []byte) (workstation, dom, osVer string) {
	if len(data) < 32 || !strings.HasPrefix(string(data), NTLMSSPSig) {
		return
	}
	if binary.LittleEndian.Uint32(data[8:12]) != 1 {
		return
	}
	flags := binary.LittleEndian.Uint32(data[12:16])
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
	if flags&0x00001000 != 0 {
		dom = string(field(16))
	}
	if flags&0x00002000 != 0 {
		workstation = string(field(24))
	}
	if flags&0x02000000 != 0 && len(data) >= 40 {
		osVer = fmt.Sprintf("Windows %d.%d build %d", data[32], data[33],
			binary.LittleEndian.Uint16(data[34:36]))
	}
	return
}

func FindNTLMSSP(buf []byte) []byte {
	idx := bytes.Index(buf, []byte(NTLMSSPSig))
	if idx < 0 {
		return nil
	}
	return buf[idx:]
}

// ---------- ASN.1 DER / SPNEGO helpers ----------

var ntlmsspOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
var spnegoOID = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

func DerLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func DerTag(tag byte, data []byte) []byte {
	out := []byte{tag}
	out = append(out, DerLen(len(data))...)
	return append(out, data...)
}

func BuildSPNEGONegotiateToken() []byte {
	mechTypeList := DerTag(0x30, ntlmsspOID)
	mechTypes := DerTag(0xa0, mechTypeList)
	innerSeq := DerTag(0x30, mechTypes)
	negTokenInit := DerTag(0xa0, innerSeq)
	content := append(spnegoOID, negTokenInit...)
	return DerTag(0x60, content)
}

func WrapSPNEGOChallenge(ntlmChallenge []byte) []byte {
	negState := DerTag(0xa0, []byte{0x0a, 0x01, 0x01})
	supportedMech := DerTag(0xa1, ntlmsspOID)
	responseToken := DerTag(0xa2, DerTag(0x04, ntlmChallenge))
	inner := append(negState, supportedMech...)
	inner = append(inner, responseToken...)
	return DerTag(0xa1, DerTag(0x30, inner))
}
